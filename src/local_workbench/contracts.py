"""Pinned SDK integration: literal text, bounded diagnostics, invocation identity.

Keep the SDK-specific seam here; never patch installed dependency files.
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import re
import sqlite3
import time
import types
import uuid
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools.base import Tool
from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from mcp_types import CallToolResult, TextContent
from pydantic import ConfigDict, Field, ValidationError, create_model

from .errors import WorkbenchError
from .context import work_context


MAX_STRUCTURED_ERROR_BYTES = 8192


def closed_native_release(tool, arguments):
    """Admission candidate; native private cleanup still authenticates binding."""
    allowed = {'workspace', 'action', 'work_session_id', 'claim_id', 'request_id', 'max_bytes'}
    return (tool == 'native_app' and arguments.get('action') == 'release'
        and isinstance(arguments.get('claim_id'), str)
        and re.fullmatch(r'[0-9a-f]{32}', arguments['claim_id']) is not None
        and all(value is None or key in allowed for key, value in arguments.items()))


def closed_browser_recovery(tool, arguments):
    """Admission candidate only; the server still checks the retained record.

    Upload-stage cleanup can mutate a live file input and is never recovery
    authority for a closed session. No legacy grant or new target is admitted.
    """
    if (tool != 'selected_browser' or arguments.get('action') not in ('claim_status', 'cleanup')
            or arguments.get('lease_id') is not None or arguments.get('upload_stage_id') is not None
            or not isinstance(arguments.get('claim_id'), str)
            or not re.fullmatch(r'[0-9a-f]{32}', arguments['claim_id'])):
        return False
    return arguments['action'] == 'claim_status' or (
        type(arguments.get('claim_epoch')) is int and arguments['claim_epoch'] >= 1
        and isinstance(arguments.get('target_generation'), str)
        and re.fullmatch(r'[0-9a-f]{32}', arguments['target_generation']) is not None)


def _bounded_error_structure(result, text):
    # Large failure details stay in the original, complete text payload. Do
    # not double them merely to offer a second representation.
    return result if len(text.encode('utf-8')) <= MAX_STRUCTURED_ERROR_BYTES else None


def permits_text(annotation) -> bool:
    if annotation is str:
        return True
    origin = get_origin(annotation)
    if origin is Annotated:
        return permits_text(get_args(annotation)[0])
    if origin in (Union, types.UnionType):
        return any(permits_text(member) for member in get_args(annotation))
    return origin is Literal and any(isinstance(value, str) for value in get_args(annotation))


def permits_scalar(annotation) -> bool:
    """Keep scalar null strings for Pydantic instead of SDK nullable coercion."""
    if annotation in (bool, int, float):
        return True
    origin = get_origin(annotation)
    if origin is Annotated:
        return permits_scalar(get_args(annotation)[0])
    if origin in (Union, types.UnionType):
        return any(permits_scalar(member) for member in get_args(annotation))
    return False


class LiteralTextMetadata(FuncMetadata):
    async def call_fn(self,fn,fn_is_async,arguments,arguments_to_pass_directly=None):
        arguments=dict(arguments)
        session_id=arguments.pop('work_session_id',None)
        token=work_context.set(session_id)
        try:
            return await super().call_fn(fn,fn_is_async,arguments,arguments_to_pass_directly)
        finally:work_context.reset(token)

    def pre_parse_json(self, data):
        fields = {}
        for name, field in self.arg_model.model_fields.items():
            fields[name] = field
            if field.alias:
                fields[field.alias] = field
        literal = {key: value for key, value in data.items()
                   if isinstance(value, str) and key in fields and (permits_text(fields[key].annotation)
                       # SDK 2.2 preserves other JSON scalars but turns a raw
                       # null string into None before optional scalar validation.
                       # Keep container JSON preprocessing unchanged.
                       or value.strip() == 'null' and permits_scalar(fields[key].annotation))}
        other = {key: value for key, value in data.items() if key not in literal}
        return {**super().pre_parse_json(other), **literal}


class InvocationLog:
    """Small received/completed records. No argument values or raw error inputs."""
    def __init__(self, state_dir, instance_id, executor=None):
        self.path = state_dir / "invocations.sqlite3"
        self.instance_id = instance_id
        self.executor = executor
        self.sessions = None
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS invocations (trace_id TEXT PRIMARY KEY, request_id TEXT, tool TEXT NOT NULL, instance_id TEXT NOT NULL, started REAL NOT NULL, finished REAL, outcome TEXT, argument_types TEXT NOT NULL, error_code TEXT, returned_bytes INTEGER)")
            db.execute("CREATE INDEX IF NOT EXISTS invocation_request ON invocations(request_id, started)")

    async def dispatch(self, function, *args):
        return await asyncio.get_running_loop().run_in_executor(self.executor,functools.partial(function,*args))

    @contextlib.contextmanager
    def db(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db

    def begin(self, trace_id, tool, arguments, known_fields, correlate_request=True):
        # In read tools, request_id is a lookup target, not a new mutation
        # attempt. Recording that query as an attempt pollutes its own result.
        request_id = arguments.get("request_id") if correlate_request else None
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", request_id):
            request_id = None
        kinds = {key: type(arguments[key]).__name__ for key in known_fields if key in arguments}
        with self.db() as db:
            db.execute("INSERT INTO invocations VALUES (?,?,?,?,?,NULL,'received',?,NULL,NULL)",
                       (trace_id, request_id, tool, self.instance_id, time.time(), json.dumps(kinds)))

    def finish(self, trace_id, result, returned_bytes):
        with self.db() as db:
            db.execute("UPDATE invocations SET finished=?,outcome=?,error_code=?,returned_bytes=? WHERE trace_id=?",
                       (time.time(), "error" if result.get("ok") is False else "returned",
                        result.get("error", {}).get("code"), returned_bytes, trace_id))

    def status(self, trace_id=None, request_id=None, limit=10):
        if (trace_id is None) == (request_id is None) or type(limit) is not int or not 1 <= limit <= 25:
            raise WorkbenchError("invalid_query", "Supply one trace_id or request_id and limit 1..25.")
        value = trace_id if trace_id is not None else request_id
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
            raise WorkbenchError("invalid_query", "Invalid invocation identifier.")
        column = "trace_id" if trace_id is not None else "request_id"
        with self.db() as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(f"SELECT * FROM invocations WHERE {column}=? ORDER BY started DESC,trace_id DESC LIMIT ?",
                              (value, limit + 1)).fetchall()
        events = [dict(row) for row in rows[:limit]]
        for event in events:
            event["argument_types"] = json.loads(event["argument_types"])
        return {"ok": True, "invocations": events, "more": len(rows) > limit,
                "scope": "requests received by this service; no visibility into upstream blocks",
                "note": "received without a finish means outcome unknown; reconcile the operation before retrying"}


class ObservedTool(Tool):
    observer: Any = Field(default=None, exclude=True)

    async def run(self, arguments, context, convert_result=False):
        gate = getattr(self.observer, 'activity_gate', None)
        try:
            with contextlib.ExitStack() as admitted:
                if gate is not None:
                    control = self.name in {'job_cancel', 'job_status', 'operation_status', 'invocation_status'}
                    control = control or self.name == 'terminal' and arguments.get('action') in ('stop', 'interrupt')
                    control = control or self.name == 'service' and arguments.get('action') == 'stop'
                    control = control or self.name == 'browser_download' and arguments.get('action') == 'cancel'
                    control = control or self.name == 'selected_download' and arguments.get('action') in ('cancel', 'stop')
                    control = control or self.name == 'native_app' and arguments.get('action') == 'cancel'
                    control = control or self.name == 'selected_browser' and arguments.get('action') in ('stop', 'detach')
                    admitted.enter_context(gate.admission(control=control))
                return await self._run_observed(arguments, context, convert_result)
        except WorkbenchError as exc:
            result = {**exc.as_dict(), 'schema_version': 1, 'server_instance_id': self.observer.instance_id}
            text = json.dumps(result)
            return CallToolResult(content=[TextContent(type='text', text=text)],
                                  structured_content=_bounded_error_structure(result, text), isError=True)

    async def _run_observed(self, arguments, context, convert_result=False):
        trace_id, started = uuid.uuid4().hex, time.monotonic()
        recorded = True
        try:
            await self.observer.dispatch(self.observer.begin, trace_id, self.name, arguments,
                                    tuple(self.parameters.get("properties", {})),
                                    bool(self.annotations and self.annotations.read_only_hint is False))
        except (OSError, sqlite3.Error):
            recorded = False
        from .context import invocation_trace
        trace_token = invocation_trace.set(trace_id)
        try:
            policy = getattr(self.observer, 'capability_policy', None)
            if policy is not None:
                policy.check(self.name, arguments)
            sessions = self.observer.sessions
            read_only_action = bool(self.annotations and self.annotations.read_only_hint) or (
                self.name in ('browser_download', 'selected_download') and arguments.get('action') == 'state') or (
                self.name == 'native_app' and arguments.get('action') == 'receipt')
            admission = sessions.admission(arguments.get('work_session_id'),
                allow_closed=read_only_action or closed_browser_recovery(self.name, arguments)
                    or closed_native_release(self.name, arguments)) if sessions else contextlib.nullcontext()
            with admission:
                response = await super().run(arguments, context, convert_result=True)
        except WorkbenchError as exc:
            response = CallToolResult(content=[TextContent(type='text', text=json.dumps(exc.as_dict()))], isError=True)
        except ToolError as exc:
            cause = exc.__cause__
            if isinstance(cause, ValidationError):
                errors = cause.errors(include_input=False, include_context=False, include_url=False)
                fields = [{"field": str(error["loc"][0]) if error["loc"] and error["loc"][0] in self.parameters.get("properties", {}) else "arguments",
                           "code": error["type"]} for error in errors[:16]]
                result = {"ok": False, "error": {"code": "argument_validation", "message": "Arguments do not match the tool schema.",
                                                "fields": fields, "phase": "validation", "effect_state": "none"}}
            else:
                result = {"ok": False, "error": {"code": "tool_error", "message": "The tool could not return a result; reconcile before retrying.",
                                                "effect_state": "unknown"}}
            response = CallToolResult(content=[TextContent(type="text", text=json.dumps(result))], isError=True)
        finally:
            invocation_trace.reset(trace_token)
        result = json.loads(response.content[0].text)
        error = result.get('error')
        if (self.name == 'native_app' and arguments.get('action') == 'acquire'
                and response.is_error and isinstance(error, dict)
                and error.get('code') == 'native_process_identity_changed'
                and error.get('effect_state') == 'none'):
            error.setdefault('recovery',
                'Acquisition was refused before input. The process may have changed or app_identity may be incomplete. '
                'Run native_app discover again, select the intended window, then copy its complete app object unchanged '
                'into app_identity, including signingIdentifier, teamID, designatedRequirement and processGeneration '
                'when returned. Preserve nulls and full launchedAt precision; do not invent missing values or replay input.')
        result.update(schema_version=1, trace_id=trace_id, server_instance_id=self.observer.instance_id,
                      elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        session_id=arguments.get('work_session_id')
        if isinstance(session_id,str) and self.observer.sessions is not None:
            try:
                request_id=arguments.get('request_id')
                if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',request_id):
                    request_id=None
                await self.observer.dispatch(self.observer.sessions.record,session_id,trace_id,self.name,
                                             request_id,result)
                result['invocation_work_session_id']=session_id
            except (WorkbenchError,OSError,sqlite3.Error):
                result['session_recorded']=False
        if not recorded:
            result["invocation_recorded"] = False
        response.content[0].text = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if response.is_error:
            # Keep a real MCP failure, including any OAuth challenge. Some
            # clients consume structured details instead of the text block.
            response.structured_content = _bounded_error_structure(result, response.content[0].text)
        try:
            await self.observer.dispatch(self.observer.finish, trace_id, result,
                                    len(response.model_dump_json(by_alias=True, exclude_none=True).encode()))
        except (OSError, sqlite3.Error):
            result["invocation_recorded"] = False
            response.content[0].text = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
            if response.is_error:
                response.structured_content = _bounded_error_structure(result, response.content[0].text)
        return response


def registered_tool(fn, observer, **options):
    tool = ObservedTool.from_function(fn, structured_output=False, **options)
    metadata = tool.fn_metadata
    arguments = create_model(metadata.arg_model.__name__, __base__=metadata.arg_model,
                             __config__=ConfigDict(**{**metadata.arg_model.model_config, "extra": "forbid"}),
                             work_session_id=(str|None,None))
    tool.parameters = arguments.model_json_schema(by_alias=True)
    tool.fn_metadata = LiteralTextMetadata(arg_model=arguments, output_schema=metadata.output_schema,
                                          output_model=metadata.output_model, wrap_output=metadata.wrap_output)
    tool.observer = observer
    return tool
