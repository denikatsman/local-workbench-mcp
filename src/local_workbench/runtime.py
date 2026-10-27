"""Operational provenance and passive, explicitly host-scoped tool discovery."""
from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import marshal
import os
from pathlib import Path
import re
import shutil
import sys
import time

from .errors import WorkbenchError
from . import __version__

DEFAULT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"


class RuntimeIdentity:
    def __init__(self, instance_id, tools):
        self.instance_id, self.started_at = instance_id, time.time()
        self.source_root = Path(__file__).parent
        self.sources = self._disk_manifest()
        self.tools = [{"name": tool.name, "description": tool.description, "parameters": tool.parameters,
                       "annotations": tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True) if tool.annotations else None,
                       "meta": tool.meta, "output_schema": tool.output_schema}
                      for tool in tools]
        self.schema_digest = self._digest(self.tools)
        self.dependencies = {}
        for name in ('mcp','mcp-types','pydantic','playwright','Pillow'):
            try:self.dependencies[name]=importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:self.dependencies[name]='not_installed'
        code = {}
        for name, module in tuple(sys.modules.items()):
            if not name.startswith("local_workbench.") or module is None:
                continue
            for key, value in vars(module).items():
                if getattr(value, "__module__", None) != name:
                    continue
                members = vars(value).items() if inspect.isclass(value) else [(key, value)]
                for member, function in members:
                    if isinstance(function, (staticmethod, classmethod)):
                        function = function.__func__
                    if inspect.isfunction(function):
                        code[name + ":" + key + ":" + member] = hashlib.sha256(marshal.dumps(function.__code__)).hexdigest()
        self.loaded_code_digest = self._digest(code)

    @staticmethod
    def _digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _disk_manifest(self):
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(self.source_root.glob("*.py"))}

    def describe(self, include_tools=False, check_disk=False):
        result = {"ok": True, "server_instance_id": self.instance_id, "started_at": self.started_at,
                  "version": __version__,
                  "schema_sha256": self.schema_digest, "tool_names": [tool["name"] for tool in self.tools],
                  "startup_source_sha256": self._digest(self.sources), "loaded_callable_code_sha256": self.loaded_code_digest,
                  "identity_scope": "startup disk files and loaded Python callable bytecode; not whole-process attestation",
                  "python": {"executable": sys.executable, "version": sys.version.split()[0]},
                  "installed_dependency_versions_at_startup": dict(self.dependencies),
                  "execution_environment": {"default_path": DEFAULT_PATH, "shell_startup_files": "not sourced unless explicitly invoked"}}
        if check_disk:
            current = self._disk_manifest()
            result["disk_drift"] = {"checked_at": time.time(), "matches_startup": current == self.sources,
                                    "changed_files": [name for name in sorted(set(current) | set(self.sources))
                                                      if current.get(name) != self.sources.get(name)]}
        if include_tools:
            # Detailed schemas remain available through the protocol's tools/list.
            result["tools"] = [{"name": tool["name"], "description": tool["description"]} for tool in self.tools]
        return result


def resolve_environment(config, workspace, programs):
    selected = config.workspace(workspace)
    if not selected.executable:
        raise WorkbenchError("execution_denied", "Host toolchain discovery requires an executable workspace.")
    if not isinstance(programs, list) or not 1 <= len(programs) <= 32 or any(
            not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", name) for name in programs):
        raise WorkbenchError("invalid_programs", "Request 1..32 simple executable names.")
    home = Path.home()
    directories = [selected.root / ".venv/bin", selected.root / "node_modules/.bin", home / ".cargo/bin"]
    gaps = []
    for parent in (home / ".nvm/versions/node", home / ".pyenv/versions"):
        try:
            with os.scandir(parent) as entries:
                found = []
                for entry in entries:
                    if len(found) >= 100:
                        gaps.append({"path": str(parent), "reason": "candidate_limit"})
                        break
                    if entry.is_dir():
                        found.append(Path(entry.path) / "bin")
                directories.extend(sorted(found, reverse=True))
        except FileNotFoundError:
            pass
        except OSError:
            gaps.append({"path": str(parent), "reason": "inaccessible"})
    results = []
    for program in programs:
        default = shutil.which(program, path=DEFAULT_PATH)
        candidates = []
        for directory in directories:
            candidate = directory / program
            if candidate.is_file() and os.access(candidate, os.X_OK):
                candidates.append({"path": str(candidate), "path_prefix": str(directory), "state": "found_not_selected"})
        results.append({"program": program, "default_executable": default, "candidates": candidates,
                        "state": "available_in_default_path" if default else "found_not_selected" if candidates
                        else "unknown_due_to_incomplete_discovery" if gaps else "not_found_in_checked_locations"})
    return {"ok": True, "workspace": workspace, "programs": results, "default_path": DEFAULT_PATH,
            "gaps": gaps, "scope": "default PATH, project virtualenv/bin, node_modules/.bin, NVM, pyenv, Cargo",
            "version_commands_executed": False, "shell_configuration_executed": False,
            "next_step": "select an absolute executable; use an explicit job env PATH for its companion tools"}
