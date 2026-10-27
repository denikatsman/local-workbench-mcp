"""Bounded, provenance-bearing views over retained original bytes."""
from __future__ import annotations

import hashlib
import io
import json
import re
import time
import threading

from .errors import WorkbenchError


def response_size(result):
    text = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    return len(json.dumps({"content": [{"type": "text", "text": text}]},
                          ensure_ascii=True, separators=(",", ":")).encode()) + 1024


def add_result_continuation(envelope, artifact, max_bytes):
    """Describe an original JSON spill using only host-store metadata.

    This read guide never replaces outcome facts or changes the stored result.
    If it cannot fit, return the exact existing envelope without new failure.
    """
    artifact_id = artifact.get('artifact_id')
    total_bytes = artifact.get('bytes')
    if (envelope.get('inline_complete') is not False
            or envelope.get('result_artifact') != artifact_id
            or not isinstance(artifact_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact_id)
            or type(total_bytes) is not int or total_bytes < 0
            or type(max_bytes) is not int or max_bytes <= 0):
        return envelope
    continuation = {'kind': 'read_original_result', 'format': 'application/json',
        'tool': 'artifact_read', 'arguments': {'artifact_id': artifact_id, 'offset': 0, 'max_bytes': 16384},
        'total_bytes': total_bytes, 'parse_after': 'eof', 'continue_offset_field': 'next_offset',
        'replay_input': False, 'refreshes_authority': False}
    if artifact.get('sha256') == artifact_id[7:]:
        continuation['sha256'] = artifact['sha256']
    candidate = {**envelope, 'result_continuation': continuation}
    if (response_size(candidate) <= max_bytes
            and len(json.dumps(candidate, ensure_ascii=True).encode()) + 512 <= max_bytes):
        return candidate
    return envelope


def display_bytes(data):
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="backslashreplace"), True


class ArtifactViews:
    def __init__(self, store):
        self.store = store
        self._image_slots = threading.BoundedSemaphore(2)

    def preview(self, artifact_id, max_width=1600, max_height=1200):
        from PIL import Image, UnidentifiedImageError
        if any(type(value) is not int or not 64 <= value <= 2048 for value in (max_width,max_height)):
            raise WorkbenchError("invalid_dimensions", "Preview dimensions must be 64..2048 pixels.")
        path = self.store.path(artifact_id)
        if path.stat().st_size > 16 * 1024 * 1024:
            raise WorkbenchError("preview_limit", "Image preview input is limited to 16 MiB; raw bytes remain available.")
        if not self._image_slots.acquire(blocking=False):
            raise WorkbenchError("preview_busy", "Two image previews are already running; retry after they finish.")
        try:
            try:
                with self.store.reading(artifact_id) as source, Image.open(source) as original:
                    if original.format not in {"PNG","JPEG","GIF","WEBP"}:
                        raise WorkbenchError("unsupported_mime", "Preview supports PNG, JPEG, GIF and WebP.")
                    source_size = original.size
                    if source_size[0] * source_size[1] > 16_000_000:
                        raise WorkbenchError("preview_limit", "Image exceeds the 16 megapixel decode limit.")
                    original.seek(0)
                    original.load()
                    rgba = original.convert("RGBA")
                    rgba.thumbnail((max_width,max_height), Image.Resampling.LANCZOS)
                    preview = Image.new("RGB",rgba.size,"white")
                    preview.paste(rgba, mask=rgba.getchannel("A"))
                    for quality in (80,65,50):
                        buffer = io.BytesIO()
                        preview.save(buffer,format="JPEG",quality=quality)
                        encoded = buffer.getvalue()
                        if len(encoded) <= 2 * 1024 * 1024:
                            break
                    else:
                        raise WorkbenchError("preview_limit", "Preview exceeds the encoded image budget; request smaller dimensions.")
                    artifact = self.store.put_bytes(encoded,"image-preview:"+artifact_id)
                    return {"ok":True,"source_artifact":artifact_id,"preview_artifact":artifact,
                            "source_dimensions":list(source_size),"dimensions":list(preview.size),"mime_type":"image/jpeg",
                            "transform":{"name":"image_preview","version":1,"frame":0,"quality":quality,"alpha_background":"white"},
                            "raw_source_retained":True,"presentation":"native_image_content"}
            except (UnidentifiedImageError,Image.DecompressionBombError,OSError,ValueError) as exc:
                raise WorkbenchError("invalid_image", "Image could not be decoded within the supported limits.") from exc
        finally:
            self._image_slots.release()

    @staticmethod
    def budget(max_bytes):
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError("invalid_range", "max_bytes must be 4096..262144 including result overhead.")

    def view(self, artifact_id, kind="text", offset=0, length=16384, start_line=1, line_count=40,
             json_pointer="", max_bytes=8192):
        self.budget(max_bytes)
        if kind not in {"text", "lines", "hex", "json"}:
            raise WorkbenchError("invalid_view", "Use text, lines, hex, or json.")
        if type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= 262144:
            raise WorkbenchError("invalid_range", "Use a nonnegative byte offset and length 1..262144.")
        path = self.store.path(artifact_id)
        total = path.stat().st_size
        if offset > total:
            raise WorkbenchError("invalid_range", "Offset exceeds the source length.", total_bytes=total)
        common = {"ok": True, "source_artifact": artifact_id, "source_bytes": total,
                  "transform": kind, "transform_version": 1, "raw_source_retained": True,
                  "integrity_verified_this_call": False}
        if kind == "json":
            if total > 8 * 1024 * 1024:
                raise WorkbenchError("view_limit", "JSON parsing is bounded to 8 MiB; use exact pages or NDJSON query for larger input.")
            if not isinstance(json_pointer, str) or len(json_pointer) > 4096:
                raise WorkbenchError("invalid_pointer", "JSON pointer must be a string up to 4096 characters.")
            try:
                with self.store.reading(artifact_id) as source:
                    value = json.load(source)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise WorkbenchError("invalid_json", "Source is not a supported JSON document.") from exc
            if json_pointer:
                if not json_pointer.startswith("/"):
                    raise WorkbenchError("invalid_pointer", "Use an empty pointer for the document or an RFC 6901 /path.")
                for part in json_pointer[1:].split("/"):
                    if re.search(r"~(?![01])", part):
                        raise WorkbenchError("invalid_pointer", "Only ~0 and ~1 are valid pointer escapes.")
                    key = part.replace("~1", "/").replace("~0", "~")
                    try:
                        if isinstance(value, list):
                            if not key.isascii() or not key.isdecimal() or len(key) > 10 or (len(key) > 1 and key.startswith("0")):
                                raise KeyError(key)
                            value = value[int(key)]
                        elif isinstance(value, dict):
                            value = value[key]
                        else:
                            raise KeyError(key)
                    except (KeyError, IndexError) as exc:
                        raise WorkbenchError("pointer_not_found", "The requested JSON value does not exist.") from exc
            result = {**common, "json_pointer": json_pointer, "value": value, "view_complete": True,
                      "coordinate_units": "JSON pointer; original formatting remains in source_artifact"}
            if response_size(result) > max_bytes:
                encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
                derived = self.store.put_bytes(encoded, "json-view:" + artifact_id + ":" + json_pointer)
                result = {**common, "json_pointer": json_pointer, "view_complete": False, "derived_artifact": derived,
                          "value_type": type(value).__name__,
                          "coordinate_units": "JSON pointer; original formatting remains in source_artifact",
                          "note": "Selected value is retained in full; retrieve its exact pages."}
                if response_size(result) > max_bytes:
                    raise WorkbenchError("response_budget", "Increase max_bytes to include this pointer's metadata.",
                                         derived_artifact_id=derived["artifact_id"])
                return result
            return result
        with self.store.reading(artifact_id) as source:
            source.seek(offset)
            requested_complete = True
            if kind == "lines":
                if type(start_line) is not int or start_line < 1 or type(line_count) is not int or not 1 <= line_count <= 200:
                    raise WorkbenchError("invalid_range", "Lines are 1-based; line_count must be 1..200.")
                if offset:
                    raise WorkbenchError("invalid_range", "Use start_line for a line view; use text and next_offset for byte continuation.")
                current_line, deadline = 1, time.monotonic() + 3
                while current_line < start_line:
                    part = source.readline(65536)
                    if not part:
                        raise WorkbenchError("line_not_found", "Requested start line exceeds the source.")
                    current_line += part.endswith(b"\n")
                    if source.tell() > 16 * 1024 * 1024 or time.monotonic() > deadline:
                        raise WorkbenchError("line_index_limit", "Line discovery budget reached; continue with a byte view.",
                                             byte_offset=source.tell(), current_line=current_line)
                offset = source.tell()
                captured = source.read(262144)
                ends = [i + 1 for i, value in enumerate(captured) if value == 10]
                if len(ends) >= line_count:
                    captured = captured[:ends[line_count - 1]]
                else:
                    requested_complete = offset + len(captured) == total
                common.update(start_line=start_line, requested_lines=line_count)
            else:
                captured = source.read(length)
        def render(count):
            chunk = captured[:count]
            if kind == "hex":
                shown = "\n".join(f"{offset+i:08x}  " + chunk[i:i+16].hex(" ") for i in range(0, len(chunk), 16))
                transformed = True
            else:
                shown, transformed = display_bytes(chunk)
            complete = count == len(captured) and requested_complete
            return {**common, "data": shown, "display_transformed": transformed,
                    "byte_start": offset, "byte_end": offset + count, "source_bytes_returned": count,
                    "coordinate_units": "UTF-8 byte offsets; lines are 1-based",
                    "view_complete": complete, "source_eof": offset + count == total,
                    "next_offset": None if offset + count == total else offset + count,
                    "continuation_kind": "hex" if kind == "hex" else "text"}
        low, high, best = 0, len(captured), render(0)
        while low <= high:
            middle = (low + high) // 2
            candidate = render(middle)
            if response_size(candidate) <= max_bytes:
                best, low = candidate, middle + 1
            else:
                high = middle - 1
        return best

    def search(self, artifact_id, query, offset=0, case_sensitive=True, before_bytes=80, after_bytes=160,
               max_matches=20, max_bytes=8192, max_scan_bytes=16 * 1024 * 1024):
        self.budget(max_bytes)
        if not isinstance(query, str) or not 1 <= len(query.encode()) <= 4096:
            raise WorkbenchError("invalid_query", "Use a literal query containing 1..4096 UTF-8 bytes.")
        for value, minimum, maximum in [(offset,0,2**63-1),(before_bytes,0,4096),(after_bytes,0,4096),
                                         (max_matches,1,100),(max_scan_bytes,65536,64*1024*1024)]:
            if type(value) is not int or not minimum <= value <= maximum:
                raise WorkbenchError("invalid_range", "Search limits are outside the supported range.")
        path = self.store.path(artifact_id)
        total = path.stat().st_size
        if offset > total:
            raise WorkbenchError("invalid_range", "Offset exceeds the source.")
        needle = query.encode()
        if not case_sensitive:
            needle = needle.lower()
        result = {"ok": True, "source_artifact": artifact_id, "source_bytes": total,
                  "query_sha256": hashlib.sha256(query.encode()).hexdigest(), "matches": [],
                  "case_folding": "exact bytes" if case_sensitive else "ASCII bytes only",
                  "scan_started_at": offset, "scan_complete": False, "next_offset": offset,
                  "stop_reason": None, "raw_source_retained": True, "transform_version": 1}
        position, eligible, tail = offset, offset, b""
        deadline = time.monotonic() + 3
        with self.store.reading(artifact_id) as source, self.store.reading(artifact_id) as context:
            source.seek(offset)
            while position < total:
                if position - offset >= max_scan_bytes or time.monotonic() > deadline:
                    result.update(next_offset=max(offset, eligible, position-len(tail)), stop_reason="scan_budget")
                    return result
                chunk = source.read(min(65536, max_scan_bytes-(position-offset)))
                if not chunk:
                    break
                data = tail + chunk
                base = position - len(tail)
                haystack = data if case_sensitive else data.lower()
                cursor = max(0, eligible-base)
                while (index := haystack.find(needle, cursor)) >= 0:
                    match = base + index
                    begin, end = max(0, match-before_bytes), min(total, match+len(needle)+after_bytes)
                    context.seek(begin)
                    snippet, transformed = display_bytes(context.read(end-begin))
                    item = {"byte_offset": match, "match_bytes": len(needle), "context_start": begin,
                            "context_end": end, "text": snippet, "display_transformed": transformed}
                    candidate = {**result, "matches": result["matches"]+[item], "next_offset": match+len(needle)}
                    if response_size({**candidate, "stop_reason": "response_budget", "next_offset": total}) > max_bytes:
                        if result["matches"]:
                            result.update(next_offset=match, stop_reason="response_budget")
                            return result
                        item = {"byte_offset": match, "match_bytes": len(needle), "snippet_omitted": "response_budget"}
                    result["matches"].append(item)
                    eligible = match+len(needle)
                    cursor = index+len(needle)
                    if len(result["matches"]) >= max_matches:
                        result.update(next_offset=eligible if eligible < total else None,
                                      scan_complete=eligible == total, stop_reason="match_limit" if eligible < total else None)
                        return result
                position += len(chunk)
                tail = data[-(len(needle)-1):] if len(needle)>1 else b""
        result.update(scan_complete=True, next_offset=None)
        return result
