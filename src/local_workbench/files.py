from __future__ import annotations

import contextlib
import difflib
import errno
import fnmatch
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from pathlib import Path

from .config import Config
from .errors import WorkbenchError
from .store import ArtifactStore, Journal, validate_page
from .views import response_size
import regex as bounded_regex


def _same_file(a, b):
    return (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns)


class FileTools:
    """Descriptor-relative file operations; symlinks are visible but never followed."""

    def __init__(self, config: Config, store: ArtifactStore, journal: Journal):
        self.config, self.store, self.journal = config, store, journal
        self._roots = {name: os.open(item.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) for name, item in config.workspaces.items()}

    def close(self):
        for descriptor in self._roots.values():
            os.close(descriptor)
        self._roots.clear()

    def _root_descriptor(self, workspace):
        """Reopen only the configured directory whose identity was admitted at startup."""
        root = self.config.workspace(workspace).root
        try:
            current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise WorkbenchError('workspace_unavailable',
                                 'The configured workspace is unavailable. Restore its location before retrying.',
                                 workspace=workspace, effect_state='none') from error
        try:
            expected = os.fstat(self._roots[workspace])
            observed = os.fstat(current)
            if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino):
                raise WorkbenchError('workspace_changed',
                                     'The configured workspace now identifies a different directory. Explicitly reconfigure it before use.',
                                     workspace=workspace, effect_state='none')
            return current
        except BaseException:
            os.close(current)
            raise

    def _check_root(self, workspace):
        checked = self._root_descriptor(workspace)
        os.close(checked)

    @staticmethod
    def _parts(path: str, allow_root=False) -> list[str]:
        if not isinstance(path, str) or not path or "\x00" in path or "\\" in path or path.startswith("/"):
            raise WorkbenchError("unsafe_path", "Use a relative POSIX path without NULs or backslashes.")
        if ".." in path.split("/"):
            raise WorkbenchError("unsafe_path", "Parent traversal is not allowed.")
        parts = [p for p in path.split("/") if p not in ("", ".")]
        if not allow_root and not parts:
            raise WorkbenchError("unsafe_path", "This operation requires a file or subdirectory path.")
        return parts

    @contextlib.contextmanager
    def _parent(self, workspace: str, path: str):
        self.config.workspace(workspace)
        parts = self._parts(path)
        descriptor = self._root_descriptor(workspace)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield descriptor, parts[-1]
        except TimeoutError:
            # Regex timeouts raised by a caller inside this descriptor scope are
            # not filesystem failures (TimeoutError also subclasses OSError).
            raise
        except FileNotFoundError as error:
            raise WorkbenchError("not_found", "A file or parent directory does not exist.", path=path) from error
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise WorkbenchError("unsafe_path", "Symlinks and non-directory parents are not followed.", path=path) from error
            raise WorkbenchError("filesystem_error", "Filesystem operation failed.", path=path, reason=str(error)) from error
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def _regular(self, workspace, path):
        with self._parent(workspace, path) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise WorkbenchError("not_regular_file", "Only regular files can be read or edited.", path=path)
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    yield stream, info
            finally:
                os.close(descriptor)

    def authorize_native_launch_file(self, workspace, path):
        """Existing no-follow workspace file authority; no URI or path escape."""
        item = self.config.workspace(workspace)
        if not item.writable or not item.executable:
            raise WorkbenchError('native_launch_file_denied', 'Opening an editable app file requires a writable executable workspace.')
        parts = self._parts(path)
        with self._regular(workspace, path) as (stream, info):
            if info.st_nlink != 1:
                raise WorkbenchError('unsafe_path', 'App launch files must have one link.')
            root_fd = self._root_descriptor(workspace)
            try: root_info = os.fstat(root_fd)
            finally: os.close(root_fd)
            current = os.fstat(stream.fileno())
            if not _same_file(info, current):
                raise WorkbenchError('file_changed', 'The launch file changed during authorization.')
            return {'workspace_root': str(item.root), 'relative_path': '/'.join(parts),
                'root_device': root_info.st_dev, 'root_inode': root_info.st_ino,
                'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'size': info.st_size,
                'modified_seconds': info.st_mtime_ns // 1000000000, 'modified_nanoseconds': info.st_mtime_ns % 1000000000,
                'changed_seconds': info.st_ctime_ns // 1000000000, 'changed_nanoseconds': info.st_ctime_ns % 1000000000}

    def workspace_info(self):
        from .capability_profiles import CapabilityPolicy
        return {"ok": True, "workspaces": [{"name": name, "root": str(item.root), "writable": item.writable, "executable": item.executable} for name, item in self.config.workspaces.items()],
                "capability_policy": CapabilityPolicy(self.config.capability_profile, self.config.history_access).describe(),
                "limits": {"max_artifact_bytes": self.config.max_artifact_bytes, "max_storage_bytes": self.config.max_storage_bytes, "max_job_output_bytes": self.config.max_job_output_bytes, "max_jobs": self.config.max_jobs, "max_page_bytes": 262144},
                "storage_bytes": self.store.storage_bytes(),
                "semantics": {"file_paths": "relative, no symlink following", "paging": "exact bytes; base64 if a page is not independently valid UTF-8", "snapshots": "immutable SHA-256; continue with artifact_read rather than read_file", "execution": "runs as the host user when explicitly enabled; workspace roots do not sandbox commands", "retention": "no automatic pruning", "edits": "hash precondition + durable before/after artifacts + atomic single-file replacement; external writers are not locked"}}

    def read_file(self, workspace: str, path: str, offset=0, max_bytes=16384):
        validate_page(offset, max_bytes)
        with self._regular(workspace, path) as (stream, before):
            if before.st_size > self.config.max_artifact_bytes:
                raise WorkbenchError("artifact_limit", "File exceeds snapshot limit; increase configured limit to retrieve it completely.", total_bytes=before.st_size)
            artifact = self.store.put_stream(stream, f"file:{workspace}:{path}")
            after = os.fstat(stream.fileno())
            if not _same_file(before, after):
                raise WorkbenchError("file_changed", "File changed during snapshot; snapshot is retained but not a verified stable revision.", candidate_artifact=artifact["artifact_id"])
        self._check_root(workspace)
        return {**self.store.read(artifact["artifact_id"], offset, max_bytes), "workspace": workspace, "path": path,
                "capture_id":artifact["capture_id"],"revision_sha256": artifact["sha256"], "mtime_ns": before.st_mtime_ns, "snapshot_stable": True}

    def _walk(self, workspace, path, recursive=True, max_depth=None, exclude_globs=()):
        """Yield every entry, including failures; no dotfile/gitignore filtering."""
        self.config.workspace(workspace)
        parts = self._parts(path, allow_root=True)
        descriptor = self._root_descriptor(workspace)
        try:
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child

            def walk(current, prefix, depth=0):
                try:
                    names = sorted(os.listdir(current))
                except OSError as error:
                    yield {"path": prefix or ".", "type": "error", "error": str(error)}
                    return
                for name in names:
                    relative = "/".join(filter(None, (prefix, name)))
                    try:
                        info = os.stat(name, dir_fd=current, follow_symlinks=False)
                        kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
                        record={"path": relative, "type": kind, "bytes": info.st_size, "mtime_ns": info.st_mtime_ns}
                        excluded=next((pattern for pattern in exclude_globs if fnmatch.fnmatchcase(relative,pattern)
                                       or ('/' not in pattern and fnmatch.fnmatchcase(name,pattern))),None)
                        if excluded is not None:
                            record.update(excluded=True,exclusion_pattern=excluded)
                        elif recursive and kind=='directory' and max_depth is not None and depth+1>=max_depth:
                            record['descent_skipped']='max_depth'
                        yield record
                        if excluded is not None or record.get('descent_skipped'):
                            continue
                        if recursive and kind == "directory":
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                            try:
                                yield from walk(child, relative,depth+1)
                            finally:
                                os.close(child)
                    except OSError as error:
                        yield {"path": relative, "type": "error", "error": str(error)}

            yield from walk(descriptor, "/".join(parts))
            # A root replaced during traversal cannot become a complete absence claim.
            self._check_root(workspace)
        except OSError as error:
            raise WorkbenchError("unsafe_path", "Directory is unavailable or crosses a symlink.", reason=str(error)) from error
        finally:
            os.close(descriptor)

    def _manifest(self, records, source, summary):
        with tempfile.TemporaryFile(dir=self.store.temporary) as target:
            count = 0
            available = self.config.max_storage_bytes - self.store.storage_bytes()
            for record in records:
                payload = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
                count += len(payload)
                if count > self.config.max_artifact_bytes:
                    raise WorkbenchError("artifact_limit", "Complete result exceeds the artifact limit. Narrow the query or increase the limit; no partial result was published.")
                if count * 2 > available:
                    raise WorkbenchError("storage_limit", "Insufficient storage for a complete result.")
                target.write(payload)
            target.seek(0)
            artifact = self.store.put_stream(target, source)
        return {"ok": True, **summary, "format": "ndjson", **artifact, "page": self.store.read(artifact["artifact_id"])}

    def list_files(self, workspace: str, path=".", recursive=True):
        summary = {"entries": 0, "errors": 0, "complete": True, "workspace": workspace, "path": path, "recursive": recursive, "hidden_included": True, "gitignore_applied": False, "consistency": "live traversal, not an atomic directory snapshot"}

        def records():
            for record in self._walk(workspace, path, recursive):
                summary["entries"] += 1
                if record["type"] == "error":
                    summary["errors"] += 1
                    summary["complete"] = False
                yield record

        return self._manifest(records(), f"listing:{workspace}:{path}", summary)

    def inventory(self, workspace, path='.', max_depth=4, exclude_globs=None, max_entries=10000, max_bytes=8192):
        if type(max_depth) is not int or not 1<=max_depth<=64 or type(max_entries) is not int or not 1<=max_entries<=100000:
            raise WorkbenchError('invalid_range','Use depth 1..64 and entries 1..100000.')
        if type(max_bytes) is not int or not 4096<=max_bytes<=262144:
            raise WorkbenchError('invalid_range','max_bytes must be 4096..262144.')
        excludes=[] if exclude_globs is None else exclude_globs
        if not isinstance(excludes,list) or len(excludes)>100 or any(not isinstance(x,str) or not x or len(x)>512 for x in excludes):
            raise WorkbenchError('invalid_exclusions','Use up to 100 nonempty glob strings, each at most 512 characters.')
        summary={'workspace':workspace,'path':path,'entries':0,'types':{},'errors':0,'excluded_entries':0,
                 'depth_limited_directories':0,'complete_under_policy':True,'all_descendants_visited':True,
                 'policy':{'max_depth':max_depth,'exclude_globs':excludes,'max_entries':max_entries,
                           'hidden_included':True,'symlinks_followed':False,'case_sensitive_globs':True},
                 'consistency':'live metadata traversal; file contents are not read; no atomic directory snapshot'}
        self.config.workspace(workspace)
        root_info = os.fstat(self._roots[workspace])
        summary['root_identity'] = {'device_id': root_info.st_dev, 'directory_inode': root_info.st_ino,
                                    'binding': 'startup directory; device/inode rechecked before and after traversal'}
        extensions={};deadline=time.monotonic()+10
        def records():
            with contextlib.closing(self._walk(workspace,path,True,max_depth,excludes)) as entries:
                for item in entries:
                    if summary['entries']>=max_entries or time.monotonic()>deadline:
                        summary.update(complete_under_policy=False,all_descendants_visited=False,unvisited_count='unknown')
                        yield {'kind':'coverage_gap','reason':'entry_or_time_budget','unvisited_count':'unknown'}
                        break
                    summary['entries']+=1
                    kind=item['type'];summary['types'][kind]=summary['types'].get(kind,0)+1
                    if kind=='error':
                        summary['errors']+=1;summary['complete_under_policy']=False;summary['all_descendants_visited']=False
                    if item.get('excluded'):
                        summary['excluded_entries']+=1;summary['all_descendants_visited']=False
                    if item.get('descent_skipped'):
                        summary['depth_limited_directories']+=1;summary['all_descendants_visited']=False
                    if kind=='file':
                        extension=Path(item['path']).suffix.lower()[:40] or '(none)'
                        extensions[extension]=extensions.get(extension,0)+1
                    yield item
            self._check_root(workspace)
        result=self._manifest(records(),'inventory:'+workspace+':'+path,summary)
        result.pop('page',None)
        common=sorted(extensions.items(),key=lambda item:(-item[1],item[0]))
        result['extension_counts']=dict(common[:20])
        result['other_extension_classes']=max(0,len(common)-20)
        result['role_classification']='not inferred from file extensions; inspect source markers when needed'
        if response_size(result)>max_bytes:
            policy_artifact=self.store.put_bytes(json.dumps(summary,ensure_ascii=True).encode(),'inventory-summary')
            result={'ok':True,'artifact_id':result['artifact_id'],'summary_artifact':policy_artifact,
                    'entries':summary['entries'],'complete_under_policy':summary['complete_under_policy'],
                    'all_descendants_visited':summary['all_descendants_visited'],'view_complete':False}
        return result

    def search_text(self, workspace: str, query: str, path=".", regex=False, case_sensitive=True):
        if not isinstance(query, str) or not query or len(query.encode("utf-8")) > 65536:
            raise WorkbenchError("invalid_query", "query must contain 1–65536 UTF-8 bytes.")
        try:
            needle = query.encode("utf-8")
            if not case_sensitive:
                needle = needle.lower()
            pattern = bounded_regex.compile(query.encode("utf-8"), 0 if case_sensitive else bounded_regex.IGNORECASE) if regex else None
        except (bounded_regex.error, UnicodeError) as error:
            raise WorkbenchError("invalid_query", "Search expression is invalid.", reason=str(error)) from error
        summary = {"workspace": workspace, "path": path, "matches": 0, "files_scanned": 0, "unsearched_entries": 0, "complete": True, "regex": regex, "case_sensitive": case_sensitive, "case_folding": "ASCII for case-insensitive byte searches", "consistency": "matches reference immutable source artifacts; directory traversal is live", "match_format": "byte offsets and lengths; retrieve exact surrounding content with artifact_read", "regex_policy": "line-based, 256 KiB maximum line, 100 ms per line; failures reported explicitly", "time_budget_seconds": 20}
        deadline = time.monotonic() + 20

        def matches(stream):
            position = 0
            if regex:
                while line := stream.readline(262145):
                    if time.monotonic() > deadline:
                        raise WorkbenchError("search_deadline", "Search time budget reached; narrow the query.")
                    if len(line) > 262144:
                        raise WorkbenchError("regex_line_limit", "Regex line exceeds 256 KiB. Use literal search or a command job for this source.")
                    for match in pattern.finditer(line, timeout=0.1):
                        yield position + match.start(), match.end() - match.start()
                    position += len(line)
            else:
                tail = b""
                eligible = 0
                while chunk := stream.read(65536):
                    if time.monotonic() > deadline:
                        raise WorkbenchError("search_deadline", "Search time budget reached; narrow the query.")
                    data = tail + chunk
                    base = position - len(tail)
                    haystack = data if case_sensitive else data.lower()
                    cursor = max(0, eligible - base)
                    while (index := haystack.find(needle, cursor)) >= 0:
                        if time.monotonic() > deadline:
                            raise WorkbenchError("search_deadline", "Search time budget reached; narrow the query.")
                        yield base + index, len(needle)
                        cursor = index + len(needle)
                        eligible = base + cursor
                    position += len(chunk)
                    tail = data[-(len(needle) - 1):] if len(needle) > 1 else b""

        def entries():
            if self._parts(path, allow_root=True):
                with self._parent(workspace, path) as (parent, name):
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    yield {"path": path, "type": "file" if stat.S_ISREG(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"}
                    return
            yield from self._walk(workspace, path, recursive=True)

        def records():
            for entry in entries():
                if time.monotonic() > deadline:
                    summary["complete"] = False
                    yield {"kind": "search_deadline", "message": "Traversal stopped after 20 seconds. Narrow the path or use a command job; unvisited entries are unknown."}
                    break
                if entry["type"] == "directory":
                    continue
                if entry["type"] != "file":
                    summary["unsearched_entries"] += 1
                    summary["complete"] = False
                    yield {"kind": "unsearched", **entry}
                    continue
                filename = entry["path"]
                try:
                    with self._regular(workspace, filename) as (stream, before):
                        first = next(matches(stream), None)
                        if first is not None:
                            stream.seek(0)
                            artifact = self.store.put_stream(stream, f"search-source:{workspace}:{filename}")
                            if not _same_file(before, os.fstat(stream.fileno())):
                                raise WorkbenchError("file_changed", "File changed during search snapshot.")
                            with self.store.reading(artifact["artifact_id"]) as snapshot:
                                for byte_offset, length in matches(snapshot):
                                    summary["matches"] += 1
                                    yield {"kind": "match", "path": filename, "artifact_id": artifact["artifact_id"],
                                           "capture_id":artifact["capture_id"],"byte_offset": byte_offset, "match_bytes": length}
                        if not _same_file(before, os.fstat(stream.fileno())):
                            summary["complete"] = False
                            yield {"kind": "changed_during_search", "path": filename}
                    summary["files_scanned"] += 1
                except (WorkbenchError, TimeoutError) as error:
                    summary["unsearched_entries"] += 1
                    summary["complete"] = False
                    yield {"kind": "unsearched", "path": filename, "error": error.as_dict()["error"] if isinstance(error, WorkbenchError) else {"code": "regex_timeout", "message": "Regex exceeded its per-line time budget."}}

            self._check_root(workspace)

        return self._manifest(records(), f"search:{workspace}:{path}", summary)

    def _writable(self, workspace):
        if not self.config.workspace(workspace).writable:
            raise WorkbenchError("read_only", "Writes are not enabled for this workspace.")

    @staticmethod
    def _revision(expected):
        if expected is not None and not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise WorkbenchError("invalid_revision", "expected_sha256 must be the exact revision_sha256 from read_file, or null for create-only.")

    def _current(self, parent, name):
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return None, None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise WorkbenchError("not_regular_file", "Only regular files can be replaced.")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                artifact = self.store.put_stream(stream, "before-write")
            if not _same_file(before, os.fstat(descriptor)):
                raise WorkbenchError("file_changed", "Target changed while preparing the edit.")
            return artifact, before
        finally:
            os.close(descriptor)

    def _check_revision(self, before, expected):
        actual = before["sha256"] if before else None
        if actual != expected:
            raise WorkbenchError("revision_conflict", "Target differs from the expected revision; read it again before editing.", expected_sha256=expected, actual_sha256=actual, current_artifact=before["artifact_id"] if before else None)

    def _write(self, workspace, path, expected_sha256, after_bytes, dry_run=False, prepared=None, request_id=None):
        with self._parent(workspace, path) as (parent, name):
            parent_stat=os.fstat(parent)
            parent_identity={'device':str(parent_stat.st_dev),'inode':str(parent_stat.st_ino)}
            before, info = self._current(parent, name) if prepared is None else prepared
            self._check_revision(before, expected_sha256)
            after_path = after_bytes if isinstance(after_bytes, Path) else None
            after = {"artifact_id": "sha256:" + after_path.name, "sha256": after_path.name, "bytes": after_path.stat().st_size} if after_path else self.store.put_bytes(after_bytes, f"after-write:{workspace}:{path}")
            diff = None
            diff_status = "not_generated_large_file"
            if after["bytes"] <= 65536 and (before is None or before["bytes"] <= 65536):
                if before:
                    with self.store.reading(before['artifact_id']) as previous:
                        previous_bytes = previous.read()
                else:
                    previous_bytes = b''
                try:
                    old_text = previous_bytes.decode("utf-8")
                    new_text = (after_path.read_bytes() if after_path else after_bytes).decode("utf-8")
                    if old_text.count("\n") > 2000 or new_text.count("\n") > 2000:
                        diff_status = "not_generated_many_lines"
                    else:
                        diff_bytes = "".join(difflib.unified_diff(old_text.splitlines(keepends=True), new_text.splitlines(keepends=True), fromfile=path + " (before)", tofile=path + " (after)")).encode()
                        diff = self.store.put_bytes(diff_bytes, f"diff:{workspace}:{path}")
                        diff_status = "available"
                except UnicodeError:
                    diff_status = "not_generated_binary"
            response = {"ok": True, "workspace": workspace, "path": path, "dry_run": dry_run, "changed": before is None or before["sha256"] != after["sha256"], "before_artifact": before["artifact_id"] if before else None, "after_artifact": after["artifact_id"], "sha256": after["sha256"], "bytes": after["bytes"], "diff_artifact": diff["artifact_id"] if diff else None, "diff_status": diff_status, "external_writer_atomic_cas": False}
            response.update(would_change=response["changed"], applied_this_call=False,
                            effect_state="none", durability="not_applicable",parent_identity=parent_identity,
                            workspace_root=str(self.config.workspace(workspace).root))
            self._check_root(workspace)
            if dry_run or not response["changed"]:
                return response
            self.journal.checkpoint(request_id, {**response, "phase": "prepared"})
            temporary_name = ".workbench-write-" + uuid.uuid4().hex
            published, phase = False, "stage"
            staging_identity = None
            try:
                descriptor = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                with os.fdopen(descriptor, "wb") as target:
                    staging_info = os.fstat(target.fileno())
                    staging_identity = (staging_info.st_dev, staging_info.st_ino)
                    if after_path:
                        # Verify the exact descriptor copied into the staging
                        # file. A historic capture hash or a prior verify call
                        # cannot certify bytes reopened at this boundary.
                        source_fd = os.open(after_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(source_fd, "rb") as source:
                            source_before = os.fstat(source.fileno())
                            if not stat.S_ISREG(source_before.st_mode):
                                raise WorkbenchError("artifact_corrupt", "Publication source is not a regular artifact.", effect_state="none")
                            staged_hash, staged_bytes = hashlib.sha256(), 0
                            while data := source.read(1024 * 1024):
                                staged_bytes += len(data)
                                if staged_bytes > after["bytes"]:
                                    raise WorkbenchError("artifact_corrupt", "Artifact grew while staging publication.", effect_state="none")
                                staged_hash.update(data); target.write(data)
                            source_after = os.fstat(source.fileno())
                            if (not _same_file(source_before, source_after) or staged_bytes != after["bytes"]
                                    or staged_hash.hexdigest() != after["sha256"]):
                                raise WorkbenchError("artifact_corrupt", "Staged bytes do not match the artifact revision.", effect_state="none")
                    else:
                        target.write(after_bytes)
                    target.flush()
                    # Preserve ordinary permissions, never copy setuid/setgid onto replacement content.
                    os.fchmod(target.fileno(), stat.S_IMODE(info.st_mode) & 0o777 if info else 0o644)
                    os.fsync(target.fileno())
                # Recheck the current content immediately before publication. This coordinates service edits;
                # POSIX does not provide a hash-based compare-and-swap against uncooperative external writers.
                current, current_info = self._current(parent, name)
                self._check_revision(current, expected_sha256)
                if info is not None and not _same_file(info, current_info):
                    raise WorkbenchError("revision_conflict", "File identity or metadata changed while staging the edit.")
                phase = "publish"
                self.journal.checkpoint(request_id, {**response, "phase": "publishing", "effect_state": "unknown",
                                                     "durability": "unknown"})
                self._check_root(workspace)
                if before is None:
                    # Atomic no-clobber creation: another writer cannot slip a new target into this gap.
                    try:
                        os.link(temporary_name, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                    except FileExistsError as error:
                        raise WorkbenchError("revision_conflict", "Target was created by another writer.") from error
                    published = True
                    os.unlink(temporary_name, dir_fd=parent)
                else:
                    os.replace(temporary_name, name, src_dir_fd=parent, dst_dir_fd=parent)
                    published = True
                phase = "parent_directory_fsync"
                os.fsync(parent)
                response.update(applied_this_call=True, effect_state="published", durability="confirmed")
                self.journal.checkpoint(request_id, {**response, "phase": "published"})
            except OSError as error:
                publication_unknown = not published and phase == "publish"
                raise WorkbenchError("filesystem_error", "File publication or durability confirmation failed; inspect the effect state before retrying.",
                                     path=path, phase=phase, effect_state="published" if published else "unknown" if publication_unknown else "none",
                                     applied_this_call=None if publication_unknown else published,
                                     durability="unknown" if published or publication_unknown else "not_applicable",
                                     before_artifact=response["before_artifact"], after_artifact=response["after_artifact"],
                                     intended_sha256=after["sha256"], request_id=request_id,workspace=workspace,
                                     workspace_root=response['workspace_root'],parent_identity=parent_identity) from error
            finally:
                try:
                    if staging_identity is not None:
                        current_stage = os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
                        if (current_stage.st_dev, current_stage.st_ino) == staging_identity:
                            os.unlink(temporary_name, dir_fd=parent)
                        else:
                            response["cleanup_warning"] = "Staging pathname changed ownership; its current entry was preserved."
                except FileNotFoundError:
                    pass
                except OSError:
                    response["cleanup_warning"] = "Owned staging file could not be removed: " + temporary_name
            return response

    def _resource(self, workspace, path):
        # Directory identity also coordinates case/Unicode aliases on macOS.
        # String-normalized path locks alone can let two managed writers race
        # on the same case-insensitive filesystem entry.
        with self._parent(workspace,path) as (parent,_):
            info=os.fstat(parent)
        return f"directory:{info.st_dev}:{info.st_ino}"

    def reconcile_content(self, receipt):
        """Observe a recorded target without allocating another full snapshot."""
        record=receipt.get('result') or {}
        if record.get('ok') is False:record=record.get('error',{})
        workspace,path=record.get('workspace'),record.get('path')
        if not workspace or not path or not record.get('parent_identity') or not record.get('after_artifact'):
            return {'supported':False,'reason':'record lacks a content target and parent identity; original receipt is unchanged'}
        if record.get('workspace_root')!=str(self.config.workspace(workspace).root):
            return {'supported':True,'target_matches':'identity_changed','target_read':False}
        with self._parent(workspace,path) as (parent,name):
            parent_stat=os.fstat(parent)
            actual_parent={'device':str(parent_stat.st_dev),'inode':str(parent_stat.st_ino)}
            if actual_parent!=record['parent_identity']:
                return {'supported':True,'target_matches':'identity_changed','target_read':False}
            try:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            except FileNotFoundError:
                return {'supported':True,'target_matches':'absent','current_sha256':None,'target_read':False}
            try:
                before=os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    return {'supported':True,'target_matches':'type_changed','target_read':False}
                with os.fdopen(fd,'rb',closefd=False) as source:
                    digest=hashlib.file_digest(source,'sha256').hexdigest()
                after=os.fstat(fd)
                current=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if not _same_file(before,after) or not _same_file(after,current):
                    return {'supported':True,'target_matches':'changed_during_observation','current_sha256':digest,'stable':False}
            finally:os.close(fd)
        intended=record['after_artifact'].removeprefix('sha256:')
        previous=(record.get('before_artifact') or '').removeprefix('sha256:')
        match='intended' if digest==intended else 'before' if digest==previous else 'different'
        return {'supported':True,'target_matches':match,'current_sha256':digest,'stable':True,'target_read':True,
                'historical_effect':'not inferred solely from current content equality',
                'next_action':'desired bytes are present; do not blindly reapply' if match=='intended' else 'decide next action against the observed current hash'}

    def write_file(self, workspace: str, path: str, request_id: str, expected_sha256=None, content=None, artifact_id=None, dry_run=False):
        self._writable(workspace)
        self._parts(path)
        self._revision(expected_sha256)
        if (content is None) == (artifact_id is None):
            raise WorkbenchError("invalid_input", "Supply exactly one of content or artifact_id.")
        if content is not None and len(content.encode("utf-8")) > 262144:
            raise WorkbenchError("input_limit", "Use artifact_upload for content larger than 256 KiB.")
        payload = {"tool": "write_file", "workspace": workspace, "path": path, "expected_sha256": expected_sha256,
                   "content_hash": hashlib.sha256(content.encode()).hexdigest() if content is not None else None, "artifact_id": artifact_id, "dry_run": dry_run}

        def perform():
            if content is not None:
                return self._write(workspace, path, expected_sha256, content.encode('utf-8'), dry_run, request_id=request_id)
            with self.store.reading(artifact_id):
                return self._write(workspace, path, expected_sha256, self.store.path(artifact_id), dry_run, request_id=request_id)

        return self.journal.run(request_id, payload, perform, resource=self._resource(workspace, path))

    def edit_file(self, workspace: str, path: str, request_id: str, expected_sha256: str, edits: list[dict], dry_run=False):
        self._writable(workspace)
        self._revision(expected_sha256)
        if expected_sha256 is None or not isinstance(edits, list) or not 1 <= len(edits) <= 128:
            raise WorkbenchError("invalid_input", "Edits require the existing SHA-256 and at least one replacement.")
        if len(json.dumps(edits, ensure_ascii=False).encode("utf-8")) > 262144:
            raise WorkbenchError("input_limit", "Replacement arguments exceed 256 KiB; upload a complete replacement artifact instead.")
        payload = {"tool": "edit_file", "workspace": workspace, "path": path, "expected_sha256": expected_sha256, "edits": edits, "dry_run": dry_run}

        def perform():
            with self._parent(workspace, path) as (parent, name):
                before, info = self._current(parent, name)
            self._check_revision(before, expected_sha256)
            if before["bytes"] > 16 * 1024 * 1024:
                raise WorkbenchError("edit_limit", "Exact text replacements are limited to 16 MiB; upload a complete replacement artifact or use an explicitly enabled command job.")
            try:
                with self.store.reading(before['artifact_id']) as source:
                    text = source.read().decode('utf-8')
            except UnicodeError as error:
                raise WorkbenchError("not_utf8", "Exact text edits require UTF-8; use binary artifact replacement for other encodings.") from error
            for index, edit in enumerate(edits):
                if set(edit) - {"old_text", "new_text", "expected_occurrences"}:
                    raise WorkbenchError("invalid_edit", "Unknown replacement field.", edit=index)
                old, new, expected = edit.get("old_text"), edit.get("new_text"), edit.get("expected_occurrences", 1)
                if not isinstance(old, str) or not old or not isinstance(new, str) or type(expected) is not int or expected < 1:
                    raise WorkbenchError("invalid_edit", "Each edit requires nonempty old_text, new_text, and a positive expected_occurrences.", edit=index)
                actual = text.count(old)
                if actual != expected:
                    raise WorkbenchError("edit_conflict", "Replacement occurrence count differs from expectation; no edit was applied.", edit=index, expected=expected, actual=actual)
                projected_bytes = len(text.encode("utf-8")) + actual * (len(new.encode("utf-8")) - len(old.encode("utf-8")))
                if projected_bytes > min(16 * 1024 * 1024, self.config.max_artifact_bytes):
                    raise WorkbenchError("edit_limit", "Replacement expansion exceeds the bounded text-edit size; no edit was applied.", projected_bytes=projected_bytes)
                text = text.replace(old, new)
            return self._write(workspace, path, expected_sha256, text.encode("utf-8"), dry_run, prepared=(before, info), request_id=request_id)

        return self.journal.run(request_id, payload, perform, resource=self._resource(workspace, path))

    def make_directory(self, workspace: str, path: str, request_id: str):
        self._writable(workspace)
        self._parts(path)

        def perform():
            with self._parent(workspace, path) as (parent, name):
                self.journal.checkpoint(request_id, {"workspace": workspace, "path": path, "phase": "before_mkdir",
                                                     "effect_state": "unknown"})
                try:
                    os.mkdir(name, mode=0o755, dir_fd=parent)
                except FileExistsError as error:
                    raise WorkbenchError("already_exists", "Target already exists; no directory was created.") from error
                try:
                    os.fsync(parent)
                except OSError as error:
                    raise WorkbenchError("filesystem_error", "Directory was created but durability is unknown.",
                                         path=path, phase="parent_directory_fsync", effect_state="published", durability="unknown") from error
            return {"ok": True, "workspace": workspace, "path": path, "created": True,
                    "applied_this_call": True, "effect_state": "published", "durability": "confirmed"}

        return self.journal.run(request_id, {"tool": "make_directory", "workspace": workspace, "path": path}, perform,
                                resource=self._resource(workspace, path))
