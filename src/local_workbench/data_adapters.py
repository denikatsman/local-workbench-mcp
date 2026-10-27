"""Scoped, bounded data inspection with raw snapshots and explicit consistency."""
import contextlib
import hashlib
import json
import os
import plistlib
import sqlite3
import tempfile
import time
from pathlib import Path

from .errors import WorkbenchError
from .queries import ArtifactQueries
from .views import response_size


class DataAdapters:
    def __init__(self, files):
        self.files, self.store = files, files.store

    def plist(self, workspace, path, pointer='', max_bytes=8192):
        snapshot = self.files.read_file(workspace, path, max_bytes=1)
        if snapshot['total_bytes'] > 8388608:
            raise WorkbenchError('plist_limit', 'Plist parsing is limited to 8 MiB; raw snapshot bytes remain available.')
        try:
            with self.store.reading(snapshot['artifact_id']) as source:
                value = ArtifactQueries.pointer(plistlib.load(source), pointer)
        except (ValueError, plistlib.InvalidFileException, RecursionError) as error:
            raise WorkbenchError('invalid_plist', 'The selected source is not a supported plist.') from error
        # Dates/data have explicit tagged representations rather than ambiguous strings.
        def convert(value):
            import datetime
            import base64
            if isinstance(value, bytes):
                return {'type': 'data', 'base64': base64.b64encode(value).decode()}
            if isinstance(value, datetime.datetime):
                return {'type': 'date', 'iso8601': value.isoformat()}
            if isinstance(value, plistlib.UID):
                return {'type': 'uid', 'value': value.data}
            if isinstance(value, dict):
                return {key: convert(item) for key, item in value.items()}
            if isinstance(value, list):
                return [convert(item) for item in value]
            return value
        result = {'ok': True, 'source_artifact': snapshot['artifact_id'], 'capture_id': snapshot['capture_id'],
            'pointer': pointer, 'value': convert(value), 'transform_version': 1, 'raw_source_retained': True,
            'coordinate_units': 'RFC 6901 pointer over decoded plist values', 'source_stable': snapshot['snapshot_stable']}
        return self._bounded(result, max_bytes, 'plist-projection')

    def _bounded(self, result, max_bytes, source):
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        if response_size(result) <= max_bytes:
            return {**result, 'view_complete': True}
        artifact = self.store.put_bytes(json.dumps(result, ensure_ascii=True).encode(), source)
        return {'ok': True, 'result_artifact': artifact, 'source_artifact': result.get('source_artifact'),
                'source_artifacts': result.get('source_artifacts'), 'view_complete': False,
                'scope': result.get('scope'), 'continuation': 'Retrieve exact result bytes with artifact_read.'}

    def _snapshot_database(self, workspace, path, directory):
        sources, stamps, total = [], {}, 0
        # Copy only the exact DB and its standard WAL companion; no directory scan.
        for suffix in ('', '-wal'):
            selected = path + suffix
            try:
                with self.files._regular(workspace, selected) as (stream, before):
                    total += before.st_size
                    if total > 268435456:
                        raise WorkbenchError('database_limit', 'Database plus WAL exceeds 256 MiB.')
                    artifact = self.store.put_stream(stream, 'sqlite-source:' + workspace + ':' + selected)
                    after = os.fstat(stream.fileno())
                stamp = lambda info: [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
                if stamp(before) != stamp(after):
                    raise WorkbenchError('database_changed', 'A database component changed during capture; no consistent query is claimed.')
                stamps[selected] = stamp(after)
                with self.store.reading(artifact['artifact_id']) as source, (directory / ('database.sqlite3' + suffix)).open('xb') as destination:
                    while chunk := source.read(1048576):
                        destination.write(chunk)
                sources.append({'component': 'database' if not suffix else 'wal', **artifact})
            except WorkbenchError as error:
                if suffix and error.code == 'not_found':
                    continue
                raise
        for selected, expected in stamps.items():
            with self.files._parent(workspace, selected) as (parent, name):
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            observed = [current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns]
            if observed != expected:
                raise WorkbenchError('database_changed', 'Database/WAL changed across the capture bracket; retry explicitly.')
        if path + '-wal' not in stamps:
            with self.files._parent(workspace, path + '-wal') as (parent, name):
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise WorkbenchError('database_changed', 'A WAL appeared during capture; the query was not run.')
        return sources

    def sqlite(self, workspace, path, sql, parameters=None, max_rows=100, timeout_ms=1000, max_bytes=8192):
        if not isinstance(sql, str) or not 1 <= len(sql.encode()) <= 16384 or type(max_rows) is not int or not 1 <= max_rows <= 1000:
            raise WorkbenchError('invalid_query', 'Use one SQL statement of at most 16 KiB and max_rows 1..1000.')
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 5000:
            raise WorkbenchError('invalid_timeout', 'SQLite execution deadline must be 1..5000 ms.')
        parameters = [] if parameters is None else parameters
        if not isinstance(parameters, list) or len(parameters) > 100 or any(type(item) not in (str, int, float, type(None)) for item in parameters):
            raise WorkbenchError('invalid_parameters', 'Use at most 100 scalar SQL parameters.')
        with tempfile.TemporaryDirectory(prefix='sqlite-query-', dir=self.store.temporary) as owned:
            directory = Path(owned)
            sources = self._snapshot_database(workspace, path, directory)
            database = directory / 'database.sqlite3'
            deadline = time.monotonic() + timeout_ms / 1000
            allowed_actions = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
            denied_functions = {'load_extension', 'readfile', 'writefile', 'fts3_tokenizer'}
            def authorize(action, argument, second, database_name, trigger):
                if action not in allowed_actions or action == sqlite3.SQLITE_FUNCTION and (second or argument or '').lower() in denied_functions:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=timeout_ms / 1000)) as connection:
                connection.enable_load_extension(False)
                connection.set_authorizer(authorize)
                connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8388608)
                connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
                try:
                    cursor = connection.execute(sql, parameters)
                    columns = [item[0] for item in cursor.description or []]
                    rows = cursor.fetchmany(max_rows + 1)
                    complete = len(rows) <= max_rows
                    rows = rows[:max_rows]
                    def cell(value):
                        if isinstance(value, bytes):
                            import base64
                            return {'type': 'blob', 'bytes': len(value), 'base64': base64.b64encode(value).decode()}
                        return value
                    result = {'ok': True, 'source_artifact': sources[0]['artifact_id'], 'source_artifacts': sources,
                        'sqlite_version': sqlite3.sqlite_version, 'sql_sha256': hashlib.sha256(sql.encode()).hexdigest(),
                        'columns': columns, 'rows': [[cell(value) for value in row] for row in rows],
                        'query_complete': complete, 'max_rows': max_rows, 'mutation_allowed': False,
                        'extension_loading_allowed': False, 'source_files_modified': False,
                        'consistency': 'Private copy of DB/WAL within a stable file-metadata bracket; not a live transactional snapshot.',
                        'scope': 'This one explicitly selected database and query; limits and consistency are stated.'}
                except sqlite3.Error as error:
                    raise WorkbenchError('sqlite_query_refused', 'The read-only query failed or exceeded its deadline/size limits.',
                        sqlite_error=getattr(error, 'sqlite_errorname', None), source_artifacts=sources, mutation_performed=False) from error
            return self._bounded(result, max_bytes, 'sqlite-query-result')
