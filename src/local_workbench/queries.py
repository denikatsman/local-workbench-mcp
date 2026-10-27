"""Bounded structured projections and byte queries over immutable artifacts."""
import json
import re
import time

import regex

from .errors import WorkbenchError
from .views import ArtifactViews, response_size


class ArtifactQueries:
    def __init__(self, store):
        self.store = store

    @staticmethod
    def pointer(value, pointer):
        if not isinstance(pointer, str) or len(pointer.encode()) > 4096 or pointer and not pointer.startswith('/'):
            raise WorkbenchError('invalid_pointer', 'Use an empty pointer or an RFC 6901 pointer of at most 4096 bytes.')
        for part in pointer[1:].split('/') if pointer else []:
            if re.search(r'~(?![01])', part):
                raise WorkbenchError('invalid_pointer', 'Only ~0 and ~1 are valid pointer escapes.')
            key = part.replace('~1', '/').replace('~0', '~')
            try:
                if isinstance(value, dict):
                    value = value[key]
                elif isinstance(value, list) and key.isascii() and key.isdecimal() and not (len(key) > 1 and key.startswith('0')):
                    value = value[int(key)]
                else:
                    raise KeyError(key)
            except (KeyError, IndexError, ValueError) as error:
                raise WorkbenchError('pointer_not_found', 'The requested value is unavailable in this record.') from error
        return value

    def query(self, artifact_id, kind, query='', offset=0, json_pointer='', limit=20, max_scan_bytes=8388608, max_bytes=8192):
        ArtifactViews.budget(max_bytes)
        if kind not in ('ndjson', 'regex', 'strings') or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise WorkbenchError('invalid_query', 'Use ndjson/regex/strings, a nonnegative offset and limit 1..100.')
        if type(max_scan_bytes) is not int or not 65536 <= max_scan_bytes <= 8388608:
            raise WorkbenchError('invalid_range', 'Each query scans 64 KiB through 8 MiB.')
        result = {'ok': True, 'source_artifact': artifact_id, 'transform': kind, 'transform_version': 1,
                  'byte_start': offset, 'records': [], 'raw_source_retained': True, 'scan_complete': False,
                  'view_complete': True, 'next_offset': offset, 'coordinate_units': 'UTF-8 byte offsets; no text normalization'}
        with self.store.reading(artifact_id) as source:
            source.seek(0, 2)
            total = source.tell()
            result['source_bytes'] = total
            if offset > total:
                raise WorkbenchError('invalid_range', 'The byte cursor exceeds the source.')
            if kind == 'ndjson':
                if not isinstance(json_pointer, str) or len(json_pointer.encode()) > 4096 or json_pointer and not json_pointer.startswith('/') or re.search(r'~(?![01])', json_pointer):
                    raise WorkbenchError('invalid_pointer', 'Use a valid RFC 6901 pointer of at most 4096 UTF-8 bytes.')
                result['json_pointer'] = json_pointer
                if offset:
                    source.seek(offset - 1)
                    if source.read(1) != b'\n':
                        raise WorkbenchError('invalid_cursor', 'NDJSON continuation starts at a record boundary; use the returned next_offset.')
                source.seek(offset)
                deadline = time.monotonic() + 3
                for _ in range(limit):
                    start = source.tell()
                    if start - offset >= max_scan_bytes or time.monotonic() >= deadline:
                        result['stop_reason'] = 'scan_budget'
                        break
                    raw = source.readline(1048577)
                    if not raw:
                        break
                    if len(raw) > 1048576:
                        raise WorkbenchError('ndjson_record_limit', 'A record exceeds 1 MiB; retrieve its exact bytes with artifact_read.',
                                             source_artifact=artifact_id, byte_start=start)
                    item = {'byte_start': start, 'byte_end': source.tell()}
                    try:
                        value = self.pointer(json.loads(raw), json_pointer)
                        item['value'] = value
                    except (ValueError, UnicodeError, RecursionError) as error:
                        item['error'] = 'invalid_json'
                    except WorkbenchError as error:
                        item['error'] = error.code
                    candidate = {**result, 'records': result['records'] + [item], 'next_offset': source.tell()}
                    if response_size(candidate) > max_bytes and 'value' in item:
                        derived = self.store.put_bytes(json.dumps(item.pop('value'), ensure_ascii=True).encode(), 'ndjson-value:' + artifact_id)
                        item.update(derived_artifact=derived, value_in_artifact=True)
                        candidate = {**result, 'records': result['records'] + [item], 'next_offset': source.tell()}
                    if response_size(candidate) > max_bytes:
                        source.seek(start)
                        result['view_complete'] = False
                        break
                    result['records'].append(item)
                    result['next_offset'] = source.tell()
                result['scan_complete'] = source.tell() == total
            else:
                source.seek(offset)
                raw = source.read(max_scan_bytes)
                end = offset + len(raw)
                if kind == 'regex':
                    if not isinstance(query, str) or not 1 <= len(query.encode()) <= 4096:
                        raise WorkbenchError('invalid_regex', 'Use a UTF-8 regex of 1..4096 bytes.')
                    try:
                        pattern = regex.compile(query.encode())
                    except regex.error as error:
                        raise WorkbenchError('invalid_regex', 'The byte regex could not compile.') from error
                    result['regex_scope'] = 'This bounded byte window; anchors/lookaround use its boundaries. No whole-source negative claim is implied by a partial window.'
                    try:
                        for match in pattern.finditer(raw, timeout=.25):
                            item = {'byte_start': offset + match.start(), 'byte_end': offset + match.end(),
                                    'preview': match.group()[:512].decode('utf-8', 'backslashreplace'), 'preview_complete': len(match.group()) <= 512}
                            if len(result['records']) >= limit or response_size({**result, 'records': result['records'] + [item]}) > max_bytes:
                                result.update(view_complete=False, stop_reason='result_budget')
                                break
                            result['records'].append(item)
                    except TimeoutError:
                        result.update(view_complete=False, stop_reason='regex_timeout')
                else:
                    result['encoding_scope'] = 'ASCII printable byte runs of at least four bytes; other encodings are not an absence claim.'
                    for match in re.finditer(rb'[\x20-\x7e]{4,}', raw):
                        item = {'byte_start': offset + match.start(), 'byte_end': offset + match.end(),
                                'preview': match.group()[:512].decode('ascii'), 'preview_complete': len(match.group()) <= 512,
                                'window_segment_may_continue': match.end() == len(raw) and end < total}
                        if len(result['records']) >= limit or response_size({**result, 'records': result['records'] + [item]}) > max_bytes:
                            result.update(view_complete=False, stop_reason='result_budget')
                            break
                        result['records'].append(item)
                result['next_offset'] = end
                result['scan_complete'] = end == total and result['view_complete']
                result['coverage'] = 'Captured matches within the evaluated window; omitted matches require re-querying this window with a narrower pattern/larger result budget.'
                if not result['view_complete']:
                    result['requery_window'] = {'offset': offset, 'max_scan_bytes': max_scan_bytes}
            result['byte_end'] = result['next_offset']
            if result['scan_complete']:
                result['next_offset'] = None
        return result

    def batch(self, reads, offset=0, max_bytes=8192):
        ArtifactViews.budget(max_bytes)
        if not isinstance(reads, list) or not 1 <= len(reads) <= 32 or type(offset) is not int or not 0 <= offset <= len(reads):
            raise WorkbenchError('invalid_batch', 'Use 1..32 read requests and a valid item offset.')
        result = {'ok': True, 'items': [], 'next_item_offset': None, 'shared_max_bytes': max_bytes,
                  'coordinate_units': 'Each item uses exact artifact byte cursors; items have a shared serialized response budget.'}
        for index in range(offset, len(reads)):
            spec = reads[index]
            if not isinstance(spec, dict) or set(spec) - {'artifact_id', 'offset', 'max_bytes'} or 'artifact_id' not in spec:
                raise WorkbenchError('invalid_batch', 'Each read takes artifact_id, offset and max_bytes only.')
            if type(spec.get('max_bytes', 4096)) is not int or not 1 <= spec.get('max_bytes', 4096) <= 262144:
                raise WorkbenchError('invalid_batch', 'Each byte page must be an integer of 1..262144 bytes.')
            try:
                page = self.store.read(spec['artifact_id'], spec.get('offset', 0), min(spec.get('max_bytes', 4096), max_bytes // 2))
            except WorkbenchError as error:
                page = error.as_dict()
            item = {'item_index': index, 'result': page}
            if response_size({**result, 'items': result['items'] + [item]}) > max_bytes:
                result['next_item_offset'] = index
                break
            result['items'].append(item)
        if not result['items'] and result['next_item_offset'] is not None:
            raise WorkbenchError('response_budget', 'Reduce the first requested byte page or increase the shared response budget.')
        return result
