"""Optional best-effort producer cancellation facts; never cancellation authority."""
import json
import re

CALLERS = {'explicit_command','arm_expiry','context_fence','permission_revoke','ambiguity',
           'page_event','filename_event','api_start','blob_start','unspecified'}
REASONS = {'explicit_or_host_control','arm_expired','native_connection_lost','workbench_shutdown',
           'idle_disconnect','connection_timeout','connection_setup_failed','document_changed','trust_generation_changed',
           'local_setup_revoked','permission_reduced','permission_removed','authority_or_capture_ended',
           'ambiguity_barrier','current_admission_ended','cancel_already_requested','blob_current_ended','post_start_guard_ended','unspecified'}
ERRORS = {'none','timeout','protocol_rejection','javascript_exception','unclassified_error'}
FIELDS = {'sequence','worker_generation','context_kind','native_id','caller','reason','command_id',
          'started_wall_ms','started_monotonic_ms','returned_monotonic_ms','attempted','acknowledged','error_stage','error_class','protocol_code'}
MAXIMUM = 9007199254740991


def projection(value, producer_id, kind, native_id):
    def empty(omitted=True):
        return {'version':1,'coverage':'not_recorded','producer_id':producer_id,'entries':[],
                'total_requests':None,'omitted':omitted}
    def integer(v):return type(v) is int and 0 <= v <= MAXIMUM
    def clock(v):return v is None or integer(v)
    def identifier(v):return type(v) is str and re.fullmatch('[a-f0-9]{32}',v) is not None
    try:
        if (type(value) is not dict or set(value) != {'version','coverage','producer_id','entries','total_requests','omitted'}
                or type(value['version']) is not int or value['version'] != 1 or value['producer_id'] != producer_id
                or not identifier(producer_id) or type(value['omitted']) is not bool
                or type(value['entries']) is not list or len(value['entries']) > 8):return empty()
        if value['coverage'] == 'not_recorded':
            return empty(value['omitted']) if value['entries']==[] and value['total_requests'] is None else empty()
        if (value['coverage'] != 'new_producer_best_effort' or not integer(value['total_requests'])
                or value['total_requests'] > len(value['entries']) and not value['omitted']):return empty()
        rows=[];sequence=0
        for row in value['entries']:
            if (type(row) is not dict or set(row) != FIELDS or not integer(row['sequence'])
                    or not sequence < row['sequence'] <= value['total_requests'] or not identifier(row['worker_generation'])
                    or row['context_kind'] != kind or type(row['context_kind']) is not str or kind not in ('ordinary','private')
                    or row['native_id'] is not None and (type(row['native_id']) is not int or not 0 <= row['native_id'] <= 2147483647 or row['native_id'] != native_id)
                    or type(row['caller']) is not str or row['caller'] not in CALLERS
                    or type(row['reason']) is not str or row['reason'] not in REASONS
                    or row['command_id'] is not None and not identifier(row['command_id'])
                    or any(not clock(row[k]) for k in ('started_wall_ms','started_monotonic_ms','returned_monotonic_ms'))
                    or row['started_monotonic_ms'] is not None and row['returned_monotonic_ms'] is not None and row['returned_monotonic_ms'] < row['started_monotonic_ms']
                    or type(row['attempted']) is not bool or type(row['acknowledged']) is not bool
                    or row['attempted'] != (row['native_id'] is not None) or row['acknowledged'] and not row['attempted']
                    or row['error_stage'] not in ('none','no_native_id','native_cancel','state_refresh')
                    or type(row['error_class']) is not str or row['error_class'] not in ERRORS
                    or row['protocol_code'] is not None and (type(row['protocol_code']) is not int or row['protocol_code'] not in (-32700,-32600,-32601,-32602,-32603,-32000))
                    or (row['error_class']=='protocol_rejection') != (row['protocol_code'] is not None)):return empty()
            sequence=row['sequence'];rows.append(dict(row))
        return {'version':1,'coverage':value['coverage'],'producer_id':producer_id,'entries':rows,
                'total_requests':value['total_requests'],'omitted':value['omitted']}
    except (TypeError,ValueError,KeyError):return empty()


def normalize(row):
    if 'producer_cancel_evidence' in row:
        row['producer_cancel_evidence']=projection(row['producer_cancel_evidence'],row.get('download_id'),row.get('context_kind'),row.get('browser_download_id'))
        # Optional bytes may not make an existing authoritative record invalid.
        if len(json.dumps(row).encode()) > 32768:row.pop('producer_cancel_evidence')


def merge(before, after, producer_id, kind, native_id):
    """Preserve recorded facts against late snapshots; disagreements expose gaps."""
    a,b=(projection(value,producer_id,kind,native_id) for value in (before,after))
    if a['coverage']!='new_producer_best_effort':return b
    if b['coverage']!='new_producer_best_effort':return {**a,'omitted':True}
    rows={item['sequence']:dict(item) for item in a['entries']}
    omitted=a['omitted'] or b['omitted']
    mutable={'acknowledged','returned_monotonic_ms','error_stage','error_class','protocol_code'}
    for item in b['entries']:
        old=rows.get(item['sequence'])
        if old is None:rows[item['sequence']]=dict(item);continue
        if old==item:continue
        if any(old[k]!=item[k] for k in FIELDS-mutable):omitted=True;continue
        old_pending=not old['acknowledged'] and old['returned_monotonic_ms'] is None and old['error_class']=='none'
        new_pending=not item['acknowledged'] and item['returned_monotonic_ms'] is None and item['error_class']=='none'
        if new_pending:continue
        if old_pending:rows[item['sequence']]=dict(item);continue
        if old['acknowledged'] and item['acknowledged'] and old['returned_monotonic_ms']==item['returned_monotonic_ms']:
            if old['error_class']=='none':rows[item['sequence']]=dict(item)
            elif item['error_class']!='none' and old!=item:omitted=True
        else:omitted=True
    entries=sorted(rows.values(),key=lambda item:item['sequence'])
    first_native=next((item for item in entries if item['attempted']),None)
    while len(entries)>8:
        index=next(i for i,item in enumerate(entries) if i!=0 and item is not first_native)
        entries.pop(index);omitted=True
    total=max(a['total_requests'],b['total_requests'])
    return {**a,'entries':entries,'total_requests':total,'omitted':omitted or total>len(entries)}
