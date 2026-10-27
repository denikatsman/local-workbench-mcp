"""Optional content-free response diagnostics; never authority/cleanup evidence."""
import re

TAGS = {
    'capture_lease_identity',
    'capture_debugger_attached',
    'capture_detaching',
    'capture_owner',
    'capture_grant',
    'capture_peer',
    'capture_runtime',
    'capture_installation',
    'capture_target',
    'capture_target_generation',
    'capture_epoch',
    'capture_session_binding',
    'capture_child_binding',
    'capture_competing_lease',
    'capture_owned',
    'capture_claim_active',
    'capture_input_eligible',
    'capture_releasing',
    'capture_unexpired',
    'capture_stopped',
    'route',
    'cancel_requested',
    'ambiguity',
    'worker_generation',
    'runtime_generation',
    'installation',
    'profile',
    'context',
    'context_kind',
    'binding_context_kind',
    'claim_context_kind',
    'response_or_unexpired_arm',
    'trust_enabled',
    'trust_control',
    'trust_network',
    'trust_file_download',
    'trust_identity',
    'peer_identity',
    'durable_claim',
    'owner_identity',
    'claim_epoch',
    'target_generation',
    'browser_target',
    'main_frame',
    'loader',
    'document_epoch',
    'origin',
    'claim_network',
    'claim_control',
    'capture_enabled',
    'capture_current',
    'fetch_request_id_type',
    'fetch_request_id_empty',
    'fetch_request_id_length',
    'network_request_id_type',
    'network_request_id_empty',
    'network_request_id_length',
    'attachment_supported',
    'document_resource_type',
    'status_integer',
    'status_minimum_200',
    'status_maximum_299',
    'history_capacity',
}
PHASES = {
    'initial_response_admission',
    'post_observation_ack',
    'post_attempt_ack',
    'final_capture_ownership',
    'continuation_wait',
    'admission_wait',
}
ERRORS = {'none','timeout','protocol_rejection','retired_interception','javascript_exception','unclassified_error'}
FIELDS = {'phase','failed_predicate','phase_id','request_key','method','error_class','protocol_code'}


def projection(value, limit):
    empty = {'version': 1, 'entries': [], 'omitted': True, 'conflicted': False}
    def identifier(v):
        return v is None or isinstance(v, str) and re.fullmatch('[a-f0-9]{32}', v) is not None
    if (not isinstance(value, dict) or set(value) != {'version','entries','omitted','conflicted'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['omitted']) is not bool or type(value['conflicted']) is not bool
            or not isinstance(value['entries'], list) or len(value['entries']) > limit):
        return empty
    entries, seen = [], set()
    for row in value['entries']:
        if (not isinstance(row, dict) or set(row) != FIELDS
                or not isinstance(row['phase'], str) or row['phase'] not in PHASES
                or row['failed_predicate'] is not None and (not isinstance(row['failed_predicate'], str) or row['failed_predicate'] not in TAGS)
                or not identifier(row['phase_id']) or not identifier(row['request_key'])
                or not isinstance(row['error_class'], str) or row['error_class'] not in ERRORS
                or not isinstance(row['method'], str) or row['method'] not in {'none','continue_request','continue_response'}
                or row['protocol_code'] is not None and (type(row['protocol_code']) is not int or row['protocol_code'] not in {-32700,-32600,-32601,-32602,-32603,-32000})):
            return empty
        if limit == 4:
            if row['phase'] not in {'initial_response_admission','post_observation_ack','post_attempt_ack','final_capture_ownership'} or row['method'] != 'none':
                return empty
        elif row['phase'] not in {'continuation_wait','admission_wait'} or row['failed_predicate'] is not None:
            return empty
        if (row['error_class'] == 'protocol_rejection' and row['protocol_code'] is None
                or row['error_class'] == 'retired_interception' and row['protocol_code'] != -32602
                or row['error_class'] not in {'protocol_rejection','retired_interception'} and row['protocol_code'] is not None):
            return empty
        key = row['phase'] if limit == 4 else row['phase_id']
        if key is None or key in seen:
            return empty
        seen.add(key); entries.append(dict(row))
    return {'version': 1, 'entries': entries, 'omitted': value['omitted'], 'conflicted': value['conflicted']}


def merge(before, after):
    """Diagnostic disagreement cannot alter an authority receipt outcome."""
    blank = {'version': 1, 'entries': [], 'omitted': False, 'conflicted': False}
    a, b = projection(before if before is not None else blank, 32), projection(after if after is not None else blank, 32)
    rows = {row['phase_id']: row for row in a['entries']}
    conflict = a['conflicted'] or b['conflicted']
    omitted = a['omitted'] or b['omitted']
    for row in b['entries']:
        old = rows.get(row['phase_id'])
        if old is not None and old != row:
            conflict = True
        elif old is None:
            if len(rows) < 32: rows[row['phase_id']] = row
            else: omitted = True
    return {'version': 1, 'entries': list(rows.values()), 'omitted': omitted, 'conflicted': conflict}
