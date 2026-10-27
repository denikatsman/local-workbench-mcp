"""Shared native/browser interaction envelope; authority stays with its owner.

Legacy grants are never promoted by this parser. A valid receipt describes
dispatch/effect observations, not automatic task acceptance.
"""
import math
import re

from .errors import WorkbenchError
from .response_diagnostics import projection as diagnostic_projection

VERSION = 1
CLAIM_STATES = {'active','suspended_transport','suspended_contention','modal_blocked','released','revoked','target_closed'}


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def native_identity(value):
    if not isinstance(value, dict):
        raise WorkbenchError('invalid_app_target', 'Use the exact app identity returned by native discovery.')
    required = {'bundleID','bundlePath','executable','pid','launchedAt'}
    if (not required.issubset(value) or any(not isinstance(value[k], str) or not value[k] or len(value[k].encode()) > 4096 for k in ('bundleID','bundlePath','executable'))
            or type(value['pid']) is not int or not 0 < value['pid'] <= 2147483647
            or type(value['launchedAt']) not in (float,int) or not math.isfinite(value['launchedAt']) or value['launchedAt'] <= 0):
        raise WorkbenchError('invalid_app_target', 'The app identity is malformed or incomplete.')
    if value.get('processGeneration') is not None and not identifier(value['processGeneration']):
        raise WorkbenchError('invalid_app_target', 'Use the complete process generation returned by native discovery.')
    return value


def browser_identity(value):
    """Browser labels are authenticated bridge bindings, not process attestation."""
    if (not isinstance(value, dict) or value.get('backend') != 'browser'
            or any(not identifier(value.get(k)) for k in ('profile_id', 'context_id', 'target_generation', 'connection_generation'))
            or value.get('context_kind') not in ('ordinary', 'private')
            or type(value.get('tab_id')) is not int or value['tab_id'] < 0
            or not isinstance(value.get('browser_target_id'), str) or not 1 <= len(value['browser_target_id']) <= 256
            or value.get('target_id') != 'browser-tab:' + value['context_id'] + ':' + value['browser_target_id']):
        raise WorkbenchError('invalid_browser_target', 'Use the exact target identity returned by browser discovery.')
    return value


def browser_response_capture(value):
    """Content-free phase history; unknown continuation is separate from cleanup."""
    error = WorkbenchError('interaction_protocol_error', 'The browser returned invalid response-capture history.', effect_state='unknown')
    rows = value.get('response_capture_receipts', [])
    if (not isinstance(rows, list) or len(rows) > 32
            or 'response_capture_overflow' in value and type(value['response_capture_overflow']) is not bool
            or 'response_history_persistence' in value and value['response_history_persistence'] != 'unsaved'):
        raise error
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'phase_id','claim_epoch','fetch_id','session_id','continuation','resource_cleanup'}
                or not identifier(row.get('phase_id')) or row['phase_id'] in seen
                or type(row.get('claim_epoch')) is not int or not 1 <= row['claim_epoch'] <= value['claim_epoch']
                or not isinstance(row.get('fetch_id'), str) or not 1 <= len(row['fetch_id'].encode()) <= 256
                or row.get('session_id') is not None and (not isinstance(row['session_id'], str) or not 1 <= len(row['session_id'].encode()) <= 256)
                or row.get('continuation') not in {'not_attempted','attempted','acknowledged','unverified','rejected_retired_id'}
                or row.get('resource_cleanup') not in {'pending','unverified','detached','session_gone','target_gone','continued','request_failed'}):
            raise error
        if (row['continuation'] == 'acknowledged' and row['resource_cleanup'] not in {'continued','detached','session_gone','target_gone'}
                or row['continuation'] == 'rejected_retired_id' and row['resource_cleanup'] != 'request_failed'):
            raise error
        seen.add(row['phase_id'])
    if 'response_capture_diagnostics' in value:
        value['response_capture_diagnostics'] = diagnostic_projection(value['response_capture_diagnostics'], 32)
    return any(row['resource_cleanup'] in {'pending','unverified'} for row in rows)


def browser_initialization_record(value):
    """Historical cleanup handle, never a document or input claim."""
    error = WorkbenchError('interaction_protocol_error', 'The browser returned an invalid initialization history record.', effect_state='unknown')
    if (not isinstance(value, dict) or type(value.get('interaction_version')) is not int or value['interaction_version'] != VERSION
            or value.get('record_kind') != 'browser_incomplete_initialization' or value.get('authority') != 'cleanup_only'
            or value.get('state') != 'quarantined' or not identifier(value.get('claim_id'))
            or not identifier(value.get('installation_id')) or not identifier(value.get('runtime_generation'))
            or type(value.get('claim_epoch')) is not int or value['claim_epoch'] < 1
            or not isinstance(value.get('owner_session'), str) or not 1 <= len(value['owner_session'].encode()) <= 128
            or value.get('cleanup_state') not in {'unverified','completed','target_gone','not_owned'}
            or value.get('pointer_release_state') not in {'not_needed','acknowledged','held','unverified','not_recorded'}
            or value.get('keyboard_release_state', 'not_needed') not in {'not_needed','acknowledged','prepared','held','unverified','not_recorded','target_gone'}
            or type(value.get('resource_unsettled')) is not bool
            or value.get('debugger_attachment') not in {'owned_at_last_record','not_attached_at_last_record','not_recorded'}
            or value.get('provenance') not in {'user','agent'} or value.get('cleanup_policy') not in {'keep','close_on_release'}
            or any(k in value for k in ('control','network','observation_id','frame_id','loader_id','document_epoch'))):
        raise error
    try:
        browser_identity(value.get('target'))
    except WorkbenchError:
        raise error
    if any(k in value['target'] for k in ('frame_id','loader_id','document_epoch','origin','title')):
        raise error
    expected_unsettled = value['cleanup_state'] == 'unverified' or value['pointer_release_state'] in {'held','unverified','not_recorded'}
    expected_unsettled = expected_unsettled or value.get('keyboard_release_state', 'not_needed') in {'prepared','held','unverified','not_recorded'}
    capture_unsettled = browser_response_capture(value)
    expected_unsettled = expected_unsettled or capture_unsettled
    if value['resource_unsettled'] != expected_unsettled:
        raise error
    if 'initialization_request_id' in value:
        request = value['initialization_request_id']
        try:
            request_bytes = len(request.encode()) if isinstance(request, str) else 0
        except UnicodeError:
            raise error
        if not 1 <= request_bytes <= 256:
            raise error
    return value


def claim(value, *, backend, runtime_generation, owner_session, expected_claim_id=None, require_active=False):
    error = WorkbenchError('interaction_protocol_error', 'The component did not return a current target-bound claim.', effect_state='unknown')
    if not isinstance(value, dict) or type(value.get('interaction_version')) is not int or value['interaction_version'] != VERSION:
        raise error
    if (expected_claim_id is not None and value.get('claim_id') != expected_claim_id) or (require_active and value.get('state') != 'active'):
        raise error
    target = value.get('target')
    if (not identifier(value.get('claim_id')) or value.get('state') not in CLAIM_STATES
            or type(value.get('claim_epoch')) is not int or value['claim_epoch'] <= 0
            or not identifier(value.get('installation_id')) or value.get('runtime_generation') != runtime_generation
            or value.get('owner_session') != owner_session or not isinstance(target, dict)
            or target.get('backend') != backend or not identifier(target.get('target_generation'))
            or not isinstance(target.get('target_id'), str) or len(target['target_id']) > 256):
        raise error
    if backend == 'native':
        if not re.fullmatch(r'native-window:[0-9a-f]{64}', target['target_id']) or not isinstance(target.get('window_id'),str) or not target['window_id']:
            raise error
        native_identity(target.get('app'))
    elif backend == 'browser':
        try:
            browser_identity(target)
        except WorkbenchError:
            raise error
        if (not identifier(value.get('runtime_generation')) or not isinstance(value.get('owner_session'), str)
                or not 1 <= len(value['owner_session'].encode()) <= 128
                or type(target.get('document_epoch')) is not int or target['document_epoch'] < 1
                or any(not isinstance(target.get(k), str) or not 1 <= len(target[k]) <= 256 for k in ('frame_id', 'loader_id'))):
            raise error
        browser_response_capture(value)
    return value


def browser_input_evidence(result, action=None):
    """Optional versioned command/readback facts; legacy receipts stay unchanged."""
    if 'input_evidence' not in result:
        return None
    value = result['input_evidence']
    error = WorkbenchError('interaction_protocol_error', 'The browser input evidence was malformed or overstated.', effect_state='unknown')
    if (not isinstance(value, dict) or set(value) != {'version', 'attempted', 'protocol_acknowledged',
            'recipient_observed', 'state_observed', 'task_verified', 'retry_allowed'}
            or type(value.get('version')) is not int or value['version'] != 1
            or value.get('attempted') is not True or value.get('protocol_acknowledged') is not True
            or value.get('recipient_observed') != 'not_established'
            or value.get('state_observed') not in ('changed', 'unchanged', 'not_established')
            or value.get('task_verified') is not False or value.get('retry_allowed') is not False
            or result.get('input_dispatched') is not True or result.get('native_input_dispatched') is not None
            or result.get('events_trusted') is not None or result.get('dispatch_scope') != 'cdp_command_only'
            or result.get('dispatch_state') != 'acknowledged' or result.get('dispatch_effect_state') != 'unknown'
            or result.get('task_completion') != 'not_established'):
        raise error
    if action is not None and (action not in ('drag', 'click_point', 'click', 'press', 'insert_text', 'scroll')
            or result.get('effect_scope') != ('sampled_scroll_offsets' if action == 'scroll' else 'recipient_effect_not_established')):
        raise error
    if result.get('effect_scope') == 'sampled_scroll_offsets':
        if (result.get('effect_state') not in ('applied', 'unknown')
                or result.get('effect_state') == 'applied' and (value['state_observed'] != 'changed'
                    or result.get('scroll_offsets_changed') is not True
                    or not isinstance(result.get('readback'), dict) or result['readback'].get('stable_in_window') is not True)):
            raise error
    elif result.get('effect_scope') != 'recipient_effect_not_established' or result.get('effect_state') != 'unknown':
        raise error
    return dict(value)


def browser_input_error_receipt(error, action, parameters, binding, request_id):
    """Validate additive original-insert facts without granting readback authority.

    The caller retains the original error even if this optional extension fails
    validation. No arbitrary error payload or page content is passed through.
    """
    value = error.get('input_error_receipt')
    if value is None and 'input_error_receipt' not in error:
        return None
    invalid = WorkbenchError('interaction_protocol_error', 'The browser input error receipt was malformed or overstated.', effect_state='unknown')
    def bounded_text(item):
        try:
            return isinstance(item, str) and 1 <= len(item.encode()) <= 256
        except UnicodeError:
            return False
    fields = {'version', 'action', 'operation_request_id', 'transport_request_id', 'observation_id', 'target_id',
              'attempted', 'protocol_acknowledged', 'recipient_observed', 'state_observed', 'task_verified', 'retry_allowed',
              'browser_target_id', 'frame_id', 'loader_id', 'frame_session_id', 'execution_context_unique_id', 'binding', 'readback'}
    binding_fields = {'installation_id', 'runtime_generation', 'peer_id', 'owner_session', 'claim_id', 'claim_epoch',
                      'target_generation', 'document_generation', 'profile_id', 'context_id', 'context_kind'}
    if (not isinstance(value, dict) or set(value) != fields or action != 'insert_text'
            or error.get('effect_state') != 'unknown' or type(value.get('version')) is not int or value['version'] != 1
            or value.get('action') != action or value.get('attempted') is not True
            or type(value.get('protocol_acknowledged')) is not bool
            or value.get('recipient_observed') != 'not_established' or value.get('state_observed') != 'not_established'
            or value.get('task_verified') is not False or value.get('retry_allowed') is not False
            or not isinstance(binding, dict) or 'claim_id' not in binding
            or not isinstance(value.get('binding'), dict) or set(value['binding']) != binding_fields):
        raise invalid
    lifetime = value['binding']
    for key in binding_fields - {'document_generation'}:
        if (lifetime.get(key) != binding.get(key)
                or key == 'claim_epoch' and (type(lifetime[key]) is not int or lifetime[key] < 1)):
            raise invalid
    if (type(lifetime.get('document_generation')) is not int or lifetime['document_generation'] < 1
            or lifetime['document_generation'] != parameters.get('expected_generation')):
        raise invalid
    intended = parameters.get('parameters', {})
    if (any(not bounded_text(value.get(key))
            for key in ('operation_request_id', 'transport_request_id', 'observation_id', 'target_id',
                        'browser_target_id', 'frame_id', 'loader_id', 'execution_context_unique_id'))
            or value['transport_request_id'] != request_id
            or value['operation_request_id'] != (parameters.get('operation_request_id') or request_id)
            or any(value[key] != intended.get(key) for key in ('observation_id', 'target_id'))
            or value['browser_target_id'] != binding.get('browser_target_id')
            or value['frame_session_id'] is not None and not bounded_text(value['frame_session_id'])):
        raise invalid
    frame_id = intended.get('frame_id') or binding.get('frame_id')
    if (frame_id is not None and value['frame_id'] != frame_id
            or frame_id == binding.get('frame_id') and value['loader_id'] != binding.get('loader_id')):
        raise invalid
    readback = value['readback']
    acknowledged = value['protocol_acknowledged']
    if (not isinstance(readback, dict) or set(readback) != {'state', 'stage', 'reason'}
            or readback.get('state') != ('unavailable' if acknowledged else 'not_started')
            or readback.get('reason') != ('guarded_readback_unavailable' if acknowledged else 'command_response_unavailable')
            or readback.get('stage') not in (('post_readback', 'capture', 'retained_metadata', 'finish', 'cleanup_guard')
                                           if acknowledged else ('insert_command',))):
        raise invalid
    return {**value, 'binding': dict(lifetime), 'readback': dict(readback)}


def receipt(request_id, claim_value, action, result):
    """A bounded view of a real component response; never invents readback."""
    evidence = browser_input_evidence(result, action) if claim_value['target']['backend'] == 'browser' else None
    return {'interaction_version':VERSION,'request_id':request_id,'claim_id':claim_value['claim_id'],
        'claim_epoch':claim_value['claim_epoch'],'target_id':claim_value['target']['target_id'],
        'target_generation':claim_value['target']['target_generation'],'backend':claim_value['target']['backend'],
        'action':action,'dispatch':'acknowledged' if result.get('ok') is True else 'unknown',
        'dispatch_scope':'component_response_only',
        'effect_state':result.get('effect_state','not_established'),
        'verification_state':result.get('verification_state','not_established'),
        'task_completion':result.get('task_completion','not_established'),
        **({'input_evidence':evidence,'effect_scope':result['effect_scope']} if evidence is not None else {})}
