"""Signed native app executor; remote calls never grant apps or OS permissions."""
import base64
import contextlib
import contextvars
import copy
import hashlib
import itertools
import json
import logging
import math
import os
import re
import threading
import time

from .errors import WorkbenchError
from .permissions import BRIDGE_KEYS, ActivityGate, NativePermissions
from .views import add_result_continuation, response_size
from .context import work_context, work_admission, invocation_trace
from . import interaction_contract


# Request-local cancellation authority; copied into retained native task contexts.
# It is never serialized into tool arguments or the durable operation payload.
native_request_cancellation = contextvars.ContextVar('native_request_cancellation', default=None)


def _uncertain_native_error(error, request_id):
    return WorkbenchError(error.code,
        error.message + ' Inspect the original receipt; do not replay uncertain input.',
        **{**error.details, 'effect_state': 'unknown', 'retry_allowed': False,
           'request_id': request_id, 'original_request_id': request_id})


def _native_result_summary(result, wrapper, max_bytes):
    """Copy bounded outcome facts only; never derive effect or input authority."""
    def include(key, value):
        candidate = {**wrapper, key: value}
        # Match observation projection's escaped transport and envelope headroom.
        if (response_size(candidate) <= max_bytes
                and len(json.dumps(candidate, ensure_ascii=True).encode()) + 512 <= max_bytes):
            wrapper[key] = value

    for key in ('dispatch_state', 'effect_state', 'verification_state', 'task_completion',
                'operation_receipt_unavailable'):
        value = result.get(key)
        if type(value) is str and re.fullmatch(r'[a-z_]{1,80}', value):
            include(key, value)
    for key in ('host_reconciled', 'receipt_owner_unverified'):
        if type(result.get(key)) is bool:
            include(key, result[key])
    if type(result.get('observation_scope')) is dict:
        include('observation_scope', result['observation_scope'])
        include('subtree_observation_version', result.get('subtree_observation_version'))
    receipt = result.get('operation_receipt')
    # Only the existing compact receipt contract is eligible. Keep it whole:
    # diagnostic extensions, nested content and oversized identifiers stay in
    # the original artifact rather than becoming partial authority objects.
    fields = {'interaction_version', 'request_id', 'claim_id', 'claim_epoch', 'target_id',
              'target_generation', 'backend', 'action', 'dispatch', 'effect_state',
              'verification_state', 'task_completion'}
    # Keep the immutable legacy shape and the one known scope extension.
    # Browser evidence or other diagnostic fields remain artifact-only; never
    # trim an unexpected receipt into a different apparent authority object.
    if (type(receipt) is dict and set(receipt) in (fields, fields | {'dispatch_scope'})
            and ('dispatch_scope' not in receipt or receipt['dispatch_scope'] == 'component_response_only')
            and all(type(value) is int if key in ('interaction_version', 'claim_epoch')
                    else type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value)
                    for key, value in receipt.items())):
        include('operation_receipt', receipt)
    return wrapper


def _observation_summary(result, wrapper, max_bytes):
    """Project one existing observation; never refresh or create input authority."""
    window = result.get('window')
    if (result.get('ok') is not True or not interaction_contract.identifier(result.get('observation_id'))
            or type(window) is not dict or type(window.get('id')) is not str or not window['id']
            or type(window.get('controls')) is not list
            or any(type(control) is not dict or not interaction_contract.identifier(control.get('id'))
                   for control in window['controls'])):
        return None
    summary = {'scope': 'partial_native_observation', 'tree_omitted': True}
    if 'incomplete' in window:
        # Provider traversal coverage and this projection's omissions are
        # distinct; false here never means the projection is a full tree.
        summary['source_window_incomplete'] = window['incomplete']
    for key in ('version', 'request_id', 'app_generation', 'launch_id', 'runtime_generation',
                'observation_id', 'owner', 'app', 'lease_id', 'input_epoch', 'checked_at',
                'observation_scope', 'subtree_observation_version'):
        if key in result:
            summary[key] = result[key]
    summary['window'] = {key: window[key] for key in
        ('id', 'title', 'bounds', 'cgWindowID', 'minimized', 'minimizedSettable', 'attachedSheetParentID') if key in window}
    projected = summary['window']
    if type(window.get('fullscreen')) is bool:
        projected['fullscreen'] = window['fullscreen']
    projected.update(controls=[], controls_omitted=len(window['controls']))

    def fits():
        # Include escaped MCP text framing as well as reserve for the standard
        # trace/schema envelope; Unicode can grow again inside that framing.
        projected_result = {**wrapper, 'observation_summary': summary}
        return (response_size(projected_result) <= max_bytes
                and len(json.dumps(projected_result, ensure_ascii=True).encode()) + 512 <= max_bytes)

    if 'keyboard' in result:
        summary['keyboard'] = result['keyboard']
        if not fits():
            del summary['keyboard']
            summary['keyboard_omitted'] = True
    if not fits():
        return None
    controls = window['controls']
    admission_order = sorted(range(len(controls)), key=lambda index: controls[index].get('focused') is not True)
    retained_indices = []
    for index in admission_order:
        control = controls[index]
        # Keep descriptors whole, including security/truncation flags. One huge
        # descriptor must not prevent a later small control from being useful.
        # Admit explicit focus first, without changing source traversal order
        # in the returned subset or treating duplicate IDs as one descriptor.
        projected['controls'].append(control)
        projected['controls_omitted'] -= 1
        if not fits():
            projected['controls'].pop()
            projected['controls_omitted'] += 1
        else:
            retained_indices.append(index)
    projected['controls'] = [controls[index] for index in sorted(retained_indices)]
    return summary


class NativeRequestCancellation:
    def __init__(self, owner, request_id, claim_id, runtime, submit, diagnostic=None, lifetime=None):
        self.binding = (owner, request_id, claim_id, runtime)
        self.diagnostic = diagnostic
        self.submit = submit
        self.lock = threading.Lock()
        self.cancelled = False
        self.attached = True
        self.completed = False
        self.cleanup = None
        self.reason = None
        self.unsubscribe = None
        if lifetime is not None:
            self.unsubscribe = lifetime.subscribe(self.transport_lost)

    def _note(self, stage, **fields):
        try:
            if self.diagnostic is not None:
                self.diagnostic.note(stage, **fields)
        except Exception:
            pass

    def request(self):
        self._request('explicit_peer_cancel')

    def transport_lost(self):
        self._request('http_disconnect')

    def _request(self, reason):
        # No await/default-executor dependency inside an already cancelled scope.
        with self.lock:
            if not self.attached or self.cancelled:
                return
            self.cancelled = True
            self.reason = reason
            cleanup = self.cleanup
        self._note('native_cancel_requested', armed=cleanup is not None, cause=reason)
        if cleanup is not None:
            try:
                self.submit(cleanup)
                self._note('native_cancel_submitted')
            except RuntimeError:
                self._note('native_cancel_submit_unavailable')
                logging.warning('Native cancellation control executor unavailable; recover original receipt')

    def detach(self):
        with self.lock:
            self.attached = False
            unsubscribe, self.unsubscribe = self.unsubscribe, None
        if unsubscribe is not None:
            unsubscribe()

    def finish(self):
        with self.lock:
            self.completed = True
        self.detach()

    def before_dispatch(self, native, owner, request_id, claim_id):
        with self.lock:
            if self.binding != (owner, request_id, claim_id, native.instance_id):
                raise WorkbenchError('native_cancellation_owner_mismatch',
                    'The request cancellation authority does not match this operation.', effect_state='none')
            if self.cancelled:
                raise WorkbenchError('native_operation_cancelled',
                    'The request ended before native dispatch.', effect_state='none')
            # NativeCancellation holds an exact owner/request pending cancel if
            # this priority message reaches it before the operation socket does.
            def cleanup():
                with self.lock:
                    if self.completed:
                        return
                try:
                    result = native.control_channel.request('cancel_operation', _timeout=3, _allow_failure=True,
                        operation_id=request_id, claim_id=claim_id, owner_session=owner)
                    self._note('native_cancel_control_result', ok=result.get('ok') is True)
                    if result.get('ok') is not True:
                        logging.warning('Native request cleanup unconfirmed for %s; recover original receipt', request_id)
                except Exception:
                    self._note('native_cancel_control_exception')
                    logging.exception('Native request cleanup failed for %s; original outcome remains unknown', request_id)
            self.cleanup = cleanup


_POINTER_FAILURE_PHASES = frozenset((
    'initial_validation', 'release_validation', 'event_validation', 'release_permission', 'event_permission',
    'release_send', 'event_send', 'release_admission', 'event_admission', 'mouse_up_creation', 'mouse_down_creation',
    'hold_wait_validation', 'hold_wait_permission', 'hold_wait_clock', 'hold_wait_sleep', 'press_validation',
    'press_permission', 'press_send', 'press_admission', 'drag_down_validation', 'drag_down_send',
    'drag_down_admission', 'wheel_creation'))
_POINTER_FAILURE_REASONS = frozenset((
    'native_input_failure', 'accessibility_required', 'screen_recording_required', 'human_input_interrupted',
    'native_activation_point_unavailable', 'native_drag_invalid', 'native_event_creation_failed',
    'native_event_source_unavailable', 'native_focus_cleanup_unverified', 'native_focus_event_unavailable',
    'native_hold_clock_invalid', 'native_hold_duration_outside_scope', 'native_hold_wait_limit',
    'native_input_permission_revoked', 'native_point_outside_scope', 'native_release_unverified',
    'native_scroll_delta_outside_scope', 'native_targeted_input_partial', 'native_targeted_pointer_unavailable',
    'native_window_geometry_unavailable', 'native_window_identity_changed', 'native_window_moved',
    'native_process_identity_changed', 'native_element_process_mismatch', 'native_element_identity_unavailable',
    'native_attribute_timeout_unavailable', 'native_same_process_window_isolation_unavailable',
    'native_capture_required', 'native_capture_not_granted', 'native_freshness_clock_invalid', 'native_claim_target_mismatch',
    'native_lease_ended', 'native_trusted_setup_required', 'native_capability_not_trusted',
    'native_claim_capabilities_changed', 'native_control_not_granted', 'native_operation_cancelled',
    'native_access_stopped', 'native_cancellation_finished', 'unknown_native_window', 'native_window_minimized'))


def _activation_context(value):
    """Bounded preparation/sender metadata; it never establishes delivery."""
    keys = {'read_attempted', 'disposition', 'selected_mode'}
    if (type(value) is not dict or not keys <= set(value) or set(value) - keys - {'background_prelude'}
            or type(value['read_attempted']) is not bool
            or type(value['disposition']) is not str
            or value['disposition'] not in ('not_read', 'available', 'unsupported', 'no_value', 'read_failed', 'malformed', 'outside_bounds')
            or type(value['selected_mode']) is not str
            or value['selected_mode'] not in ('activation_point', 'code_context_only', 'window_context_only')
            or 'background_prelude' in value and type(value['background_prelude']) is not bool
            or (value['disposition'] == 'not_read') != (value['selected_mode'] == 'code_context_only')
            or value['disposition'] == 'not_read' and value['read_attempted']
            or value['disposition'] in ('available', 'unsupported', 'no_value', 'malformed', 'outside_bounds') and not value['read_attempted']
            or value['selected_mode'] == 'window_context_only' and value['disposition'] not in ('unsupported', 'no_value', 'outside_bounds')):
        return None
    return dict(value)


def _activation_context_result(result, action):
    """Filter detached native, historical and saved point receipt views."""
    clean = dict(result)
    error = clean.get('error')
    raw = clean.pop('activation_context', error.get('activation_context') if type(error) is dict else None)
    context = _activation_context(raw) if action == 'point' else None
    if type(error) is dict:
        clean['error'] = dict(error)
        clean['error'].pop('activation_context', None)
        if context is not None:
            clean['error']['activation_context'] = context
    if context is not None:
        clean['activation_context'] = context
    return clean


def _pointer_failure_summary(value):
    if (type(value) is not dict or set(value) != {'reason', 'phase', 'sent_events', 'possibly_sent'}
            or type(value['reason']) is not str or value['reason'] not in _POINTER_FAILURE_REASONS
            or type(value['phase']) is not str or value['phase'] not in _POINTER_FAILURE_PHASES
            or type(value['sent_events']) is not int or not 0 <= value['sent_events'] <= 64
            or type(value['possibly_sent']) is not bool):
        return None
    # Send counts include focus events; this is not recipient delivery proof.
    return dict(value)


def _window_identity_diagnostic(value):
    """Fixed native identity metadata; no toolkit text or permissive passthrough."""
    keys = {'state', 'getterAvailability', 'provenance', 'axError', 'timeoutError',
            'maximumSeconds', 'elapsedSeconds', 'candidateWindowID', 'logicalBounds',
            'compositorBounds', 'captureLayout'}
    states = {'ambiguous', 'getterError', 'zeroID', 'timeoutSetupFailed', 'budgetExhausted',
              'geometryUnavailable', 'inventoryUnavailable', 'metadataUnavailable',
              'ownerMismatch', 'boundsMismatch', 'identityChanged', 'unverified', 'aliasBlocked'}
    if (type(value) is not dict or set(value) - keys or type(value.get('state')) is not str or value['state'] not in states
            or type(value.get('getterAvailability')) is not str
            or value['getterAvailability'] not in {'available', 'getterUnavailable', 'unsupportedPlatform'}
            or value.get('provenance') not in (None, 'private_ax_window_id', 'unique_geometry_fallback')
            or type(value.get('maximumSeconds')) not in (int, float) or value['maximumSeconds'] != .3):
        return None
    for key in ('axError', 'timeoutError'):
        if value.get(key) is not None and (type(value[key]) is not int or not -(2**31) <= value[key] < 2**31):
            return None
    elapsed = value.get('elapsedSeconds')
    if elapsed is not None and (type(elapsed) not in (int, float) or not 0 <= elapsed <= 1e12):
        return None
    candidate = value.get('candidateWindowID')
    if candidate is not None and (type(candidate) is not int or not 1 <= candidate <= 2**32 - 1):
        return None
    def rectangle(raw):
        return (type(raw) is dict and set(raw) == {'x', 'y', 'width', 'height'}
                and all(type(raw[k]) in (int, float) and abs(raw[k]) <= 1e9 and math.isfinite(raw[k]) for k in raw)
                and raw['width'] > 0 and raw['height'] > 0)
    for key in ('logicalBounds', 'compositorBounds'):
        if value.get(key) is not None and (candidate is None or not rectangle(value[key])):
            return None
    layout = value.get('captureLayout')
    if layout is not None:
        layout_keys = {'state', 'maximumSeconds', 'elapsedSeconds', 'capturedPixels', 'atomicSnapshot',
                       'scWindowID', 'scOwnerPID', 'scFrame', 'scIsActive', 'scIsOnScreen',
                       'filterContentRect', 'filterPointPixelScale', 'filterWindowCount',
                       'filterHasOnlyCandidateWindow'}
        if (type(layout) is not dict or set(layout) - layout_keys
                or layout.get('state') not in ('observed', 'unavailable', 'identityChanged')
                or type(layout.get('maximumSeconds')) not in (int, float) or layout['maximumSeconds'] != 2
                or type(layout.get('elapsedSeconds')) not in (int, float) or not 0 <= layout['elapsedSeconds'] <= 1e12
                or layout.get('capturedPixels') is not False or layout.get('atomicSnapshot') is not False
                or value['state'] != 'boundsMismatch' or candidate is None
                or value.get('logicalBounds') is None or value.get('compositorBounds') is None):
            return None
        for key in ('scIsActive', 'scIsOnScreen', 'filterHasOnlyCandidateWindow'):
            if layout.get(key) is not None and type(layout[key]) is not bool:
                return None
        if layout.get('scWindowID') is not None and (type(layout['scWindowID']) is not int or layout['scWindowID'] != candidate):
            return None
        if layout.get('scOwnerPID') is not None and (type(layout['scOwnerPID']) is not int or not 1 <= layout['scOwnerPID'] < 2**31):
            return None
        for key in ('scFrame', 'filterContentRect'):
            if layout.get(key) is not None and not rectangle(layout[key]):
                return None
        scale = layout.get('filterPointPixelScale')
        if scale is not None and (type(scale) not in (int, float) or not 0 < scale <= 8):
            return None
        count = layout.get('filterWindowCount')
        if count is not None and (type(count) is not int or not 0 <= count <= 2**31 - 1):
            return None
        if layout.get('filterHasOnlyCandidateWindow') is True and count != 1:
            return None
        required = {'scWindowID', 'scOwnerPID', 'scFrame', 'scIsActive', 'scIsOnScreen',
                    'filterContentRect', 'filterPointPixelScale'}
        if layout['state'] == 'observed' and any(layout.get(k) is None for k in required):
            return None
    return copy.deepcopy(value)


def _inspection_capture_result(result, parameters):
    """Keep observation-only metadata exact and bounded before publishing bytes."""
    metadata = result.get('inspection')
    keys = {'windowID', 'ownerPID', 'logicalBounds', 'compositorBounds', 'scFrame', 'filterContentRect',
            'filterPointPixelScale', 'filterWindowCount', 'filterHasOnlyCandidateWindow',
            'ignoreGlobalClipSingleWindow', 'ignoreShadowsSingleWindow', 'contentMappingVerified', 'frameAgeKnown'}
    def rectangle(raw):
        return (type(raw) is dict and set(raw) == {'x', 'y', 'width', 'height'}
                and all(type(raw[k]) in (int, float) and abs(raw[k]) <= 1e9 and math.isfinite(raw[k]) for k in raw)
                and raw['width'] > 0 and raw['height'] > 0)
    forbidden = {'display_scale', 'image_scale_x', 'image_scale_y', 'full_display_resolution', 'visual_validity_policy',
                 'visual_validity_budget_seconds', 'original_capture_id', 'remaining_validity_seconds', 'validity_timing_scope'}
    if (result.get('capture_purpose') != 'inspection' or result.get('input_armed') is not False
            or result.get('content_mapping_verified') is not False or result.get('frame_age_known') is not False
            or not parameters.get('observation_id') or result.get('source_observation_id') != parameters['observation_id']
            or result.get('lease_id') != (parameters.get('claim_id') or parameters.get('lease_id'))
            or set(result) & forbidden or type(metadata) is not dict or set(metadata) != keys
            or type(metadata.get('windowID')) is not int or not 1 <= metadata['windowID'] <= 2**32 - 1
            or type(metadata.get('ownerPID')) is not int or not 1 <= metadata['ownerPID'] < 2**31
            or any(not rectangle(metadata.get(key)) for key in ('logicalBounds', 'compositorBounds', 'scFrame', 'filterContentRect'))
            or type(metadata.get('filterPointPixelScale')) not in (int, float) or not 0 < metadata['filterPointPixelScale'] <= 8
            or type(metadata.get('filterWindowCount')) is not int or metadata['filterWindowCount'] != 1
            or any(metadata.get(key) is not True for key in ('filterHasOnlyCandidateWindow', 'ignoreGlobalClipSingleWindow', 'ignoreShadowsSingleWindow'))
            or metadata.get('contentMappingVerified') is not False or metadata.get('frameAgeKnown') is not False):
        raise WorkbenchError('native_capture_inspection_protocol',
            'The inspection reply did not verify its exact observation-only scope. Obtain a fresh observation before a new capture.', effect_state='none')
    return {**result, 'inspection': copy.deepcopy(metadata)}


def _visual_refresh_details(value, observation_id):
    """Retain only bounded, same-observation refresh evidence; never retry advice."""
    policies = {'trusted_capture_and_observation_30s': 30, 'legacy_capture_5s_observation_30s': 5}
    keys = {'visual_validity_policy', 'visual_validity_budget_seconds', 'original_capture_id',
            'source_observation_id', 'capture_call_age_seconds', 'observation_age_seconds',
            'remaining_validity_seconds', 'freshness_clock', 'capture_age_anchor',
            'frame_age_known', 'atomic_with_dispatch', 'content_unchanged', 'refresh_required',
            'visual_validity_state', 'refresh_action'}
    if type(value) is not dict or not keys <= value.keys():
        return None
    result = {key: value[key] for key in keys}
    policy = result['visual_validity_policy']
    if (type(policy) is not str or policy not in policies
            or type(result['visual_validity_budget_seconds']) not in (int, float)
            or result['visual_validity_budget_seconds'] != policies[policy]
            or result['source_observation_id'] != observation_id
            or not all(type(result[key]) is str and re.fullmatch(r'[0-9a-f]{32}', result[key])
                       for key in ('source_observation_id', 'original_capture_id'))
            or result['freshness_clock'] != 'system_uptime_monotonic'
            or result['capture_age_anchor'] != 'signed_app_capture_call_start'
            or result['frame_age_known'] is not False or result['atomic_with_dispatch'] is not False
            or result['content_unchanged'] != 'not_established'
            or result['refresh_required'] is not True
            or result['visual_validity_state'] not in ('expired', 'consumed', 'capture_refresh_failed',
                'source_unavailable', 'geometry_changed', 'window_replaced', 'clock_invalid', 'inspection_capture')
            or result['refresh_action'] != 'observe_and_explicitly_capture_then_select_coordinates_for_new_intent'):
        return None
    for key in ('capture_call_age_seconds', 'observation_age_seconds', 'remaining_validity_seconds'):
        number = result[key]
        if number is not None and (type(number) not in (int, float)
                or abs(number) > 1.7976931348623157e308 or not math.isfinite(number) or number < 0):
            return None
    if result['remaining_validity_seconds'] is not None and result['remaining_validity_seconds'] > policies[policy]:
        return None
    return result if len(json.dumps(result, allow_nan=False).encode()) <= 4096 else None


_GEOMETRY_FAILURE_REASON_CODES = {
    'deadline': 'native_window_geometry_unavailable',
    'position_changed': 'native_window_moved', 'size_changed': 'native_window_moved',
    'bounds_changed': 'native_window_moved',
    'nonfinite_or_invalid_dimensions': 'native_window_geometry_unavailable',
    'cg_identity_changed': 'native_window_identity_changed',
    'non_retryable_read': 'native_window_geometry_unavailable',
    'attempt_limit': 'native_window_geometry_unavailable',
}
_GEOMETRY_VALUE_STATES = frozenset(('decoded', 'axError', 'noValue', 'wrongType', 'wrongValueType',
    'conversionFailed', 'nonfinite', 'invalidDimensions', 'notRead', 'timeoutSetupFailed'))


def _geometry_failure(value):
    """Closed failure evidence; never accept geometry or arbitrary trace metadata."""
    def integer(raw, minimum, maximum):
        return type(raw) is int and minimum <= raw <= maximum

    def seconds(raw, maximum, positive=False):
        return (type(raw) in (int, float) and 0 <= raw <= maximum and math.isfinite(raw)
                and (not positive or raw > 0))

    keys = {'reason', 'error_code', 'attempt_count', 'maximum_attempts', 'elapsed_seconds',
            'total_seconds', 'maximum_attribute_seconds', 'attempts'}
    if type(value) is not dict or set(value) != keys:
        return None
    reason, code = value['reason'], value['error_code']
    if (type(reason) is not str or type(code) is not str
            or code not in _POINTER_FAILURE_REASONS | {'native_geometry_guard_failed'}
            or (reason != 'guard_refused' and _GEOMETRY_FAILURE_REASON_CODES.get(reason) != code)
            or not integer(value['maximum_attempts'], 1, 3)
            or not integer(value['attempt_count'], 0, value['maximum_attempts'])
            or not seconds(value['total_seconds'], .5, positive=True)
            or not seconds(value['maximum_attribute_seconds'], .1, positive=True)
            or (value['elapsed_seconds'] is not None and not seconds(value['elapsed_seconds'], 9007199254740991))
            or type(value['attempts']) is not list or len(value['attempts']) != value['attempt_count']):
        return None
    attempts = []
    for index, sample in enumerate(value['attempts'], 1):
        if (type(sample) is not dict or set(sample) != {'attempt', 'position', 'size'}
                or not integer(sample['attempt'], 1, 3) or sample['attempt'] != index):
            return None
        clean = {'attempt': index}
        for axis in ('position', 'size'):
            attribute = sample[axis]
            if (type(attribute) is not dict or set(attribute) != {'ax_error', 'value_state', 'timeout_setup_error'}
                    or type(attribute['value_state']) is not str or attribute['value_state'] not in _GEOMETRY_VALUE_STATES
                    or any(attribute[key] is not None and not integer(attribute[key], -2147483648, 2147483647)
                           for key in ('ax_error', 'timeout_setup_error'))):
                return None
            clean[axis] = dict(attribute)
        attempts.append(clean)
    projected = {**value, 'attempts': attempts}
    if len(json.dumps(projected, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()) > 4096:
        return None
    return projected


def _geometry_failure_result(result, action):
    """Sanitize a detached result view; stored native and terminal host receipts stay immutable."""
    clean = _activation_context_result(result, action)
    geometry = None
    if action == 'point' and result.get('ok') is False:
        summary = _pointer_failure_summary(result.get('failure_summary'))
        error = result.get('error')
        cause = summary['reason'] if summary is not None else error.get('code') if type(error) is dict else None
        if 'failure_summary' not in result or summary is not None:
            projected = _geometry_failure(result.get('geometry_failure'))
            if projected is not None and projected['error_code'] == cause:
                geometry = projected
    clean.pop('geometry_failure', None)
    if type(clean.get('error')) is dict:
        clean['error'] = dict(clean['error'])
        clean['error'].pop('geometry_failure', None)
        if geometry is not None:
            clean['error']['geometry_failure'] = geometry
    if geometry is not None:
        clean['geometry_failure'] = geometry
    return clean


def _restore_result(value, window_id):
    """One closed Swift restore-result contract, bound to original request authority."""
    def integer(raw, low, high):
        return type(raw) is int and low <= raw <= high

    def number(raw, low, high):
        return type(raw) in (int, float) and low <= raw <= high and math.isfinite(raw)

    def state(raw):
        return (type(raw) is dict and {'windowID'} <= set(raw)
                and not set(raw) - {'windowID', 'minimized', 'minimizedSettable'}
                and type(raw['windowID']) is str and raw['windowID'] == window_id
                and all(raw.get(key) is None or type(raw[key]) is bool for key in ('minimized', 'minimizedSettable')))

    base = {'action', 'window_id', 'input_backend', 'before', 'after', 'dispatch_state', 'dispatch_result',
            'exact_requested_state', 'observations_invalidated', 'verification_state'}
    poll = {'readback_attempts', 'readback_elapsed_ms', 'readback_maximum_ms', 'readback_budget_exhausted'}
    optional = poll | {'terminal_readback_error'}
    try:
        valid_window = type(window_id) is str and bool(window_id) and len(window_id.encode()) <= 256
    except UnicodeError:
        valid_window = False
    if (not valid_window
            or type(value) is not dict or not base <= set(value) or set(value) - base - optional
            or value['action'] != 'restore_window' or value['input_backend'] != 'semantic_ax'
            or type(value['window_id']) is not str or value['window_id'] != window_id
            or not state(value['before']) or value['after'] is not None and not state(value['after'])
            or value['dispatch_state'] not in ('not_dispatched', 'dispatched')
            or value['dispatch_result'] is not None and not integer(value['dispatch_result'], -2147483648, 2147483647)
            or type(value['exact_requested_state']) is not bool or type(value['observations_invalidated']) is not bool
            or value['verification_state'] not in ('not_dispatched', 'already_restored', 'minimized_false_verified',
                                                  'minimized_false_not_verified', 'readback_unavailable')):
        return None
    has_poll = bool(set(value) & poll)
    if has_poll and (not poll <= set(value) or not integer(value['readback_attempts'], 0, 8)
            or not number(value['readback_elapsed_ms'], 0, 60000)
            or not number(value['readback_maximum_ms'], 500, 500)
            or type(value['readback_budget_exhausted']) is not bool):
        return None
    terminal = value.get('terminal_readback_error')
    if 'terminal_readback_error' in value and (not has_poll or type(terminal) is not str
            or terminal not in _POINTER_FAILURE_REASONS | {'native_restore_readback_unavailable'}):
        return None
    if has_poll and value['readback_attempts'] == 0 and (
            value['dispatch_state'] != 'dispatched' or value['exact_requested_state'] is not False
            or value['after'] is not None or value['verification_state'] not in ('minimized_false_not_verified', 'readback_unavailable')
            or not (value['readback_budget_exhausted'] is True or terminal is not None)):
        return None
    dispatched = value['dispatch_state'] == 'dispatched'
    exact = value['exact_requested_state']
    verification = value['verification_state']
    after_false = value['after'] is not None and value['after'].get('minimized') is False
    if dispatched:
        if (value['observations_invalidated'] is not True or value['before'].get('minimized') is not True
                or value['before'].get('minimizedSettable') is not True
                or verification not in ('minimized_false_verified', 'minimized_false_not_verified', 'readback_unavailable')):
            return None
        verified = (value['dispatch_result'] == 0 and after_false and has_poll
                    and value['readback_budget_exhausted'] is False and terminal is None
                    and value['readback_elapsed_ms'] < value['readback_maximum_ms'])
        if exact:
            if verification != 'minimized_false_verified' or not verified:
                return None
        elif verification == 'minimized_false_verified' or verification == 'minimized_false_not_verified' and (not has_poll or verified):
            return None
    else:
        if value['dispatch_result'] is not None or value['observations_invalidated'] is not False or has_poll or terminal is not None:
            return None
        if exact:
            if verification != 'already_restored' or value['before'].get('minimized') is not False or not after_false:
                return None
        elif verification != 'not_dispatched' or value['after'] is not None:
            return None
    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        return json.loads(encoded) if len(encoded.encode()) <= 8192 else None
    except (ValueError, TypeError):
        return None


def _restore_outcome(result, window_id):
    """Detached normalization only: never modify signed or immutable host receipts."""
    clean = dict(result)
    error = clean.get('error')
    error = dict(error) if type(error) is dict else None
    raw = clean.pop('restore_result', None)
    if error is not None:
        nested = error.pop('restore_result', None)
        if raw is None:
            raw = nested
        elif nested is not None and not _same_native_parameters(raw, nested):
            raw = None
        clean['error'] = error
    restored = _restore_result(raw, window_id)
    expected_effect = ('applied' if restored['dispatch_state'] == 'dispatched' else 'none') if restored else None
    if clean.get('ok') is True:
        if (restored is None or restored['exact_requested_state'] is not True
                or clean.get('effect_state') != expected_effect or error is not None
                or clean.get('task_completion', 'not_established') != 'not_established'):
            clean.update(ok=False, effect_state='unknown', task_completion='not_established',
                error={'code': 'native_restore_protocol_unverified', 'effect_state': 'unknown',
                       'message': 'The restore response did not verify the exact original window. Inspect its original receipt; do not replay the setter.'})
            clean.pop('operation_receipt', None)
        else:
            clean['restore_result'] = restored
    elif clean.get('ok') is False:
        # Optional invalid error evidence cannot alter the original refusal/effect.
        failure_effect = 'unknown' if restored and restored['dispatch_state'] == 'dispatched' else 'none'
        outer_effect = clean.get('effect_state', error.get('effect_state') if error else None)
        if (error is None or error.get('effect_state') not in ('none', 'unknown')
                or outer_effect != error.get('effect_state')):
            clean.update(effect_state='unknown', task_completion='not_established',
                         error={'code': 'native_restore_protocol_unverified', 'effect_state': 'unknown'})
            clean.pop('operation_receipt', None)
        elif (restored is not None and restored['exact_requested_state'] is False
                and outer_effect == failure_effect and error is not None and error.get('effect_state') == failure_effect):
            clean['restore_result'] = restored
    else:
        clean.update(ok=False, effect_state='unknown', task_completion='not_established',
                     error={'code': 'native_restore_protocol_unverified', 'effect_state': 'unknown'})
        clean.pop('operation_receipt', None)
    return clean


def _validate_historical_receipt(envelope, parameters):
    """Bind read-only history to its original owner, without live authority."""
    error = WorkbenchError('interaction_protocol_error', 'The native history did not match the original operation and claim.', effect_state='unknown')
    if type(envelope) is not dict or envelope.get('ok') is not True:
        raise error
    if envelope.get('state') == 'not_found' and 'receipt' not in envelope:
        return
    record = envelope.get('receipt')
    if 'claim_id' not in parameters:
        if type(record) is dict:
            owner = record.get('owner_session')
            original = record.get('parameters')
            parameter_owner = original.get('owner_session') if type(original) is dict else None
            if any(value is not None and value != '' and value != parameters['owner_session']
                   for value in (owner, parameter_owner)):
                raise error
            if owner is None or owner == '':
                # Old unbound history remains useful, but cannot prove ownership
                # or authorize input. Mark only this detached response.
                envelope['receipt_owner_unverified'] = True
        return
    if type(record) is not dict:
        raise error
    original = record.get('parameters')
    pending = record.get('state') == 'pending'
    binding = envelope.get('historical_binding')
    sparse = pending and 'parameters' not in record
    if sparse:
        fields = {'version', 'source', 'operation_id', 'claim_id', 'owner_session',
                  'runtime_generation', 'target_generation', 'window_id', 'payload_sha256', 'native_action'}
        if (type(binding) is not dict or set(binding) != fields
                or type(binding.get('version')) is not int or binding['version'] != 1
                or binding.get('source') != 'verified_provider_receipt'
                or any(binding.get(key) != parameters.get(key)
                       for key in ('operation_id', 'claim_id', 'owner_session'))
                or binding.get('operation_id') != record.get('operation_id')
                or binding.get('owner_session') != record.get('owner_session')
                or binding.get('payload_sha256') != record.get('payload_sha256')
                or binding.get('native_action') != record.get('native_action')
                or binding.get('native_action') not in ('key_pair', 'key_chord', 'key_sequence', 'insert_text')
                or not interaction_contract.identifier(binding.get('runtime_generation'))
                or not interaction_contract.identifier(binding.get('target_generation'))
                or type(binding.get('window_id')) is not str or not binding['window_id']
                or ('window_id' in parameters and binding['window_id'] != parameters['window_id'])
                or any(key in record and record[key] != binding[key]
                       for key in ('claim_id', 'runtime_generation', 'target_generation', 'window_id'))):
            raise error
    if (record.get('state') not in ('completed', 'pending') or 'state' in envelope
            or type(parameters.get('operation_id')) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parameters['operation_id']) is None
            or record.get('operation_id') != parameters['operation_id']
            or (not sparse and record.get('claim_id') != parameters['claim_id'])
            or record.get('owner_session') != parameters['owner_session']
            or (not sparse and not interaction_contract.identifier(record.get('runtime_generation')))
            or type(record.get('payload_sha256')) is not str
            or re.fullmatch(r'[0-9a-f]{64}', record['payload_sha256']) is None
            or record.get('native_action') not in ('acquire', 'release', 'control', 'point', 'fixture_probe_point',
                'revoke', 'clipboard_temporary', 'clipboard_restore', 'clipboard_release', 'move', 'resize',
                'restore_window', 'key_pair', 'key_chord', 'key_sequence', 'insert_text')
            or (not sparse and (type(original) is not dict
                or original.get('claim_id') != parameters['claim_id']
                or original.get('owner_session') != parameters['owner_session']
                or ('window_id' in parameters and original.get('window_id') != parameters['window_id'])))
            or (pending and (record.get('effect_state') != 'unknown' or 'result' in record))
            or (not pending and (type(record.get('result')) is not dict or type(record['result'].get('ok')) is not bool))):
        raise error
    if pending and not sparse and record['native_action'] in ('key_pair', 'key_chord', 'key_sequence', 'insert_text'):
        try:
            _validate_provider_input(record['native_action'],
                {key: value for key, value in original.items() if key != 'owner_session'})
        except WorkbenchError:
            raise error from None


def _restore_receipt_view(envelope, parameters):
    record = envelope.get('receipt')
    if type(record) is not dict:
        return envelope
    if record.get('state') == 'pending':
        return envelope
    if record.get('native_action') != 'restore_window':
        raw = record.get('result')
        if type(raw) is dict and ('restore_result' in raw
                or type(raw.get('error')) is dict and 'restore_result' in raw['error']):
            return {**envelope, 'receipt': {**record, 'result': _restore_outcome({'ok': True}, None)}}
        return envelope
    original = record.get('parameters')
    bound = (type(original) is dict and set(original) == {'claim_id', 'owner_session', 'window_id'}
             and record.get('state') == 'completed'
             and type(parameters.get('operation_id')) is str
             and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parameters['operation_id']) is not None
             and record.get('operation_id') == parameters.get('operation_id')
             and type(parameters.get('owner_session')) is str and bool(parameters['owner_session'])
             and len(parameters['owner_session'].encode()) <= 128
             and record.get('owner_session') == parameters.get('owner_session')
             and type(record.get('claim_id')) is str and interaction_contract.identifier(record['claim_id'])
             and original.get('claim_id') == record['claim_id'] and original.get('owner_session') == record['owner_session']
             and type(record.get('runtime_generation')) is str and interaction_contract.identifier(record['runtime_generation'])
             and ('claim_id' not in parameters or record['claim_id'] == parameters['claim_id'])
             and ('window_id' not in parameters or original.get('window_id') == parameters['window_id']))
    native_result = record.get('result')
    native_result = native_result if type(native_result) is dict else {}
    clean = _restore_outcome(native_result, original.get('window_id') if bound else None)
    if not bound:
        clean = _restore_outcome({'ok': True}, None)
    return {**envelope, 'receipt': {**record, 'result': clean}}


def _raise_restore_failure(result):
    error = result.get('error', {})
    code = error.get('code', 'native_restore_protocol_unverified')
    if type(code) is not str or re.fullmatch(r'[a-z_]{1,80}', code) is None:
        code = 'native_restore_protocol_unverified'
    details = {key: value for key, value in error.items() if key not in ('code', 'message')}
    if 'restore_result' in result:
        details['restore_result'] = result['restore_result']
    for key in ('replayed', 'applied_this_call'):
        if key in result:
            details[key] = result[key]
    raise WorkbenchError(code, error.get('message', 'The original restore outcome could not be verified.'), **details)


def _clipboard_recovery(value):
    if (type(value) is not dict or set(value) != {'clipboard_lease_id', 'preimage_retained', 'state', 'automatic_restoration', 'durability'}
            or type(value['clipboard_lease_id']) is not str or re.fullmatch(r'[a-f0-9]{32}', value['clipboard_lease_id']) is None
            or type(value['preimage_retained']) is not bool or value['preimage_retained'] is not True
            or type(value['state']) is not str or value['state'] not in ('temporary_verified', 'recovery_only')
            or value['automatic_restoration'] is not False or value['durability'] != 'app_process_memory'):
        return None
    return dict(value)


def _validate_clipboard_payload(parameters):
    representations = parameters.get('representations')
    if representations is not None:
        if ('text' in parameters or type(representations) is not list or not 1 <= len(representations) <= 3):
            raise WorkbenchError('invalid_native_clipboard_payload', 'Supply text or 1..3 distinct plain_text, markdown or html representations.', effect_state='none')
        entries = representations
    elif type(parameters.get('text')) is str:
        entries = [{'format': 'plain_text', 'text': parameters['text']}]
    else:
        raise WorkbenchError('invalid_native_clipboard_payload', 'Supply explicit clipboard text or representations.', effect_state='none')
    seen, byte_count = set(), 0
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {'format', 'text'} or type(entry['format']) is not str
                or entry['format'] not in ('plain_text', 'markdown', 'html') or entry['format'] in seen
                or type(entry['text']) is not str):
            raise WorkbenchError('invalid_native_clipboard_payload', 'Each representation requires one unique supported format and exact UTF-8 text.', effect_state='none')
        try:
            byte_count += len(entry['text'].encode('utf-8', errors='strict'))
        except UnicodeEncodeError:
            raise WorkbenchError('invalid_native_clipboard_payload', 'Clipboard text must encode as valid UTF-8.', effect_state='none') from None
        if byte_count > 32768:
            raise WorkbenchError('native_clipboard_payload_limit', 'Clipboard representations permit at most 32768 aggregate UTF-8 bytes.', effect_state='none')
        seen.add(entry['format'])


def _validate_provider_input(action, parameters):
    """One exact source proof; receiver binding IDs never cross MCP."""
    captured = action == 'key_pair' and 'observation_id' in parameters
    source = 'observation_id' if captured else 'provider_observation_id'
    required = {'claim_id', 'window_id', source} | (
        {'keys'} if action == 'key_sequence' else ({'key_code', 'characters', 'characters_ignoring_modifiers'} | ({'modifiers'} if action == 'key_chord' else set())) if action in ('key_pair', 'key_chord', 'key_sequence') else {'text'})
    if (set(parameters) != required
            or type(parameters.get('claim_id')) is not str or not interaction_contract.identifier(parameters['claim_id'])
            or type(parameters.get('window_id')) is not str or not parameters['window_id']
            or type(parameters.get(source)) is not str
            or (not interaction_contract.identifier(parameters[source]) if captured else
                re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', parameters[source]) is None)):
        raise WorkbenchError('invalid_native_provider_input',
            'Use the exact claim_id/window_id and one observation proof: UUID provider_observation_id, or only for captured key_pair, observation_id with a fresh input capture. Never supply both.', effect_state='none')
    if action == 'key_sequence':
        descriptors = parameters['keys']
        if type(descriptors) is not list or not 2 <= len(descriptors) <= 8:
            raise WorkbenchError('invalid_native_key_sequence', 'Supply 2..8 explicit key descriptors.', effect_state='none')
        for key in descriptors:
            if (type(key) is not dict or set(key) != {'key_code', 'characters', 'characters_ignoring_modifiers', 'modifiers'}
                    or type(key.get('modifiers')) is not list or len(key['modifiers']) > 1
                    or any(type(v) is not str or v not in ('shift', 'control', 'option') for v in key['modifiers'])):
                raise WorkbenchError('invalid_native_key_sequence', 'Each sequence key requires exact key fields and zero or one advertised Shift/Control/Option modifier.', effect_state='none')
            single = {k: v for k, v in key.items() if k != 'modifiers'}
            single.update({k: parameters[k] for k in ('claim_id', 'window_id', 'provider_observation_id')})
            _validate_provider_input('key_pair', single)
        return
    fields = ('characters', 'characters_ignoring_modifiers') if action in ('key_pair', 'key_chord') else ('text',)
    try:
        for field in fields:
            value = parameters[field]
            if type(value) is not str:
                raise ValueError
            units = len(value.encode('utf-16-le')) // 2
            if (action in ('key_pair', 'key_chord') and not 1 <= units <= 8
                    or action == 'insert_text' and (units > 4096 or len(value.encode('utf-8')) > 16384)):
                raise ValueError
    except (ValueError, UnicodeError):
        raise WorkbenchError('invalid_native_provider_text',
            'key_pair character strings require 1..8 UTF-16 units each; insert_text permits at most 4096 UTF-16 units and 16384 UTF-8 bytes, without range overrides.', effect_state='none') from None
    if action in ('key_pair', 'key_chord') and (type(parameters['key_code']) is not int
            or not 0 <= parameters['key_code'] <= 127 or 54 <= parameters['key_code'] <= 63):
        raise WorkbenchError('invalid_native_key_code',
            'Supply an exact integer hardware key_code 0..127 excluding modifier codes 54..63; no layout or modifier flags are inferred.', effect_state='none')

    if action == 'key_chord':
        modifiers = parameters['modifiers']
        if (type(modifiers) is not list or not 1 <= len(modifiers) <= 4
                or any(type(value) is not str for value in modifiers)
                or len(set(modifiers)) != len(modifiers)
                or not set(modifiers).issubset({'command', 'control', 'option', 'shift'})):
            raise WorkbenchError('invalid_native_modifiers',
                'Supply one to four unique modifiers: command, control, option or shift. The observed receiver must support key_chord.', effect_state='none')


_CURSOR_PHASES = frozenset(('enqueue', 'uiStart', 'lookupStart', 'metadataQueueStart', 'bindingStart', 'bindingEnd',
    'stackReadStart', 'stackReadEnd', 'metadataReadEnd', 'completionStart', 'superseded', 'timeout', 'refusal',
    'showRequest', 'showReturn', 'hideRequest', 'hideReturn', 'invalidate'))
_CURSOR_REASONS = frozenset(('cursor_request_invalid', 'cursor_app_identity_unknown', 'cursor_app_identity_changed',
    'cursor_window_binding_unknown', 'cursor_window_binding_changed', 'cursor_target_missing', 'cursor_target_changed',
    'cursor_target_moved', 'cursor_target_offscreen', 'cursor_target_visibility_unknown', 'cursor_target_transparent',
    'cursor_window_list_unavailable', 'cursor_window_stack_limit', 'cursor_window_stack_unknown',
    'cursor_window_stack_changed', 'cursor_occlusion_metadata_unknown', 'cursor_target_occluded',
    'cursor_screen_coordinates_unknown', 'cursor_presentation_expired', 'cursor_metadata_timeout', 'cursor_target_required'))


def _cursor_diagnostics(value, operation_id, claim_id, owner_session, runtime):
    """Validate a separate timing view; never reconcile or enrich an input receipt."""
    def refuse():
        raise WorkbenchError('native_cursor_diagnostics_protocol', 'The cursor timing reply did not match its bounded owner and schema.', effect_state='none')
    if type(value) is not dict:
        refuse()
    base = {'ok', 'receipt_view', 'state', 'diagnostics_only'}
    # The authenticated bridge adds only these correlation fields.
    bridge = {'version', 'request_id', 'app_generation', 'launch_id', 'runtime_generation'}
    if (set(value) - bridge not in (base, base | {'cursor_diagnostics'})
            or value.get('ok') is not True or value.get('receipt_view') != 'cursor_diagnostics'
            or value.get('diagnostics_only') is not True):
        refuse()
    if value.get('state') == 'unavailable' and 'cursor_diagnostics' not in value:
        return {key: value[key] for key in base}
    trace = value.get('cursor_diagnostics')
    fields = {'schemaVersion', 'clock', 'owner', 'startedAt', 'checkedAt', 'collecting', 'detailed', 'droppedEvents', 'events'}
    expected = {'operationID': operation_id, 'claimID': claim_id, 'ownerSession': owner_session, 'runtimeGeneration': runtime}
    number = lambda n: type(n) in (float, int) and math.isfinite(n) and n >= 0
    integer = lambda n: type(n) is int and 0 <= n <= 2**64 - 1
    uuid = lambda n: type(n) is str and re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', n) is not None
    if (value.get('state') != 'available' or type(trace) is not dict or set(trace) != fields
            or type(trace['schemaVersion']) is not int or trace['schemaVersion'] != 1
            or trace['clock'] != 'ProcessInfo.systemUptime' or trace['owner'] != expected
            or not number(trace['startedAt']) or not number(trace['checkedAt']) or trace['checkedAt'] < trace['startedAt']
            or type(trace['collecting']) is not bool or trace['collecting'] != (trace['checkedAt'] - trace['startedAt'] < 10)
            or trace['checkedAt'] - trace['startedAt'] >= 60 or type(trace['detailed']) is not bool
            or not integer(trace['droppedEvents']) or type(trace['events']) is not list or len(trace['events']) > 128):
        refuse()
    last_sequence, last_time, generation = 0, trace['startedAt'], None
    for event in trace['events']:
        if (type(event) is not dict or not {'sequence', 'uptime', 'phase', 'generation'} <= set(event)
                or set(event) - {'sequence', 'uptime', 'phase', 'generation', 'ticketSerial', 'lookup', 'requestedPoint', 'reason'}
                or not integer(event['sequence']) or event['sequence'] <= last_sequence
                or not number(event['uptime']) or not last_time <= event['uptime'] <= trace['checkedAt']
                or event['uptime'] - trace['startedAt'] >= 10 or type(event['phase']) is not str or event['phase'] not in _CURSOR_PHASES
                or not uuid(event['generation']) or generation is not None and generation != event['generation']
                or 'ticketSerial' in event and not integer(event['ticketSerial'])
                or 'lookup' in event and not uuid(event['lookup'])
                or 'requestedPoint' in event and type(event['requestedPoint']) is not bool
                or 'reason' in event and (type(event['reason']) is not str or event['reason'] not in _CURSOR_REASONS)):
            refuse()
        last_sequence, last_time, generation = event['sequence'], event['uptime'], event['generation']
    if len(json.dumps(trace, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()) > 24 * 1024:
        refuse()
    return {key: value[key] for key in base | {'cursor_diagnostics'}}


def _same_native_parameters(left, right):
    # Foundation may serialize a JSON double 10.0 as 10. Booleans still must
    # never match numeric fields; ownership strings and key sets are exact.
    if type(left) is dict and type(right) is dict:
        return left.keys() == right.keys() and all(_same_native_parameters(left[key], right[key]) for key in left)
    if type(left) is list and type(right) is list:
        return len(left) == len(right) and all(_same_native_parameters(a, b) for a, b in zip(left, right))
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    return type(left) is type(right) and left == right


class NativeAppOperations:
    def __init__(self, config, store, journal, instance_id, environ=None, file_tools=None):
        self.config, self.store, self.journal, self.instance_id = config, store, journal, instance_id
        self.file_tools = file_tools
        environment = os.environ if environ is None else environ
        mapped = {key: environment.get(key.replace('LOCAL_WORKBENCH_NATIVE', 'LOCAL_WORKBENCH_AUTOMATION'), '') for key in BRIDGE_KEYS}
        self.channel = NativePermissions(instance_id, ActivityGate(), lambda: {}, environ=mapped)
        controls = {key:environment.get(key.replace('LOCAL_WORKBENCH_NATIVE','LOCAL_WORKBENCH_AUTOMATION_CONTROL'),'') for key in BRIDGE_KEYS}
        self.control_channel = NativePermissions(instance_id, ActivityGate(), lambda: {}, environ=controls)
        self.activity_gate = None
        self.sessions = None
        self._tasks_lock = threading.RLock()
        self._tasks = {}
        self._closing = False

    def active_ids(self, owner_session=None):
        with self._tasks_lock:
            return [identifier for identifier, task in self._tasks.items()
                    if owner_session is None or task['owner_session'] == owner_session]

    def session_resource_ids(self, owner_session):
        """Close fence, including idle host claims and unsettled cleanup.

        Session admission pins acquisition through publication. The host's
        global diagnostic sample cannot attribute every held operation, so
        unclassified activity conservatively prevents close as well.
        """
        with self._tasks_lock:
            live = set(self._tasks)
            ids = [identifier for identifier, task in self._tasks.items()
                   if task['owner_session'] == owner_session]
        owned_tasks = set(ids)
        if not self.channel.configured:
            return ids
        status = self._request('operation', action='status', owner_session=owner_session)
        def unavailable(**details):
            raise WorkbenchError('native_activity_unavailable',
                'Native resource accounting is incomplete; preserve this work session until it can be checked.',
                effect_state='none', **details)
        claims, clipboard = status.get('claims'), status.get('clipboard_leases')
        activity = status.get('native_activity')
        if (type(claims) is not list or type(clipboard) is not list or type(activity) is not dict
                or type(activity.get('version')) is not int or activity['version'] != 1
                or activity.get('scope') != 'global_native_activity'
                or activity.get('ids_complete') is not True or activity.get('ids_truncated') is not False
                or type(activity.get('active_ids')) is not list
                or any(type(value) is not str or not value for value in activity['active_ids'])
                or type(activity.get('reported_id_count')) is not int
                or activity['reported_id_count'] != len(activity['active_ids'])
                or type(activity.get('busy')) is not bool
                or activity['busy'] != bool(activity['active_ids'])
                or activity.get('state') != ('busy' if activity['busy'] else 'sampled_empty')):
            unavailable()
        unrelated, owned_claims = set(), set()
        seen = set()
        for row in claims:
            if type(row) is not dict:
                unavailable()
            claim = interaction_contract.claim(row, backend='native',
                runtime_generation=row.get('runtime_generation'), owner_session=row.get('owner_session'))
            if (not interaction_contract.identifier(claim['runtime_generation']) or claim['claim_id'] in seen
                    or type(claim['owner_session']) is not str or not claim['owner_session']):
                unavailable()
            seen.add(claim['claim_id'])
            if claim['owner_session'] == owner_session:
                owned_claims.add(claim['claim_id'])
                # Runtime suspension removes input eligibility, but the host
                # retains window/process bindings until exact release.
                if claim['state'] in ('active', 'suspended_transport', 'modal_blocked', 'suspended_contention'):
                    ids.append(claim['claim_id'])
            else:
                unrelated.add(claim['claim_id'])
        clipboard_ids = set()
        for row in clipboard:
            if type(row) is not dict or not interaction_contract.identifier(row.get('clipboard_lease_id')):
                unavailable()
            # Host filtering also includes legacy ownerless clipboard leases.
            # Only the retained exact claim establishes attribution here.
            if row.get('lease_id') not in owned_claims:
                unavailable(reason='clipboard_recovery_owner_unverified')
            clipboard_ids.add('clipboard:' + row['clipboard_lease_id'])
        ids.extend(clipboard_ids)
        # The global sample has no owner for operation IDs. Refuse to infer
        # either ownership or idleness; it can include held, undurable cleanup.
        unattributed = set(activity['active_ids']) - seen - live - clipboard_ids
        if unattributed:
            unavailable(reason='global_native_activity_owner_unverified',
                unattributed_activity_ids=sorted(unattributed))
        ids.extend(value for value in activity['active_ids'] if value not in unrelated
                   and value not in live - owned_tasks)
        return sorted(set(ids))

    def _pending_result(self, request_id, checkpoint, *, live_task):
        return {'ok': True, 'operation_id': request_id, 'request_id': request_id,
                'operation_state': 'pending', 'terminal': False, 'effect_state': 'unknown',
                'claim_id': checkpoint.get('claim_id'), 'owner_session': checkpoint.get('owner_session'),
                'server_generation': self.instance_id, 'phase': checkpoint.get('phase'),
                'live_task': live_task, 'recovery_only': not live_task,
                'prompts_triggered': False,
                'note': 'Admission is not dispatch or effect proof. Inspect operation_status; never resend with a new ID.'}

    def _task_result(self, task, wait_ms):
        started = time.monotonic()
        # Wait only for durable reservation, not for the native action queue.
        if not task['ready'].wait(3):
            raise WorkbenchError('native_admission_pending', 'Admission has not yet been confirmed durable. Inspect the original request ID.',
                                 request_id=task['request_id'], effect_state='unknown')
        remaining = max(0, wait_ms / 1000 - (time.monotonic() - started))
        if task['done'].wait(remaining):
            return _activation_context_result(task['result'], task['payload']['action'])
        checkpoint = self.journal.status(task['request_id']).get('result') or {}
        checkpoint = {**checkpoint, 'claim_id': task['claim_id'], 'owner_session': task['owner_session'],
                      'phase': checkpoint.get('phase', 'native_finalizing')}
        return self._pending_result(task['request_id'], checkpoint, live_task=True)

    def _start_task(self, request_id, payload, perform, resource, wait_ms, checkpoint, claimed):
        # Pin before registering; session close takes the session lock before
        # consulting active_ids, so never take these locks in the reverse order.
        pins = contextlib.ExitStack()
        reused = False
        try:
            if self.activity_gate is not None:
                pins.enter_context(self.activity_gate.admission())
            if self.sessions is not None:
                pins.enter_context(self.sessions.retain(checkpoint['owner_session']))
            with self._tasks_lock:
                if self._closing:
                    raise WorkbenchError('native_executor_stopping', 'The native executor is shutting down.', effect_state='none')
                task = self._tasks.get(request_id)
                if task is not None:
                    if json.dumps(task['payload'], sort_keys=True) != json.dumps(payload, sort_keys=True):
                        raise WorkbenchError('request_conflict', 'This request_id was already used with different arguments.')
                    reused = True
                else:
                    if len(self._tasks) >= 4:
                        raise WorkbenchError('native_operation_capacity', 'Finish or cancel pending native operations before admitting another.', effect_state='none')
                    task = {'request_id': request_id, 'payload': payload, 'owner_session': checkpoint['owner_session'],
                            'claim_id': checkpoint['claim_id'], 'trace_id': invocation_trace.get(),
                            'ready': threading.Event(), 'done': threading.Event(), 'pins': pins,
                            'reconcile_lock': threading.Lock(), 'claimed': claimed}
                    context = contextvars.copy_context()
                    context.run(work_admission.set, None)
                    thread = threading.Thread(target=context.run, args=(self._run_task, task, perform, resource, checkpoint),
                                              name='native-operation-' + request_id[:24], daemon=False)
                    task['thread'] = thread
                    self._tasks[request_id] = task
                    try:
                        thread.start()
                    except BaseException:
                        del self._tasks[request_id]
                        raise
        except BaseException:
            pins.close()
            raise
        if reused:
            pins.close()
        return self._task_result(task, wait_ms)

    def _run_task(self, task, perform, resource, checkpoint):
        identifier = task['request_id']
        try:
            result = self.journal.run(identifier, task['payload'], perform, resource=resource,
                                      initial_checkpoint=checkpoint, on_reserved=task['ready'].set,
                                      preserve_uncertain=True)
        except WorkbenchError as error:
            result = error.as_dict()
        except Exception:
            result = WorkbenchError('native_operation_uncertain', 'The retained native operation failed unexpectedly. Inspect its original request ID.',
                                    request_id=identifier, effect_state='unknown').as_dict()
        durable = False
        try:
            state = self.journal.status(identifier)['state']
            if self.sessions is not None:
                self.sessions._append(task['owner_session'], 'native-completion:' + identifier, {
                    'kind': 'native_operation_completion', 'request_id': identifier,
                    'admission_trace_id': task['trace_id'], 'runtime_generation': self.instance_id,
                    'claim_id': task['claim_id'], 'operation_state': state,
                    'ok': result.get('ok', True), 'error_code': result.get('error', {}).get('code'),
                    'references': {key: result[key] for key in ('result_artifact', 'capture_id', 'image_artifact') if key in result},
                    'verification': 'not_established',
                })
            durable = state in ('completed', 'failed')
        except Exception:
            # Keep ownership/idle pins if finalization or lineage is ambiguous.
            result = {**result, 'completion_recorded': False, 'recovery_required': True}
        task['result'] = result
        task['ready'].set()
        if durable:
            with self._tasks_lock:
                self._tasks.pop(identifier, None)
            task['pins'].close()
        task['done'].set()

    def _reconciled_result(self, request_id, record, action, parameters, claimed):
        result = _geometry_failure_result(json.loads(json.dumps(record['result'])), action)
        if action == 'restore_window':
            result = _restore_outcome(result, parameters.get('window_id'))
        if result['ok'] is False:
            summary = _pointer_failure_summary(result.pop('failure_summary', None))
            if summary is not None:
                result['failure_summary'] = summary
            error = result.get('error', {})
            code = error.get('code', 'native_operation_failed') if isinstance(error, dict) else 'native_operation_failed'
            if not isinstance(code, str) or not re.fullmatch(r'[a-z_]{1,80}', code):
                code = 'native_operation_failed'
            result['error'] = {**(error if isinstance(error, dict) else {}), 'code': code,
                               'message': 'The signed app recorded a failed operation. Inspect the retained native outcome.'}
            result['error'].pop('failure_summary', None)
            if summary is not None:
                result['error']['failure_summary'] = summary
        if claimed is not None:
            result['operation_receipt'] = interaction_contract.receipt(request_id, claimed, action, result)
        else:
            result['operation_receipt_unavailable'] = 'original_target_binding_not_persisted'
        return result

    def _reconcile_restarted(self, request_id, envelope, owner_session, max_bytes, workspace):
        """Read-only native history may settle a dead runtime, never grant authority."""
        record = envelope.get('receipt')
        if (workspace is None or not isinstance(record, dict) or record.get('state') != 'completed'
                or record.get('operation_id') != request_id or record.get('owner_session') != owner_session
                or not interaction_contract.identifier(record.get('claim_id'))
                or not interaction_contract.identifier(record.get('runtime_generation'))
                or record['runtime_generation'] == self.instance_id
                or not isinstance(record.get('payload_sha256'), str)
                or re.fullmatch(r'[0-9a-f]{64}', record['payload_sha256']) is None
                or not isinstance(record.get('parameters'), dict)
                or not isinstance(record.get('result'), dict) or type(record['result'].get('ok')) is not bool):
            return False
        parameters = record['parameters']
        if parameters.get('owner_session') != owner_session or parameters.get('claim_id') != record['claim_id']:
            return False
        # The native serializer can collapse 10.0 to 10. Recover only an exact
        # original journal hash, with a bounded set of lossless numeric spellings.
        try:
            numeric = [key for key, value in parameters.items()
                       if type(value) in (int, float) and math.isfinite(value) and value == int(value)]
        except (OverflowError, ValueError):
            return False
        if len(numeric) > 8:
            return False
        # Historical receipt reads are allowed after close. Admission retains
        # the same close-race pin without reopening the session or a live claim.
        pin = self.sessions.admission(owner_session, allow_closed=True) if self.sessions is not None else contextlib.nullcontext()
        with pin, self.journal._key_lock('request', request_id):
            with self._tasks_lock:
                if request_id in self._tasks:
                    return False
            current = self.journal.status(request_id)
            value = current.get('result')
            if not isinstance(value, dict):
                return False
            checkpoint = value if current['state'] == 'pending' else value.get('native_recovery_binding')
            if not isinstance(checkpoint, dict):
                return False
            expected = {'native_operation_id': request_id, 'claim_id': record['claim_id'],
                        'owner_session': owner_session, 'native_action': record.get('native_action'),
                        'runtime_generation': record['runtime_generation']}
            if (record.get('native_action') not in ('point', 'fixture_probe_point', 'control', 'move', 'resize',
                                                   'restore_window', 'key_pair', 'key_chord', 'key_sequence', 'insert_text')
                    or any(checkpoint.get(key) != item for key, item in expected.items())):
                return False
            matched = False
            for spellings in itertools.product((int, float), repeat=len(numeric)):
                candidate = dict(parameters)
                for key, number_type in zip(numeric, spellings):
                    candidate[key] = number_type(candidate[key])
                if not _same_native_parameters(candidate, parameters):
                    continue
                try:
                    recovered = self.journal.recover(request_id, {'tool': 'native_app', 'workspace': workspace,
                        'action': record['native_action'], 'parameters': candidate})
                except WorkbenchError as error:
                    if error.code != 'request_conflict':
                        raise
                    continue
                matched = recovered is not None
                break
            if not matched:
                return False
            claimed = checkpoint.get('claimed')
            if claimed is not None:
                try:
                    interaction_contract.claim(claimed, backend='native', runtime_generation=record['runtime_generation'],
                        owner_session=owner_session, expected_claim_id=record['claim_id'])
                except WorkbenchError:
                    return False
            if current['state'] == 'pending':
                binding = {**expected, 'admission_trace_id': checkpoint.get('admission_trace_id'),
                           'native_payload_sha256': record['payload_sha256']}
                result = self._reconciled_result(request_id, record, record['native_action'], parameters, claimed)
                result.update(server_generation=self.instance_id, prompts_triggered=False, checked_at=time.time(),
                    potentially_sensitive=True, reconciled_from_native_receipt=True,
                    original_runtime_generation=record['runtime_generation'], native_recovery_binding=binding,
                    native_payload_sha256=record['payload_sha256'], original_checkpoint=checkpoint,
                    original_transport_outcome=checkpoint.get('transport_outcome'))
                raw = json.dumps(result, ensure_ascii=True).encode()
                if len(raw) > max_bytes:
                    stored = self.store.put_bytes(raw, json.dumps({'kind': 'native_app_result', 'potentially_sensitive': True}))
                    original_result = result
                    result = {key: result[key] for key in ('ok', 'server_generation', 'original_runtime_generation',
                        'reconciled_from_native_receipt', 'native_recovery_binding', 'potentially_sensitive')}
                    result.update(result_artifact=stored['artifact_id'], capture_id=stored['capture_id'], inline_complete=False)
                    if record['result']['ok'] is False:
                        result['error'] = json.loads(raw)['error']
                    _native_result_summary(original_result, result, max_bytes)
                    result = add_result_continuation(result, stored, max_bytes)
                self.journal._finalize(request_id, 'completed' if result['ok'] else 'failed', result)
            else:
                if checkpoint.get('native_payload_sha256') != record['payload_sha256']:
                    return False
                # Terminal original results are immutable, including a prior
                # successful commit whose lineage append was interrupted.
                result = value
            if self.sessions is not None:
                self.sessions._append(owner_session, 'native-reconciliation:' + request_id, {
                    'kind': 'native_operation_reconciliation', 'request_id': request_id,
                    'admission_trace_id': checkpoint.get('admission_trace_id'),
                    'runtime_generation': record['runtime_generation'], 'reconciliation_runtime_generation': self.instance_id,
                    'claim_id': record['claim_id'], 'execution_terminal': True,
                    'references': {key: result[key] for key in ('result_artifact', 'capture_id') if key in result},
                    'effect_verification': 'not_established'})
        return True

    def _reconcile_task(self, request_id, envelope, owner_session, max_bytes, workspace=None):
        """A terminal signed record ends host execution; it is not effect proof."""
        with self._tasks_lock:
            task = self._tasks.get(request_id)
        if task is None:
            return self._reconcile_restarted(request_id, envelope, owner_session, max_bytes, workspace)
        if not task['done'].is_set() or task['owner_session'] != owner_session:
            return False
        record = envelope.get('receipt')
        expected = {'operation_id': request_id, 'claim_id': task['claim_id'], 'owner_session': owner_session,
                    'runtime_generation': self.instance_id, 'native_action': task['payload']['action']}
        if (not isinstance(record, dict) or record.get('state') != 'completed'
                or any(record.get(key) != value for key, value in expected.items())
                or not _same_native_parameters(record.get('parameters'), task['payload']['parameters'])
                or not isinstance(record.get('result'), dict) or type(record['result'].get('ok')) is not bool):
            return False
        with task['reconcile_lock']:
            with self._tasks_lock:
                if self._tasks.get(request_id) is not task:
                    return False
            current = self.journal.status(request_id)
            result = self._reconciled_result(request_id, record, task['payload']['action'], task['payload']['parameters'], task['claimed'])
            result.update(server_generation=self.instance_id, prompts_triggered=False, checked_at=time.time(),
                          potentially_sensitive=True, reconciled_from_native_receipt=True,
                          original_transport_outcome=task['result'])
            # Preserve the original transport failure and native outcome before
            # clearing ownership, including when the inline result is too large.
            raw = json.dumps(result, ensure_ascii=True).encode()
            if current['state'] in ('completed', 'failed'):
                # A prior attempt may have committed the immutable receipt but
                # failed to append lineage. Repair only that missing event.
                result = current['result']
                if task['payload']['action'] == 'restore_window':
                    result = _restore_outcome(result, task['payload']['parameters'].get('window_id'))
            elif len(raw) > max_bytes:
                original_result = result
                normalized_error = result.get('error')
                stored = self.store.put_bytes(raw, json.dumps({'kind': 'native_app_result', 'potentially_sensitive': True}))
                result = {'ok': result['ok'], 'result_artifact': stored['artifact_id'], 'capture_id': stored['capture_id'],
                          'inline_complete': False, 'potentially_sensitive': True, 'server_generation': self.instance_id,
                          'reconciled_from_native_receipt': True}
                if normalized_error is not None:
                    result['error'] = normalized_error
                _native_result_summary(original_result, result, max_bytes)
                result = add_result_continuation(result, stored, max_bytes)
            if current['state'] == 'pending':
                self.journal._finalize(request_id, 'completed' if result['ok'] else 'failed', result)
            if self.sessions is not None:
                self.sessions._append(owner_session, 'native-reconciliation:' + request_id, {
                    'kind': 'native_operation_reconciliation', 'request_id': request_id,
                    'admission_trace_id': task['trace_id'], 'runtime_generation': self.instance_id,
                    'claim_id': task['claim_id'], 'execution_terminal': True,
                    'references': {key: result[key] for key in ('result_artifact', 'capture_id') if key in result},
                    'effect_verification': 'not_established'})
            with self._tasks_lock:
                self._tasks.pop(request_id, None)
            task['pins'].close()
        return True

    def close(self):
        """Stop admission and join retained work while the native app is alive."""
        with self._tasks_lock:
            self._closing = True
            tasks = list(self._tasks.values())
        for task in tasks:
            try:
                self.control_channel.request('cancel_operation', _timeout=3, _allow_failure=True,
                    operation_id=task['request_id'], claim_id=task['claim_id'], owner_session=task['owner_session'])
            except WorkbenchError:
                pass  # No acknowledgement is never release proof.
        for task in tasks:
            task['thread'].join()
            with self._tasks_lock:
                retained = task['request_id'] in self._tasks
            if retained:
                try:
                    envelope = self._request('operation', _timeout=3, action='receipt', operation_id=task['request_id'], owner_session=task['owner_session'])
                    self._reconcile_task(task['request_id'], envelope, task['owner_session'], 8192)
                except (WorkbenchError, OSError, ValueError):
                    pass
        # Unverified terminal state remains pinned and visible. Forced process
        # loss cannot certify release; no worker is resumed on restart.

    def _request(self, method, _timeout=None, **parameters):
        # Large signed apps require code/resource verification before launch and
        # an authenticated provider handshake afterward. Preserve those checks
        # within a bounded wait; cancellation/control calls keep their own limit.
        timeout = _timeout if _timeout is not None else 60 if parameters.get('action') == 'launch' else 12
        result = self.channel.request(method, _timeout=timeout, _allow_failure=True, **parameters)
        if result.get('ok') is True and 'result_capture' in result:
            result = self._captured_result(result)
        result = _geometry_failure_result(result, parameters.get('action'))
        if parameters.get('action') == 'restore_window':
            result = _restore_outcome(result, parameters.get('window_id'))
        if parameters.get('action') == 'receipt' and type(result.get('receipt')) is dict:
            record = result['receipt']
            if type(record.get('result')) is dict:
                result['receipt'] = {**record, 'result': _geometry_failure_result(record['result'], record.get('native_action'))}
            result = _restore_receipt_view(result, parameters)
        if result.get('ok') is not True:
            error = result.get('error', {})
            code = error.get('code', 'native_operation_unavailable')
            if not isinstance(code, str) or not re.fullmatch(r'[a-z_]{1,80}', code): code = 'native_operation_unavailable'
            messages = {
                'native_focused_key_profile_unavailable': 'This app has no locally reviewed captured-key profile. The operation was not converted to raw or foreground keyboard input.',
                'native_focused_key_provider_unavailable': 'The original local receiver is unavailable for captured keyboard input. Inspect the original receipt; no new permission grant or fallback is implied.',
                'native_focused_key_receiver_unavailable': 'Scoped focus preparation did not qualify the exact selected receiver. Inspect the original preparation receipt before deciding on a new intent.',
                'native_focused_key_not_dispatched': 'The receiver did not establish a key dispatch. Inspect its original result and recovery record; do not replay an uncertain operation.',
                'native_focus_cleanup_unverified': 'Focus cleanup could not be verified. Preserve the original operation and inspect its receipt/recovery; this does not establish a missing macOS approval.',
                'native_target_claimed': 'Another work session owns this exact window. Use a different discovered window or wait for its owner to release it; macOS reapproval does not transfer ownership.',
                'native_claim_owner_mismatch': 'Use the original work session for its claim, release or recovery receipt. Another task does not inherit that ownership; macOS reapproval does not transfer it.',
                'native_provider_observation_expired': 'The provider observation expired. Obtain a fresh observation for the exact claimed window immediately before a new intent. Preserve the original receipt and its effect state; this error does not call for permission changes.',
                'native_provider_observation_consumed': 'This provider observation was already consumed. Inspect the original receipt rather than repeating its input; a fresh observation does not authorize replay of an uncertain effect.',
                'native_provider_observation_owner_mismatch': 'This provider observation does not belong to the exact claim and work session. Use that owner or obtain a fresh observation under your own authorized claim.',
                'native_electron_worker_closed': 'The renderer input worker ended before a confirmed response. Inspect the original receipt and current keyboard readiness; do not replay uncertain input or change permissions based on this error.',
                'native_operation_unavailable': 'The signed app could not complete this operation on the exact target. Inspect the original receipt and current target capabilities before a different action; do not replay an uncertain effect. This result alone does not establish a missing macOS approval.',
                'native_capture_unavailable': 'The exact authorized window could not be captured. Inspect its current window identity and capture diagnostic; this result alone does not establish a missing macOS approval.',
                'clipboard_lease_active': 'A temporary clipboard transaction remains unresolved. Its original owner must explicitly restore or release its recovery handle, or choose Restore/Keep current in the local app, before another write. Expiry and Stop do not discard it.',
                'native_clipboard_owner_mismatch': 'This clipboard recovery or receipt belongs to its original work-session owner. Use that session or the local app clipboard choice; another claim does not transfer ownership.',
                'native_clipboard_receipt_owner_unavailable': 'The original clipboard receipt lacks verified work-session ownership. Its private recovery metadata cannot be returned; inspect the local app recovery state without replaying the write.',
                'native_action_unsupported': 'Use an action from the fresh control observation, such as AXPress. Observe with an explicit window_id first.',
                'native_window_identity_capacity': 'Native window identities are in use. Release finished claims, then discover the specific app again.',
                'native_control_identity_capacity': 'Native control observations are in use. Let older observations expire or release finished claims, then observe this window again.',
                'native_window_moved': 'The target window moved after observation. Observe its current geometry before a new action; do not repeat an unknown effect.',
                'native_window_minimized': 'The exact window is minimized. Use explicit restore_window, verify its result, then obtain a fresh observation and capture before a new point intent.',
                'native_restore_protocol_unverified': 'The restore response did not verify the exact original window. Inspect its original receipt; do not replay the setter.',
                'stale_native_observation': 'This native observation expired or was consumed. Obtain a fresh observation for the exact claimed window.',
                'native_activation_point_unavailable': 'Scoped native input could not verify usable activation metadata. Inspect the original receipt before selecting a new intent; this error does not indicate missing macOS approval.',
                'native_capture_inspection_requires_exact_identity': 'Inspection requires an exact available window-ID getter and verified owner. Obtain a fresh exact-window observation; geometry fallback does not qualify.',
                'native_capture_inspection_scope_unverified': 'The exact single-window inspection scope changed or could not be verified. Obtain a fresh observation before another inspection; this capture cannot arm point input.',
                'native_capture_inspection_unsupported': 'This native backend does not support observation-only inspection capture. The default input capture keeps its existing identity and geometry requirements.',
                'native_capture_required': 'This exact capture is missing, consumed or expired. For a new point intent, observe and explicitly capture the claimed window, then select coordinates again. Inspect the original receipt before repeating any uncertain input; macOS reapproval is not indicated by this error.',
                'native_freshness_clock_invalid': 'The native freshness clock could not verify the original deadline. No new deadline is inferred; inspect the original receipt before selecting a new observation and capture.',
                'native_control_changed': 'The control changed after observation. Observe the exact claimed window again and use its current control. Inspect the original receipt before repeating any uncertain action.',
                'stale_native_tree_revision': 'This tree revision expired or does not belong to the claimed window. Omit tree_base_revision to obtain a fresh full tree for this window.',
                'native_window_capture_ambiguous': 'This accessibility window could not be matched to one exact capture window. Rediscover the app and inspect its current window identity and geometry.',
                'native_window_identity_unavailable': 'The exact window identity could not be verified. Inspect its identity diagnostic and obtain a fresh observation before a new capture; this error does not establish a missing macOS approval.',
                'native_window_identity_budget_exhausted': 'The essential window identity check exhausted its admission budget. Obtain a fresh observation for a new capture; do not repeat an uncertain input or infer that macOS reapproval is required.',
                'native_result_storage_limit': 'The signed app has reached its bounded temporary-result storage limit. Allow unfinished transfers to complete or expire; inspect the original receipt before repeating any uncertain action. This is not a macOS permission failure.',
                'native_capture_storage_limit': 'The signed app has reached its bounded image storage limit. Release finished claims or allow their observations to expire before a new capture. Preserve other tasks and inspect any uncertain original action; macOS reapproval is not indicated.',
            }
            message = messages.get(code, 'The signed app refused or could not verify this operation. Inspect local App access and permission readiness.')
            details = {'effect_state': error.get('effect_state', 'unknown')}
            # Failed AX calls can have partial effects. Retain their correlated
            # return code, not the control's potentially sensitive readback.
            ax_result = result.get('dispatch_result')
            requested = result.get('requested_action')
            if (parameters.get('action') == 'control'
                    and type(ax_result) is int and -(2 ** 31) <= ax_result < 2 ** 31 and ax_result != 0
                    and type(requested) is str and requested == parameters.get('control_action')
                    and re.fullmatch(r'[A-Za-z_]{1,80}', requested)):
                details['ax_dispatch'] = {'return_code': ax_result, 'requested_action': requested,
                                          'effect_verified': False, 'retry_allowed': False}
            identity = _window_identity_diagnostic(error.get('window_identity'))
            if identity is not None:
                details['window_identity'] = identity
                if code == 'native_window_moved' and identity['state'] == 'boundsMismatch':
                    message = ('The exact window has different Accessibility and compositor frames. '
                               'Inspect window_identity before another capture or input; '
                               'repeating an unchanged observation may not resolve this geometry conflict.')
            if parameters.get('action') in ('point', 'fixture_probe_point'):
                refresh = _visual_refresh_details(error, parameters.get('observation_id'))
                if refresh is not None:
                    details.update(refresh)
            if parameters.get('action') in ('clipboard_temporary', 'clipboard_restore'):
                recovery = _clipboard_recovery(result.get('clipboard_recovery'))
                if recovery is not None:
                    details['clipboard_recovery'] = recovery
            if parameters.get('action') == 'point':
                if 'activation_context' in result:
                    details['activation_context'] = result['activation_context']
                summary = _pointer_failure_summary(result.get('failure_summary'))
                if summary is not None:
                    details['failure_summary'] = summary
                if 'geometry_failure' in result:
                    details['geometry_failure'] = result['geometry_failure']
            # Preserve bounded signed-fixture dispatch evidence even when the
            # action fails. This is not approval, effect proof, or retry advice.
            diagnostic = result.get('diagnostic')
            if parameters.get('action') == 'fixture_probe_point' and isinstance(diagnostic, dict):
                try:
                    encoded = json.dumps(diagnostic, ensure_ascii=True, allow_nan=False)
                except (ValueError, TypeError):
                    encoded = None
                if encoded is not None and len(encoded.encode()) <= 16384:
                    details['diagnostic'] = diagnostic
            geometry = result.get('geometry_result')
            if parameters.get('action') in ('move','resize','receipt') and isinstance(geometry, dict):
                try: encoded = json.dumps(geometry, ensure_ascii=True, allow_nan=False)
                except (ValueError, TypeError): encoded = None
                if encoded is not None and len(encoded.encode()) <= 16384: details['geometry_result'] = geometry
            restored = result.get('restore_result')
            if parameters.get('action') == 'restore_window' and restored is not None:
                details['restore_result'] = restored
            if parameters.get('action') == 'key_pair' and parameters.get('observation_id'):
                # Error normalization must not erase the original provider
                # result/recovery after a later focus cleanup failure. Keep it
                # in the existing immutable, caller-attributed artifact store.
                details['retry_allowed'] = False
                try:
                    raw = json.dumps(result, ensure_ascii=True, allow_nan=False).encode()
                    stored = self.store.put_bytes(raw, json.dumps({
                        'kind': 'captured_key_original_failure', 'potentially_sensitive': True}))
                    details['original_native_result_artifact'] = stored['artifact_id']
                except (WorkbenchError, OSError, TypeError, ValueError):
                    # The native receipt remains the fallback; storage failure
                    # cannot replace the original error or turn it into a retry.
                    details['original_native_result_artifact_unavailable'] = True
            failure = WorkbenchError(code, message, **details)
            # Caller provenance, deliberately outside serialized error details:
            # an authenticated error report is a receipt even when its effect
            # is unknown. Transport exceptions never reach this branch.
            failure._native_response_received = True
            raise failure
        return result

    def _captured_result(self, envelope):
        # The private channel has verified this response's correlation. The
        # payload was stored before those fields were stamped, so use the
        # original response envelope, never the later capture-page envelopes.
        fields = ('version', 'request_id', 'app_generation', 'launch_id', 'runtime_generation')
        if (type(envelope.get('version')) is not int or envelope['version'] != 1
                or any(type(envelope.get(key)) is not str or not envelope[key] for key in fields[1:])):
            raise WorkbenchError('native_result_protocol', 'The large native reply has no verified correlation.', effect_state='unknown')
        try:
            payload = json.loads(self._capture_bytes(envelope['result_capture']))
        except (ValueError, WorkbenchError) as error:
            raise WorkbenchError('native_result_protocol', 'The large native reply could not be verified. Inspect its receipt before repeating an uncertain action.', effect_state='unknown') from error
        if (not isinstance(payload, dict) or type(payload.get('ok')) is not bool
                or payload['ok'] is False and not isinstance(payload.get('error'), dict)):
            raise WorkbenchError('native_result_protocol', 'The large native reply is malformed.', effect_state='unknown')
        for key in fields:
            if key in payload and (type(payload[key]) is not type(envelope[key]) or payload[key] != envelope[key]):
                raise WorkbenchError('native_result_protocol', 'The large native reply changed its correlation.', effect_state='unknown')
            payload[key] = envelope[key]
        descriptor = envelope['result_capture']
        if descriptor.get('payload_kind') == 'result':
            # Release only a verified result transfer. An image's active input
            # permit is separate, and cleanup loss never rewrites an effect.
            cleanup = {'state': 'pending', 'expiry_seconds': 120}
            try:
                reply = self.channel.request('release_result_payload', _timeout=3, _allow_failure=True,
                    capture_id=descriptor['capture_id'], bytes=descriptor['bytes'], sha256=descriptor['sha256'])
                if (type(reply) is dict and reply.get('ok') is True and reply.get('released') is True
                        and all(type(reply.get(k)) is type(descriptor[k]) and reply[k] == descriptor[k]
                                for k in ('capture_id', 'bytes', 'sha256'))
                        and reply.get('input_authority_changed') is False):
                    cleanup = {'state': 'released'}
            except (WorkbenchError, OSError, ValueError, TypeError):
                pass
            payload['native_transfer_cleanup'] = cleanup
        # Nested receipts retain their original execution identity and owner.
        return payload

    def _capture_bytes(self, descriptor):
        if (not isinstance(descriptor, dict) or not isinstance(descriptor.get('capture_id'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', descriptor['capture_id'])
                or type(descriptor.get('bytes')) is not int or not 0 <= descriptor['bytes'] <= 8388608
                or not isinstance(descriptor.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', descriptor['sha256'])):
            raise WorkbenchError('native_capture_protocol', 'The native capture descriptor is malformed.')
        raw, offset = bytearray(), 0
        while offset < descriptor['bytes']:
            page = self._request('capture_page', capture_id=descriptor['capture_id'], offset=offset, count=32768)
            if (page.get('capture_id') != descriptor['capture_id'] or page.get('offset') != offset
                    or page.get('total_bytes') != descriptor['bytes']):
                raise WorkbenchError('native_capture_protocol', 'The native capture page changed identity or byte cursor.')
            try: chunk = base64.b64decode(page['data'], validate=True)
            except (KeyError, ValueError, TypeError) as error: raise WorkbenchError('native_capture_protocol', 'The native capture page is invalid.') from error
            if not 1 <= len(chunk) <= 32768 or offset + len(chunk) > descriptor['bytes']:
                raise WorkbenchError('native_capture_protocol', 'The native capture page exceeded its declared range.')
            raw.extend(chunk); offset += len(chunk)
        if hashlib.sha256(raw).hexdigest() != descriptor['sha256']:
            raise WorkbenchError('native_capture_integrity', 'The capture bytes failed their native SHA-256 check.')
        return bytes(raw)

    def operation(self, workspace, action='status', request_id=None, max_bytes=8192, wait_ms=None, **parameters):
        request_cancellation = native_request_cancellation.get()
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied', 'Native app access requires an executable workspace.')
        if type(max_bytes) is not int or not 4096 <= max_bytes <= 262144:
            raise WorkbenchError('invalid_range', 'Use max_bytes 4096..262144.')
        if action not in ('status', 'discover', 'launch', 'acquire', 'release', 'claim_status', 'cancel', 'observe', 'capture', 'control', 'point', 'fixture_probe_point', 'revoke', 'receipt',
                          'clipboard_temporary', 'clipboard_restore', 'clipboard_release', 'move', 'resize', 'restore_window', 'key_pair', 'key_chord', 'key_sequence', 'insert_text'):
            raise WorkbenchError('invalid_native_action', 'Use a supported native operation.')
        parameters = {key: value for key, value in parameters.items() if value is not None}
        if 'release_binding' in parameters:
            raise WorkbenchError('invalid_native_claim', 'Retirement binding belongs to the local host, not tool arguments.', effect_state='none')
        if 'launch_file_authority' in parameters:
            raise WorkbenchError('invalid_native_launch', 'File authority belongs to the local host, not tool arguments.')
        bootstrap = any(k in parameters for k in ('open_file', 'initial_bounds', 'initial_display_id'))
        if bootstrap:
            code = (parameters.get('bundle_id') == 'com.microsoft.VSCode'
                    or parameters.get('app_path') == '/Applications/Visual Studio Code.app')
            relative = parameters.get('open_file')
            if (action != 'launch' or type(relative) is not str or not relative
                    or relative.startswith('/') or re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', relative)
                    or set(parameters) - {'bundle_id', 'app_path', 'open_file', 'initial_bounds', 'initial_display_id'}):
                raise WorkbenchError('invalid_native_launch', 'Use an existing workspace-relative file and an exact launch target; no URI, profile or endpoint input.')
            b = parameters.get('initial_bounds')
            if code and (type(b) is not dict or set(b) != {'x','y','width','height'}
                    or any(type(v) not in (int,float) or not math.isfinite(v) for v in b.values())
                    or b['width'] < 640 or b['height'] < 480
                    or type(parameters.get('initial_display_id')) is not int
                    or not 1 <= parameters['initial_display_id'] <= 4294967295):
                raise WorkbenchError('invalid_native_launch', 'Use one Code launch, a relative owned file and exact initial display bounds.')
            if not code and any(k in parameters for k in ('initial_bounds', 'initial_display_id')):
                raise WorkbenchError('invalid_native_launch', 'Initial bounds and display belong only to the managed Code bootstrap.')
        if action in ('key_pair', 'key_chord', 'key_sequence', 'insert_text'):
            _validate_provider_input(action, parameters)
            if action == 'key_sequence':
                parameters = json.loads(json.dumps(parameters, ensure_ascii=True, allow_nan=False))
            if request_id is None:
                raise WorkbenchError('request_id_required', 'Provider input requires a stable request_id.', effect_state='none')
            self.journal.validate_id(request_id)
        elif any(key in parameters for key in ('provider_observation_id', 'key_code', 'characters', 'characters_ignoring_modifiers', 'keys')) or ('modifiers' in parameters and action != 'point'):
            raise WorkbenchError('invalid_native_provider_input', 'Provider input fields belong only to key_pair, key_chord, key_sequence or insert_text.', effect_state='none')
        if action == 'point' and 'modifiers' in parameters:
            modifiers = parameters['modifiers']
            if (type(modifiers) is not list or not 1 <= len(modifiers) <= 4
                    or any(type(value) is not str for value in modifiers)
                    or len(set(modifiers)) != len(modifiers)
                    or not set(modifiers).issubset({'command', 'control', 'option', 'shift'})):
                raise WorkbenchError('native_pointer_modifiers_invalid',
                    'Use one to four unique pointer modifiers: command, control, option or shift.', effect_state='none')
            required = {'claim_id', 'window_id', 'observation_id', 'control_action', 'x', 'y', 'modifiers'}
            if (set(parameters) != required or parameters.get('control_action') != 'click'
                    or any(type(parameters.get(key)) is not str or not parameters[key]
                           for key in ('claim_id', 'window_id', 'observation_id'))
                    or any(type(parameters.get(key)) not in (int, float)
                           or abs(parameters[key]) > 1.7976931348623157e308 or not math.isfinite(parameters[key])
                           for key in ('x', 'y'))):
                raise WorkbenchError('native_pointer_modifiers_outside_scope',
                    'Pointer modifiers require one exact claimed window, fresh observation and a point click.', effect_state='none')
            # Freeze event-local flags before claim/authority callbacks can reenter.
            parameters['modifiers'] = list(modifiers)
        if 'representations' in parameters and action != 'clipboard_temporary':
            raise WorkbenchError('invalid_native_clipboard_payload', 'representations belongs only to clipboard_temporary.', effect_state='none')
        if action == 'clipboard_temporary':
            _validate_clipboard_payload(parameters)
            if type(parameters.get('expected_change_count')) is not int or not 0 <= parameters['expected_change_count'] <= 9223372036854775807:
                raise WorkbenchError('invalid_native_clipboard_count', 'Supply a nonnegative integer expected_change_count from current clipboard status.', effect_state='none')
        if 'capture_purpose' in parameters and (action != 'capture'
                or type(parameters['capture_purpose']) is not str or parameters['capture_purpose'] not in ('input', 'inspection')):
            raise WorkbenchError('invalid_native_capture_purpose', 'capture_purpose belongs only to capture and must be input or inspection.', effect_state='none')
        cursor_view = parameters.get('receipt_view') == 'cursor_diagnostics'
        if 'receipt_view' in parameters:
            if (not cursor_view or action != 'receipt' or set(parameters) != {'receipt_view', 'operation_id', 'claim_id'}
                    or request_id is not None or wait_ms is not None
                    or not isinstance(parameters.get('operation_id'), str)
                    or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parameters['operation_id']) is None):
                raise WorkbenchError('invalid_native_receipt_view', 'Cursor diagnostics require only receipt_view, operation_id and claim_id on receipt.', effect_state='none')
        dragging = parameters.get('control_action') == 'drag'
        if dragging or any(key in parameters for key in ('end_x', 'end_y', 'steps')):
            required = {'claim_id','window_id','observation_id','control_action','x','y','end_x','end_y','steps'}
            if (action != 'point' or not dragging or set(parameters) != required
                    or any(not isinstance(parameters.get(key), str) or not parameters[key]
                           for key in ('claim_id','window_id','observation_id'))
                    or any(type(parameters.get(key)) not in (int,float)
                           or abs(parameters[key]) > 1.7976931348623157e308 or not math.isfinite(parameters[key])
                           for key in ('x','y','end_x','end_y'))
                    or type(parameters.get('steps')) is not int or not 2 <= parameters['steps'] <= 16
                    or (parameters['x'],parameters['y']) == (parameters['end_x'],parameters['end_y'])):
                raise WorkbenchError('invalid_native_drag', 'Use one claimed captured window, distinct finite start/end points and integer steps 2..16.', effect_state='none')
        if action in ('move', 'resize'):
            required = ('x', 'y') if action == 'move' else ('width', 'height')
            if (any(not isinstance(parameters.get(k), str) or not parameters[k] for k in ('claim_id','window_id','observation_id'))
                    or any(type(parameters.get(k)) not in (int,float) or abs(parameters[k]) > 1.7976931348623157e308 or not math.isfinite(parameters[k])
                           or action == 'resize' and parameters[k] <= 0 for k in required)
                    or any(k not in {*required,'claim_id','window_id','observation_id'} for k in parameters)):
                raise WorkbenchError('invalid_native_geometry', 'Use an exact claimed observation and one finite move(x,y) or positive resize(width,height).', effect_state='none')
        if action == 'restore_window':
            if (set(parameters) != {'claim_id', 'window_id'}
                    or any(type(parameters.get(key)) is not str or not parameters[key] for key in ('claim_id', 'window_id'))):
                raise WorkbenchError('invalid_native_restore', 'restore_window requires only the exact claim_id and window_id, without a coordinate observation or automatic input replay.', effect_state='none')
        if action not in ('move', 'resize') and any(k in parameters for k in ('width','height')):
            raise WorkbenchError('invalid_native_geometry', 'Width and height belong only to resize.', effect_state='none')
        if any(key in parameters for key in ('selection_start', 'selection_length')) or parameters.get('control_action') == 'select_text':
            if (action != 'control' or parameters.get('control_action') != 'select_text' or 'text' in parameters
                    or any(type(parameters.get(key)) is not int or not 0 <= parameters[key] <= 32768 for key in ('selection_start', 'selection_length'))):
                raise WorkbenchError('invalid_native_text_range', 'select_text requires selection_start and selection_length in UTF-16 code units, without text.', effect_state='none')
        if parameters.get('control_action') == 'replace_selection' and (action != 'control' or type(parameters.get('text')) is not str):
            raise WorkbenchError('invalid_native_text_selection', 'replace_selection requires control action and explicit replacement text.', effect_state='none')
        if wait_ms is not None and (type(wait_ms) is not int or not 0 <= wait_ms <= 10000
                or action not in ('point', 'fixture_probe_point', 'control') or not parameters.get('claim_id')):
            raise WorkbenchError('invalid_native_wait', 'wait_ms requires a claimed point or semantic control action and an integer 0..10000.', effect_state='none')
        parameters = json.loads(json.dumps(parameters))
        if (action in ('acquire','release','claim_status','cancel') or parameters.get('claim_id')) and work_context.get() is None:
            raise WorkbenchError('work_session_required', 'Open a work session and supply work_session_id on claim calls so target ownership is explicit.')
        owner_session = work_context.get() or 'workspace:' + workspace
        if not isinstance(owner_session,str) or len(owner_session.encode()) > 128:
            raise WorkbenchError('invalid_claim_owner', 'The work-session owner is unavailable or too long.')
        parameters['owner_session'] = owner_session
        for key in ('allow_control','allow_capture','allow_clipboard'):
            if key in parameters and type(parameters[key]) is not bool:
                raise WorkbenchError('invalid_native_capability', 'Capability selections must be booleans.')
        if parameters.get('claim_id') is not None and not interaction_contract.identifier(parameters['claim_id']):
            raise WorkbenchError('invalid_native_claim', 'Use the claim ID returned by acquisition.')
        if parameters.get('claim_id') and parameters.get('lease_id'):
            raise WorkbenchError('invalid_native_claim', 'Supply one target claim, without a legacy lease alias.')
        if action == 'acquire':
            interaction_contract.native_identity(parameters.get('app_identity'))
            if not isinstance(parameters.get('window_id'),str) or not parameters['window_id']:
                raise WorkbenchError('invalid_app_target', 'Acquisition requires the discovered window ID.')
        if 'operation_id' in parameters and action not in ('receipt','cancel'):
            raise WorkbenchError('invalid_native_query', 'operation_id is only a receipt lookup; effects use request_id.')
        subtree = action == 'observe' and any(k in parameters for k in ('observation_id','control_id'))
        if subtree and (not parameters.get('claim_id') or not parameters.get('window_id')
                or any(not interaction_contract.identifier(parameters.get(k)) for k in ('observation_id','control_id'))):
            raise WorkbenchError('invalid_native_subtree_selection', 'Subtree observe requires a claimed window and both predecessor observation_id and observed anchor control_id.', effect_state='none')
        if parameters.get('tree_base_revision') is not None:
            if action != 'observe' or not parameters.get('window_id') or not interaction_contract.identifier(parameters['tree_base_revision']):
                raise WorkbenchError('invalid_native_tree_revision', 'Tree differences require an exact window and a previous observation revision.')
        if any(key in parameters for key in ('delta_x', 'delta_y')) or parameters.get('control_action') == 'scroll':
            if action not in ('point', 'fixture_probe_point') or parameters.get('control_action') != 'scroll':
                raise WorkbenchError('invalid_native_scroll', 'Wheel deltas require a targeted scroll action.')
            axes = [parameters.get(key, 0) for key in ('delta_x', 'delta_y')]
            if any(type(value) is not int or abs(value) > 2000 for value in axes) or not any(axes):
                raise WorkbenchError('invalid_native_scroll', 'Use integer wheel deltas from -2000 to 2000, with at least one nonzero axis.')
        holding = parameters.get('control_action') in ('hold', 'right_hold')
        if holding or 'hold_ms' in parameters:
            duration = parameters.get('hold_ms')
            if (action not in ('point', 'fixture_probe_point') or not holding
                    or type(duration) is not int or not 1 <= duration <= 5000):
                raise WorkbenchError('invalid_native_hold', 'Timed holds need hold/right_hold and integer hold_ms 1..5000.', effect_state='none')
        if action in ('point', 'fixture_probe_point') and parameters.get('control_action') not in (
                'click', 'double_click', 'right_click', 'scroll', 'hold', 'right_hold', 'drag'):
            raise WorkbenchError('invalid_native_point_action',
                'Point input requires an explicit control_action: click, double_click, right_click, scroll, hold, right_hold or drag.',
                effect_state='none')
        if action == 'cancel':
            target_request = parameters.get('operation_id')
            if not isinstance(target_request,str) or not parameters.get('claim_id'):
                raise WorkbenchError('invalid_native_cancellation','Cancellation requires the original operation_id and claim_id.')
            if request_id is None:raise WorkbenchError('request_id_required','Cancellation needs its own stable request_id.')
            def cancel():
                original=self.journal.status(target_request)
                if original.get('state') in ('completed', 'failed'):
                    raise WorkbenchError('native_cancellation_finished',
                        'The original operation is already terminal. Inspect its original request_id; cancellation cannot undo it.',
                        effect_state='none')
                # Journal status intentionally exposes no original arguments;
                # the pending native checkpoint retains its exact claim binding.
                checkpoint=original.get('result') or {}
                if (original.get('state') != 'pending' or checkpoint.get('claim_id') != parameters['claim_id']
                        or checkpoint.get('owner_session') != owner_session or checkpoint.get('native_action') not in ('point','fixture_probe_point','control','move','resize','key_pair','key_chord','key_sequence','insert_text')
                        or checkpoint.get('runtime_generation') != self.instance_id):
                    raise WorkbenchError('native_cancellation_owner_mismatch','The pending operation does not match this task and claim.',effect_state='none')
                result=self.control_channel.request('cancel_operation',_timeout=3,_allow_failure=True,
                    operation_id=target_request,claim_id=parameters['claim_id'],owner_session=owner_session)
                if result.get('ok') is not True:
                    error=result.get('error',{})
                    code=error.get('code','native_cancel_unavailable')
                    if not isinstance(code,str) or not re.fullmatch(r'[a-z_]{1,80}',code):code='native_cancel_unavailable'
                    raise WorkbenchError(code,'The control channel could not confirm cancellation.',effect_state='unknown')
                return result
            return self.journal.run(request_id,{'tool':'native_app','action':'cancel','workspace':workspace,
                'operation_id':target_request,'claim_id':parameters['claim_id'],'owner_session':owner_session},cancel)
        if action == 'status' and not self.channel.configured:
            return {'ok': True, 'native_available': False, 'checked_at': time.time(),
                    'prerequisite': 'Start the signed app with native App access support.', 'prompts_triggered': False}
        effects = {'launch', 'acquire', 'release', 'control', 'point', 'fixture_probe_point', 'revoke', 'clipboard_temporary', 'clipboard_restore', 'clipboard_release', 'move', 'resize', 'restore_window', 'key_pair', 'key_chord', 'key_sequence', 'insert_text'}
        journaled = action in effects or (action == 'capture' and request_id is not None)
        payload = {'tool':'native_app','workspace':workspace,'action':action,'parameters':parameters}
        if action in ('point', 'fixture_probe_point', 'control') and request_id is not None:
            recovered = self.journal.recover(request_id, payload)
            with self._tasks_lock:
                task = self._tasks.get(request_id)
                if task is not None and json.dumps(task['payload'], sort_keys=True) != json.dumps(payload, sort_keys=True):
                    raise WorkbenchError('request_conflict', 'This request_id was already used with different arguments.')
            if task is not None:
                return self._task_result(task, wait_ms or 0)
            if recovered is not None and recovered['state'] == 'pending':
                return self._pending_result(request_id, recovered['result'] or {}, live_task=False)
        if journaled and request_id is not None and self.journal.status(request_id)['state'] != 'not_found':
            # Recover the immutable receipt before querying a possibly ended
            # claim. A replay must not need live authority or dispatch again.
            try:
                recovered = self.journal.run(request_id, payload, lambda: (_ for _ in ()).throw(RuntimeError('receipt disappeared')))
            except WorkbenchError as error:
                if error.code == 'operation_uncertain':
                    if action in ('move', 'resize', 'restore_window'):
                        checkpoint = self.journal.recover(request_id, payload)['result'] or {}
                        envelope = checkpoint.get('transport_outcome')
                        outcome = envelope.get('error') if type(envelope) is dict else None
                        if (type(outcome) is dict and envelope.get('ok') is False
                                and type(outcome.get('code')) is str
                                and re.fullmatch(r'[a-z_]{1,80}', outcome['code'])
                                and type(outcome.get('message')) is str
                                and outcome.get('effect_state') == 'unknown'
                                and outcome.get('retry_allowed') is False
                                and outcome.get('original_request_id') == request_id):
                            # A detached legacy error view must not finalize or
                            # otherwise rewrite the pending original binding.
                            raise WorkbenchError(outcome['code'], outcome['message'],
                                **{**{key: value for key, value in outcome.items()
                                      if key not in ('code', 'message')},
                                   'replayed': True, 'applied_this_call': False,
                                   'original_request_id': request_id}) from error
                    raise _uncertain_native_error(error, request_id) from error
                if action != 'restore_window':
                    if 'activation_context' in error.details:
                        detached = _activation_context_result(error.as_dict(), action)['error']
                        raise WorkbenchError(detached.pop('code'), detached.pop('message'), **detached) from error
                    raise
                detached = _restore_outcome(error.as_dict(), parameters['window_id'])
                _raise_restore_failure(detached)
            if action == 'restore_window':
                recovered = _restore_outcome(recovered, parameters['window_id'])
                if recovered.get('ok') is not True:
                    _raise_restore_failure(recovered)
            return _activation_context_result(recovered, action)

        with self._tasks_lock:
            if self._closing and action in effects:
                raise WorkbenchError('native_executor_stopping', 'The native executor is shutting down.', effect_state='none')

        claimed = None
        if parameters.get('claim_id') and action not in ('claim_status', 'receipt'):
            if action == 'release':
                # The channel still authenticates this runtime. Only this private
                # cleanup view carries the retained original runtime separately.
                view = self._request('operation', action='claim_release_status',
                    claim_id=parameters['claim_id'], owner_session=owner_session)
                claimed = view.get('release_claim')
                original_runtime = claimed.get('runtime_generation') if isinstance(claimed, dict) else None
                if (not interaction_contract.identifier(original_runtime)
                        or original_runtime != self.instance_id and claimed.get('state') not in ('suspended_transport', 'revoked')):
                    raise WorkbenchError('interaction_protocol_error', 'Invalid retained cleanup authority.', effect_state='unknown')
                claimed = interaction_contract.claim(claimed, backend='native', runtime_generation=original_runtime,
                    owner_session=owner_session, expected_claim_id=parameters['claim_id'])
            else:
                claimed = interaction_contract.claim(self._request('operation', action='claim_status',
                    claim_id=parameters['claim_id'], owner_session=owner_session), backend='native',
                    runtime_generation=self.instance_id, owner_session=owner_session,
                    expected_claim_id=parameters['claim_id'], require_active=True)
            if (action in ('restore_window', 'key_pair', 'key_chord', 'key_sequence', 'insert_text')
                    or action == 'point' and 'modifiers' in parameters) and claimed['target']['window_id'] != parameters['window_id']:
                raise WorkbenchError('native_claim_target_mismatch', action + ' must name the exact claimed window.', effect_state='none')

        native_response_received = False
        def perform():
            nonlocal native_response_received
            if wait_ms is not None:
                with self._tasks_lock:
                    if self._closing:
                        raise WorkbenchError('native_executor_stopping', 'Queued native input was stopped before dispatch.', effect_state='none')
            if journaled:
                self.journal.checkpoint(request_id, {'phase': 'before_native_dispatch', 'native_operation_id': request_id,
                    'dispatch_phase': 'before_native_dispatch',
                    'lease_id': parameters.get('lease_id'), 'claim_id':parameters.get('claim_id'),
                    'owner_session':owner_session,'native_action':action,'runtime_generation':self.instance_id,'effect_state': 'unknown',
                    'claimed': claimed, 'admission_trace_id': invocation_trace.get()})
            if subtree:
                capability = self._request('operation', action='status', owner_session=owner_session)
                if type(capability.get('subtree_observation_version')) is not int or capability['subtree_observation_version'] != 1:
                    raise WorkbenchError('native_subtree_observation_unsupported', 'The native host does not advertise bounded subtree observation.', effect_state='none')
            dispatch_parameters = dict(parameters)
            if action == 'release' and claimed is not None:
                dispatch_parameters['release_binding'] = claimed
            if bootstrap:
                if self.file_tools is None:
                    raise WorkbenchError('native_launch_file_authority_unavailable', 'The local file authority is unavailable.')
                relative = dispatch_parameters.pop('open_file')
                dispatch_parameters['launch_file_authority'] = self.file_tools.authorize_native_launch_file(workspace, relative)
            if request_cancellation is not None:
                request_cancellation.before_dispatch(self, owner_session, request_id, parameters.get('claim_id'))
            try:
                result = self._request('operation', action=action,
                    **({'operation_id': request_id} if journaled else {}), **dispatch_parameters)
            except BaseException as error:
                if request_cancellation is not None:
                    if getattr(error, '_native_response_received', False):
                        request_cancellation.finish()
                    else:
                        # Socket/protocol failure leaves native execution unknown.
                        # Stop listening, but preserve already requested cleanup.
                        request_cancellation.detach()
                raise
            else:
                if request_cancellation is not None:
                    request_cancellation.finish()
            native_response_received = True
            if action == 'receipt' and not cursor_view:
                # Authenticated history survives retirement and runtime changes.
                # Check its original binding before returning or settling it;
                # this path cannot obtain or restore an input claim.
                _validate_historical_receipt(result, parameters)
            if subtree:
                scope = result.get('observation_scope')
                if (type(result.get('subtree_observation_version')) is not int or result['subtree_observation_version'] != 1
                        or result.get('lease_id') != parameters['claim_id'] or type(scope) is not dict
                        or scope.get('kind') != 'subtree' or scope.get('source_observation_id') != parameters['observation_id']
                        or scope.get('root_control_id') != parameters['control_id'] or scope.get('whole_window_complete') is not False
                        or scope.get('predecessor_must_be_current') is not True
                        or type(scope.get('scoped_hops')) is not int or not 1 <= scope['scoped_hops'] <= 2
                        or scope.get('maximum_ancestry_nodes') != 64
                        or result.get('window',{}).get('id') != parameters['window_id']):
                    raise WorkbenchError('native_subtree_observation_protocol', 'The native reply did not preserve the exact predecessor, root and partial scope.', effect_state='none')
            if action == 'restore_window':
                result = _restore_outcome(result, parameters['window_id'])
                if result.get('ok') is not True:
                    _raise_restore_failure(result)
            elif action == 'receipt':
                result = _restore_receipt_view(result, parameters)
            if cursor_view:
                result = _cursor_diagnostics(result, parameters['operation_id'], parameters['claim_id'], owner_session, self.instance_id)
            elif action == 'receipt' and parameters.get('operation_id'):
                result['host_reconciled'] = (False if result.get('receipt_owner_unverified') else
                    self._reconcile_task(parameters['operation_id'], result, owner_session, max_bytes, workspace))
            if action == 'capture':
                if parameters.get('capture_purpose') == 'inspection':
                    result = _inspection_capture_result(result, parameters)
                # The descriptor is not the final capture response: page
                # transport can still fail without an authenticated result.
                native_response_received = False
                raw = self._capture_bytes(result)
                native_response_received = True
                stored = self.store.put_bytes(raw, json.dumps({'kind': 'native_window_capture',
                    'lease_id': parameters.get('lease_id'), 'owner': result.get('owner'),
                    **({'capture_purpose': parameters['capture_purpose']} if 'capture_purpose' in parameters else {}),
                    'potentially_sensitive': True}))
                result['image_artifact'] = stored['artifact_id']; result['capture_id'] = stored['capture_id']
            if action in ('acquire','claim_status'):
                interaction_contract.claim(result, backend='native', runtime_generation=self.instance_id, owner_session=owner_session,
                    expected_claim_id=parameters.get('claim_id'), require_active=action == 'acquire')
                if action == 'acquire':
                    expected = parameters['app_identity']
                    observed = result['target']['app']
                    keys = ('bundleID','bundlePath','executable','pid','launchedAt','signingIdentifier','teamID','designatedRequirement','processGeneration')
                    if result['target']['window_id'] != parameters['window_id'] or any(expected.get(k) != observed.get(k) for k in keys):
                        raise WorkbenchError('interaction_protocol_error','Acquisition returned a different app or window.',effect_state='unknown')
            elif claimed is not None and journaled:
                result['operation_receipt'] = interaction_contract.receipt(request_id, claimed, action, result)
            result.update(server_generation=self.instance_id, prompts_triggered=False, checked_at=time.time(), potentially_sensitive=True)
            raw = json.dumps(result, ensure_ascii=True).encode()
            if len(raw) > max_bytes:
                stored = self.store.put_bytes(raw, json.dumps({'kind': 'native_app_result', 'potentially_sensitive': True}))
                wrapper = {'ok': True, 'result_artifact': stored['artifact_id'], 'capture_id': stored['capture_id'],
                           'inline_complete': False, 'potentially_sensitive': True, 'server_generation': self.instance_id}
                if action == 'observe':
                    summary = _observation_summary(result, wrapper, max_bytes)
                    if summary is not None:
                        wrapper['observation_summary'] = summary
                else:
                    _native_result_summary(result, wrapper, max_bytes)
                return add_result_continuation(wrapper, stored, max_bytes)
            return result

        if journaled:
            if request_id is None: raise WorkbenchError('request_id_required', 'Effects require a stable request_id.')
            if wait_ms is not None:
                return self._start_task(request_id, payload, perform, claimed['target']['target_id'], wait_ms, {
                    'phase': 'native_queued', 'native_operation_id': request_id, 'claim_id': parameters['claim_id'],
                    'owner_session': owner_session, 'native_action': action, 'runtime_generation': self.instance_id,
                    'effect_state': 'unknown', 'claimed': claimed, 'admission_trace_id': invocation_trace.get()}, claimed)
            def perform_synchronous():
                try:
                    return perform()
                except WorkbenchError as error:
                    if (error.details.get('effect_state') != 'none'
                            and not native_response_received
                            and not getattr(error, '_native_response_received', False)):
                        raise _uncertain_native_error(error, request_id) from error
                    raise
            return self.journal.run(request_id, payload,
                perform_synchronous, resource=claimed['target']['target_id'] if claimed else 'native-app:' + str(parameters.get('lease_id', parameters.get('clipboard_lease_id', 'clipboard'))),
                preserve_uncertain=lambda error: not native_response_received
                    and not getattr(error, '_native_response_received', False))
        return perform()
