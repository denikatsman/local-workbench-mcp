const HOST = 'tools.localworkbench.selected_tabs';
const uuid = () => crypto.randomUUID().replaceAll('-', '');
const workerGeneration = uuid();
const leases = new Map();
const INTERACTION_VERSION = 1;
function acknowledgedCdpInput(stateObserved = 'not_established') {
  // CDP success can drain a callback without a received event. These legacy
  // dispatch flags describe the command channel only, never a recipient witness.
  return { input_dispatched: true, native_input_dispatched: null, events_trusted: null,
    dispatch_scope: 'cdp_command_only', dispatch_state: 'acknowledged', dispatch_effect_state: 'unknown',
    input_evidence: { version: 1, attempted: true, protocol_acknowledged: true,
      recipient_observed: 'not_established', state_observed: stateObserved, task_verified: false, retry_allowed: false } };
}
const claims = new Map(), targets = new Map(), stoppedTargets = new Set();
const incompleteClaimHistory = new Map();
const claimPublications = new Map();
const unboundCreationHistory = new Map();
const creationAdmissions = new Map();
const retirementInvalidations = new WeakMap();
const legacyKeyboardHistory = new Map();
const contextKind = () => chrome.extension.inIncognitoContext ? 'private' : 'ordinary';
let contextId, installationId, trust, foundations, setupWaiter, acquisitionBusy = false, localSetupBusy = false;
const uploadWaiters = new Map();
const uploadContentBuffers = new Set();
const UPLOAD_CONTENT_LIMIT = 1048576, UPLOAD_CONTENT_CHUNK = 32768;
let acknowledgedTrustId, acknowledgedTrustPeer;
let targetPersistence = Promise.resolve();
let port, connection, serverGeneration, peerId, profileId, sequence = 0, idleTimer, rejectConnection;
let connectionStage = 'idle', connectionAttempt = 0, lastConnectionFailure, connectionReceipt;
const CONNECTION_PHASE_MARKER = 'LOCAL_WORKBENCH_CONNECTION_PHASE';
const connectionPhases = new Set(['bootstrap_trust_storage_read', 'bootstrap_alarm', 'attempt_started',
  'profile_storage_read', 'profile_storage_write',
  'context_storage_read', 'context_storage_write', 'foundations', 'keyboard_history_read', 'trust_storage_read',
  'session_history_read', 'durable_history_read', 'manifest_fetch', 'manifest_body', 'manifest_hash',
  'native_port', 'native_hello', 'native_ready', 'trust_restore', 'trust_ready', 'connected', 'disconnected', 'setup_failed']);
// Operational session buffer only: one in-flight write and one coalesced
// latest snapshot. A hung store cannot hold startup or grow a promise queue.
const connectionHistory = [];
let connectionOmitted = 0, connectionStorageFailures = 0, connectionUpdates = 0;
let connectionWriteBusy = false, connectionWriteScheduled = false, connectionWriteDirty = false;
const connectionCount = value => Math.min(Number.MAX_SAFE_INTEGER, value + 1);
function connectionWallTime() {
  try { const value = Date.now(); return Number.isSafeInteger(value) && value >= 0 ? value : null; } catch { return null; }
}
function scheduleConnectionSnapshot() {
  if (connectionWriteBusy || connectionWriteScheduled || !connectionWriteDirty) return;
  connectionWriteScheduled = true;
  try { setTimeout(writeConnectionSnapshot, 50); }
  catch { connectionWriteScheduled = false; connectionStorageFailures = connectionCount(connectionStorageFailures); }
}
function writeConnectionSnapshot() {
  connectionWriteScheduled = false;
  if (connectionWriteBusy || !connectionWriteDirty) return;
  connectionWriteBusy = true; connectionWriteDirty = false;
  try {
    const kind = contextKind(), version = chrome.runtime.getManifest().version;
    if (typeof version !== 'string' || version.length > 32 || !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(version)) throw new Error('version');
    const snapshot = { version: 1, worker_generation: workerGeneration, context_kind: kind,
      extension_version: version, captured_at_ms: connectionWallTime(), update_sequence: connectionUpdates,
      omitted_history: connectionOmitted, persistence_failures: connectionStorageFailures,
      history_before_worker: 'unavailable', persistence: 'best_effort',
      rows: connectionHistory.map(row => ({ ...row })) };
    // Never await this operation in startup. No retry on failure without a new
    // phase; one permanently pending write intentionally prevents more writes.
    Promise.resolve(chrome.storage.session.set({ ['workbenchConnectionPhases:' + kind]: snapshot }))
      .catch(() => { connectionStorageFailures = connectionCount(connectionStorageFailures); })
      .finally(() => { connectionWriteBusy = false; scheduleConnectionSnapshot(); });
  } catch {
    connectionWriteBusy = false; connectionStorageFailures = connectionCount(connectionStorageFailures);
    scheduleConnectionSnapshot();
  }
}
function retainConnectionPhase(row) {
  try {
    connectionHistory.push({ ...row, received_at_ms: connectionWallTime() });
    if (connectionHistory.length > 32) { connectionHistory.shift(); connectionOmitted = connectionCount(connectionOmitted); }
    connectionUpdates = connectionCount(connectionUpdates); connectionWriteDirty = true;
    scheduleConnectionSnapshot();
  } catch {} // Diagnostics cannot affect connection admission or startup.
}
function connectionPhaseReporter(attempt) {
  if (!Number.isSafeInteger(attempt) || attempt < 0) return () => {};
  // A synchronous, content-free console side channel, independent of native
  // transport and diagnostic evaluation. Each receipt marks a phase boundary,
  // never phase completion, an ACK, a recipient effect or causal proof. Missing
  // receipts cannot establish that a worker/phase never started.
  let started, previous = 0, receiptSequence = 0;
  try { const now = performance.now(); if (Number.isFinite(now)) started = now; } catch {}
  return phase => {
    try {
      if (!connectionPhases.has(phase) || receiptSequence >= Number.MAX_SAFE_INTEGER) return;
      let elapsed = null;
      try {
        const now = performance.now(), value = Math.floor(now - started);
        if (started !== undefined && Number.isSafeInteger(value) && value >= previous) {
          elapsed = value; previous = value;
        }
      } catch {} // Do not substitute wall-clock time for a monotonic clock.
      const row = { version: 1, worker_generation: workerGeneration,
        connection_attempt: attempt, sequence: ++receiptSequence, phase, elapsed_ms: elapsed };
      retainConnectionPhase(row);
      console.info(CONNECTION_PHASE_MARKER, JSON.stringify(row));
    } catch {} // Observer absence/failure must never affect connection startup.
  };
}
const connectionSetupCodes = new Set(['browser_key_history_limit', 'browser_key_history_unavailable',
  'browser_target_history_limit', 'browser_claim_history_limit', 'browser_session_storage_unavailable']);
const nativeDisconnectCodes = new Map([
  ['Specified native messaging host not found.', 'native_host_not_found'],
  ['Access to the specified native messaging host is forbidden.', 'native_host_forbidden'],
  ['Failed to start native messaging host.', 'native_host_start_failed'],
  ['Native host has exited.', 'native_host_exited'],
  ['Error when communicating with the native messaging host.', 'native_host_io_failed'],
]);
function nativeDisconnectCode(message) {
  // Never retain Chrome's raw error: it can contain local paths or other data.
  return nativeDisconnectCodes.get(message) || 'native_connection_lost';
}
function connectionDiagnostic() {
  return { stage: connectionStage, extension_version: chrome.runtime.getManifest().version,
    last_failure: lastConnectionFailure ? { ...lastConnectionFailure } : null };
}
let controlCacheVersion = 0;
let controlCacheSequence = 0, controlCacheTimer;
const controlCacheDirty = new Set();
let bodyBytesTotal = 0;
const encoder = new TextEncoder();
const hash = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
const fail = (code, effect_state = 'none') => Object.assign(new Error(code), { code, effect_state });
const safeURL = value => { try { const u = new URL(value); return u.origin + u.pathname; } catch { return '(unavailable)'; } };
const webOrigin = value => { const u = new URL(value); if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw fail('unsupported_origin'); return u.origin; };
const b64 = bytes => { let value = ''; for (let i = 0; i < bytes.length; i += 32768) value += String.fromCharCode(...bytes.subarray(i, i + 32768)); return btoa(value); };
const decoded = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

function publicLease(record) {
  return { lease_id: record.id, document_generation: record.generation, expires_at: record.expires / 1000,
    tab_id: record.tabId, window_id: record.windowId, control: record.control, network: record.network,
    state: record.state, origin: record.origin,
    browser_target_id: record.browserTargetId || null, grant_generation: record.grantGeneration || null,
    installation_id: record.installation_id || null, runtime_generation: record.runtime_generation || null,
    peer_id: record.peerId, profile_id: profileId, context_id: contextId, context_kind: contextKind(),
    operation_owner: record.operationOwner ?? null,
    input_eligible: publicInputEligible(record), debuggerAttached: record.debuggerAttached === true,
    cleanup_state: record.cleanup_state || 'not_attempted', cleanup_error: record.cleanup_error || null,
    keyboard_release_state: record.heldKey?.state || record.keyboard_release_state || 'not_needed',
    keyboard_receipt: record.heldKey ? keyboardReceipt(record.heldKey) : record.keyboard_receipt || {} };
}
function publicInputEligible(record) {
  return record.state === 'active' && !record.initializing && record.inputEligible !== false
    && !['pending','unverified'].includes(record.dialog_resolution_state)
    && !['prepared','held','unverified','not_recorded'].includes(record.heldKey?.state || record.keyboard_release_state);
}
function closeConnection(expectedPort, reason, diagnosticCode) {
  if (!expectedPort || port !== expectedPort) return;
  if (['connection_timeout', 'native_connection_lost', 'connection_setup_failed'].includes(reason)) {
    lastConnectionFailure = { stage: connectionStage, code: diagnosticCode || reason, at: Date.now() / 1000 };
  }
  connectionReceipt?.('disconnected');
  connectionStage = 'disconnected';
  const endedPeer = peerId, reject = rejectConnection;
  clearTimeout(idleTimer); idleTimer = undefined;
  // Sever the broken transport BEFORE any fence can publish. Download
  // cancellation may synchronously call managedPublish/sendNative itself.
  port = undefined; connection = undefined; serverGeneration = undefined; peerId = undefined; rejectConnection = undefined;
  claimPublications.clear();
  controlCacheVersion = 0;
  acknowledgedTrustId = undefined; acknowledgedTrustPeer = undefined;
  fencePageDownloads(null, reason);
  reject?.(fail('workbench_not_connected'));
  if (setupWaiter?.port === expectedPort) { setupWaiter.reject(fail('workbench_not_connected')); setupWaiter = undefined; }
  for (const [nonce, waiter] of uploadWaiters) if (waiter.port === expectedPort) {
    clearTimeout(waiter.timer); waiter.reject(fail('workbench_not_connected')); uploadWaiters.delete(nonce);
  }
  for (const [nonce, waiter] of pageObservationWaiters) if (waiter.port === expectedPort) {
    clearTimeout(waiter.timer); waiter.reject(fail('workbench_not_connected')); pageObservationWaiters.delete(nonce);
  }
  // A local disconnect does not notify this endpoint's onDisconnect listener.
  // Clear ownership first so detach/state cannot send through the closed port.
  for (const record of leases.values()) if (record.peerId === endedPeer) {
    if (record.durable && record.state === 'active') {
      // Transport authority is gone even if exact cleanup's existing guards
      // refuse. Keep the original epoch/held bindings for that cleanup attempt;
      // finishClaim alone advances the epoch when it admits retirement.
      record.inputEligible = false; record.observations.clear();
      record.state = 'suspended_transport'; record.reason = reason;
    }
    void detach(record, reason).catch(() => {
      // A pre-cleanup refusal must neither publish old active authority on a
      // new peer nor silently certify held/body/native-download settlement.
      if (leases.get(record.id) === record && record.peerId === endedPeer
          && !['completed','target_gone','not_owned'].includes(record.cleanup_state)) {
        record.inputEligible = false; record.cleanup_state = 'unverified';
      }
    });
  }
  try { expectedPort.disconnect(); } catch { /* Chrome already closed this endpoint. */ }
}
function sendNative(expectedPort, packet) {
  if (!expectedPort || port !== expectedPort) return false;
  try { expectedPort.postMessage(packet); return true; }
  catch { closeConnection(expectedPort, 'native_connection_lost'); return false; }
}
const pendingLocalSetups = new Map();
function reserveLocalSetup(expectedPort) {
  clearTimeout(idleTimer); idleTimer = undefined;
  pendingLocalSetups.set(expectedPort, (pendingLocalSetups.get(expectedPort) || 0) + 1);
  let ended = false, expired = false, timer;
  const finish = (timedOut = false) => {
    if (ended) return;
    ended = true; expired = timedOut; clearTimeout(timer);
    const remaining = (pendingLocalSetups.get(expectedPort) || 1) - 1;
    if (remaining) pendingLocalSetups.set(expectedPort, remaining);
    else pendingLocalSetups.delete(expectedPort);
    if (port === expectedPort) state();
  };
  // Reserve transport only for bounded local setup, never arbitrary future work.
  timer = setTimeout(() => finish(true), 8000);
  return { current: () => !expired, finish: () => finish() };
}
function state() {
  if (!port || !serverGeneration) return;
  const currentPort = port;
  const rows = [...leases.values()].filter(r => !r.durable && r.peerId === peerId
    && (!r.initializing || r.state !== 'active'));
  if (!sendNative(currentPort, { type: 'state', sequence: ++sequence, leases: rows.map(publicLease),
    ...(controlCacheVersion === 1 ? { legacy_key_history: [...legacyKeyboardHistory.values()]
      .filter(row => !rows.some(record => record.grantGeneration === row.grant_generation))
      .map(row => ({ ...row, state: 'detached', input_eligible: false, authority: 'cleanup_only', history_only: true })) } : {}) })) return;
  for (const row of rows) row.statePublished = true;
  clearTimeout(idleTimer);
  if (!trust?.enabled && !rows.some(r => r.state === 'active') && !pendingLocalSetups.has(currentPort))
    idleTimer = setTimeout(() => {
      if (!pendingLocalSetups.has(currentPort)) closeConnection(currentPort, 'idle_disconnect');
    }, 5000);
  if (contextId && trust?.enabled && acknowledgedTrustId === trust.trust_id && acknowledgedTrustPeer === peerId) {
    const publishedPeer = peerId, readyClaims = [...claims.values()].filter(claimDocumentReady);
    let batches;
    try {
      batches = claimStateBatches(readyClaims,
        [...incompleteClaimHistory.values()].filter(row => !claims.has(row.claim_id)));
    } catch {
      // Keep the original receipts. Never send a truncated identity or discard
      // history to work around the native transport's existing hard limit.
      closeConnection(currentPort, 'connection_setup_failed', 'browser_claim_history_limit'); return;
    }
    for (const batch of batches) {
      if (!sendNative(currentPort, batch.packet)) return;
      // Document qualification precedes durable storage. Cache timers may run
      // during that await, but the host must first receive this claim identity
      // on the same native connection before accepting its control cache.
      for (const row of batch.records) row.claimStatePublishedPeer = publishedPeer;
      for (const entry of batch.publications) claimPublications.set(entry.id, { peer: publishedPeer, value: entry.value });
    }
    for (const id of claimPublications.keys()) if (!claims.has(id) && !incompleteClaimHistory.has(id)) claimPublications.delete(id);
  }
  for (const record of leases.values()) if (record.peerId === peerId) queueControlCache(record);
}
function claimStateBatches(records, history) {
  // claims_state is incremental at the broker. Partition on encoded bytes,
  // including UTF-8 and envelope overhead, without changing row identity or
  // retention. Small batches also leave room for authoritative reconciliation.
  const empty = () => ({ type: 'claims_state', interaction_version: INTERACTION_VERSION,
    claims: [], incomplete_initializations: [] });
  const baseBytes = encoder.encode(JSON.stringify(empty())).length, batches = [];
  let batch = { packet: empty(), records: [], publications: [] }, bytes = baseBytes;
  const add = (field, value, record) => {
    const encoded = JSON.stringify(value), previous = claimPublications.get(value.claim_id);
    if (previous?.peer === peerId && previous.value === encoded) return;
    const rowBytes = encoder.encode(encoded).length;
    let addition = rowBytes + (batch.packet[field].length ? 1 : 0);
    if (bytes + addition > 65536 && bytes > baseBytes) {
      batches.push(batch); batch = { packet: empty(), records: [], publications: [] }; bytes = baseBytes; addition = rowBytes;
    }
    if (bytes + addition > 131072) throw fail('browser_claim_history_limit');
    batch.packet[field].push(value); bytes += addition;
    if (record) batch.records.push(record);
    batch.publications.push({ id: value.claim_id, value: encoded });
  };
  for (const record of records) add('claims', publicClaim(record), record);
  for (const row of history) add('incomplete_initializations', initializationRecord(row));
  if (bytes > baseBytes || !batches.length) batches.push(batch);
  return batches;
}
function queueControlCache(record) {
  if (controlCacheVersion !== 1 || !port || record.peerId !== peerId
      || (record.durable ? record.claimStatePublishedPeer !== peerId : record.statePublished !== true)) return;
  if (controlCacheDirty.size < 32) controlCacheDirty.add(record);
  if (controlCacheTimer) return;
  controlCacheTimer = setTimeout(() => {
    controlCacheTimer = undefined;
    const currentPort = port, records = [...controlCacheDirty]; controlCacheDirty.clear();
    if (controlCacheVersion !== 1 || !currentPort) return;
    for (const row of records) {
      if (row.peerId !== peerId || leases.get(row.id) !== row
          || row.durable && (!claimDocumentReady(row) || row.claimStatePublishedPeer !== peerId)) continue;
      const identity = row.durable ? publicClaim(row) : publicLease(row);
      const events = []; let bytes = encoder.encode(JSON.stringify(identity)).length + 1024;
      for (const entry of row.events.slice(-64).reverse()) {
        const size = encoder.encode(JSON.stringify(entry)).length + 1;
        if (bytes + size > 49152) break;
        events.unshift(entry); bytes += size;
      }
      sendNative(currentPort, { type: 'control_cache', interaction_version: 1,
        sequence: ++controlCacheSequence, checked_at: Date.now() / 1000,
        records: [{ ...identity, events, event_sequence: row.eventSequence, event_dropped: row.eventsDropped,
          cache_retained_first: events[0]?.sequence ?? null, modal: row.modal || null }] });
    }
  }, 100);
}
function cachedEvents(record, parameters = {}) {
  const after = parameters.after_sequence ?? 0, limit = parameters.limit ?? 20;
  if (!Number.isSafeInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1 || limit > 100) throw fail('invalid_event_cursor');
  const rows = record.events.filter(row => row.sequence > after).slice(0, limit);
  return { events: rows, retained_first: record.events[0]?.sequence ?? null, dropped: record.eventsDropped,
    gap_before_cursor: !!record.events.length && after < record.events[0].sequence - 1,
    next_sequence: rows.at(-1)?.sequence ?? after, checked_at: Date.now() / 1000,
    cache_only: true, pre_attach_gap: true, modal: record.modal || null,
    scope: 'Bounded cached event metadata; not a fresh renderer or effect check.' };
}
function event(record, kind, details = {}) {
  record.events.push({ ...details, sequence: ++record.eventSequence, checked_at: Date.now() / 1000, kind });
  if (record.events.length > 500) { record.events.shift(); record.eventsDropped++; }
  queueControlCache(record);
}
// Content-free callback evidence only. Invalid or non-Chrome-shaped identifiers
// are omitted rather than copying attacker-controlled callback text.
function lifecycleId(value) {
  return typeof value === 'string' && /^[0-9a-fA-F-]{1,128}$/.test(value) ? value : null;
}
const LIFECYCLE_ACTIONS = new Set(['inspect','snapshot','body','document','evaluate','evaluate_start',
  'click','click_point','fill','insert_text','press','check','select','select_text','replace_selection',
  'scroll','drag','upload','navigate']);
function lifecycleEvent(record, source, phase, params = {}, reason = null) {
  try {
    const sid = typeof params?.sessionId === 'string' ? params.sessionId : null;
    const child = sid === null ? null : record.children?.get(sid);
    const sourceSid = typeof source?.sessionId === 'string' ? source.sessionId : null;
    const rootId = record.target?.browser_target_id || record.browserTargetId;
    const details = {
      version: 1, phase, root_target_id: lifecycleId(rootId),
      source_tab_id: Number.isSafeInteger(source?.tabId) && source.tabId >= 0 ? source.tabId : null,
      source_target_id: lifecycleId(source?.targetId), source_session_id: lifecycleId(sourceSid),
      source_role: source?.sessionId == null ? 'root_address' : sourceSid === null ? 'unavailable' : record.children?.has(sourceSid) ? 'known_related' : 'unknown_related',
      source_match: source?.tabId === record.tabId ? (source?.targetId == null ? 'tab' : source.targetId === rootId ? 'tab_and_target' : 'tab_target_conflict')
        : source?.targetId && source.targetId === rootId ? 'target' : 'unavailable',
      related_session_id: lifecycleId(sid),
      related_target_id: lifecycleId(params?.targetInfo?.targetId || params?.targetId),
      known_related_target_id: lifecycleId(child?.target_id),
      related_parent_session_id: lifecycleId(child?.parent_session_id ?? (phase === 'related_attach' ? sourceSid : null)),
      related_known: sid === null ? 'unavailable' : child ? 'known' : 'unknown',
      reason: phase === 'debugger_detach' ? (['canceled_by_user','target_closed'].includes(reason) ? reason : 'other_or_unavailable') : null,
      admitted_action: LIFECYCLE_ACTIONS.has(record.lifecycleAction) ? record.lifecycleAction : null
    };
    event(record, 'debugger_lifecycle', details);
    // Passive capture remains opt-in and bound to its existing scope/budgets.
    // An empty document avoids adding a URL to this content-free event.
    if (record.diagnostics?.active) diagnosticEmit(record, { ...details, kind: 'debugger_lifecycle',
      cache_sequence: record.eventSequence, document: {} });
  } catch { /* Optional evidence never changes callback handling. */ }
}
function releaseBody(row) {
  bodyBytesTotal -= row.bodyBytes || 0;
  row.bodyBytes = 0; row.bodyChunks = []; row.futureChunks = [];
}
function retainBody(record, row, bytes, buffered = false) {
  if (record.state !== 'active' || record.requests.get(row.key) !== row || row.bodyGap) return;
  if ((row.bodyChunks?.length || 0) + (row.futureChunks?.length || 0) >= 2048
      || (row.bodyBytes || 0) + bytes.length > 2097152 || bodyBytesTotal + bytes.length > 8388608) {
    releaseBody(row); row.bodyGap = 'body_storage_limit';
    event(record, 'coverage_gap', { reason: row.bodyGap, request_key: row.key }); return;
  }
  row.bodyBytes = (row.bodyBytes || 0) + bytes.length; bodyBytesTotal += bytes.length;
  if (buffered) row.bodyChunks.unshift(bytes);
  else (row.streamReady ? row.bodyChunks : row.futureChunks).push(bytes);
}
function completeRawBody(record, row) {
  if (record.state !== 'active' || Date.now() >= record.expires || record.requests.get(row.key) !== row)
    throw fail('original_body_not_captured');
  if (row.bodyGap || !row.streamReady || !row.finished) return false;
  // An arm ACK can arrive after the last body event with no captured bytes.
  // Credit completeness only against the independent original event byte count.
  if (row.bodyLengthKnown !== true || row.observedBodyBytes !== row.bodyBytes
      || row.observedBodyEvents === 0 && ![204, 205].includes(row.status)) {
    releaseBody(row); row.bodyGap = 'raw_byte_coverage_incomplete';
    event(record, 'coverage_gap', { reason: row.bodyGap, request_key: row.key });
    return false;
  }
  return true;
}
async function streamBody(record, row, checkpoint = () => {}) {
  row.bodyChunks = []; row.futureChunks = []; row.bodyBytes = 0;
  try {
    checkpoint();
    const result = await cdp(record, 'Network.streamResourceContent', { requestId: row.requestId }, row.sessionId);
    checkpoint();
    retainBody(record, row, decoded(result.bufferedData), true);
    row.streamReady = true; row.bodyChunks.push(...row.futureChunks); row.futureChunks = [];
  } catch (error) {
    releaseBody(row); row.bodyGap = 'raw_stream_unavailable';
    try { row.streamErrorCode = JSON.parse(error.message).code; } catch { row.streamErrorCode = null; }
    row.streamErrorKind = /wasn.t found|not supported|not allowed|unknown method/i.test(error.message || '') ? 'unsupported' : /resource|identifier/i.test(error.message || '') ? 'resource_unavailable' : 'unclassified';
    event(record, 'coverage_gap', { reason: row.bodyGap, request_key: row.key, protocol_error_code: row.streamErrorCode });
  }
}
// Optional content-free samples; never an authority or effect predicate.
function responseDiagnosticMark(trace, tag, value) {
  try { if (trace && !value && trace.failed === null) trace.failed = tag; } catch {}
  return value;
}
const RESPONSE_DIAGNOSTIC_TAGS = new Set([
  "capture_lease_identity",
  "capture_debugger_attached",
  "capture_detaching",
  "capture_owner",
  "capture_grant",
  "capture_peer",
  "capture_runtime",
  "capture_installation",
  "capture_target",
  "capture_target_generation",
  "capture_epoch",
  "capture_session_binding",
  "capture_child_binding",
  "capture_competing_lease",
  "capture_owned",
  "capture_claim_active",
  "capture_input_eligible",
  "capture_releasing",
  "capture_unexpired",
  "capture_stopped",
  "route",
  "cancel_requested",
  "ambiguity",
  "worker_generation",
  "runtime_generation",
  "installation",
  "profile",
  "context",
  "context_kind",
  "binding_context_kind",
  "claim_context_kind",
  "response_or_unexpired_arm",
  "trust_enabled",
  "trust_control",
  "trust_network",
  "trust_file_download",
  "trust_identity",
  "peer_identity",
  "durable_claim",
  "owner_identity",
  "claim_epoch",
  "target_generation",
  "browser_target",
  "main_frame",
  "loader",
  "document_epoch",
  "origin",
  "claim_network",
  "claim_control",
  "capture_enabled",
  "capture_current",
  "fetch_request_id_type",
  "fetch_request_id_empty",
  "fetch_request_id_length",
  "network_request_id_type",
  "network_request_id_empty",
  "network_request_id_length",
  "attachment_supported",
  "document_resource_type",
  "status_integer",
  "status_minimum_200",
  "status_maximum_299",
  "history_capacity"
]);
const RESPONSE_DIAGNOSTIC_PHASES = new Set([
  "initial_response_admission",
  "post_observation_ack",
  "post_attempt_ack",
  "final_capture_ownership",
  "continuation_wait",
  "admission_wait"
]);
const RESPONSE_DIAGNOSTIC_ERRORS = new Set(['none','timeout','protocol_rejection','retired_interception','javascript_exception','unclassified_error']);
function responseDiagnosticProjection(value, limit) {
  const empty = { version: 1, entries: [], omitted: true, conflicted: false };
  try {
    if (!value || Object.keys(value).sort().join(',') !== 'conflicted,entries,omitted,version'
        || value.version !== 1 || typeof value.omitted !== 'boolean' || typeof value.conflicted !== 'boolean'
        || !Array.isArray(value.entries) || value.entries.length > limit) return empty;
    const entries = [], seen = new Set(), uuid = x => x === null || typeof x === 'string' && /^[a-f0-9]{32}$/.test(x);
    for (const row of value.entries) {
      if (!row || Object.keys(row).sort().join(',') !== 'error_class,failed_predicate,method,phase,phase_id,protocol_code,request_key'
          || !RESPONSE_DIAGNOSTIC_PHASES.has(row.phase) || row.failed_predicate !== null && !RESPONSE_DIAGNOSTIC_TAGS.has(row.failed_predicate)
          || !uuid(row.phase_id) || !uuid(row.request_key) || !RESPONSE_DIAGNOSTIC_ERRORS.has(row.error_class)
          || !['none','continue_request','continue_response'].includes(row.method)
          || row.protocol_code !== null && ![-32700,-32600,-32601,-32602,-32603,-32000].includes(row.protocol_code)) return empty;
      if (limit === 4 ? !['initial_response_admission','post_observation_ack','post_attempt_ack','final_capture_ownership'].includes(row.phase) || row.method !== 'none'
          : !['continuation_wait','admission_wait'].includes(row.phase) || row.failed_predicate !== null) return empty;
      if (row.error_class === 'protocol_rejection' ? row.protocol_code === null
          : row.error_class === 'retired_interception' ? row.protocol_code !== -32602 : row.protocol_code !== null) return empty;
      const key = limit === 4 ? row.phase : row.phase_id;
      if (key === null || seen.has(key)) return empty;
      seen.add(key); entries.push({ ...row });
    }
    return { version: 1, entries, omitted: value.omitted, conflicted: value.conflicted };
  } catch { return empty; }
}
function responseDiagnosticError(error) {
  try {
    if (['body_continue_timeout','download_continue_timeout','response_admission_timeout','response_history_storage_timeout',
         'download_storage_timeout','download_observation_timeout'].includes(error?.code)) return { error_class: 'timeout', protocol_code: null };
    let code = error?.code;
    if (typeof error?.message === 'string' && error.message.length <= 4096) {
      try { code = JSON.parse(error.message)?.code ?? code; } catch {}
    }
    if ([-32700,-32600,-32601,-32602,-32603,-32000].includes(code)) return { error_class: 'protocol_rejection', protocol_code: code };
    if (['TypeError','RangeError'].includes(error?.name)) return { error_class: 'javascript_exception', protocol_code: null };
  } catch {}
  return { error_class: 'unclassified_error', protocol_code: null };
}
function mergeResponseDiagnostics(before, after) {
  const blank = { version: 1, entries: [], omitted: false, conflicted: false };
  const a = responseDiagnosticProjection(before || blank, 32), b = responseDiagnosticProjection(after || blank, 32);
  const rows = new Map(a.entries.map(row => [row.phase_id, row]));
  let conflicted = a.conflicted || b.conflicted, omitted = a.omitted || b.omitted;
  for (const row of b.entries) {
    const old = rows.get(row.phase_id);
    if (old && Object.keys(old).some(key => old[key] !== row[key])) conflicted = true;
    else if (!old) { if (rows.size < 32) rows.set(row.phase_id, row); else omitted = true; }
  }
  return { version: 1, entries: [...rows.values()], omitted, conflicted };
}
function putResponseDiagnostic(holder, key, limit, phase, trace, capturePhase, method = 'none', error = null, retired = false) {
  try {
    const envelope = holder[key] ? responseDiagnosticProjection(holder[key], limit)
      : { version: 1, entries: [], omitted: false, conflicted: false };
    const row = { phase, failed_predicate: trace?.failed || null, phase_id: capturePhase?.receipt?.phase_id || null,
      request_key: capturePhase?.row?.key || null, method,
      ...(error ? responseDiagnosticError(error) : { error_class: 'none', protocol_code: null }) };
    if (retired) row.error_class = 'retired_interception';
    if (limit === 32 && row.phase_id === null) { envelope.omitted = true; holder[key] = envelope; return; }
    const index = envelope.entries.findIndex(old => limit === 4 ? old.phase === phase : old.phase_id === row.phase_id);
    if (index >= 0) envelope.entries[index] = row;
    else if (envelope.entries.length < limit) envelope.entries.push(row);
    else envelope.omitted = true;
    holder[key] = responseDiagnosticProjection(envelope, limit);
  } catch {} // Lost diagnostics never block original cleanup/dispatch.
}

function bodySessionKey(sessionId) { return sessionId || ''; }
function bodyCaptureOwner(record, sessionId) {
  return { record, id: record.id, owner: record.owner_session ?? record.operationOwner ?? null,
    epoch: record.claim_epoch, grant: record.grantGeneration, peer: record.peerId,
    runtime: record.runtime_generation, installation: record.installation_id,
    target: record.target?.browser_target_id || record.browserTargetId,
    targetGeneration: record.target?.target_generation, sessionId,
    child: sessionId ? record.children.get(sessionId) : null, generation: uuid(), enabled: false, detaching: false };
}
function bodyCaptureOwned(binding, trace) {
  const r = binding.record;
  return responseDiagnosticMark(trace, 'capture_lease_identity', leases.get(binding.id) === r)
    && responseDiagnosticMark(trace, 'capture_debugger_attached', r.debuggerAttached === true)
    && responseDiagnosticMark(trace, 'capture_detaching', !binding.detaching)
    && responseDiagnosticMark(trace, 'capture_owner', (r.owner_session ?? r.operationOwner ?? null) === binding.owner)
    && responseDiagnosticMark(trace, 'capture_grant', r.grantGeneration === binding.grant)
    && responseDiagnosticMark(trace, 'capture_peer', r.peerId === binding.peer)
    && responseDiagnosticMark(trace, 'capture_runtime', r.runtime_generation === binding.runtime)
    && responseDiagnosticMark(trace, 'capture_installation', r.installation_id === binding.installation)
    && responseDiagnosticMark(trace, 'capture_target', (r.target?.browser_target_id || r.browserTargetId) === binding.target)
    && responseDiagnosticMark(trace, 'capture_target_generation', r.target?.target_generation === binding.targetGeneration)
    && responseDiagnosticMark(trace, 'capture_epoch', (r.claim_epoch === binding.epoch || r.releasing && r.claim_epoch === binding.epoch + 1))
    && responseDiagnosticMark(trace, 'capture_session_binding', r.bodyCaptureSessions?.get(bodySessionKey(binding.sessionId)) === binding)
    && responseDiagnosticMark(trace, 'capture_child_binding', (!binding.sessionId || r.children.get(binding.sessionId) === binding.child))
    && responseDiagnosticMark(trace, 'capture_competing_lease', ![...leases.values()].some(other => other !== r && other.state === 'active' && other.tabId === r.tabId));
}
function bodyCaptureCurrent(binding, trace) {
  const r = binding.record;
  return responseDiagnosticMark(trace, 'capture_owned', bodyCaptureOwned(binding, trace))
    && responseDiagnosticMark(trace, 'capture_claim_active', r.state === 'active')
    && responseDiagnosticMark(trace, 'capture_input_eligible', r.inputEligible !== false)
    && responseDiagnosticMark(trace, 'capture_releasing', !r.releasing)
    && responseDiagnosticMark(trace, 'capture_unexpired', Date.now() < r.expires)
    && responseDiagnosticMark(trace, 'capture_stopped', (!r.durable || !stoppedTargets.has(r.target.target_id)));
}
function adoptLegacyOwner(record, owner) {
  if (record.durable || record.operationOwner !== undefined || owner === undefined || owner === null) return;
  // Validate the original attachment before changing either owner. No await may
  // split this transition and leave enabled root/child capture with the old owner.
  const bindings = [...record.bodyCaptureSessions?.values() || []]
    .filter(binding => binding.owner === null && bodyCaptureCurrent(binding));
  record.operationOwner = owner;
  for (const binding of bindings) binding.owner = owner;
}
function bodyWait(promise, ms, cancel, code) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(fail(code)), ms);
    if (cancel) cancel.reject = reject;
  })]).finally(() => { clearTimeout(timer); if (cancel) cancel.reject = null; });
}
function bodyReceiptUnsettled(receipt) {
  return ['pending', 'unverified'].includes(receipt.resource_cleanup);
}
function restoreBodyReceipts(record) {
  if (!Array.isArray(record.response_capture_receipts)) return;
  for (const receipt of record.response_capture_receipts) {
    if (['not_attempted', 'attempted'].includes(receipt.continuation)) receipt.continuation = 'unverified';
    if (bodyReceiptUnsettled(receipt)) receipt.resource_cleanup = 'unverified';
  }
}
function recordBodyReceipt(record, phase) {
  if (!record.durable) return true;
  const receipts = (record.response_capture_receipts || [])
    .filter(receipt => !['acknowledged', 'rejected_retired_id'].includes(receipt.continuation));
  if (receipts.length >= 32) {
    record.response_capture_overflow = true;
    return false;
  }
  phase.receipt = { phase_id: uuid(), claim_epoch: phase.binding.epoch,
    fetch_id: phase.fetchId, session_id: phase.binding.sessionId || null,
    continuation: 'not_attempted', resource_cleanup: 'pending' };
  receipts.push(phase.receipt); record.response_capture_receipts = receipts;
  return true;
}
function publishBodyReceipt(phase) {
  if (!phase.receipt) return;
  phase.receipt.continuation = phase.continuation;
  if (phase.cleanup) phase.receipt.resource_cleanup = phase.cleanup;
}
async function persistBodyState(record) {
  if (!record.durable) return true;
  try { await bodyWait(persistTargets(), 350, null, 'response_history_storage_timeout'); return true; }
  catch { record.response_history_persistence = 'unsaved'; return false; }
}
function fenceBodyCapture(record, reason, sessionId) {
  if (!sessionId) fencePageDownloads(record, reason);
  for (const binding of record.bodyCaptureSessions?.values() || []) {
    if (sessionId !== undefined && binding.sessionId !== sessionId) continue;
    binding.detaching = true;
  }
  for (const phase of record.bodyPauses?.values() || []) {
    if (sessionId !== undefined && phase.binding.sessionId !== sessionId) continue;
    phase.captureClosed = true;
    if (phase.row) { releaseBody(phase.row); phase.row.bodyGap = 'capture_cancelled'; }
    phase.cancel?.reject?.(fail(reason));
  }
}
function settleBodyCapture(record, disposition, sessionId) {
  for (const [key, phase] of record.bodyPauses || []) {
    if (sessionId !== undefined && phase.binding.sessionId !== sessionId) continue;
    phase.captureClosed = true;
    phase.cleanup = disposition;
    publishBodyReceipt(phase);
    phase.cancel?.reject?.(fail('body_attachment_ended'));
    record.bodyPauses.delete(key);
  }
}
async function enableBodyCapture(record, sessionId, checkpoint = () => {}, send = cdp) {
  checkpoint();
  record.bodyCaptureSessions ||= new Map(); record.bodyPauses ||= new Map(); record.bodyPhaseHistory ||= new Map();
  const binding = bodyCaptureOwner(record, sessionId);
  record.bodyCaptureSessions.set(bodySessionKey(sessionId), binding);
  try {
    await send(record, 'Fetch.enable', { patterns: [
      { urlPattern: 'http://*', requestStage: 'Response' },
      { urlPattern: 'https://*', requestStage: 'Response' }] }, sessionId);
    checkpoint();
    if (!bodyCaptureCurrent(binding)) throw fail('body_capture_owner_changed');
    binding.enabled = true;
  } catch (error) {
    checkpoint();
    let code; try { code = JSON.parse(String(error.message).slice(0, 4096)).code; } catch {}
    if (code !== -32601 && !/wasn.t found|not supported|unknown method/i.test(String(error.message))) throw error;
    record.bodyCaptureSessions.delete(bodySessionKey(sessionId));
    event(record, 'coverage_gap', { reason: 'response_stage_capture_unavailable', child_session: sessionId || null });
  }
}
function bodyProtocolError(error) {
  try { const parsed = JSON.parse(String(error.message).slice(0, 4096)); return { code: parsed.code, message: parsed.message }; }
  catch { return { code: error.code || null, message: '' }; }
}
function bodyRecovery(record, phase, reason) {
  phase.captureClosed = true; phase.state = 'unverified';
  if (phase.receipt) { publishBodyReceipt(phase); phase.receipt.resource_cleanup = 'unverified'; }
  if (phase.row) { releaseBody(phase.row); phase.row.bodyGap = reason; }
  record.cleanup_state = 'unverified'; record.inputEligible = false;
  event(record, 'coverage_gap', { reason, request_key: phase.row?.key || null, continuation_state: phase.continuation });
  // Preserve unknown state before ownership-aware cleanup. A continuation is never replayed.
  if (record.bodyRecoveryScheduled) return;
  record.bodyRecoveryScheduled = true;
  void persistBodyState(record).then(() => {
    if (record.state === 'active' && !record.releasing) return detach(record, 'response_capture_unverified');
  }).catch(() => { record.cleanup_state = 'unverified'; state(); });
}
function admitBodyPauses(record) {
  if (record.bodyRecoveryScheduled) return;
  let occupied = [...record.bodyPauses.values()].filter(phase => phase.admitted).length;
  for (const phase of record.bodyPauses.values()) {
    if (phase.admitted || phase.captureClosed || !bodyCaptureOwned(phase.binding)) continue;
    const pending = (record.response_capture_receipts || [])
      .filter(receipt => !['acknowledged', 'rejected_retired_id'].includes(receipt.continuation));
    if (occupied >= 32 || record.durable && pending.length >= 32) break;
    if (!recordBodyReceipt(record, phase)) break;
    phase.admitted = true;
    occupied++;
    phase.admissionResolve?.(); phase.admissionResolve = undefined;
  }
}
async function handleBodyPause(record, source, params) {
  if (pageDownloadPauseCandidate(record, source, params)) {
    await handlePageDownloadPause(record, source, params); return;
  }
  const binding = record.bodyCaptureSessions?.get(bodySessionKey(source.sessionId));
  if (!binding || !bodyCaptureOwned(binding)) return;
  if (typeof params.requestId !== 'string' || params.requestId.length > 256) {
    bodyRecovery(record, { binding }, 'invalid_response_pause'); return;
  }
  const errorPhase = typeof params.responseErrorReason === 'string';
  const status = Number.isInteger(params.responseStatusCode) ? params.responseStatusCode : null;
  const phaseKey = binding.generation + ':' + params.requestId + ':' + (errorPhase ? 'error:' + params.responseErrorReason : 'response:' + status);
  if (record.bodyPhaseHistory.has(phaseKey)) return;
  const row = [...record.requests.values()].reverse().find(r => r.requestId === params.networkId
    && bodySessionKey(r.sessionId) === bodySessionKey(source.sessionId) && r.frameId === params.frameId);
  const phase = { binding, phaseKey, fetchId: params.requestId, row, state: 'pending',
    continuation: 'not_attempted', captureClosed: false, cancel: {} };
  record.bodyPhaseHistory.set(phaseKey, phase);
  while (record.bodyPhaseHistory.size > 256) {
    const oldest = [...record.bodyPhaseHistory.keys()].find(key => !record.bodyPauses.has(key));
    if (oldest === undefined) break;
    record.bodyPhaseHistory.delete(oldest);
  }
  // Bound original paused identities separately from the 32 admitted capture
  // receipts. Waiting phases have issued no stream/continuation SDK command.
  if (record.bodyPauses.size >= 256) { bodyRecovery(record, phase, 'response_pause_limit'); return; }
  record.bodyPauses.set(phaseKey, phase);
  admitBodyPauses(record);
  if (!phase.admitted) {
    try {
      await bodyWait(new Promise(resolve => {
        phase.admissionResolve = resolve; admitBodyPauses(record);
      }), 5000, phase.cancel, 'response_admission_timeout');
    } catch (error) {
      phase.admissionResolve = undefined;
      putResponseDiagnostic(record, 'response_capture_diagnostics', 32, 'admission_wait', null, phase, 'none', error);
      if (!phase.cleanup && bodyCaptureOwned(binding)) bodyRecovery(record, phase, error.code || 'response_admission_unverified');
      return;
    }
  }
  const current = () => {
    if (phase.captureClosed || !bodyCaptureCurrent(binding) || row && record.requests.get(row.key) !== row)
      throw fail('body_capture_cancelled');
  };
  try {
    // Save the original phase before arming. A stalled store ends capture; the
    // finally block still releases this original response without reading it.
    if (record.durable && !await persistBodyState(record)) {
      phase.captureClosed = true;
      if (row) row.bodyGap = 'response_history_unsaved';
    }
    if (row && errorPhase) { releaseBody(row); row.bodyGap = 'response_failed'; }
    const canArm = row && !phase.captureClosed && !errorPhase && status !== null && !(status >= 300 && status < 400)
      && binding.enabled && bodyCaptureCurrent(binding);
    if (canArm) {
      row.bodyGap = undefined;
      row.streamPromise = streamBody(record, row, current);
      try { await bodyWait(row.streamPromise, 500, phase.cancel, 'body_arm_timeout'); }
      catch (error) {
        phase.captureClosed = true; releaseBody(row); row.bodyGap = error.code || 'raw_stream_unavailable';
        event(record, 'coverage_gap', { reason: row.bodyGap, request_key: row.key });
      }
    } else if (row && !errorPhase) row.bodyGap = 'response_arm_mapping_unavailable';
  } finally {
    if (!bodyCaptureOwned(binding)) return;
    // Cleanup authority is the original owned attachment, including expiry/Stop fencing.
    // It neither reads a new body nor grants ordinary input to an ended owner.
    const method = errorPhase ? 'Fetch.continueRequest' : 'Fetch.continueResponse';
    phase.continuation = 'attempted';
    publishBodyReceipt(phase);
    const address = { targetId: binding.target, ...(binding.sessionId ? { sessionId: binding.sessionId } : {}) };
    try {
      await bodyWait(chrome.debugger.sendCommand(address, method, { requestId: phase.fetchId }), 500, null, 'body_continue_timeout');
      if (!bodyCaptureOwned(binding)) return;
      phase.continuation = 'acknowledged'; phase.state = 'completed';
      phase.cleanup = 'continued'; publishBodyReceipt(phase);
      record.bodyPauses.delete(phaseKey); admitBodyPauses(record);
    } catch (error) {
      phase.continuation = 'unverified';
      putResponseDiagnostic(record, 'response_capture_diagnostics', 32, 'continuation_wait', null, phase, errorPhase ? 'continue_request' : 'continue_response', error);
      publishBodyReceipt(phase);
      // A late SDK failure cannot undo an independently acknowledged detach or
      // revoke the parent because its original child session has already ended.
      if (phase.cleanup || !bodyCaptureOwned(binding)) {
        if (record.durable) void persistBodyState(record).then(() => state());
        return;
      }
      const parsed = bodyProtocolError(error);
      if (parsed.code === -32602 && String(parsed.message).replace(/\.$/, '') === 'Invalid InterceptionId'
          && row?.failed === true) {
        putResponseDiagnostic(record, 'response_capture_diagnostics', 32, 'continuation_wait', null, phase, errorPhase ? 'continue_request' : 'continue_response', error, true);
        phase.continuation = 'rejected_retired_id'; phase.state = 'terminal';
        phase.cleanup = 'request_failed'; publishBodyReceipt(phase);
        record.bodyPauses.delete(phaseKey); admitBodyPauses(record);
        event(record, 'coverage_gap', { reason: 'response_interception_retired', request_key: row.key });
      } else { phase.continuation = 'unverified'; bodyRecovery(record, phase, 'response_continuation_unverified'); }
    }
    if (record.durable) void persistBodyState(record).then(() => state());
  }
}

async function detach(record, reason, releaseDebugger = true) {
  endNavigation(record);
  if (record.durable) {
    if (['released', 'revoked', 'target_closed'].includes(record.state)) return;
    const transport = ['native_connection_lost', 'workbench_shutdown', 'idle_disconnect', 'connection_timeout', 'connection_setup_failed'].includes(reason);
    const contention = reason === 'replaced_with_devtools';
    if (!transport && !contention && reason !== 'tab_closed') stoppedTargets.add(record.target.target_id);
    return finishClaim(record, transport ? 'suspended_transport' : contention ? 'suspended_contention' : reason === 'tab_closed' ? 'target_closed' : 'revoked', reason, releaseDebugger);
  }
  if (record.legacyCleanupPromise) return record.legacyCleanupPromise;
  if (record.state !== 'active') return;
  const original = { grant: record.grantGeneration, target: record.browserTargetId, peer: record.peerId,
    runtime: record.runtime_generation, installation: record.installation_id, owner: record.operationOwner };
  record.inputEligible = false; record.state = 'detached'; record.reason = reason;
  record.cleanup_state = 'pending';
  for (const row of record.requests.values()) releaseBody(row);
  event(record, 'detached', { reason }); state();
  record.legacyCleanupPromise = (async () => {
    let closed = false, timer;
    const deadline = performance.now() + 3500;
    const current = () => {
      if (closed || performance.now() >= deadline) throw fail('browser_cleanup_timeout');
      if (leases.get(record.id) !== record || record.state !== 'detached' || record.inputEligible !== false
          || record.grantGeneration !== original.grant || record.browserTargetId !== original.target
          || record.peerId !== original.peer || record.runtime_generation !== original.runtime
          || record.installation_id !== original.installation || record.operationOwner !== original.owner)
        throw fail('browser_cleanup_owner_mismatch');
      if ([...leases.values()].some(other => other !== record && other.state === 'active'
          && (other.target?.browser_target_id || other.browserTargetId) === original.target))
        throw fail('browser_cleanup_owner_mismatch');
    };
    try {
      await Promise.race([(async () => {
        current(); const keyState = await releaseHeldKey(record, reason); current();
        try { await bodyWait(persistLegacyKeyboard(record), 350, null, 'browser_keyboard_history_storage_timeout'); }
        catch (error) { record.cleanup_error = error.code || 'browser_keyboard_history_unsaved'; }
        current();
        const actual = (await chrome.debugger.getTargets()).find(t => t.id === original.target); current();
        if (!actual) {
          fenceBodyCapture(record, 'body_target_gone'); settleBodyCapture(record, 'target_gone');
          record.debuggerAttached = false; record.cleanup_state = 'target_gone';
        }
        else if (releaseDebugger && record.debuggerAttached === true) {
          fenceBodyCapture(record, 'body_attachment_detaching');
          await chrome.debugger.detach({ targetId: original.target }); current();
          settleBodyCapture(record, 'detached');
          record.debuggerAttached = false; record.cleanup_state = 'completed';
        } else if (record.debuggerAttached !== true) record.cleanup_state = 'completed';
        else throw fail('browser_cleanup_attachment_unverified');
        if (keyState === 'unverified') record.cleanup_state = 'unverified';
      })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_cleanup_timeout')), 3500); })]);
    } catch (error) {
      record.cleanup_state = 'unverified'; record.cleanup_error = error.code || 'browser_cleanup_failed';
      event(record, 'cleanup_unverified', { reason: record.cleanup_error });
    } finally { closed = true; clearTimeout(timer); state(); }
  })();
  return record.legacyCleanupPromise;
}

async function ensureConnection() {
  if (connection) return connection;
  const attempt = ++connectionAttempt;
  const receipt = connectionPhaseReporter(attempt); connectionReceipt = receipt;
  receipt('attempt_started');
  connectionStage = 'profile_storage';
  connection = new Promise(async (resolve, reject) => {
    let connectingPort;
    rejectConnection = reject;
    try {
      receipt('profile_storage_read');
      const stored = await chrome.storage.local.get('workbenchProfileId');
      profileId = stored.workbenchProfileId || uuid();
      if (!stored.workbenchProfileId) {
        receipt('profile_storage_write');
        await chrome.storage.local.set({ workbenchProfileId: profileId });
      }
      const contextKey = 'workbenchContext:' + contextKind();
      receipt('context_storage_read');
      const contextStored = await chrome.storage.local.get(contextKey);
      contextId = contextStored[contextKey] || uuid();
      if (!contextStored[contextKey]) {
        receipt('context_storage_write');
        await chrome.storage.local.set({ [contextKey]: contextId });
      }
      connectionStage = 'restoring_history';
      receipt('foundations');
      await initializeFoundations(receipt);
      connectionStage = 'extension_manifest';
      receipt('manifest_fetch');
      const manifestResponse = await fetch(chrome.runtime.getURL('manifest.json'));
      receipt('manifest_body');
      const manifestBytes = new Uint8Array(await manifestResponse.arrayBuffer());
      connectionStage = 'native_host';
      receipt('native_port');
      const currentPort = chrome.runtime.connectNative(HOST);
      connectingPort = currentPort;
      port = currentPort;
      const timer = setTimeout(() => closeConnection(currentPort, 'connection_timeout'), 4000);
      const connected = () => {
        if (port !== currentPort) return;
        receipt('connected');
        connectionStage = 'connected'; lastConnectionFailure = undefined;
        clearTimeout(timer); rejectConnection = undefined; resolve();
      };
      currentPort.onMessage.addListener(packet => {
        if (port !== currentPort) return;
        if (packet.type === 'browser_diagnostic_ack') {
          const r=claims.get(packet.claim_id),d=r?.diagnostics;
          if (r?.peerId===peerId && d?.id===packet.record_id && Number.isSafeInteger(packet.sequence)
              &&packet.sequence>0&&packet.sequence<=d.sequence) {
            let released=0;
            for(const [sequence,bytes]of d.unacked)if(sequence<=packet.sequence){d.unacked.delete(sequence);d.unackedBytes-=bytes;released+=bytes;}
            if(packet.capture_active===false)diagnosticEnd(r,'host_capture_ended');
            else if(released)diagnosticWakeCredit(r,true);
          }
        } else if (packet.type === 'ready') {
          receipt('native_ready');
          serverGeneration = packet.server_generation; peerId = packet.peer_id; installationId = packet.install_id;
          controlCacheVersion = packet.control_cache_version === 1 ? 1 : 0;
          acknowledgedTrustId = undefined; acknowledgedTrustPeer = undefined;
          if (trust?.enabled && trust.installation_id !== installationId) trust = { ...trust, enabled: false, reason: 'installation_changed' };
          connectionStage = trust?.enabled ? 'restoring_access' : 'connected';
          if (trust?.enabled) {
            receipt('trust_restore');
            sendNative(currentPort, { type: 'trust_state', interaction_version: INTERACTION_VERSION, trust });
          }
          state();
          // Restoring local trust is a separate, acknowledged handshake. Keep
          // its deadline active; callers must not race the server's trust check.
          if (!trust?.enabled) connected();
        } else if (packet.type === 'trust_ready') {
          receipt('trust_ready');
          if (!serverGeneration || !peerId || packet.interaction_version !== INTERACTION_VERSION
              || !(setupWaiter?.trustId === packet.trust_id || trust?.enabled && trust.trust_id === packet.trust_id)) return;
          acknowledgedTrustId = packet.trust_id; acknowledgedTrustPeer = peerId;
          if (setupWaiter?.trustId === packet.trust_id) { setupWaiter.resolve(packet); setupWaiter = undefined; }
          if (trust?.enabled && trust.trust_id === packet.trust_id) connected();
          if (trust?.enabled) state();
        } else if (packet.type === 'managed_download_observation_result') {
          const waiter = pageObservationWaiters.get(packet.ack_nonce);
          if (waiter?.port === currentPort) {
            pageObservationWaiters.delete(packet.ack_nonce); clearTimeout(waiter.timer);
            if (packet.ok === true) waiter.resolve(); else waiter.reject(fail(packet.error?.code || 'download_observation_unsaved'));
          }
        } else if (packet.type === 'upload_admission_result' || packet.type === 'upload_content_result') {
          const waiter = uploadWaiters.get(packet.nonce);
          if (waiter?.port === currentPort) {
            uploadWaiters.delete(packet.nonce); clearTimeout(waiter.timer);
            if (waiter.content && (packet.request_id !== waiter.requestId || packet.peer_id !== waiter.peer
                || packet.worker_generation !== workerGeneration || packet.type !== waiter.replyType)) {
              waiter.reject(fail('upload_authority_changed')); return;
            }
            if (packet.ok === true) waiter.resolve(packet.type === 'upload_content_result' ? packet.content : packet.authority);
            else waiter.reject(fail(packet.error?.code || 'upload_authority_invalid'));
          }
        } else if (packet.type === 'claim_history_reconciled') {
          if (packet.interaction_version !== INTERACTION_VERSION || packet.peer_id !== peerId
              || packet.server_generation !== serverGeneration || packet.trust_id !== acknowledgedTrustId
              || !Array.isArray(packet.claims) || packet.claims.length > 100) return;
          for (const row of packet.claims) {
            const record = claims.get(row.claim_id);
            if (!record?.restored_history || record.peerId !== null || row.state === 'active'
                || !['suspended_transport','suspended_contention','released','revoked','target_closed'].includes(row.state)
                || ['owner_session','installation_id','runtime_generation','provenance','cleanup_policy','network','control'].some(k => row[k] !== record[k])
                || (row.capture_responses ?? null) !== (record.capture_responses ?? null)
                || ['target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind'].some(k => row.target?.[k] !== record.target[k])) continue;
            if ([record, row].some(value => value.response_capture_receipts !== undefined
                  && (!Array.isArray(value.response_capture_receipts) || value.response_capture_receipts.length > 32
                    || new Set(value.response_capture_receipts.map(receipt => receipt?.phase_id)).size !== value.response_capture_receipts.length)
                || value.response_capture_overflow !== undefined && typeof value.response_capture_overflow !== 'boolean'
                || value.response_history_persistence !== undefined && value.response_history_persistence !== 'unsaved')) continue;
            // Merge before clearing restored_history or writing either snapshot.
            // A broker acknowledgement may contain phases absent from storage,
            // while storage may contain phases the broker never observed.
            const diagnosticHistory = record.response_capture_diagnostics || row.response_capture_diagnostics
              ? mergeResponseDiagnostics(record.response_capture_diagnostics, row.response_capture_diagnostics) : null;
            const receipts = new Map(); let compatible = true;
            for (const receipt of [...(record.response_capture_receipts || []), ...(row.response_capture_receipts || [])]) {
              const keys = ['phase_id','claim_epoch','fetch_id','session_id','continuation','resource_cleanup'];
              if (!receipt || Object.keys(receipt).length !== keys.length || keys.some(k => !(k in receipt))
                  || typeof receipt.phase_id !== 'string' || !/^[a-f0-9]{32}$/.test(receipt.phase_id)
                  || !Number.isSafeInteger(receipt.claim_epoch) || receipt.claim_epoch < 1 || receipt.claim_epoch > row.claim_epoch
                  || typeof receipt.fetch_id !== 'string' || !receipt.fetch_id || new TextEncoder().encode(receipt.fetch_id).length > 256
                  || receipt.session_id !== null && (typeof receipt.session_id !== 'string' || !receipt.session_id || new TextEncoder().encode(receipt.session_id).length > 256)
                  || !['not_attempted','attempted','unverified','acknowledged','rejected_retired_id'].includes(receipt.continuation)
                  || !['pending','unverified','detached','session_gone','target_gone','continued','request_failed'].includes(receipt.resource_cleanup)
                  || receipt.continuation === 'acknowledged' && !['continued','detached','session_gone','target_gone'].includes(receipt.resource_cleanup)
                  || receipt.continuation === 'rejected_retired_id' && receipt.resource_cleanup !== 'request_failed') { compatible = false; break; }
              const old = receipts.get(receipt.phase_id);
              if (!old) { receipts.set(receipt.phase_id, { ...receipt }); continue; }
              if (['claim_epoch','fetch_id','session_id'].some(k => old[k] !== receipt[k])) { compatible = false; break; }
              for (const [field, uncertain] of [['continuation',['not_attempted','attempted','unverified']], ['resource_cleanup',['pending','unverified']]]) {
                const before = old[field], after = receipt[field];
                if (before === after) continue;
                if (!uncertain.includes(before) && !uncertain.includes(after)) { compatible = false; break; }
                if (uncertain.includes(before) && (!uncertain.includes(after) || uncertain.indexOf(after) > uncertain.indexOf(before))) old[field] = after;
              }
            }
            if (!compatible || receipts.size > 32 || [...receipts.values()].some(receipt =>
              receipt.continuation === 'acknowledged' && !['continued','detached','session_gone','target_gone'].includes(receipt.resource_cleanup)
              || receipt.continuation === 'rejected_retired_id' && receipt.resource_cleanup !== 'request_failed')) continue;
            record.response_capture_receipts = [...receipts.values()];
            if (diagnosticHistory) record.response_capture_diagnostics = diagnosticHistory;
            if (row.response_capture_overflow) record.response_capture_overflow = true;
            if (row.response_history_persistence === 'unsaved') record.response_history_persistence = 'unsaved';
            record.state = row.state; record.claim_epoch = row.claim_epoch; record.target = row.target;
            record.cleanup_state = row.cleanup_state; record.debuggerAttached = row.debuggerAttached === true;
            if (record.response_capture_receipts.some(bodyReceiptUnsettled)) record.cleanup_state = 'unverified';
            if (retiredAbsentResource(row)) {
              record.resource_retirement = { ...row.resource_retirement }; record.inputEligible = false;
            }
            record.reason = row.reason; record.restored_history = false;
            if (row.state === 'revoked') stoppedTargets.add(row.target.target_id);
          }
          void persistTargets().then(state).catch(() => {});
        } else if (packet.type === 'shutdown') {
          closeConnection(currentPort, 'workbench_shutdown');
        } else if (packet.type === 'command') {
          void command(packet);
        }
      });
      currentPort.onDisconnect.addListener(() => {
        clearTimeout(timer); const error = chrome.runtime.lastError;
        closeConnection(currentPort, 'native_connection_lost', nativeDisconnectCode(error?.message));
      });
      const hello = { type: 'hello', extension_id: chrome.runtime.id,
        extension_version: chrome.runtime.getManifest().version, manifest_sha256: await (receipt('manifest_hash'), hash(manifestBytes)),
        worker_generation: workerGeneration, profile_id: profileId, private_context: chrome.extension.inIncognitoContext,
        interaction_version: INTERACTION_VERSION, context_id: contextId, capture_responses_version: 1, managed_download_version: 1, page_download_version: 1, private_page_download_version: 1, diagnostics_version: 1, diagnostics_stream_buffer_version: 1, blob_download_version: 1 };
      receipt('native_hello');
      sendNative(currentPort, hello);
    } catch (error) {
      receipt('setup_failed');
      const code = connectionSetupCodes.has(error?.code) ? error.code : 'connection_setup_failed';
      if (connectingPort) closeConnection(connectingPort, 'connection_setup_failed', code);
      else {
        if (attempt === connectionAttempt) {
          lastConnectionFailure = { stage: connectionStage, code, at: Date.now() / 1000 };
          connectionStage = 'disconnected';
        }
        connection = undefined; rejectConnection = undefined;
      }
      reject(fail('workbench_not_connected'));
    }
  });
  return connection;
}

async function initializeFoundations(receipt = () => {}) {
  if (foundations) return foundations;
  foundations = (async () => {
    const keyHistory = 'workbenchLegacyKeyboard:' + contextKind();
    receipt('keyboard_history_read');
    const savedKeys = await (contextKind() === 'ordinary' ? chrome.storage.local : chrome.storage.session).get(keyHistory);
    const keyRows = savedKeys[keyHistory] || [];
    if (!Array.isArray(keyRows) || keyRows.length > 32) throw fail('browser_key_history_limit');
    for (const row of keyRows) {
      if (row?.profile_id !== profileId || row.context_id !== contextId || !row.grant_generation || !row.browser_target_id)
        throw fail('browser_key_history_unavailable');
      legacyKeyboardHistory.set(row.grant_generation, { ...row, state: 'detached', input_eligible: false,
        keyboard_release_state: 'unverified', history_only: true });
    }
    const key = 'workbenchTrust:' + contextKind();
    receipt('trust_storage_read');
    const saved = await chrome.storage.local.get(key);
    trust = saved[key];
    if (trust && (trust.interaction_version !== INTERACTION_VERSION || trust.profile_id !== profileId || trust.context_id !== contextId
        || trust.context_kind !== contextKind())) trust = undefined;
    const targetKey = 'workbenchTargets:' + contextKind();
    receipt('session_history_read');
    const session = await chrome.storage.session?.get(targetKey);
    let rows = session?.[targetKey];
    if (!rows && contextKind() === 'ordinary') {
      receipt('durable_history_read');
      const durable = (await chrome.storage.local.get(targetKey))[targetKey];
      if (durable && trust?.installation_id && durable.installation_id === trust.installation_id && durable.profile_id === profileId
          && durable.context_id === contextId) {
        if (durable.unbound_creations !== undefined && !Array.isArray(durable.unbound_creations)) throw fail('browser_target_history_limit');
        // A failed create with no actual target ID is not safe to rebind after
        // a browser-session reset. Keep its durable receipt, not authority.
        const bound = target => typeof target.browser_target_id === 'string' && target.browser_target_id.length > 0;
        rows = { ...durable, targets: (durable.targets || []).filter(bound),
          unbound_creations: [...(durable.unbound_creations || []), ...(durable.targets || []).filter(target => !bound(target))] };
      }
    }
    if (rows?.interaction_version === INTERACTION_VERSION && rows.context_id === contextId) {
      if (rows.unbound_creations !== undefined && !Array.isArray(rows.unbound_creations)
          || (rows.unbound_creations || []).length > 1000) throw fail('browser_target_history_limit');
      for (const receipt of (rows.unbound_creations || [])) {
        if (typeof receipt?.target_generation === 'string') unboundCreationHistory.set(receipt.target_generation, receipt);
      }
      for (const target of (rows.targets || []).slice(0, 1000)) {
        if (target.creation_window_id !== undefined && (!Number.isSafeInteger(target.creation_window_id)
            || target.creation_window_id < 0 || target.creation_pending !== true || target.provenance !== 'agent'))
          throw fail('browser_target_history_limit');
        targets.set(target.tab_id, target);
      }
      for (const row of (rows.incomplete_claims || [])) if (row.creation_window_id !== undefined
          && (!Number.isSafeInteger(row.creation_window_id) || row.creation_window_id < 0 || row.provenance !== 'agent'
            || row.creation_window_settled !== undefined && typeof row.creation_window_settled !== 'boolean'
            || row.creation_retirement_eligible !== undefined && typeof row.creation_retirement_eligible !== 'boolean'))
        throw fail('browser_target_history_limit');
      for (const id of (rows.stopped || []).slice(0, 1000)) stoppedTargets.add(id);
      const quarantine = row => {
        restoreBodyReceipts(row);
        if (row.response_capture_receipts?.some(bodyReceiptUnsettled)) row.cleanup_state = 'unverified';
        if (typeof row?.claim_id === 'string') incompleteClaimHistory.set(row.claim_id,
          { ...row, historyCleanupBusy: false, historyPublication: undefined,
            cleanup_state: row.cleanup_state === 'pending' ? 'unverified' : row.cleanup_state });
        if (row?.drag_active || ['held', 'unverified'].includes(row?.pointer_release_state)
            || ['prepared','held','unverified'].includes(row?.keyboard_release_state)) {
          if (typeof row?.target?.target_id === 'string') stoppedTargets.add(row.target.target_id);
        }
      };
      // IDs can become complete before setup/admission finishes. This bucket
      // is historical even then; never reconstruct live authority from it.
      for (const row of (rows.incomplete_claims || []).slice(0, 1000)) quarantine(row);
      for (const row of (rows.claims || []).slice(0, 1000)) {
        if (incompleteClaimHistory.has(row?.claim_id)) continue;
        const document = row?.target;
        if (!document || !Number.isSafeInteger(document.document_epoch) || document.document_epoch < 1
            || !document.frame_id || !document.loader_id) {
          quarantine(row);
          continue;
        }
        const restoredState = ['active', 'suspended_transport', 'suspended_contention', 'modal_blocked'].includes(row.state) ? 'suspended_transport' : row.state;
        const record = { ...row, state: restoredState, cleanup_state: row.cleanup_state === 'pending' ? 'unverified' : row.cleanup_state,
          claim_epoch: row.claim_epoch + (row.state === 'active' ? 1 : 0),
          restored_history: true, inputEligible: row.input_eligible,
          peerId: null, durable: true, id: row.claim_id, tabId: row.target.tab_id,
          pendingDialog: row.pending_dialog || null,
          requests: new Map(), observations: new Map(), children: new Map(), contextUniqueIds: new Map(),
          events: [], eventSequence: 0, eventsDropped: 0, expires: Infinity };
        // The serialized view must not outlive settlement of the in-memory
        // identity; incomplete history still uses the public field directly.
        delete record.pending_dialog;
        // Presentation defaults cannot establish terminal detach/input proof.
        // Preserve serialized input evidence and keep incomplete cold receipts
        // unresolved before any normalized claim publication reaches the host.
        if (['released','revoked','target_closed'].includes(record.state)
            && ['completed','target_gone'].includes(record.cleanup_state)
            && (record.debuggerAttached !== false || record.inputEligible !== false))
          record.cleanup_state = 'unverified';
        restoreBodyReceipts(record);
        if (record.response_capture_receipts?.some(bodyReceiptUnsettled)) {
          record.cleanup_state = 'unverified'; record.inputEligible = false;
          stoppedTargets.add(row.target.target_id);
        }
        if (['prepared','held','unverified'].includes(row.keyboard_release_state)) {
          record.keyboard_release_state = 'unverified'; record.cleanup_state = 'unverified'; record.inputEligible = false;
          stoppedTargets.add(row.target.target_id);
        }
        if (record.pendingDialog || ['pending','unverified'].includes(row.dialog_resolution_state)) {
          record.dialog_resolution_state = 'unverified'; record.cleanup_state = 'unverified'; record.inputEligible = false;
          stoppedTargets.add(row.target.target_id);
        }
        claims.set(record.id, record); leases.set(record.id, record);
      }
    }
  })();
  return foundations;
}
function publicClaim(record) {
  if (record.passive_diagnostics === true) { record.diagnosticOnly = true; record.inputEligible = false; }
  return { interaction_version: INTERACTION_VERSION, claim_id: record.id, claim_epoch: record.claim_epoch,
    ...(record.initializing && record.initializationRequestId ? { initialization_request_id: record.initializationRequestId } : {}),
    installation_id: record.installation_id, runtime_generation: record.runtime_generation, owner_session: record.owner_session,
    // Restored history has only the saved target; live document bindings follow navigation.
    state: record.state, target: { ...record.target,
      // Durable privacy receipts can omit origin. Do not manufacture an own
      // property with undefined before the exact terminal-retirement check.
      ...(Object.hasOwn(record,'origin') ? { origin:record.origin }
        : Object.hasOwn(record.target,'origin') ? { origin:record.target.origin } : {}),
      frame_id: record.mainFrameId || record.target.frame_id,
      loader_id: record.loaderId || record.target.loader_id, document_epoch: record.generation || record.target.document_epoch },
    ...(record.diagnosticOnly ? { passive_diagnostics: true } : {}),
    provenance: record.provenance, cleanup_policy: record.cleanup_policy, control: record.control, network: record.network,
    ...(record.capture_responses != null ? { capture_responses: record.capture_responses } : {}),
    reason: record.reason || null, cleanup_state: record.cleanup_state || 'not_attempted',
    cleanup_close_owned: record.cleanup_close_owned === true, cleanup_release_debugger: record.cleanup_release_debugger === true,
    debuggerAttached: record.debuggerAttached === true, input_eligible: publicInputEligible(record),
    keyboard_release_state: record.heldKey?.state || record.keyboard_release_state || 'not_needed',
    keyboard_receipt: record.heldKey ? keyboardReceipt(record.heldKey) : record.keyboard_receipt || {},
    dialog_resolution_state: record.dialog_resolution_state || 'not_needed',
    ...(record.pendingDialog ? { pending_dialog: { ...record.pendingDialog,
      state: record.state === 'active' && record.debuggerAttached ? 'unresolved' : 'unverified' } } : {}),
    ...(record.response_capture_receipts?.length ? { response_capture_receipts: record.response_capture_receipts } : {}),
    ...(record.response_capture_diagnostics ? { response_capture_diagnostics: responseDiagnosticProjection(record.response_capture_diagnostics, 32) } : {}),
    ...(record.response_capture_overflow ? { response_capture_overflow: true } : {}),
    ...(record.response_history_persistence ? { response_history_persistence: record.response_history_persistence } : {}),
    ...(record.dialog_receipt ? { dialog_receipt: record.dialog_receipt } : {}),
    ...(record.resource_retirement ? { resource_retirement: record.resource_retirement } : {}),
    ...(record.restored_history ? { restored_history: true } : {}),
    ...(record.dragActive || record.heldDrag || record.pointer_release_state ? { drag_active: record.dragActive === true,
      pointer_release_state: record.heldDrag?.state || record.pointer_release_state || 'not_needed',
      pointer_release_acknowledged: record.heldDrag ? record.heldDrag.releaseAcknowledged === true : record.pointer_release_acknowledged === true,
      pointer_release_error: record.heldDrag ? record.heldDrag.releaseError || null : record.pointer_release_error || null } : {}) };
}
function claimDocumentReady(record) {
  if (record.initializing) return false;
  const value = publicClaim(record).target;
  return Number.isSafeInteger(value.document_epoch) && value.document_epoch > 0
    && typeof value.frame_id === 'string' && value.frame_id.length > 0 && value.frame_id.length <= 256
    && typeof value.loader_id === 'string' && value.loader_id.length > 0 && value.loader_id.length <= 256;
}
function retiredAbsentResource(row) {
  const proof = row.resource_retirement, target = row.target;
  return proof?.disposition === 'target_absent' && proof.source === 'chrome.tabs.get'
    && row.state === 'target_closed' && row.debuggerAttached === false
    && (row.inputEligible === false || row.input_eligible === false)
    && target && ['tab_id','browser_target_id','target_generation'].every(k => proof[k] === target[k]);
}
function heldClaimResource(row) {
  if (retiredAbsentResource(row)) return false;
  return row.releasing || row.historyCleanupBusy || ['pending', 'unverified'].includes(row.cleanup_state)
    || row.response_capture_receipts?.some(bodyReceiptUnsettled)
    || !!(row.pendingDialog || row.pending_dialog) || ['pending','unverified'].includes(row.dialog_resolution_state)
    || row.drag_active || row.dragActive || ['held','unverified','not_recorded'].includes(row.pointer_release_state)
    || ['held','unverified'].includes(row.heldDrag?.state)
    || ['prepared','held','unverified'].includes(row.heldKey?.state || row.keyboard_release_state)
    || ['active', 'suspended_transport', 'suspended_contention', 'modal_blocked'].includes(row.state);
}
function retainedResources() {
  const resources = new Map();
  for (const row of incompleteClaimHistory.values()) if (heldClaimResource(row)) resources.set(row.claim_id, row);
  for (const row of claims.values()) if (heldClaimResource(row)) resources.set(row.id, row);
  for (const row of legacyKeyboardHistory.values()) if (['prepared','held','unverified','not_recorded'].includes(row.keyboard_release_state))
    resources.set('legacy-key:' + row.grant_generation, row);
  for (const row of leases.values()) if (!row.durable && ['pending','unverified'].includes(row.cleanup_state))
    resources.set('legacy-key:' + row.grantGeneration, row);
  return [...resources.values()];
}
function retainedClaimHistory(rows) {
  if (!Array.isArray(rows) || rows.length > 1000) throw fail('browser_claim_history_limit');
  const resources = rows.filter(heldClaimResource);
  if (resources.length > 32) throw fail('browser_claim_limit');
  const settled = rows.filter(row => !heldClaimResource(row));
  return [...resources, ...settled.slice(-(100 - resources.length))];
}
async function persistTargets() {
  const publish = async () => {
    if (!chrome.storage.session) throw fail('browser_session_storage_unavailable');
    if (stoppedTargets.size > 1000 || targets.size > 1000 || unboundCreationHistory.size > 1000) throw fail('browser_target_history_limit');
    const retained = retainedClaimHistory([...claims.values()]);
    const retainedIds = new Set(retained.map(row => row.id));
    for (const [id] of claims) if (!retainedIds.has(id)) { claims.delete(id); leases.delete(id); }
    for (const row of retained) if (!claimDocumentReady(row)) incompleteClaimHistory.set(row.id, publicClaim(row));
    if (retainedResources().length > 32) throw fail('browser_claim_limit');
    const unsettled = [...incompleteClaimHistory.values()].filter(heldClaimResource);
    if (unsettled.length > 32) throw fail('browser_claim_history_limit');
    const settled = [...incompleteClaimHistory.values()].filter(row => !heldClaimResource(row));
    const keptIncomplete = [...unsettled, ...settled.slice(-(100 - unsettled.length))];
    incompleteClaimHistory.clear();
    for (const row of keptIncomplete) incompleteClaimHistory.set(row.claim_id, row);
    const key = 'workbenchTargets:' + contextKind();
    const snapshot = { interaction_version: INTERACTION_VERSION, installation_id: installationId,
      profile_id: profileId, context_id: contextId, targets: [...targets.values()], stopped: [...stoppedTargets],
      claims: retained.filter(claimDocumentReady).map(publicClaim), incomplete_claims: [...incompleteClaimHistory.values()].map(row => {
        const { historyCleanupBusy, historyPublication, ...saved } = row; return saved;
      }),
      unbound_creations: [...unboundCreationHistory.values()] };
    // Ordinary ownership receipts must survive extension updates/reload. The
    // private context keeps its existing in-memory browser-session lifetime.
    // Store identity/policy only; page content and URLs never enter receipts.
    if (contextKind() === 'ordinary') {
      const durable = { ...snapshot, claims: snapshot.claims.map(row => ({ ...row,
        target: durableTarget(row.target) })), incomplete_claims: snapshot.incomplete_claims.map(row => ({ ...row,
        target: durableTarget(row.target) })) };
      await chrome.storage.local.set({ [key]: durable });
    }
    await chrome.storage.session.set({ [key]: snapshot });
  };
  targetPersistence = targetPersistence.catch(() => {}).then(publish);
  return targetPersistence;
}
function durableTarget(target) {
  const { origin, title, window_id, ...identity } = target;
  return identity;
}
function initializationRecord(row) {
  if (row.historyPublication) return row.historyPublication;
  const identity = row.target;
  const target = Object.fromEntries(['backend','target_id','browser_target_id','tab_id','target_generation','profile_id',
    'context_id','context_kind','connection_generation'].map(key => [key, identity[key]]));
  const pointer = row.drag_active ? 'unverified' : row.pointer_release_state || 'not_needed';
  const cleanup = ['completed','target_gone','not_owned'].includes(row.cleanup_state) ? row.cleanup_state : 'unverified';
  return { interaction_version: INTERACTION_VERSION, record_kind: 'browser_incomplete_initialization', authority: 'cleanup_only',
    ...(row.initialization_request_id ? { initialization_request_id: row.initialization_request_id } : {}),
    claim_id: row.claim_id, claim_epoch: row.claim_epoch, installation_id: row.installation_id,
    runtime_generation: row.runtime_generation, owner_session: row.owner_session, state: 'quarantined', target,
    cleanup_state: cleanup, pointer_release_state: pointer, keyboard_release_state: row.keyboard_release_state || 'not_needed',
    ...(row.response_capture_receipts?.length ? { response_capture_receipts: row.response_capture_receipts } : {}),
    ...(row.response_capture_overflow ? { response_capture_overflow: true } : {}),
    resource_unsettled: cleanup === 'unverified' || ['held','unverified','not_recorded'].includes(pointer)
      || ['prepared','held','unverified'].includes(row.keyboard_release_state)
      || row.response_capture_receipts?.some(bodyReceiptUnsettled) === true,
    debugger_attachment: row.debuggerAttached === true ? 'owned_at_last_record' : row.debuggerAttached === false ? 'not_attached_at_last_record' : 'not_recorded',
    provenance: row.provenance, cleanup_policy: row.cleanup_policy };
}
async function localSetup(options) {
  if (localSetupBusy || setupWaiter) throw fail('browser_setup_pending');
  localSetupBusy = true;
  let reservation;
  try {
  await ensureConnection();
  const currentPort = port, currentPeer = peerId, currentInstall = installationId;
  reservation = reserveLocalSetup(currentPort);
  const current = () => {
    if (!reservation.current() || port !== currentPort || peerId !== currentPeer
        || installationId !== currentInstall || !serverGeneration) throw fail('workbench_not_connected');
  };
  current();
  if (contextKind() === 'private' && !await chrome.extension.isAllowedIncognitoAccess()) throw fail('private_context_not_enabled');
  current();
  if (typeof options?.control !== 'boolean' || typeof options?.network !== 'boolean') throw fail('invalid_setup');
  if (options.file_upload !== undefined && typeof options.file_upload !== 'boolean') throw fail('invalid_setup');
  if (options.file_download !== undefined && typeof options.file_download !== 'boolean') throw fail('invalid_setup');
  if (options.file_download && !await managedPermission()) throw fail('download_permission_required');
  current();
  const incomingWasEnabled = trust?.file_download === true;
  const candidate = { interaction_version: INTERACTION_VERSION, trust_id: uuid(), installation_id: installationId,
    profile_id: profileId, context_id: contextId, context_kind: contextKind(), enabled: true,
    control: options.control, network: options.network, file_upload: options.file_upload === true,
    file_download: options.file_download === true, setup_at: Date.now() / 1000 };
  if (trust?.enabled) fencePageDownloads(null, 'trust_generation_changed');
  const accepted = new Promise((resolve, reject) => {
    setupWaiter = { trustId: candidate.trust_id, resolve, reject, port: currentPort };
    setTimeout(() => { if (setupWaiter?.trustId === candidate.trust_id) { setupWaiter = undefined; reject(fail('setup_not_acknowledged')); } }, 4000);
  });
  current();
  sendNative(currentPort, { type: 'local_setup', interaction_version: INTERACTION_VERSION, trust: candidate });
  await accepted;
  current();
  await chrome.storage.local.set({ ['workbenchTrust:' + contextKind()]: candidate });
  current();
  for (const record of leases.values()) endNavigation(record);
  trust = candidate;
  if (incomingWasEnabled && !candidate.file_download) await managedRevoke();
  await chrome.alarms.create('workbench:reconnect', { periodInMinutes: 1 });
  current();
  state(); return { ...trust };
  } finally { reservation?.finish(); localSetupBusy = false; }
}
function requireTrust(packet) {
  if (!trust?.enabled || trust.interaction_version !== INTERACTION_VERSION || trust.installation_id !== installationId
      || packet.interaction_version !== INTERACTION_VERSION || packet.trust_id !== trust.trust_id
      || packet.context_id !== contextId || packet.profile_id !== profileId || packet.context_kind !== contextKind()
      || packet.runtime_generation !== serverGeneration) throw fail('browser_setup_required');
}
async function inventory(packet) {
  requireTrust(packet);
  const currentPort = port, currentPeer = peerId;
  const tabs = (await chrome.tabs.query({})).filter(tab => !!tab.incognito === (contextKind() === 'private'));
  const debugTargets = await chrome.debugger.getTargets();
  if (port !== currentPort || peerId !== currentPeer) throw fail('workbench_not_connected');
  const rows = [];
  for (const tab of tabs.slice(0, 1000)) {
    const actual = debugTargets.find(t => t.tabId === tab.id && t.type === 'page');
    if (!actual || typeof actual.id !== 'string') continue;
    let site; try { site = webOrigin(tab.url); } catch { continue; }
    const target = rememberTarget(tab, actual, site, currentPeer);
    if (rows.length < 100) rows.push(target);
  }
  const present = new Set(tabs.map(t => t.id));
  for (const [id, row] of targets) if (!present.has(id) && !(row.creation_pending && row.creation_window_id != null)) targets.delete(id);
  await persistTargets();
  return { ok: true, interaction_version: INTERACTION_VERSION, targets: rows, inventory_omitted: Math.max(0, tabs.length - rows.length),
    profile_id: profileId, context_id: contextId, context_kind: contextKind(), runtime_generation: serverGeneration };
}
function rememberTarget(tab, actual, site, currentPeer) {
  let target = targets.get(tab.id);
  if (!target || target.browser_target_id !== actual.id) {
    // A tab number can be reused after browser restart. Pending provenance may
    // bind once, but must never transfer across a known actual target change.
    const pendingCreation = target?.creation_pending && !target.browser_target_id ? target : {};
    target = { backend: 'browser', target_id: 'browser-tab:' + contextId + ':' + actual.id,
      browser_target_id: actual.id, tab_id: tab.id, target_generation: pendingCreation.target_generation || uuid(), profile_id: profileId,
      context_id: contextId, context_kind: contextKind(), provenance: pendingCreation.provenance || 'user',
      cleanup_policy: pendingCreation.cleanup_policy || 'keep', ...(pendingCreation.creation_pending ? { creation_pending: true, ...(pendingCreation.creation_window_id != null ? { creation_window_id: pendingCreation.creation_window_id } : {}) } : {}), ...(pendingCreation.creator_session ? { creator_session: pendingCreation.creator_session } : {}) };
    targets.set(tab.id, target);
  }
  const { creation_pending, creation_window_id, ...publicTarget } = target;
  return { ...publicTarget, connection_generation: currentPeer, origin: site, title: String(tab.title || '').slice(0, 180),
    window_id: tab.windowId, stopped: stoppedTargets.has(target.target_id) };
}
async function exactTarget(tabId) {
  const currentPort = port, currentPeer = peerId;
  const tab = await chrome.tabs.get(tabId);
  if (!tab || !!tab.incognito !== (contextKind() === 'private')) throw fail('stale_browser_target');
  const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === tabId && t.type === 'page');
  if (port !== currentPort || peerId !== currentPeer) throw fail('workbench_not_connected');
  if (!actual || typeof actual.id !== 'string') throw fail('stale_browser_target');
  return rememberTarget(tab, actual, webOrigin(tab.url || tab.pendingUrl), currentPeer);
}
const terminalClaim = record => ['released', 'revoked', 'target_closed'].includes(record.state);
function ownsTarget(record) {
  if (claims.get(record.id) !== record || terminalClaim(record) && !record.releasing) return false;
  const current = targets.get(record.tabId);
  if (!current || current.target_id !== record.target.target_id || current.target_generation !== record.target.target_generation) return false;
  return ![...claims.values()].some(other => other !== record && (!terminalClaim(other) || other.releasing || other.cleanup_state === 'unverified')
    && other.target.target_id === record.target.target_id && other.target.target_generation === record.target.target_generation);
}
async function ownsActualTarget(record, checkpoint = () => {}) {
  checkpoint();
  if (!ownsTarget(record)) return false;
  const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === record.tabId && t.type === 'page');
  checkpoint();
  return actual?.id === record.target.browser_target_id && ownsTarget(record);
}
async function releaseHeldDrag(record, reason) {
  const held = record.heldDrag;
  if (!held?.pressAttempted) return record.pointer_release_state === 'unverified' ? 'unverified' : 'not_needed';
  if (held.releasePromise) return held.releasePromise;
  if (held.releaseAttempted) return held.state;
  held.releasePromise = (async () => {
    let closed = false, timer;
    const deadline = performance.now() + 750;
    const current = () => {
      if (closed || performance.now() >= deadline) throw fail('browser_drag_release_timeout');
      if (leases.get(record.id) !== record || record.heldDrag !== held || record.peerId !== held.peer
          || !ownsTarget(record) || record.owner_session !== held.owner || record.runtime_generation !== held.runtime
          || record.installation_id !== held.installation || record.target.target_generation !== held.targetGeneration
          || record.target.browser_target_id !== held.browserTarget || record.debuggerAttached !== true
          || !(record.claim_epoch === held.epoch && record.state === 'active' || record.releasing && record.claim_epoch === held.epoch + 1))
        throw fail('browser_drag_release_owner_mismatch');
    };
    try {
      await Promise.race([(async () => {
        current();
        // The original attached target is the release recipient. Global target
        // enumeration cannot prove attachment ownership and must not delay up.
        held.releaseAttempted = true; held.state = 'unverified'; held.releaseReason = reason;
        if (held.clickReceipt) held.clickReceipt.up_attempted = true;
        held.releaseDuringModal = record.modal != null;
        await chrome.debugger.sendCommand({ targetId: held.browserTarget }, 'Input.dispatchMouseEvent', {
          type: 'mouseReleased', x: held.point.x, y: held.point.y, button: 'left', buttons: 0, clickCount: held.clickCount ?? 1 });
        held.releaseAcknowledged = true;
        if (held.clickReceipt) held.clickReceipt.up_acknowledged = true;
        current();
        if (held.releaseDuringModal || record.modal != null) throw fail('browser_pointer_release_modal_unverified');
        held.state = 'acknowledged';
      })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_drag_release_timeout')), 750); })]);
    } catch (error) { held.state = 'unverified'; held.releaseError = error.code || 'browser_drag_release_failed'; }
    finally {
      closed = true; clearTimeout(timer);
      // A late original UP must not publish into a replacement hold.
      if (leases.get(record.id) === record && record.heldDrag === held) record.pointer_release_state = held.state;
    }
    return held.state;
  })();
  return held.releasePromise;
}

function keyboardReceipt(held) {
  return { hold_id: held.id, operation_request_id: held.operation,
    down_attempted: held.downAttempted, down_acknowledged: held.downAcknowledged === true,
    up_attempted: held.releaseAttempted, up_acknowledged: held.releaseAcknowledged === true || held.state === 'acknowledged',
    release_state: held.state, release_reason: held.releaseReason || null, release_error: held.releaseError || null,
    browser_target_id: held.browserTarget, frame_id: held.frame.frame_id, loader_id: held.frame.loader_id,
    frame_session_id: held.frame.session_id, execution_context_unique_id: held.contextUniqueId,
    key: held.key.key, code: held.key.code, windows_virtual_key_code: held.key.windowsVirtualKeyCode,
    modifiers: held.key.modifiers || 0,
    binding: { installation_id: held.installation, runtime_generation: held.runtime, peer_id: held.peer,
      owner_session: held.owner, document_generation: held.generation, claim_id: held.claimId || null,
      claim_epoch: held.epoch ?? null, target_generation: held.targetGeneration || null,
      lease_id: held.leaseId, grant_generation: held.grant || null } };
}
function keyboardErrorMetadata(record, packet, admitted, previousHeld) {
  const held = record?.heldKey, operation = packet.operation_request_id || packet.request_id;
  if (!held || !admitted || held.peer !== admitted.peer || held.installation !== admitted.installation
      || held.runtime !== admitted.runtime || held.owner !== admitted.owner || held.browserTarget !== admitted.browserTarget
      || held.targetGeneration !== admitted.targetGeneration || held.grant !== admitted.grant) return {};
  const packetBound = record.durable ? packet.claim_id === admitted.id && packet.owner_session === admitted.owner
    && packet.runtime_generation === admitted.runtime && packet.target_generation === admitted.targetGeneration
    && packet.claim_epoch === admitted.epoch : packet.lease_id === admitted.id
      && (packet.operation_owner ?? null) === admitted.owner;
  if (!packetBound) return {};
  if (held.operation === operation && held.generation === packet.expected_generation
      && (!record.durable || held.epoch === packet.claim_epoch)) return { keyboard_receipt: keyboardReceipt(held) };
  const cleanup = record.durable ? ['stop','release','cleanup'].includes(packet.action) && !packet.upload_cleanup
    : packet.action === 'detach';
  // A control can clean an earlier operation's hold. Keep that origin and
  // exact held binding separate from evidence for this request's dispatch.
  if (cleanup && held === previousHeld && held.downAttempted && admitted.keyboardUnsettled
      && held.generation <= admitted.generation && (!record.durable || held.epoch <= admitted.epoch))
    return { keyboard_cleanup_receipt: { cleanup_request_id: operation, scope: 'historical_held_key_cleanup',
      keyboard_receipt: keyboardReceipt(held) } };
  return {};
}
async function persistLegacyKeyboard(record) {
  const unsettled = ['prepared','held','unverified'].includes(record.heldKey?.state || record.keyboard_release_state);
  if (unsettled) legacyKeyboardHistory.set(record.grantGeneration, { ...publicLease(record), history_only: true });
  else legacyKeyboardHistory.delete(record.grantGeneration);
  if (legacyKeyboardHistory.size > 32) throw fail('browser_key_history_limit');
  const key = 'workbenchLegacyKeyboard:' + contextKind();
  const rows = [...legacyKeyboardHistory.values()];
  await (contextKind() === 'ordinary' ? chrome.storage.local : chrome.storage.session).set({ [key]: rows });
}
function keyCleanupCurrent(record, held) {
  if (leases.get(record.id) !== record || record.heldKey !== held || record.debuggerAttached !== true
      || record.peerId !== held.peer || record.runtime_generation !== held.runtime || record.installation_id !== held.installation
      || record.generation !== held.generation || held.contextInvalidated
      || record.contextUniqueIds?.get((held.frame.session_id || '') + ':' + held.contextId) !== held.contextUniqueId)
    throw fail('browser_key_release_owner_mismatch');
  if (record.durable) {
    if (!ownsTarget(record) || record.owner_session !== held.owner
        || record.target.browser_target_id !== held.browserTarget || record.target.target_generation !== held.targetGeneration
        || !(record.claim_epoch === held.epoch && record.state === 'active'
          || record.releasing && record.claim_epoch === held.epoch + 1)) throw fail('browser_key_release_owner_mismatch');
  } else if (record.grantGeneration !== held.grant || record.browserTargetId !== held.browserTarget
      || (record.operationOwner ?? null) !== held.owner
      || !['active','detached'].includes(record.state)) throw fail('browser_key_release_owner_mismatch');
  if (held.frame.session_id) {
    const child = record.children.get(held.frame.session_id);
    if (!child || child.session_epoch !== held.frame.session_epoch || child.target_id !== held.frame.renderer_root_id)
      throw fail('browser_key_release_session_changed');
  }
}
async function releaseHeldKey(record, reason) {
  const held = record.heldKey;
  if (!held?.downAttempted) return record.keyboard_release_state === 'unverified' ? 'unverified' : 'not_needed';
  if (held.releasePromise) return held.releasePromise;
  if (held.releaseAttempted) return held.state;
  held.releasePromise = (async () => {
    let closed = false, timer;
    const deadline = performance.now() + 750;
    const current = () => {
      if (closed || performance.now() >= deadline) throw fail('browser_key_release_timeout');
      keyCleanupCurrent(record, held);
    };
    try {
      await Promise.race([(async () => {
        current();
        // keyCleanupCurrent validates the retained original binding;
        // sendCommand rejects a gone/detached target without a tab-ID fallback.
        held.releaseAttempted = true; held.state = 'unverified'; held.releaseReason = reason;
        held.releaseDuringModal = record.modal != null;
        // Address the original attached agent host/session, never a tab-ID
        // fallback. Omit text and editing commands from the single matching up.
        await chrome.debugger.sendCommand({ targetId: held.browserTarget,
          ...(held.frame.session_id ? { sessionId: held.frame.session_id } : {}) },
          'Input.dispatchKeyEvent', { type: 'keyUp', ...held.key });
        held.releaseAcknowledged = true;
        current();
        if (held.releaseDuringModal || record.modal != null) throw fail('browser_key_release_modal_unverified');
        held.state = 'acknowledged';
      })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_key_release_timeout')), 750); })]);
    } catch (error) { held.state = 'unverified'; held.releaseError = error.code || 'browser_key_release_failed'; }
    finally { closed = true; clearTimeout(timer); record.keyboard_release_state = held.state; state(); }
    return held.state;
  })();
  return held.releasePromise;
}
async function prepareHeldKey(record, packet, observation, frame, key, checkpoint) {
  checkpoint();
  if (['prepared','held','unverified'].includes(record.heldKey?.state || record.keyboard_release_state)) throw fail('browser_key_release_unverified');
  const contextUniqueId = record.contextUniqueIds?.get((frame.session_id || '') + ':' + observation.contextId);
  if (!contextUniqueId) throw fail('execution_context_identity_unavailable');
  const held = { id: uuid(), operation: packet.operation_request_id || packet.request_id, peer: record.peerId,
    claimId: record.durable ? record.id : null, leaseId: record.id,
    runtime: record.runtime_generation, installation: record.installation_id, generation: record.generation,
    owner: record.owner_session || packet.operation_owner || null, epoch: record.claim_epoch,
    grant: record.grantGeneration, browserTarget: record.durable ? record.target.browser_target_id : record.browserTargetId,
    targetGeneration: record.target?.target_generation, frame: { ...frame }, contextId: observation.contextId, contextUniqueId,
    key, downAttempted: false, downAcknowledged: false, releaseAttempted: false, state: 'prepared' };
  record.heldKey = held; record.keyboard_release_state = 'prepared';
  // Persist conservative intent before a down can be attempted. Restoration
  // quarantines intent; it never reconstructs live cleanup/input authority.
  try {
    if (record.durable) await persistTargets(); else await persistLegacyKeyboard(record);
    checkpoint(); state(); return held;
  } catch (error) {
    // This helper has not attempted down. Clean its conservative preparation
    // without emitting an up or reviving input eligibility after cancellation.
    if (record.heldKey === held && !held.downAttempted) {
      held.state = 'not_needed'; record.keyboard_release_state = 'not_needed';
      try { if (record.durable) await persistTargets(); else await persistLegacyKeyboard(record); } catch {}
      state();
    }
    throw error;
  }
}

// Retire attribution only: an absent original tab cannot retain a live resource,
// but absence proves neither input release nor the original dialog/input effect.
async function retireAbsentClaim(record, packet) {
  if (retiredAbsentResource(record)) return { ok: true, ...publicClaim(record) };
  const originalPort = port, originalPeer = peerId, originalTrust = trust?.trust_id;
  const epoch = record.claim_epoch;
  const current = () => {
    requireTrust(packet);
    if (port !== originalPort || peerId !== originalPeer || trust.trust_id !== originalTrust
        || claims.get(record.id) !== record || record.releasing || record.claim_epoch !== epoch
        || record.owner_session !== packet.owner_session || record.installation_id !== installationId
        || record.target.profile_id !== profileId || record.target.context_id !== contextId
        || record.target.context_kind !== contextKind()
        || record.runtime_generation !== serverGeneration && !validCleanupBinding(packet, record))
      throw fail('browser_cleanup_owner_mismatch');
  };
  current();
  let absent = false;
  try { await bodyWait(chrome.tabs.get(record.tabId), 1500, null, 'browser_target_absence_timeout'); }
  catch (error) {
    // Match only Chrome's exact missing-ID response, never a query omission,
    // permission failure, modal error, or another/reused tab's disappearance.
    absent = error?.message === `No tab with id: ${record.tabId}.`;
  }
  current();
  if (!absent) return null;
  record.inputEligible = false; record.debuggerAttached = false;
  record.state = 'target_closed'; record.reason = 'exact_tab_absent_resource_retirement'; record.claim_epoch++;
  record.resource_retirement = { disposition: 'target_absent', source: 'chrome.tabs.get',
    tab_id: record.tabId, browser_target_id: record.target.browser_target_id,
    target_generation: record.target.target_generation, peer_id: originalPeer,
    runtime_generation: serverGeneration, checked_at: Date.now() / 1000 };
  event(record, 'resource_retired', { reason: record.reason });
  // Keep UNKNOWN diagnostics and original receipts verbatim; no UP, dialog
  // handler, target attach/detach, close, or resource reacquisition is sent.
  await persistTargets(); state();
  return { ok: true, ...publicClaim(record) };
}

async function finishClaim(record, stateValue, reason, releaseDebugger = true, closeOwned = false) {
  diagnosticEnd(record, reason);
  if (!record.heldDrag?.pressAttempted && (record.drag_active
      || ['held','unverified','not_recorded'].includes(record.pointer_release_state))) throw fail('browser_input_release_unverified');
  endNavigation(record);
  fencePageDownloads(record, reason);
  record.inputEligible = false; record.releasing = true;
  record.dialogDetails = undefined;
  if (record.pendingDialog) record.dialog_resolution_state = 'unverified';
  record.cleanup_state = 'pending'; record.cleanup_close_owned = closeOwned; record.cleanup_release_debugger = releaseDebugger;
  for (const row of record.requests.values()) releaseBody(row);
  record.observations.clear(); record.state = stateValue; record.reason = reason; record.claim_epoch++;
  event(record, stateValue, { reason });
  // Persist Stop before exposing completion; in-memory revocation still holds on storage failure.
  let saved = true;
  try { await bodyWait(persistTargets(), 500, null, 'browser_stop_storage_timeout'); } catch { saved = false; }
  state();
  let tabClosed = false, cleanupClosed = false, cleanupTimer;
  const cleanupDeadline = performance.now() + 3500;
  const cleanupCurrent = () => {
    if (cleanupClosed || performance.now() >= cleanupDeadline) throw fail('browser_cleanup_timeout');
    if (claims.get(record.id) !== record || !record.releasing || record.inputEligible !== false) throw fail('browser_cleanup_owner_mismatch');
  };
  try {
    await Promise.race([(async () => {
    cleanupCurrent();
    const dragRelease = await releaseHeldDrag(record, reason);
    cleanupCurrent();
    const keyRelease = await releaseHeldKey(record, reason);
    cleanupCurrent();
    const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === record.tabId && t.type === 'page');
    cleanupCurrent();
    const current = targets.get(record.tabId);
    if (actual?.id !== record.target.browser_target_id || !current || current.target_generation !== record.target.target_generation) {
      fenceBodyCapture(record, 'body_target_gone'); settleBodyCapture(record, 'target_gone');
      record.cleanup_state = 'target_gone'; record.debuggerAttached = false;
      // Lost local metadata/ownership is not proof that the original modal
      // ended. Only the independently queried original target's absence is.
      if (actual?.id !== record.target.browser_target_id) {
        record.pendingDialog = null; record.modal = null;
        if (['pending','unverified'].includes(record.dialog_resolution_state)) record.dialog_resolution_state = 'target_gone';
      }
    } else if (!ownsTarget(record)
        || [...leases.values()].some(other => other !== record && other.tabId === record.tabId && other.state === 'active')
        || [...incompleteClaimHistory.values()].some(row => row.claim_id !== record.id && heldClaimResource(row)
          && row.target?.target_id === record.target.target_id && row.target?.target_generation === record.target.target_generation)) {
      record.cleanup_state = 'not_owned'; record.debuggerAttached = false;
    } else {
      if (releaseDebugger && record.debuggerAttached
          && !(closeOwned && record.provenance === 'agent' && record.cleanup_policy === 'close_on_release')) {
        fenceBodyCapture(record, 'body_attachment_detaching');
        await chrome.debugger.detach({ targetId: record.target.browser_target_id }); cleanupCurrent();
        settleBodyCapture(record, 'detached'); record.debuggerAttached = false;
      }
      if (closeOwned && record.provenance === 'agent' && record.cleanup_policy === 'close_on_release') {
        if (!await ownsActualTarget(record, cleanupCurrent)) record.cleanup_state = 'not_owned';
        else {
          // Close through the original attached agent host before detaching.
          // Closing after detach has no owned debugger address and is refused.
          if (!record.debuggerAttached) throw fail('browser_owned_close_attachment_unavailable');
          fenceBodyCapture(record, 'body_target_closing');
          const closed = await chrome.debugger.sendCommand({ targetId: record.target.browser_target_id },
            'Target.closeTarget', { targetId: record.target.browser_target_id }); cleanupCurrent();
          if (closed?.success !== true) throw fail('browser_owned_close_unverified');
          const settleDeadline = Math.min(cleanupDeadline, performance.now() + 1000);
          while (true) {
            if (performance.now() >= settleDeadline) throw fail('browser_owned_close_unverified');
            const remaining = (await chrome.debugger.getTargets()).some(t => t.id === record.target.browser_target_id);
            if (performance.now() >= settleDeadline) throw fail('browser_owned_close_unverified');
            cleanupCurrent(); if (!remaining) { tabClosed = true; record.debuggerAttached = false; settleBodyCapture(record, 'target_gone'); break; }
            await new Promise(resolve => setTimeout(resolve, 25)); cleanupCurrent();
          }
        }
      }
      if (record.cleanup_state === 'pending') record.cleanup_state = 'completed';
    }
    if (dragRelease === 'unverified' || keyRelease === 'unverified') record.cleanup_state = 'unverified';
    if (tabClosed) {
      record.pendingDialog = null; record.modal = null;
      if (['pending','unverified'].includes(record.dialog_resolution_state)) record.dialog_resolution_state = 'target_gone';
    }
    if (record.pendingDialog) record.cleanup_state = 'unverified';
    })(), new Promise((_, reject) => { cleanupTimer = setTimeout(() => reject(fail('browser_cleanup_timeout')), 3500); })]);
    return { ok: true, ...publicClaim(record), stop_persistence: saved ? 'saved' : 'unsaved', tab_closed: tabClosed };
  } catch (error) {
    record.cleanup_state = 'unverified';
    event(record, 'cleanup_unverified', { reason: error.code || 'browser_cleanup_failed' });
    throw fail('browser_cleanup_unverified', 'unknown');
  } finally {
    cleanupClosed = true; clearTimeout(cleanupTimer);
    record.releasing = false;
    try { await bodyWait(persistTargets(), 500, null, 'browser_cleanup_storage_timeout'); }
    catch { /* In-memory diagnostics remain visible; physical cleanup already ran. */ }
    state();
  }
}
function requireCreationAdmission(tabId, windowId, permit) {
  if (permit && (permit.cancelled || creationAdmissions.get(tabId) !== permit)) throw fail('browser_cleanup_pending');
  for (const row of incompleteClaimHistory.values()) if (row.creation_window_id != null && row.historyCleanupBusy
      && (row.target?.tab_id === tabId || row.creation_window_id === windowId))
    throw fail('browser_cleanup_pending');
  const pending = creationAdmissions.get(tabId);
  if (pending && pending !== permit
      || targets.get(tabId)?.creation_pending && (!pending || pending !== permit))
    throw fail('browser_target_creation_pending');
  for (const row of targets.values()) if (row.creation_pending && row.creation_window_id != null
      && row.creation_window_id === windowId
      && (!permit || creationAdmissions.get(row.tab_id) !== permit))
    throw fail('browser_window_creation_pending');
  for (const row of incompleteClaimHistory.values()) if (row.creation_window_id != null
      && row.creation_window_settled !== true && row.creation_window_id === windowId
      && (!permit || creationAdmissions.get(row.target?.tab_id) !== permit))
    throw fail('browser_window_creation_pending');
}
async function invalidateCreationRetirement(tabId, browserTargetId, checkpoint) {
  checkpoint();
  const writes = [];
  for (const row of incompleteClaimHistory.values()) {
    if (row.creation_window_id == null || row.target?.tab_id !== tabId || row.target.browser_target_id !== browserTargetId) continue;
    let publication = retirementInvalidations.get(row);
    if (row.creation_retirement_eligible !== true && !publication) continue;
    if (!publication || !publication.pending && !publication.durable) {
      publication = { pending: true, durable: false };
      retirementInvalidations.set(row, publication);
      row.creation_retirement_eligible = false;
      const original = publication;
      publication.promise = persistTargets().then(() => { original.durable = true; })
        .finally(() => { original.pending = false; });
    }
    // A concurrent admission may see false before its write completes. It
    // must await this exact publication, or retry a failed metadata save.
    writes.push(publication.promise);
  }
  await Promise.all(writes); checkpoint();
}
async function acquire(packet, creationPermit) {
  requireTrust(packet);
  validateCaptureResponses(packet);
  if ([...claims.values()].some(row => row.restored_history)) throw fail('browser_claim_reconciliation_pending');
  if (acquisitionBusy) throw fail('browser_acquisition_pending');
  const acquirePort = port, acquirePeer = peerId, acquireInstallation = installationId,
    acquireControl = packet.parameters?.diagnostic_scope ? false : trust.control, acquireNetwork = packet.parameters?.capture_responses == null ? trust.network : trust.network && packet.parameters.capture_responses;
  const diagnosticScope = packet.parameters?.diagnostic_scope;
  if (diagnosticScope && (!trust.network || contextKind() !== 'ordinary' || !diagnosticChat(diagnosticScope.chat_url)
      || diagnosticScope.observed_document_url != null && (!diagnosticProjectChat(diagnosticScope.observed_document_url)
        || diagnosticChat(diagnosticScope.observed_document_url) !== diagnosticScope.chat_url)
      || diagnosticScope.body_bytes != null && (!Number.isSafeInteger(diagnosticScope.body_bytes) || diagnosticScope.body_bytes<4096)
      || diagnosticScope.stream_buffer_bytes !== undefined && !diagnosticStreamBudgetValid(diagnosticScope.stream_buffer_bytes))) throw fail('diagnostic_scope');
  acquisitionBusy = true;
  let admissionTarget = packet.target;
  const admission = () => {
    requireTrust(packet);
    if (port !== acquirePort || peerId !== acquirePeer) throw fail('workbench_not_connected');
    requireCreationAdmission(packet.target?.tab_id, admissionTarget?.window_id, creationPermit);
  };
  try {
    if (typeof packet.owner_session !== 'string' || !packet.owner_session || encoder.encode(packet.owner_session).length > 128) throw fail('work_session_required');
    if (!Number.isInteger(packet.target?.tab_id)) throw fail('stale_browser_target');
    const target = await exactTarget(packet.target.tab_id);
    admissionTarget = target; admission();
    if (!target || ['profile_id', 'context_id', 'context_kind', 'tab_id', 'browser_target_id', 'target_generation', 'connection_generation'].some(k => target[k] !== packet.target[k])) throw fail('stale_browser_target');
    if (target.stopped) throw fail('browser_target_stopped');
    if ([...legacyKeyboardHistory.values()].some(row => row.browser_target_id === target.browser_target_id))
      throw fail('browser_key_release_unverified');
    if (target.provenance === 'agent' && target.cleanup_policy === 'close_on_release' && target.creator_session !== packet.owner_session) throw fail('browser_target_owned');
    for (const row of incompleteClaimHistory.values()) if (!claims.has(row.claim_id) && heldClaimResource(row)
        && row.target?.target_id === target.target_id && row.target?.target_generation === target.target_generation) {
      throw fail(row.owner_session === packet.owner_session ? 'browser_cleanup_pending' : 'browser_target_owned');
    }
    for (const record of leases.values()) if (record.tabId === target.tab_id && (!record.durable || record.target.target_id === target.target_id && record.target.target_generation === target.target_generation)
        && (record.releasing || record.cleanup_state === 'unverified' || ['pending','unverified'].includes(record.dialog_resolution_state)
          || record.state === 'active' || record.durable && ['suspended_transport', 'suspended_contention', 'modal_blocked'].includes(record.state))) {
      if (record.releasing) throw fail('browser_target_owned');
      if (record.cleanup_state === 'unverified') throw fail(record.owner_session === packet.owner_session ? 'browser_cleanup_pending' : 'browser_target_owned');
      if (['pending','unverified'].includes(record.dialog_resolution_state)) throw fail('browser_dialog_effect_unverified');
      if (!record.durable || record.owner_session !== packet.owner_session) throw fail('browser_target_owned');
      if (record.state === 'active' && record.peerId === peerId) {
        if (record.network !== acquireNetwork) throw fail('browser_capture_policy_conflict');
        return { ok: true, ...publicClaim(record) };
      }
      await finishClaim(record, 'released', 'transport_reconciliation');
    }
    if (retainedResources().length >= 32) throw fail('browser_claim_limit');
    admission();
    await chrome.debugger.attach({ tabId: target.tab_id }, '1.3');
    // A successful attachment needs an owned cleanup record even if authority
    // changed during the await and the subsequent detach cannot be confirmed.
    const record = { id: uuid(), durable: true, target, tabId: target.tab_id, windowId: target.window_id, origin: target.origin,
      diagnosticOnly: !!diagnosticScope, diagnosticScope, inputEligible: diagnosticScope ? false : undefined,
      generation: 1, expires: Infinity, control: acquireControl, network: acquireNetwork,
      ...(packet.parameters?.capture_responses != null ? { capture_responses: packet.parameters.capture_responses } : {}), peerId: acquirePeer, state: 'active',
      debuggerAttached: true,
      claim_epoch: 1, owner_session: packet.owner_session, installation_id: acquireInstallation, runtime_generation: packet.runtime_generation,
      provenance: target.provenance, cleanup_policy: target.cleanup_policy, events: [], eventSequence: 0, eventsDropped: 0,
      observations: new Map(), children: new Map(), contextUniqueIds: new Map(), requests: new Map(), initializing: true,
      initializationNavigation: 0,
      initializationRequestId: typeof packet.operation_request_id === 'string'
        && encoder.encode(packet.operation_request_id).length > 0 && encoder.encode(packet.operation_request_id).length <= 256
        ? packet.operation_request_id : null };
    claims.set(record.id, record); leases.set(record.id, record);
    const readiness = acquisitionReadiness();
    const setupCdp = (record, method, ...args) => readiness.run(ACQUISITION_COMMAND_STAGES[method], method,
      () => cdp(record, method, ...args));
    try {
      admission();
      // Bound attached-document setup independently from input budgets. A
      // late metadata/setup reply must not admit a claim after timeout.
      let waiting = true, timer;
      const deadline = performance.now() + 5000;
      const current = () => {
        if (!waiting) throw fail('browser_document_readiness_timeout');
        if (performance.now() >= deadline) { readiness.freeze(); throw fail('browser_document_readiness_timeout'); }
        admission();
        if (port !== acquirePort || peerId !== acquirePeer || record.state !== 'active' || !ownsTarget(record)) throw fail('workbench_not_connected');
      };
      try {
        await Promise.race([(async () => {
          const readDocument = async () => {
            current(); const navigation = record.initializationNavigation;
            const frame = (await setupCdp(record, 'Page.getFrameTree')).frameTree?.frame;
            current(); return { navigation, frame };
          };
          // Await logical focus before queuing domain setup for an inactive renderer.
          if (!record.diagnosticOnly) await initializeRootInput(record, current, setupCdp); current();
          const initialDocument = await (async () => {
            current(); await Promise.all([
              setupCdp(record, 'Page.enable').then(() => current()),
              setupCdp(record, 'Runtime.enable').then(() => current())
            ]); current();
            const [, document] = await Promise.all([(async () => {
            if (record.network) {
              await setupCdp(record, 'Network.enable', record.diagnosticOnly ? {maxTotalBufferSize:Math.min(2147483647,2*(diagnosticScope.body_bytes || 8388608)),
                maxResourceBufferSize:Math.min(2147483647,diagnosticScope.body_bytes || 8388608),maxPostDataSize:Math.min(2147483647,diagnosticScope.body_bytes || 8388608)}
                : {maxTotalBufferSize:8388608,maxResourceBufferSize:2097152,maxPostDataSize:0}); current();
              if (!record.diagnosticOnly) await enableBodyCapture(record, undefined, current, setupCdp); current();
            }
            try { if (!record.diagnosticOnly) await setupCdp(record, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true,
              filter: [{ type: 'iframe', exclude: false }, { type: 'worker', exclude: false }, { exclude: true }] }); }
            catch { current(); event(record, 'coverage_gap', { reason: 'related_target_attachment_unavailable' }); }
            current();
            })(), readDocument()]);
            return document;
          })();
          current();
          let document = initialDocument;
          while (true) {
            current();
            const { navigation, frame } = document;
            let site = null;
            try { site = webOrigin(frame?.securityOrigin || frame?.url); } catch {}
            if (site && frame?.id && frame?.loaderId) {
              if (site !== record.origin) throw fail('stale_browser_document');
              if (!await readiness.run('target_identity', null, () => ownsActualTarget(record, current))) throw fail('stale_browser_target');
              current();
              // A navigation delivered during either metadata await requires
              // another fresh read. Publication below is synchronous.
              if (navigation === record.initializationNavigation) {
                await readiness.run('creation_persistence', null, () => invalidateCreationRetirement(target.tab_id, target.browser_target_id, current)); current();
                if (navigation !== record.initializationNavigation) { document = await readDocument(); continue; }
                if (record.diagnosticOnly && diagnosticChat(frame.url) !== diagnosticScope.chat_url) throw fail('diagnostic_document_mismatch');
                if (record.diagnosticOnly && (diagnosticScope.observed_document_url != null || diagnosticProjectChat(frame.url))
                    && frame.url !== diagnosticScope.observed_document_url) throw fail('diagnostic_document_mismatch');
                record.loaderId = frame.loaderId; record.mainFrameId = frame.id;
                if (creationPermit) creationPermit.admitted = true;
                record.initializing = false; incompleteClaimHistory.delete(record.id);
                return;
              }
            }
            await readiness.run('document_poll', null, () => new Promise(resolve => setTimeout(resolve, 50)));
            document = await readDocument();
          }
        })(), new Promise((_, reject) => { timer = setTimeout(() => {
          readiness.freeze(); reject(fail('browser_document_readiness_timeout'));
        }, 5000); })]);
      } finally { waiting = false; clearTimeout(timer); }
      await persistTargets();
      admission();
      if (port !== acquirePort || peerId !== acquirePeer || record.state !== 'active' || !ownsTarget(record)) throw fail('workbench_not_connected');
      state(); return { ok: true, ...publicClaim(record) };
    } catch (error) {
      let failure = error;
      try { await finishClaim(record, 'released', 'setup_failed'); }
      catch (cleanupError) { failure = cleanupError; }
      if (record.initializing) {
        // A failed initialization never became a document/input claim. Move
        // its exact retained resource into the existing cleanup-only lane so
        // the caller can obtain a fresh detach/absence witness before retrying.
        const history = publicClaim(record);
        incompleteClaimHistory.set(record.id, history);
        claims.delete(record.id); leases.delete(record.id);
        try { await persistTargets(); }
        catch {
          claims.set(record.id, record); leases.set(record.id, record);
          throw fail('browser_initialization_history_persistence_failed', 'unknown');
        }
        state();
        if (packet.action === 'acquire' && typeof packet.request_id === 'string'
            && /^[0-9a-f]{32}$/.test(packet.request_id) && record.initializationRequestId) {
          failure.acquisition_failure = { transport_request_id: packet.request_id,
            request_id: packet.operation_request_id, initialization_record: initializationRecord(history),
            input_authority: 'never_published', page_effects: 'not_established',
            ...(readiness.snapshot ? { readiness_diagnostics: readiness.snapshot } : {}) };
        }
      }
      throw failure;
    }
  } finally { acquisitionBusy = false; }
}
function boundedDialogText(value, maxBytes = 8192) {
  const input = typeof value === 'string' ? value : '';
  let low = 0, high = Math.min(input.length, maxBytes);
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (encoder.encode(input.slice(0, middle)).length <= maxBytes) low = middle;
    else high = middle - 1;
  }
  if (low && low < input.length && /[\uD800-\uDBFF]/.test(input[low - 1]) && /[\uDC00-\uDFFF]/.test(input[low])) low--;
  return { text: input.slice(0, low), truncated: low < input.length };
}
function dialogCurrent(record, packet) {
  const expected = packet.control_binding;
  const actual = publicClaim(record), target = actual.target;
  if (!expected || record.state !== 'active' || record.releasing || claims.get(record.id) !== record
      || record.peerId !== peerId || record.runtime_generation !== serverGeneration
      || record.installation_id !== installationId || record.owner_session !== packet.owner_session
      || record.claim_epoch !== packet.claim_epoch || record.target.target_generation !== packet.target_generation
      || !record.debuggerAttached || leases.get(record.id) !== record
      || ['claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id'].some(k =>
        expected[k] !== (k === 'peer_id' ? record.peerId : actual[k]))
      || ['target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind','connection_generation']
        .some(k => expected[k] !== target[k])) throw fail('browser_claim_owner_mismatch');
}
async function dialogControl(record, packet) {
  const p = packet.parameters || {};
  dialogCurrent(record, packet);
  if (!Number.isSafeInteger(p.dialog_sequence) || p.dialog_sequence < 1) throw fail('invalid_dialog_sequence');
  const modal = record.modal;
  if (!modal || modal.sequence !== p.dialog_sequence) throw fail('stale_browser_dialog');
  if (packet.action === 'dialog_read') {
    if (!record.dialogDetails || record.dialogDetails.sequence !== modal.sequence) throw fail('browser_dialog_details_unavailable');
    return { ok: true, ...publicClaim(record), dialog: { ...modal, ...record.dialogDetails },
      checked_at: Date.now() / 1000, source: 'selected_dialog_opening_event',
      renderer_checked: false, task_completion: 'not_established' };
  }
  if (!record.control || !trust?.control || typeof p.dialog_accept !== 'boolean') throw fail('browser_control_not_granted');
  if (p.dialog_prompt_text != null && (typeof p.dialog_prompt_text !== 'string'
      || encoder.encode(p.dialog_prompt_text).length > 8192 || modal.type !== 'prompt' || !p.dialog_accept))
    throw fail('invalid_dialog_prompt');
  if (record.dialogOperation) throw fail('browser_dialog_operation_pending');
  if (record.dialog_resolution_state === 'unverified') throw fail('browser_dialog_effect_unverified');
  const operation = { sequence: modal.sequence, requestedAccept: p.dialog_accept,
    promptText: p.dialog_prompt_text, close: null, acknowledged: false, attempted: false };
  record.dialogOperation = operation;
  record.dialog_resolution_state = 'pending';
  let timer, ended = false;
  const deadline = performance.now() + 1500;
  const receipt = () => ({ dialog_sequence: modal.sequence, dialog_type: modal.type,
    browser_target_id: record.target.browser_target_id, frame_id: modal.frame_id || null,
    frame_session_id: modal.frame_session_id || null, operation_request_id: packet.operation_request_id,
    dispatch_attempted: operation.attempted, dispatch_acknowledged: operation.acknowledged,
    close_observed: operation.close != null, requested_accept: operation.requestedAccept,
    close_identity_verified: operation.close?.identityVerified === true,
    accepted: operation.close?.accepted ?? null, prompt_input_matches: operation.close?.promptMatch ?? null,
    dialog_transition_observed: record.modalSequence !== modal.sequence });
  const current = () => {
    if (ended || performance.now() >= deadline) throw fail('browser_dialog_timeout');
    dialogCurrent(record, packet);
    if (record.dialogOperation !== operation || record.modalSequence !== modal.sequence
        || record.modal !== modal && !operation.close) throw fail('stale_browser_dialog');
  };
  record.dialog_receipt = receipt();
  try {
    await Promise.race([(async () => {
      await persistTargets(); current(); state(); operation.attempted = true;
      await chrome.debugger.sendCommand({ targetId: record.target.browser_target_id,
        ...(modal.frame_session_id ? { sessionId: modal.frame_session_id } : {}) },
        'Page.handleJavaScriptDialog', { accept: p.dialog_accept,
          ...(p.dialog_prompt_text != null ? { promptText: p.dialog_prompt_text } : {}) });
      operation.acknowledged = true; current();
      if (!operation.close) await new Promise(resolve => { operation.closed = resolve; });
      current();
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_dialog_timeout')), 1500); })]);
    const matched = operation.close.identityVerified === true && operation.close.accepted === p.dialog_accept
      && (modal.type !== 'prompt' || !p.dialog_accept || p.dialog_prompt_text == null || operation.close.promptMatch === true);
    record.dialog_resolution_state = matched ? 'acknowledged' : 'unverified';
    record.dialog_receipt = receipt();
    if (!matched) record.inputEligible = false;
    return { ok: true, ...publicClaim(record), dialog_receipt: receipt(), effect_state: matched ? 'applied' : 'unknown',
      task_completion: 'not_established', identity_scope: 'Original target plus sampled dialog sequence; CDP has no atomic dialog token.' };
  } catch (error) {
    // A late handler result cannot undo independently verified original-target
    // disappearance. The original effect receipt remains unknown; its closed
    // resource must not be reconstructed from the stale operation lifetime.
    const targetGone = record.dialog_resolution_state === 'target_gone';
    if (!targetGone) record.dialog_resolution_state = operation.attempted ? 'unverified' : record.pendingDialog ? 'pending' : 'not_needed';
    record.dialog_receipt = receipt();
    if (operation.attempted) {
      record.inputEligible = false;
      if (!targetGone) record.cleanup_state = 'unverified';
    }
    throw Object.assign(fail(error.code || 'browser_dialog_failed', operation.attempted ? 'unknown' : 'none'),
      { dialog_receipt: receipt() });
  } finally {
    ended = true; clearTimeout(timer); operation.promptText = undefined;
    if (record.dialogOperation === operation) record.dialogOperation = undefined;
    try { await persistTargets(); } catch { /* Keep current quarantine and the host's original Journal receipt. */ }
    state();
  }
}
async function executeDurable(packet) {
  validateClickCount(packet);
  requireTrust(packet);
  validateCaptureResponses(packet);
  if (packet.action === 'discover') return inventory(packet);
  if (packet.action === 'acquire') return acquire(packet);
  if (packet.action === 'create') {
    if ([...claims.values()].some(row => row.restored_history)) throw fail('browser_claim_reconciliation_pending');
    if (!trust.control || !['keep', 'close_on_release'].includes(packet.cleanup_policy)) throw fail('browser_control_not_granted');
    webOrigin(packet.url);
    if (typeof packet.owner_session !== 'string' || !packet.owner_session || packet.owner_session.length > 128) throw fail('work_session_required');
    const creationPort = port, creationPeer = peerId, privateContext = contextKind() === 'private';
    const existingTabs = await chrome.tabs.query({});
    if (!existingTabs.some(t => !!t.incognito === privateContext)) throw fail('browser_context_window_unavailable');
    requireTrust(packet);
    if (!trust.control || port !== creationPort || peerId !== creationPeer) throw fail('workbench_not_connected');
    if (targets.size >= 1000 || unboundCreationHistory.size >= 1000) throw fail('browser_target_history_limit');
    const creationGeneration = uuid();
    const unknownCreation = async (code, reported) => {
      unboundCreationHistory.set(creationGeneration, { target_generation: creationGeneration,
        profile_id: profileId, context_id: contextId, context_kind: contextKind(),
        provenance: 'agent', cleanup_policy: packet.cleanup_policy, creator_session: packet.owner_session,
        creation_pending: true, creation_outcome: 'unknown', runtime_generation: packet.runtime_generation,
        peer_id: creationPeer, operation_request_id: packet.operation_request_id || packet.request_id,
        reported_window_id: Number.isSafeInteger(reported?.id) ? reported.id : null,
        reported_tab_ids: Array.isArray(reported?.tabs) ? reported.tabs.slice(0, 32)
          .map(t => t?.id).filter(id => Number.isSafeInteger(id) && id >= 0) : [] });
      try { await persistTargets(); } catch { /* Keep the raw receipt in memory and the host's unknown journal. */ }
      throw fail(code, 'unknown');
    };
    // Keep new task tabs active in their own inactive window. This does not
    // move existing user tabs or establish support for hidden-tab operation.
    let createdWindow, correctedWindow = false, correctionAckState;
    try { createdWindow = await chrome.windows.create({ url: packet.url, focused: false,
      incognito: privateContext, type: 'normal', state: 'normal' }); }
    catch (error) { return unknownCreation(error.code || 'created_browser_window_unverified'); }
    const createdTabs = createdWindow?.tabs;
    if (!Number.isSafeInteger(createdWindow?.id) || createdWindow.id < 0 || !Array.isArray(createdTabs) || createdTabs.length !== 1
        || !Number.isSafeInteger(createdTabs[0]?.id) || createdTabs[0].id < 0 || createdTabs[0].windowId !== createdWindow.id
        || !!createdTabs[0].incognito !== privateContext
        || existingTabs.some(t => t.id === createdTabs[0].id || t.windowId === createdWindow.id))
      return unknownCreation('created_browser_window_unverified', createdWindow);
    const tab = createdTabs[0];
    // Reserve before exposing persisted/discoverable provenance. Only this
    // create stack owns the object-identity permit; public owner data cannot
    // bypass it. Saved creation_pending also quarantines a restarted worker.
    const creationAdmission = { updatePending: false, ended: false, windowId: createdWindow.id, generation: creationGeneration };
    let correctionHistory;
    creationAdmissions.set(tab.id, creationAdmission);
    const releaseAdmission = () => {
      if (!creationAdmission.ended || creationAdmission.updatePending || creationAdmission.normalPending) return;
      if (correctionHistory) correctionHistory.creation_window_settled = true;
      if (creationAdmissions.get(tab.id) === creationAdmission) creationAdmissions.delete(tab.id);
      const retained = targets.get(tab.id);
      if (retained?.target_generation === creationGeneration) { delete retained.creation_pending; delete retained.creation_window_id; }
      void persistTargets().catch(() => { /* Saved pending remains conservative on storage failure. */ });
    };
    targets.set(tab.id, { tab_id: tab.id, target_generation: creationGeneration, profile_id: profileId, context_id: contextId, context_kind: contextKind(),
      provenance: 'agent', cleanup_policy: packet.cleanup_policy, creator_session: packet.owner_session, creation_pending: true, creation_window_id: createdWindow.id });
    try {
      await persistTargets();
      const found = await exactTarget(tab.id);
      await persistTargets();
      // Retain exact provenance before refusing changed focus or authority.
      // Never close a whole window: someone may have added their own tabs.
      const booleanResult = value => typeof value === 'boolean' ? String(value)
        : value === undefined ? 'missing' : 'invalid';
      if (createdWindow.focused !== false)
        throw fail('created_browser_window_focus_' + booleanResult(createdWindow.focused));
      if (createdWindow.type !== 'normal')
        throw fail('created_browser_window_type_' + (['popup', 'panel', 'app', 'devtools'].includes(createdWindow.type)
          ? createdWindow.type : createdWindow.type === undefined ? 'missing' : 'invalid'));
      if (createdWindow.state === 'fullscreen' && typeof chrome.windows.get === 'function'
          && typeof chrome.windows.update === 'function') {
        // Chrome can return fullscreen despite the explicit normal request.
        // Correct only this fresh, sole, inactive owned window, once. Sampled
        // Chrome metadata cannot provide an atomic compare-and-update fence.
        let waiting = true;
        const deadline = performance.now() + 1500, owner = packet.owner_session;
        const current = () => {
          if (!waiting || performance.now() >= deadline) throw fail('created_browser_window_correction_timeout');
          requireTrust(packet);
          const retained = targets.get(tab.id);
          if (!creationPort || port !== creationPort || peerId !== creationPeer || !trust.control)
            throw fail('workbench_not_connected');
          if (creationAdmission.cancelled || creationAdmissions.get(tab.id) !== creationAdmission
              || packet.owner_session !== owner || !retained || retained.provenance !== 'agent'
              || retained.creator_session !== owner || retained.cleanup_policy !== packet.cleanup_policy
              || ['target_id', 'browser_target_id', 'target_generation', 'profile_id', 'context_id', 'context_kind']
                .some(key => retained[key] !== found[key])
              || retained.target_generation !== creationGeneration
              || [...leases.values()].some(row => row.tabId === tab.id))
            throw fail('created_browser_window_owner_changed');
        };
        // Keep diagnostic codes within the existing [a-z_]{1,80} wire
        // contract. Tags describe only the first rejecting sampled predicate.
        const rejected = (phase, reason) => fail('created_browser_window_correction_unverified_' + phase + '_' + reason);
        const enumResult = (value, allowed) => allowed.includes(value) ? value : value === undefined ? 'missing' : 'invalid';
        const verify = async (state, phase, settling = false) => {
          current();
          const window = await chrome.windows.get(createdWindow.id, { populate: true });
          current();
          if (settling && window?.id === createdWindow.id && window.state === 'maximized') {
            creationAdmission.normalPending = true;
            correctionHistory.creation_window_settled = false;
          }
          const windowFailure = !window ? 'win_missing'
            : window.id !== createdWindow.id ? 'win_id'
            : window.focused !== false ? 'win_focus_' + booleanResult(window.focused)
            : window.type !== 'normal' ? 'win_type_' + enumResult(window.type, ['normal','popup','panel','app','devtools'])
            : window.state !== state && !(settling && window.state === 'maximized') ? 'win_state_' + enumResult(window.state, ['normal','minimized','maximized','fullscreen'])
            : window.incognito !== privateContext ? 'win_private_' + booleanResult(window.incognito)
            : !Array.isArray(window.tabs) ? 'win_tabs_type'
            : window.tabs.length !== 1 ? 'win_tab_count_' + (window.tabs.length === 0 ? 'zero' : 'many')
            : window.tabs[0].id !== tab.id ? 'tab_id'
            : window.tabs[0].windowId !== createdWindow.id ? 'tab_window'
            : window.tabs[0].active !== true ? 'tab_active_' + booleanResult(window.tabs[0].active)
            : window.tabs[0].incognito !== privateContext ? 'tab_private_' + booleanResult(window.tabs[0].incognito) : null;
          if (windowFailure) throw rejected(phase, windowFailure);
          // Sample without rememberTarget: a replacement must not overwrite
          // the original owned provenance needed for uncertain-create cleanup.
          const liveTab = await chrome.tabs.get(tab.id);
          current();
          const tabFailure = !liveTab ? 'live_missing'
            : liveTab.id !== tab.id ? 'live_id'
            : liveTab.windowId !== createdWindow.id ? 'live_window'
            : liveTab.incognito !== privateContext ? 'live_private_' + booleanResult(liveTab.incognito)
            : liveTab.active !== true ? 'live_active_' + booleanResult(liveTab.active) : null;
          if (tabFailure) throw rejected(phase, tabFailure);
          const actual = (await chrome.debugger.getTargets()).filter(t => t.tabId === tab.id && t.type === 'page');
          current();
          if (actual.length !== 1) throw rejected(phase, 'cdp_count_' + (actual.length === 0 ? 'zero' : 'many'));
          if (actual[0].id !== found.browser_target_id) throw rejected(phase, 'cdp_id');
          return window;
        };
        try {
          await bodyWait((async () => {
            // Preserve all original creation refusals before any new mutation.
            if (createdWindow.incognito !== privateContext)
              throw rejected('creation_return', 'win_private_' + booleanResult(createdWindow.incognito));
            if (tab.active !== true) throw rejected('creation_return', 'tab_active_' + booleanResult(tab.active));
            // Publish cleanup-only ownership before the first potentially
            // blocking correction read. This does not authorize any input.
            current();
            correctionHistory = { claim_id: uuid(), claim_epoch: 1, installation_id: installationId,
              runtime_generation: packet.runtime_generation, owner_session: owner, target: found,
              state: 'suspended_transport', cleanup_state: 'unverified', debuggerAttached: false,
              pointer_release_state: 'not_needed', keyboard_release_state: 'not_needed',
              provenance: 'agent', cleanup_policy: packet.cleanup_policy, creation_window_id: createdWindow.id,
              creation_retirement_eligible: true,
              ...(typeof packet.operation_request_id === 'string' && encoder.encode(packet.operation_request_id).length > 0
                && encoder.encode(packet.operation_request_id).length <= 256
                ? { initialization_request_id: packet.operation_request_id } : {}) };
            incompleteClaimHistory.set(correctionHistory.claim_id, correctionHistory);
            await persistTargets(); current(); state();
            await verify('fullscreen', 'preflight_one'); current();
            await verify('fullscreen', 'preflight_two'); current();
            creationAdmission.updatePending = true;
            let updated;
            try { updated = await chrome.windows.update(createdWindow.id, { state: 'normal', focused: false }); }
            finally {
              // Timeout cannot cancel Chrome's mutation. A maximized receipt
              // also keeps convergence unqualified after promise settlement.
              creationAdmission.updatePending = false;
              if (updated?.state === 'maximized' && creationAdmissions.get(tab.id) === creationAdmission) {
                creationAdmission.normalPending = true;
                correctionHistory.creation_window_settled = false;
              } else correctionHistory.creation_window_settled = true;
              releaseAdmission();
            }
            current();
            const updateFailure = !updated ? 'win_missing'
              : updated.id !== createdWindow.id ? 'win_id'
              : updated.focused !== false ? 'win_focus_' + booleanResult(updated.focused)
              : updated.type !== 'normal' ? 'win_type_' + enumResult(updated.type, ['normal','popup','panel','app','devtools'])
              : updated.state !== 'normal' && updated.state !== 'maximized' ? 'win_state_' + enumResult(updated.state, ['normal','minimized','maximized','fullscreen'])
              : updated.incognito !== privateContext ? 'win_private_' + booleanResult(updated.incognito) : null;
            if (updateFailure) throw rejected('update_ack', updateFailure);
            correctionAckState = updated.state;
            // An SDK receipt can report maximized before a later normal sample.
            // Only a complete NORMAL proof admits
            // input; passive settling shares the original overall deadline.
            correctionHistory.creation_window_settled = false;
            while (true) {
              const sampled = await verify('normal', 'post_readback', true); current();
              if (sampled.state === 'normal') {
                createdWindow = sampled;
                creationAdmission.normalPending = false;
                correctionHistory.creation_window_settled = true;
                break;
              }
              await new Promise(resolve => setTimeout(resolve, 50)); current();
            }
            correctedWindow = true;
          })(), 1500, null, 'created_browser_window_correction_timeout');
        } finally { waiting = false; }
      }
      if (createdWindow.state !== 'normal')
        throw fail('created_browser_window_state_' + (['minimized', 'maximized', 'fullscreen'].includes(createdWindow.state)
          ? createdWindow.state : createdWindow.state === undefined ? 'missing' : 'invalid'));
      if (createdWindow.incognito !== privateContext)
        throw fail('created_browser_window_context_' + booleanResult(createdWindow.incognito));
      if (tab.active !== true)
        throw fail('created_browser_tab_active_' + booleanResult(tab.active));
      requireTrust(packet);
      if (!trust.control || port !== creationPort || peerId !== creationPeer) throw fail('workbench_not_connected');
      if (correctionHistory) { correctionHistory.cleanup_state = 'completed'; correctionHistory.state = 'released'; correctionHistory.claim_epoch++; }
      const acquired = await acquire({ ...packet, target: found }, creationAdmission);
      if (correctedWindow) event(claims.get(acquired.claim_id), 'created_window_state_corrected', {
        window_id: createdWindow.id, tab_id: tab.id, from_state: 'fullscreen', verified_state: 'normal', focused: false,
        update_ack_state: correctionAckState });
      return acquired;
    } catch (error) {
      try { await persistTargets(); } catch { /* The create was attempted; never downgrade uncertainty on storage failure. */ }
      throw fail(error.code || 'created_browser_target_unavailable', 'unknown');
    } finally { creationAdmission.ended = true; releaseAdmission(); }
  }
  if (!claims.has(packet.claim_id) && incompleteClaimHistory.has(packet.claim_id)) return recoverInitialization(packet);
  const record = claims.get(packet.claim_id);
  if (!record || record.owner_session !== packet.owner_session
      || record.target.context_id !== contextId || record.installation_id !== installationId) throw fail('browser_claim_owner_mismatch');
  if (record.restored_history) throw fail('browser_claim_reconciliation_pending');
  const historical = record.runtime_generation !== serverGeneration;
  if (historical && (!['cleanup', 'claim_status'].includes(packet.action) || !validCleanupBinding(packet, record))) throw fail('browser_claim_owner_mismatch');
  if (packet.action === 'claim_status') return { ok: true, ...publicClaim(record), ...(historical ? { cleanup_binding: packet.cleanup_binding } : {}) };
  if (packet.claim_epoch !== record.claim_epoch || packet.target_generation !== record.target.target_generation) throw fail('stale_browser_claim');
  if (packet.action.startsWith('diagnostics_')) return diagnosticControl(record, packet);
  if (record.diagnosticOnly && !['claim_status','events','stop','release','cleanup'].includes(packet.action)) throw fail('diagnostic_read_only');
  if (packet.action === 'dialog_read' || packet.action === 'dialog_handle') return dialogControl(record, packet);
  if (packet.action === 'events') return { ok: true, ...publicLease(record), ...cachedEvents(record, packet.parameters), claim: publicClaim(record) };
  if (packet.action === 'cleanup' && packet.upload_cleanup) {
    if (record.state !== 'active' || packet.expected_generation !== record.generation || packet.expected_origin !== record.origin) throw fail('upload_cleanup_unverified');
    return execute({ ...packet, action: 'upload_clear_check', lease_id: record.id });
  }
  if (packet.action === 'cleanup') {
    if (record.releasing) throw fail('browser_operation_pending');
    const suspended = ['suspended_transport','suspended_contention'].includes(record.state);
    if (suspended || historical || record.cleanup_state === 'unverified') {
      const retired = await retireAbsentClaim(record, packet);
      if (retired) return { ...retired, tab_closed: false,
        ...(historical ? { cleanup_binding: packet.cleanup_binding } : {}) };
    }
    if (suspended && !record.heldDrag?.pressAttempted && (record.drag_active
        || ['held','unverified','not_recorded'].includes(record.pointer_release_state))) throw fail('browser_input_release_unverified');
    if (record.cleanup_state !== 'unverified' && !suspended) throw fail('browser_cleanup_not_pending');
    record.inputEligible = false;
    const result = await finishClaim(record, suspended || historical && !terminalClaim(record) ? 'released' : record.state,
      'cleanup_recovery', suspended || record.cleanup_release_debugger === true, !suspended && record.cleanup_close_owned === true);
    return { ...result, ...(historical ? { cleanup_binding: packet.cleanup_binding } : {}) };
  }
  if (terminalClaim(record)) throw fail('browser_claim_ended');
  if (record.releasing) throw fail('browser_operation_pending');
  if (packet.action === 'stop' || packet.action === 'release') {
    if (!ownsTarget(record)) throw fail('browser_claim_owner_mismatch');
    // Fence synchronously before target/storage/transport awaits. Cleanup uses
    // separately guarded original identities; ordinary input cannot resume.
    record.inputEligible = false;
  }
  if (packet.action === 'stop') {
    stoppedTargets.add(record.target.target_id);
    return finishClaim(record, 'revoked', 'explicit_stop');
  }
  if (packet.action === 'release') {
    return finishClaim(record, 'released', 'task_release', true, true);
  }
  if (record.state !== 'active' || record.peerId !== peerId) throw fail('browser_claim_suspended');
  if (packet.expected_generation !== record.generation || packet.expected_origin !== record.origin) throw fail('stale_browser_document');
  // Admit exact-claim Stop before any asynchronous pointer/file preflight.
  if (packet.action === 'drag') record.dragPending = true;
  if (packet.action === 'upload') record.uploadPending = true;
  const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === record.tabId && t.type === 'page');
  if (['drag', 'upload'].includes(packet.action) && (record.state !== 'active' || record.peerId !== peerId
      || record.claim_epoch !== packet.claim_epoch || record.runtime_generation !== packet.runtime_generation)) throw fail('browser_claim_owner_mismatch');
  if (actual?.id !== record.target.browser_target_id) { await finishClaim(record, 'target_closed', 'target_identity_changed'); throw fail('stale_browser_target'); }
  const result = await execute({ ...packet, lease_id: record.id });
  return { ...result, claim: publicClaim(record) };
}

async function recoverInitialization(packet) {
  requireTrust(packet);
  const row = incompleteClaimHistory.get(packet.claim_id), b = packet.cleanup_binding;
  const target = row.target;
  const recovering = packet.absence_receipt_binding !== undefined;
  const savedAbsence = row.absenceReceipt;
  const current = () => {
    requireTrust(packet);
    if (!row || incompleteClaimHistory.get(packet.claim_id) !== row || row.owner_session !== packet.owner_session
        || row.installation_id !== installationId || !['claim_status','cleanup'].includes(packet.action)
        || claims.has(row.claim_id) || row.claim_epoch !== packet.claim_epoch + (recovering ? 1 : 0) || target.target_generation !== packet.target_generation
        || !b || b.record_kind !== 'browser_incomplete_initialization' || b.action !== packet.action
        || b.claim_id !== row.claim_id || b.claim_epoch !== packet.claim_epoch || b.owner_session !== row.owner_session
        || b.original_runtime_generation !== row.runtime_generation || b.current_runtime_generation !== serverGeneration
        || b.peer_id !== peerId || b.installation_id !== installationId || b.trust_id !== trust.trust_id
        || b.profile_id !== profileId || b.context_id !== contextId || b.context_kind !== contextKind()
        || b.target_id !== target.target_id || b.target_generation !== target.target_generation
        || b.tab_id !== target.tab_id || b.browser_target_id !== target.browser_target_id
        || (packet.absence_only === true) !== (b.absence_only === true)
        || b.absence_only !== undefined && b.absence_only !== true
        || packet.absence_only !== undefined && packet.absence_only !== true
        || packet.absence_only === true && packet.action !== 'cleanup'
        || typeof b.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(b.nonce)) throw fail('browser_claim_owner_mismatch');
  };
  current();
  if (recovering) {
    // Exact durable original receipt only: never query a target or repeat cleanup.
    if (packet.action !== 'claim_status' || row.historyCleanupBusy || !savedAbsence || packet.absence_receipt_request_id !== savedAbsence.request_id
        || JSON.stringify(packet.absence_receipt_binding) !== JSON.stringify(savedAbsence.binding)
        || savedAbsence.binding.action !== 'cleanup' || savedAbsence.binding.absence_only !== true
        || savedAbsence.binding.claim_epoch !== packet.claim_epoch
        || savedAbsence.binding.owner_session !== row.owner_session || savedAbsence.binding.installation_id !== installationId
        || savedAbsence.binding.target_generation !== target.target_generation
        || savedAbsence.binding.browser_target_id !== target.browser_target_id
        || JSON.stringify(savedAbsence.history) !== JSON.stringify(initializationRecord(row)))
      throw fail('browser_absence_receipt_unavailable', 'unknown');
    return {ok:true,record_kind:'browser_incomplete_initialization',cleanup_binding:b,
      initialization_record:savedAbsence.history,cleanup_receipt:savedAbsence.receipt,
      absence_original_binding:savedAbsence.binding,absence_original_request_id:savedAbsence.request_id};
  }
  const reply = receipt => ({ ok: true, interaction_version: INTERACTION_VERSION, record_kind: 'browser_incomplete_initialization',
    initialization_record: initializationRecord(row), cleanup_binding: b, ...(receipt ? { cleanup_receipt: receipt } : {}) });
  if (packet.action === 'claim_status') return reply();
  if (row.historyCleanupBusy) throw fail('browser_operation_pending');
  if (['held','unverified','not_recorded'].includes(initializationRecord(row).pointer_release_state)) throw fail('browser_input_release_unverified');
  const absenceOnly = packet.absence_only === true;
  // This lane has no release or close authority. Auxiliary resources require
  // their existing recovery mechanism, never retirement from target absence.
  if (absenceOnly && (row.creation_window_id != null || creationAdmissions.has(target.tab_id)
      || row.children?.size || row.bodyCaptureSessions?.size || row.bodyPauses?.size || row.pendingNavigation
      || row.response_capture_overflow
      || row.response_capture_receipts?.length || row.pendingDialog || row.pending_dialog
      || ['pending','unverified'].includes(row.dialog_resolution_state) || row.heldKey || row.heldDrag
      || row.drag_active || row.dragActive || !['not_needed','released'].includes(row.keyboard_release_state || 'not_needed')))
    throw fail('browser_cleanup_auxiliary_unverified');
  const creation = creationAdmissions.get(target.tab_id);
  if (Number.isSafeInteger(row.creation_window_id) && creation?.generation === target.target_generation
      && creation.windowId === row.creation_window_id && !creation.admitted) {
    // Authorized cleanup irrevocably ends this still-unadmitted creator's
    // permit before any await. A busy reset/error cannot revive stale reads.
    creation.cancelled = true;
  }
  row.historyCleanupBusy = true;
  let open = true, timer;
  const deadline = performance.now() + 2000;
  const checkpoint = () => { current(); if (!open || performance.now() >= deadline) throw fail('browser_cleanup_timeout', 'unknown'); };
  const ownedCleanup = () => {
    const remembered = targets.get(target.tab_id);
    if (!remembered || remembered.target_generation !== target.target_generation || remembered.browser_target_id !== target.browser_target_id
        || [...leases.values()].some(r => r.tabId === target.tab_id && (r.state === 'active' || r.releasing
          || r.durable && heldClaimResource(r)))
        || [...incompleteClaimHistory.values()].some(other => other !== row && heldClaimResource(other)
          && other.target?.target_id === target.target_id && other.target?.target_generation === target.target_generation))
      throw fail('browser_cleanup_owner_mismatch');
  };
  const receipt = { detach_attempted: false, detach_acknowledged: false, target_presence: 'unknown',
    attachment_verification: 'unknown', pointer_release_state: initializationRecord(row).pointer_release_state,
    tab_closed: false, task_completion: 'not_established' };
  let resolved, reconciledCreation;
  try {
    resolved = await Promise.race([(async () => {
      checkpoint();
      const debugTargets = await chrome.debugger.getTargets();
      if (absenceOnly) {
        checkpoint();
        if (!Array.isArray(debugTargets) || debugTargets.some(t=>t.id===target.browser_target_id || t.tabId===target.tab_id))
          throw fail('browser_cleanup_owner_mismatch');
        let absent=false;
        try { await chrome.tabs.get(target.tab_id); }
        catch(error) { absent=error?.message===`No tab with id: ${target.tab_id}.`; }
        checkpoint();
        if (!absent) throw fail('browser_cleanup_absence_unverified');
        const after=await chrome.debugger.getTargets();checkpoint();
        if(!Array.isArray(after)||after.some(t=>t.id===target.browser_target_id||t.tabId===target.tab_id))
          throw fail('browser_cleanup_owner_mismatch');
        Object.assign(receipt,{absence_only:true,source:'chrome.debugger.getTargets+chrome.tabs.get',
          target_presence:'original_absent',effect_state:'none',prior_effects:'not_reconciled'});
        return 'target_gone';
      }
      let actual = debugTargets.find(t => t.tabId === target.tab_id && t.type === 'page');
      checkpoint();
      const creation = Number.isSafeInteger(row.creation_window_id) && row.provenance === 'agent';
      const pendingCreation = creation && row.creation_window_settled !== true;
      const creationTarget = targets.get(target.tab_id);
      if (creation && (pendingCreation || creationTarget?.creation_pending || packet.retire_owned_creation === true)) {
        actual = debugTargets.find(t => t.id === target.browser_target_id && t.type === 'page');
        const remembered = targets.get(target.tab_id);
        const matching = remembered?.target_generation === target.target_generation
          && remembered.browser_target_id === target.browser_target_id && remembered.provenance === 'agent'
          && remembered.creator_session === row.owner_session
          && (!remembered.creation_pending || remembered.creation_window_id === row.creation_window_id);
        if (actual && (!matching || pendingCreation && !remembered.creation_pending))
          throw fail('browser_cleanup_owner_mismatch');
        if (actual) {
          if (actual.tabId !== target.tab_id) throw fail('browser_cleanup_owner_mismatch');
          ownedCleanup();
          const live = await chrome.tabs.get(target.tab_id); checkpoint(); ownedCleanup();
          if (!live || live.windowId !== row.creation_window_id || live.incognito !== (contextKind() === 'private'))
            throw fail('browser_cleanup_owner_mismatch');
        }
        // Default cleanup never closes a keep target. Retirement is a separate
        // explicit opt-in on the existing cleanup operation, bound by the host.
        if (actual && packet.retire_owned_creation === true && row.creation_retirement_eligible === true) {
          if (actual.tabId !== target.tab_id) throw fail('browser_cleanup_owner_mismatch');
          ownedCleanup();
          if (actual.attached && row.debuggerAttached !== true) throw fail('browser_cleanup_attachment_unknown');
          if (!actual.attached) {
            await chrome.debugger.attach({ targetId: target.browser_target_id }, '1.3');
            row.debuggerAttached = true; checkpoint(); ownedCleanup();
            await persistTargets(); checkpoint();
          }
          const beforeClose = (await chrome.debugger.getTargets()).find(t => t.id === target.browser_target_id);
          checkpoint(); ownedCleanup();
          if (!beforeClose || beforeClose.tabId !== target.tab_id || beforeClose.type !== 'page')
            throw fail('browser_cleanup_owner_mismatch');
          await chrome.debugger.sendCommand({ targetId: target.browser_target_id }, 'Target.closeTarget', { targetId: target.browser_target_id });
          checkpoint();
          actual = (await chrome.debugger.getTargets()).find(t => t.id === target.browser_target_id);
          checkpoint(); receipt.tab_closed = !actual;
        }
        if (actual && pendingCreation) { receipt.target_presence = 'exact_original'; return 'unverified'; }
        if (!actual) {
          receipt.target_presence = 'original_absent';
          // An added personal tab can keep the old mutation's WINDOW alive.
          // Original-tab absence cannot settle an outstanding window update.
          if (pendingCreation) {
            let windowAbsent = false;
            try { await chrome.windows.get(row.creation_window_id, { populate: false }); }
            catch (error) { windowAbsent = error?.message === `No window with id: ${row.creation_window_id}.`; }
            checkpoint();
            if (!windowAbsent) return 'unverified';
            row.creation_window_settled = true;
          }
          if (matching) reconciledCreation = remembered;
          return 'target_gone';
        }
        // Recorded actual settlement plus current exact ownership permits the
        // ordinary detached witness below; detached metadata alone never does.
        reconciledCreation = remembered;
      }
      if (!actual || actual.id !== target.browser_target_id) { receipt.target_presence = 'original_absent'; return 'target_gone'; }
      receipt.target_presence = 'exact_original';
      ownedCleanup();
      if (actual.attached === false) { receipt.attachment_verification = 'not_attached'; return 'completed'; }
      if (row.debuggerAttached !== true) throw fail('browser_cleanup_attachment_unknown');
      checkpoint(); ownedCleanup(); receipt.detach_attempted = true;
      try { await chrome.debugger.detach({ targetId: target.browser_target_id }); receipt.detach_acknowledged = true; }
      catch { /* Only a fresh detached/absence witness may resolve failure. */ }
      checkpoint();
      const after = (await chrome.debugger.getTargets()).find(t => t.tabId === target.tab_id && t.type === 'page');
      checkpoint();
      if (!after || after.id !== target.browser_target_id) { receipt.target_presence = 'original_absent'; return 'target_gone'; }
      ownedCleanup();
      if (after.attached === false) { receipt.attachment_verification = 'not_attached'; return 'completed'; }
      throw fail('browser_cleanup_unverified', 'unknown');
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_cleanup_timeout', 'unknown')), 2000); })]);
    checkpoint();
    if (reconciledCreation?.creation_pending && row.creation_window_settled === true
        && (targets.get(target.tab_id) !== reconciledCreation || reconciledCreation.target_generation !== target.target_generation
          || reconciledCreation.browser_target_id !== target.browser_target_id
          || reconciledCreation.creation_window_id !== row.creation_window_id)) throw fail('browser_cleanup_owner_mismatch');
    const old = { cleanup_state: row.cleanup_state, state: row.state, debuggerAttached: row.debuggerAttached, claim_epoch: row.claim_epoch };
    row.historyPublication = initializationRecord(row);
    row.cleanup_state = resolved; row.state = resolved === 'unverified' ? 'suspended_transport' : 'released';
    if (resolved !== 'unverified' || receipt.target_presence === 'original_absent') row.debuggerAttached = false;
    row.claim_epoch++;
    let pendingMarker;
    if (reconciledCreation?.creation_pending && row.creation_window_settled === true) {
      pendingMarker = { creation_pending: reconciledCreation.creation_pending, creation_window_id: reconciledCreation.creation_window_id };
      delete reconciledCreation.creation_pending; delete reconciledCreation.creation_window_id;
    }
    const priorAbsenceReceipt = row.absenceReceipt;
    try {
    if (absenceOnly) {
      if (typeof packet.operation_request_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(packet.operation_request_id))
        throw fail('browser_absence_receipt_unavailable','unknown');
      const original = {binding:JSON.parse(JSON.stringify(b)),request_id:packet.operation_request_id,
        history:initializationRecord({...row,historyPublication:undefined}),receipt:JSON.parse(JSON.stringify(receipt))};
      if (encoder.encode(JSON.stringify(original)).length > 32768) throw fail('browser_absence_receipt_unavailable','unknown');
      row.absenceReceipt = original;
    }
    // historyCleanupBusy fences both target and window until this cleared
    // marker and settled cleanup result are durable. Failure restores only it.
    await persistTargets();
    } catch (error) {
      if (pendingMarker && targets.get(target.tab_id) === reconciledCreation) Object.assign(reconciledCreation, pendingMarker);
      Object.assign(row, old); row.absenceReceipt = priorAbsenceReceipt; row.historyPublication = undefined; throw fail('browser_cleanup_persistence_failed', 'unknown');
    }
    const admission = creationAdmissions.get(target.tab_id);
    if (reconciledCreation && row.creation_window_settled === true && admission?.ended
        && admission.generation === target.target_generation && admission.windowId === row.creation_window_id)
      creationAdmissions.delete(target.tab_id);
    // Persistence is outside the detached-query deadline; no later input or
    // cleanup mutation is issued, and only persisted outcome is published.
    row.historyPublication = undefined; row.historyCleanupBusy = false;
    open = false; state(); return reply(receipt);
  } finally { open = false; clearTimeout(timer); row.historyCleanupBusy = false; }
}

function validCleanupBinding(packet, record) {
  const b = packet.cleanup_binding;
  return b && typeof b === 'object' && b.action === packet.action && b.claim_id === record.id && b.claim_epoch === record.claim_epoch
    && b.original_runtime_generation === record.runtime_generation && b.current_runtime_generation === serverGeneration
    && b.peer_id === peerId && b.installation_id === installationId && b.owner_session === record.owner_session
    && b.profile_id === profileId && b.context_id === contextId && b.context_kind === contextKind()
    && record.target.profile_id === profileId && record.target.context_kind === contextKind()
    && b.target_id === record.target.target_id && b.target_generation === record.target.target_generation
    && typeof b.nonce === 'string' && /^[0-9a-f]{32}$/.test(b.nonce);
}

// Acquisition-local diagnostics contain only fixed vocabulary and bounded timing.
// They never observe unrelated child/event commands or infer recipient effects.
const ACQUISITION_COMMAND_STAGES = Object.freeze({
  'Emulation.setFocusEmulationEnabled': 'focus', 'Page.enable': 'domains', 'Runtime.enable': 'domains',
  'Network.enable': 'network', 'Fetch.enable': 'body_capture',
  'Target.setAutoAttach': 'auto_attach', 'Page.getFrameTree': 'document'
});
function acquisitionReadiness() {
  const startedAt = performance.now(), pending = new Set();
  const elapsed = (now, start) => Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, now - start));
  let started = 0, completed = 0, stage = 'focus', lastCompleted = null, snapshot = null;
  return {
    get snapshot() { return snapshot; },
    freeze() {
      const now = performance.now();
      if (!snapshot) snapshot = Object.freeze({ stage, started_count: started, completed_count: completed,
        elapsed_ms: elapsed(now, startedAt), pending: Object.freeze([...pending].map(row => Object.freeze({
          stage: row.stage, command: row.command, elapsed_ms: elapsed(now, row.startedAt) }))),
        last_completed: lastCompleted });
      return snapshot;
    },
    async run(nextStage, command, operation) {
      if (!Object.values(ACQUISITION_COMMAND_STAGES).includes(nextStage)
          && !['target_identity', 'creation_persistence', 'document_poll'].includes(nextStage)
          || command !== null && ACQUISITION_COMMAND_STAGES[command] !== nextStage
          || pending.size >= 8 || started >= 1000000) throw fail('browser_readiness_diagnostics_limit');
      // After timeout checkpoints own refusal; late settlements cannot change the witness.
      const row = { stage: nextStage, command, startedAt: performance.now() };
      if (!snapshot) { stage = nextStage; started++; pending.add(row); }
      try {
        const result = await operation();
        if (!snapshot) {
          completed++;
          lastCompleted = Object.freeze({ stage: nextStage, command,
            state: command === null ? 'completed' : 'protocol_acknowledged' });
        }
        return result;
      } finally { if (!snapshot) pending.delete(row); }
    }
  };
}

async function cdp(record, method, params = {}, sessionId, willSend = () => {}) {
  if (record.diagnosticOnly) return diagnosticCdp(record, method, params, sessionId, willSend);
  if (record.state !== 'active' || record.inputEligible === false || Date.now() >= record.expires) throw fail('browser_lease_ended');
  willSend();
  const targetId = record.target?.browser_target_id || record.browserTargetId;
  if (!targetId) throw fail('browser_debugger_address_unavailable');
  return chrome.debugger.sendCommand({ targetId, ...(sessionId ? { sessionId } : {}) }, method, params);
}

// A renderer/session can end without settling Chrome's Page.navigate promise.
// Reject only this navigation continuation; a lifecycle event is never an ACK.
function endChildNavigation(record) {
  if (record.pendingNavigation?.childFrame) endNavigation(record);
}
function endNavigation(record, sessionId) {
  const pending = record.pendingNavigation;
  if (pending && (sessionId === undefined || pending.sessionId === sessionId)) pending.end();
}
function endRemovedFrameNavigation(record, source, params) {
  const pending = record.pendingNavigation;
  // A swap is part of ordinary navigation, while removal ends this exact frame.
  // OOPIF removal may be reported by its owning session or the parent renderer.
  const sessionId = source.sessionId || null;
  if (params.reason === 'remove' && pending?.frameId === params.frameId
      && (pending.sessionId === sessionId || pending.parentSessionId === sessionId)) pending.end();
}
async function navigateWithLifetime(record, params, sessionId, checkpoint, parentSessionId) {
  const token = record.busyToken;
  let rejectEnded;
  const ended = new Promise((_, reject) => { rejectEnded = reject; });
  const pending = { frameId: params.frameId, sessionId: sessionId || null, parentSessionId: parentSessionId || null,
    childFrame: params.frameId !== record.mainFrameId, end: () => rejectEnded(fail('browser_navigation_interrupted', 'unknown')) };
  record.pendingNavigation = pending;
  try {
    // No retries or detached async continuation: only the SDK promise can finish
    // late, and Promise.race consumes its eventual ACK/error without further work.
    return await Promise.race([cdp(record, 'Page.navigate', params, sessionId, () => {
      checkpoint();
      if (record.pendingNavigation !== pending || record.busyToken !== token) throw fail('browser_operation_pending');
    }), ended]);
  } finally {
    if (record.pendingNavigation === pending) record.pendingNavigation = undefined;
  }
}

// Once per new root attachment. Logical focus keeps an inactive tab's renderer
// ready; acknowledgement alone establishes neither event delivery nor task success.
async function initializeRootInput(record, checkpoint, send = cdp) {
  checkpoint();
  record.inputInitialization = { state: 'pending', method: 'Emulation.setFocusEmulationEnabled' };
  await send(record, 'Emulation.setFocusEmulationEnabled', { enabled: true }, null, checkpoint);
  checkpoint();
  record.inputInitialization.state = 'protocol_acknowledged';
}

async function frames(record, checkpoint = () => {}) {
  for (let pass=0;pass<8;pass++) {
    checkpoint(); const epoch=record.frameTopologyEpoch||0, trees=[];
    const visited=new Set();let rootPending=true;
    for(let round=0;round<8;round++) {
      const pending=[...record.children].filter(([id,target])=>target.type==='iframe'&&!visited.has(id));
      if(visited.size+pending.length>=100)throw fail('frame_tree_incomplete');
      if(!pending.length&&!rootPending)break;
      // Renderer trees are independent reads. Preserve canonical ordering and
      // validate every session plus the whole topology epoch before publishing.
      const rootRead=rootPending?[(async()=>{
        checkpoint();const root=await cdp(record,'Page.getFrameTree');checkpoint();
        return {tree:root.frameTree,session_id:null,session_epoch:0};
      })()]:[];
      const sampled=await Promise.all([...rootRead,...pending.map(async([session_id,target])=>{
        if(!target.ready)throw fail('frame_session_unavailable');
        try {await target.ready;}catch {checkpoint();throw fail('frame_session_unavailable');}checkpoint();
        if(record.children.get(session_id)!==target || target.readiness_error)throw fail('stale_browser_frame');
        const tree=await cdp(record,'Page.getFrameTree',{},session_id);checkpoint();
        if(record.children.get(session_id)!==target || tree.frameTree?.frame?.id!==target.target_id)throw fail('frame_target_mismatch');
        return {tree:tree.frameTree,session_id,session_epoch:target.session_epoch};
      })]);checkpoint();
      trees.push(...sampled);for(const [id]of pending)visited.add(id);rootPending=false;
    }
    if([...record.children].some(([id,target])=>target.type==='iframe'&&!visited.has(id)))throw fail('frame_tree_incomplete');
    if((record.frameTopologyEpoch||0)!==epoch)continue;
    const occurrences=new Map();
    for(const row of trees) {
      const add=tree=>{
        const frame=tree.frame;if(!frame?.id||!frame.loaderId)throw fail('frame_document_unavailable');
        if(occurrences.size>=100&&!occurrences.has(frame.id))throw fail('frame_tree_incomplete');
        let origin=null;try {origin=webOrigin(frame.securityOrigin||frame.url);}catch {}
        const item={frame_id:frame.id,parent_id:frame.parentId||null,loader_id:frame.loaderId,origin,url:safeURL(frame.url),
          allowed:!!origin&&(record.durable||origin===record.origin),session_id:row.session_id,
          renderer_root_id:row.tree.frame.id,session_epoch:row.session_epoch};
        const list=occurrences.get(frame.id)||[];list.push(item);occurrences.set(frame.id,list);
        for(const child of tree.childFrames||[])add(child);
      };add(row.tree);
    }
    const canonical=new Map();
    for(const [id,list]of occurrences) {
      const owned=list.filter(row=>row.session_id&&row.renderer_root_id===id);
      if(owned.length>1)throw fail('ambiguous_frame_session');
      const selected=owned[0]||list[0];
      if(list.some(row=>row.parent_id!==selected.parent_id||row.loader_id!==selected.loader_id))throw fail('inconsistent_frame_tree');
      if(!owned.length&&list.some(row=>row.session_id!==selected.session_id))throw fail('ambiguous_frame_session');
      canonical.set(id,selected);
    }
    for(const row of canonical.values()) {
      const parent=row.parent_id?canonical.get(row.parent_id):null;
      if(row.parent_id&&!parent)throw fail('frame_parent_unavailable');
      if(row.session_id&&row.renderer_root_id===row.frame_id) {
        const session=record.children.get(row.session_id);
        if(!parent||session?.target_id!==row.frame_id||session.parent_session_id!==parent.session_id
            ||session.session_epoch!==row.session_epoch)throw fail('frame_session_lineage_mismatch');
      }
    }
    checkpoint();return [...canonical.values()];
  }
  throw fail('frame_tree_unstable');
}

async function live(record, expectedGeneration, expectedOrigin, frameId, checkpoint = () => {}) {
  checkpoint();
  if (record.state !== 'active' || Date.now() >= record.expires) { await detach(record, 'expired'); throw fail('browser_lease_ended'); }
  const tabSampleStarted = Date.now();
  const tab = await chrome.tabs.get(record.tabId);
  const tabSampleCompleted = Date.now();
  checkpoint();
  if (tab.url && webOrigin(tab.url) !== record.origin) {
    if (!record.durable) { await detach(record, 'origin_changed'); throw fail('browser_origin_changed'); }
    record.origin = webOrigin(tab.url); record.generation++; record.observations.clear(); state();
  }
  if (record.windowId !== tab.windowId) { record.windowId = tab.windowId; state(); }
  const list = await frames(record, checkpoint);
  checkpoint();
  const root = list.find(f => !f.parent_id && !f.session_id);
  if (!root || root.origin !== record.origin) { await detach(record, 'origin_changed'); throw fail('browser_origin_changed'); }
  if (record.loaderId !== root.loader_id) {
    record.loaderId = root.loader_id; record.generation++; record.observations.clear();
    event(record, 'document_changed'); state();
  }
  if (expectedGeneration !== record.generation || expectedOrigin !== record.origin) throw fail('stale_browser_document');
  const selected = frameId ? list.find(f => f.frame_id === frameId) : root;
  if (!selected || !selected.allowed) throw fail('frame_grant_required');
  return { list, frame: selected, browserTab: { source: 'chrome.tabs.get', id: tab.id, window_id: tab.windowId,
    state: typeof tab.active === 'boolean' ? 'sampled' : 'unavailable',
    active: typeof tab.active === 'boolean' ? tab.active : null,
    last_accessed_at_ms: Number.isFinite(tab.lastAccessed) ? tab.lastAccessed : null,
    sample_started_at_ms: tabSampleStarted, sample_completed_at_ms: tabSampleCompleted } };
}

// Chrome management metadata is separate from renderer focus emulation. This
// read never activates a tab/window, changes authority, or establishes an effect.
async function browserFocusSample(record, tab) {
  const windowSample = { source: 'chrome.windows.get', id: tab.window_id, state: 'unavailable', focused: null,
    sample_started_at_ms: Date.now() };
  try {
    const window = await bodyWait(chrome.windows.get(tab.window_id), 250, null, 'browser_focus_sample_timeout');
    if (window?.id === tab.window_id && typeof window.focused === 'boolean') {
      windowSample.state = 'sampled'; windowSample.focused = window.focused;
    } else windowSample.reason = 'invalid_window_metadata';
  } catch (error) {
    windowSample.reason = error?.code === 'browser_focus_sample_timeout' ? 'timeout' : 'metadata_read_failed';
  }
  windowSample.sample_completed_at_ms = Date.now();
  return { tab, window: windowSample,
    page_focus_emulation: { initialization_state: record.inputInitialization?.state || 'unverified',
      mechanism: 'Emulation.setFocusEmulationEnabled', current_dom_focus: 'not_sampled' },
    timing: 'Before requested observation or input; sequential, non-atomic Chrome metadata samples; timestamps are Unix milliseconds',
    interpretation: 'Tab active and window focused are separate samples, not a continuous coexistence or human-focus guarantee. DOM visibilityState/hasFocus may be emulated and do not prove tab activation. Input effects require independent readback.' };
}

async function world(record, selected) {
  const created = await cdp(record, 'Page.createIsolatedWorld', { frameId: selected.frame_id, worldName: 'LocalWorkbenchObservations' }, selected.session_id);
  if (!record.contextUniqueIds?.get((selected.session_id || '') + ':' + created.executionContextId)) throw fail('execution_context_identity_unavailable');
  return created.executionContextId;
}
async function value(record, expression, contextId, sessionId) {
  const result = await cdp(record, 'Runtime.evaluate', { expression, contextId, returnByValue: true, awaitPromise: true, timeout: 5000 }, sessionId);
  if (result.exceptionDetails) throw fail('browser_evaluation_failed', 'unknown');
  if (result.result?.type === 'undefined') return null;
  return result.result?.value ?? { unavailable: true, remote_type: result.result?.type };
}

// Cross-frame metadata stays separate from local DOM targets and native effects.
const FRAME_IDENTITY_KEYS = ['frame_id', 'parent_id', 'loader_id', 'session_id', 'renderer_root_id', 'session_epoch'];
function startFramePointerHold(record, packet, point, clickCount = 1, clickReceipt = null) {
  if (!record.durable) return null;
  frameClaimCurrent(record, packet);
  const held = { peer: record.peerId, owner: record.owner_session, runtime: record.runtime_generation, installation: record.installation_id,
    targetGeneration: record.target.target_generation, browserTarget: record.target.browser_target_id, epoch: record.claim_epoch,
    tabId: record.tabId, point: { ...point }, clickCount, clickReceipt, pressAttempted: true, releaseAttempted: false, state: 'held' };
  record.heldDrag = held; record.pointer_release_state = 'held'; return held;
}
async function finishFramePointerHold(record, held, point) {
  if (held) {
    if (await releaseHeldDrag(record, 'pointer_complete') !== 'acknowledged') throw fail('browser_drag_release_unverified', 'unknown');
  } else await cdp(record, 'Input.dispatchMouseEvent', { type: 'mouseReleased', ...point, button: 'left', clickCount: 1 }, null);
}
function frameClaimCurrent(record, packet, checkpoint = () => {}) {
  checkpoint();
  if (record.state !== 'active' || record.inputEligible === false || record.peerId !== peerId || !ownsTarget(record)
      || record.owner_session !== packet.owner_session || record.claim_epoch !== packet.claim_epoch
      || record.runtime_generation !== packet.runtime_generation || record.target.target_generation !== packet.target_generation)
    throw fail('browser_claim_owner_mismatch');
}
function frameContextCurrent(record, row) {
  if (record.contextUniqueIds.get((row.frame.session_id || '') + ':' + row.contextId) !== row.contextUniqueId)
    throw fail('stale_execution_context');
}
async function frameValue(record, row, expression, checkpoint = () => {}) {
  checkpoint(); frameContextCurrent(record, row);
  const result = await cdp(record, 'Runtime.evaluate', { expression, uniqueContextId: row.contextUniqueId,
    returnByValue: true, awaitPromise: true, timeout: 5000 }, row.frame.session_id);
  checkpoint(); frameContextCurrent(record, row);
  if (result.exceptionDetails) throw fail('browser_evaluation_failed');
  return result.result?.value;
}
function frameMapPoint(matrix, point) {
  const z = matrix[6] * point.x + matrix[7] * point.y + matrix[8];
  if (!Number.isFinite(z) || Math.abs(z) < 1e-9) throw fail('frame_transform_unavailable');
  const result = { x: (matrix[0] * point.x + matrix[1] * point.y + matrix[2]) / z,
    y: (matrix[3] * point.x + matrix[4] * point.y + matrix[5]) / z };
  if (!Number.isFinite(result.x) || !Number.isFinite(result.y)) throw fail('frame_transform_unavailable');
  return result;
}
function frameInverse(matrix) {
  const [a,b,c,d,e,f,g,h,i] = matrix;
  const adj = [e*i-f*h,c*h-b*i,b*f-c*e,f*g-d*i,a*i-c*g,c*d-a*f,d*h-e*g,b*g-a*h,a*e-b*d];
  const determinant = a*adj[0]+b*adj[3]+c*adj[6];
  if (!Number.isFinite(determinant) || Math.abs(determinant) < 1e-9) throw fail('frame_transform_unavailable');
  return adj.map(value => value / determinant);
}
function frameQuadMap(quad, width, height) {
  if (!(width > 0 && height > 0) || quad.length !== 8 || quad.some(value => !Number.isFinite(value)))
    throw fail('frame_transform_unavailable');
  // A folded, degenerate or back-facing content quad is not admitted.
  const turns = [];
  for (let n=0;n<4;n++) { const a=n*2,b=((n+1)%4)*2,c=((n+2)%4)*2;
    turns.push((quad[b]-quad[a])*(quad[c+1]-quad[b+1])-(quad[b+1]-quad[a+1])*(quad[c]-quad[b])); }
  if (turns.some(turn => turn <= 1e-7)) throw fail('frame_transform_unavailable');
  const [x0,y0,x1,y1,x2,y2,x3,y3] = quad;
  const dx1=x1-x2,dx2=x3-x2,dx3=x0-x1+x2-x3,dy1=y1-y2,dy2=y3-y2,dy3=y0-y1+y2-y3;
  let g=0,h=0;
  if (Math.abs(dx3)>1e-7 || Math.abs(dy3)>1e-7) {
    const determinant=dx1*dy2-dx2*dy1;
    if (Math.abs(determinant)<1e-9) throw fail('frame_transform_unavailable');
    g=(dx3*dy2-dx2*dy3)/determinant; h=(dx1*dy3-dx3*dy1)/determinant;
  }
  const matrix=[(x1-x0+g*x1)/width,(x3-x0+h*x3)/height,x0,
    (y1-y0+g*y1)/width,(y3-y0+h*y3)/height,y0,g/width,h/height,1];
  frameInverse(matrix); return matrix;
}
// Runs on the exact resolved owner, in the immediate parent document's world.
function frameOwnerState(x = null, y = null) {
  const element=this,rect=element.getBoundingClientRect();
  let hit=x===null?null:document.elementFromPoint(x,y),depth=0;
  while(hit?.shadowRoot) {
    if(depth++>=100)return {error:'shadow_hit_test_limit'};
    const nested=hit.shadowRoot.elementFromPoint(x,y);if(!nested||nested===hit)break;hit=nested;
  }
  let active=document.activeElement;while(active?.shadowRoot?.activeElement)active=active.shadowRoot.activeElement;
  const style=getComputedStyle(element);
  return {connected:element.isConnected,tag:element.tagName.toLowerCase(),rect:rect.toJSON(),
    width:element.clientWidth,height:element.clientHeight,visibility:style.visibility,pointer_events:style.pointerEvents,
    hit_matches_owner:x===null?null:hit===element,focused:active===element,
    hit_tag:hit?.tagName?.toLowerCase()||null};
}
function frameChainCurrent(record, chain, list, checkpoint = () => {}) {
  checkpoint();
  for(const row of chain) {
    const frame=list.find(item=>item.frame_id===row.frame.frame_id);
    if(!frame || FRAME_IDENTITY_KEYS.some(key=>frame[key]!==row.frame[key]))throw fail('stale_browser_frame');
    frameContextCurrent(record,row);
  }
}
async function captureFrameChain(record, selected, list, contextId, checkpoint = () => {}) {
  if(!record.durable || !selected.parent_id && !selected.session_id)return null;
  const path=[];let frame=selected;
  while(frame) {
    if(path.length>=20 || path.some(item=>item.frame_id===frame.frame_id))throw fail('frame_chain_limit');
    path.unshift(frame);frame=frame.parent_id?list.find(item=>item.frame_id===frame.parent_id):null;
  }
  if(path[0].parent_id || path[0].session_id)throw fail('frame_parent_unavailable');
  const chain=[];
  for(const frame of path) {
    checkpoint();
    const id=frame.frame_id===selected.frame_id?contextId:await world(record,frame);checkpoint();
    const unique=record.contextUniqueIds.get((frame.session_id||'')+':'+id);
    if(!unique)throw fail('execution_context_identity_unavailable');chain.push({frame:{...frame},contextId:id,contextUniqueId:unique});
  }
  const geometry=await readFrameGeometry(record,chain,checkpoint);
  frameChainCurrent(record,chain,await frames(record,checkpoint),checkpoint);
  return {chain,geometry:geometry.identity};
}
async function readFrameGeometry(record, chain, checkpoint = () => {}) {
  const identity=[1,0,0,0,1,0,0,0,1],docMaps=new Map([[chain[0].frame.frame_id,identity]]),sessionMaps=new Map([[null,identity]]);
  const viewports={},boundaries=[];
  // These reads use separate renderer contexts and have no data dependency.
  // Keep lifetime checks on each response and publish in chain order so the
  // geometry identity does not depend on callback completion order.
  const sampledViewports=await Promise.all(chain.map(row=>frameValue(record,row,
    '({width:innerWidth,height:innerHeight,scroll_x:scrollX,scroll_y:scrollY,visual:visualViewport&&{x:visualViewport.offsetLeft,y:visualViewport.offsetTop,scale:visualViewport.scale}})',checkpoint)));
  checkpoint();
  for(let index=0;index<chain.length;index++) {
    const row=chain[index],viewport=sampledViewports[index];
    if(!viewport || viewport.visual && (viewport.visual.scale!==1 || viewport.visual.x!==0 || viewport.visual.y!==0))throw fail('frame_visual_viewport_unsupported');
    viewports[row.frame.frame_id]=viewport;
  }
  const group='frame-chain:'+uuid();
  try {
    for(let index=1;index<chain.length;index++) {
      const child=chain[index],parent=chain[index-1];checkpoint();
      const owner=await cdp(record,'DOM.getFrameOwner',{frameId:child.frame.frame_id},parent.frame.session_id);checkpoint();
      const box=await cdp(record,'DOM.getBoxModel',{backendNodeId:owner.backendNodeId},parent.frame.session_id);checkpoint();
      frameContextCurrent(record,parent);
      const resolved=await cdp(record,'DOM.resolveNode',{backendNodeId:owner.backendNodeId,executionContextId:parent.contextId,objectGroup:group},parent.frame.session_id);
      checkpoint();frameContextCurrent(record,parent);
      const result=await cdp(record,'Runtime.callFunctionOn',{objectId:resolved.object.objectId,functionDeclaration:frameOwnerState.toString(),returnByValue:true},parent.frame.session_id);
      checkpoint();frameContextCurrent(record,parent);
      const state=result.result?.value;
      if(result.exceptionDetails || !state?.connected || !['iframe','frame'].includes(state.tag))throw fail('frame_owner_changed');
      const sessionMap=sessionMaps.get(parent.frame.session_id);if(!sessionMap)throw fail('frame_renderer_unavailable');
      const quad=[];for(let n=0;n<8;n+=2){const p=frameMapPoint(sessionMap,{x:box.model.content[n],y:box.model.content[n+1]});quad.push(p.x,p.y);}
      const viewport=viewports[child.frame.frame_id],map=frameQuadMap(quad,viewport.width,viewport.height);
      docMaps.set(child.frame.frame_id,map);
      if(child.frame.renderer_root_id===child.frame.frame_id)sessionMaps.set(child.frame.session_id,map);
      // Focus and hit state may change as a legitimate operation proceeds.
      delete state.focused;delete state.hit_matches_owner;delete state.hit_tag;
      boundaries.push({child_frame_id:child.frame.frame_id,parent_frame_id:parent.frame.frame_id,
        parent_session_id:parent.frame.session_id,owner_backend_node_id:owner.backendNodeId,owner_state:state,
        content_quad_renderer_css:box.model.content,content_quad_root_css:quad});
    }
  } finally {
    for(const session of new Set(chain.map(row=>row.frame.session_id))) {
      try { await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},session); }catch {/* Context teardown releases its objects. */}
      checkpoint();
    }
  }
  return {docMaps,identity:{viewports,boundaries}};
}
async function verifyFrameGeometryForInput(record, packet, observation, checkpoint = () => {}) {
  if (!observation.frameChain) return;
  const current = () => frameClaimCurrent(record, packet, checkpoint), bound = observation.frameChain;
  current(); const epoch = record.frameTopologyEpoch || 0;
  const geometry = await readFrameGeometry(record, bound.chain, current);
  if (JSON.stringify(geometry.identity) !== JSON.stringify(bound.geometry)) throw fail('frame_transform_changed');
  // Owner/hit/local-target queries and object cleanup can yield. Finish with
  // geometry-only reads; this checks the interval, without freezing the compositor.
  for (const boundary of [...bound.geometry.boundaries].reverse()) {
    const parent = bound.chain.find(row => row.frame.frame_id === boundary.parent_frame_id);
    current(); frameContextCurrent(record, parent);
    const box = await cdp(record, 'DOM.getBoxModel', { backendNodeId: boundary.owner_backend_node_id }, parent.frame.session_id);
    current(); frameContextCurrent(record, parent);
    if (JSON.stringify(box.model?.content) !== JSON.stringify(boundary.content_quad_renderer_css)) throw fail('frame_transform_changed');
  }
  for (const row of bound.chain) frameContextCurrent(record, row);
  current(); if ((record.frameTopologyEpoch || 0) !== epoch) throw fail('stale_browser_frame');
}
// Refresh identities after cross-renderer geometry awaits, before a final
// local recipient check. This remains sequential sampling, not a paint freeze.
async function freshFrameInputIdentity(record, packet, observation, checkpoint = () => {}) {
  const current = () => {
    frameClaimCurrent(record, packet, checkpoint);
    if (observation.generation !== record.generation) throw fail('stale_observation');
    for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
  };
  current();
  const selected = await live(record, packet.expected_generation, packet.expected_origin, observation.frame.frame_id, current);
  if (FRAME_IDENTITY_KEYS.some(key => selected.frame[key] !== observation.frame[key])) throw fail('stale_browser_frame');
  frameChainCurrent(record, observation.frameChain.chain, selected.list, current);
  if (!await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
  current(); return selected.frame;
}
async function frameInputGuard(record, packet, observation, point, requireFocus = false, checkpoint = () => {}) {
  if(!observation.frameChain)return {root_point:{x:point.x,y:point.y},frame_hits:[]};
  const current=()=>frameClaimCurrent(record,packet,checkpoint),bound=observation.frameChain;
  current();
  const catalog=await frames(record,current);frameChainCurrent(record,bound.chain,catalog,current);
  let geometry=await readFrameGeometry(record,bound.chain,current);
  if(JSON.stringify(geometry.identity)!==JSON.stringify(bound.geometry))throw fail('frame_transform_changed');
  if(!await ownsActualTarget(record,current))throw fail('browser_claim_owner_mismatch');current();
  // Target metadata can yield after a stable geometry read. Re-read the quads
  // even when the iframe's axis-aligned bounds remained identical.
  geometry=await readFrameGeometry(record,bound.chain,current);
  if(JSON.stringify(geometry.identity)!==JSON.stringify(bound.geometry))throw fail('frame_transform_changed');
  const topology=record.frameTopologyEpoch||0;
  const rootPoint=frameMapPoint(geometry.docMaps.get(observation.frame.frame_id),point),hits=[],group='frame-hit:'+uuid();
  try {
    for(const boundary of [...geometry.identity.boundaries].reverse()) {
      const parent=bound.chain.find(row=>row.frame.frame_id===boundary.parent_frame_id);frameContextCurrent(record,parent);
      const parentPoint=frameMapPoint(frameInverse(geometry.docMaps.get(parent.frame.frame_id)),rootPoint);
      const object=await cdp(record,'DOM.resolveNode',{backendNodeId:boundary.owner_backend_node_id,executionContextId:parent.contextId,objectGroup:group},parent.frame.session_id);
      current();frameContextCurrent(record,parent);
      const result=await cdp(record,'Runtime.callFunctionOn',{objectId:object.object.objectId,functionDeclaration:frameOwnerState.toString(),
        arguments:[{value:parentPoint.x},{value:parentPoint.y}],returnByValue:true},parent.frame.session_id);
      current();frameContextCurrent(record,parent);const state=result.result?.value;
      if(result.exceptionDetails || state?.error || !state?.connected || !state.hit_matches_owner)throw fail(state?.error||'ancestor_frame_obstructed');
      if(requireFocus && !state.focused)throw fail('target_focus_changed');
      hits.push({frame_id:boundary.parent_frame_id,owner_backend_node_id:boundary.owner_backend_node_id,...parentPoint,hit_matches_owner:true,focused:state.focused});
    }
  } finally {
    for(const session of new Set(bound.chain.map(row=>row.frame.session_id))) {
      try {await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},session);}catch {/* Context teardown releases its objects. */}
      current();
    }
  }
  frameChainCurrent(record,bound.chain,catalog,current);
  if((record.frameTopologyEpoch||0)!==topology)throw fail('stale_browser_frame');
  await verifyFrameGeometryForInput(record, packet, observation, current);
  return {root_point:rootPoint,frame_hits:hits};
}

function optionEffectivelyHidden(option) {
  for (let element = option; element && ['OPTION', 'OPTGROUP'].includes(element.tagName); element = element.parentElement) {
    const style = getComputedStyle(element);
    if (element.hidden || style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility)) return true;
  }
  return false;
}

// Isolated-world, main-frame keyboard focus proof. It is earned by a settled
// screenshot-bound click followed by an actual public EditContext focus read.
// It cannot be manufactured from role=code ancestry during ordinary snapshot.
function editingFocusWitnessState(observation, host, expected = globalThis.__workbenchEditingFocusWitness) {
  const witness = globalThis.__workbenchEditingFocusWitness;
  const refuse = () => { globalThis.__workbenchEditingFocusWitness = null; return null; };
  if (!witness || witness !== expected || witness.host !== host) return null;
  if (witness.binding !== observation.focusBinding) return refuse();
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const sample = observation.editingSample(host, true);
  if (active !== host || !sample || sample.kind !== 'public_edit_context' || sample.identity !== witness.context) return refuse();
  const sameRect = (a,b) => ['x','y','width','height'].every(k => Number.isFinite(a[k]) && a[k] === b[k]);
  for (const rows of [witness.hostChain, witness.clickedChain]) {
    for (const row of rows) {
      const element = row.element;
      if (!element.isConnected || element.getRootNode() !== row.root || element.parentElement !== row.parent
          || element.assignedSlot !== row.slot || observation.sensitiveAncestor(element)) return refuse();
      const style = getComputedStyle(element);
      if (element.hidden || element.inert || element.disabled || element.readOnly
          || element.getAttribute('aria-disabled') === 'true' || element.getAttribute('aria-readonly') === 'true'
          || style.display === 'none' || ['hidden','collapse'].includes(style.visibility) || Number(style.opacity) === 0) return refuse();
    }
  }
  if (witness.owner.getRootNode() !== witness.root || witness.clicked.getRootNode() !== witness.root
      || host.getRootNode() !== witness.root || !witness.owner.contains(host) || !witness.owner.contains(witness.clicked)
      || witness.owner.getAttribute('role') !== witness.ownerRole
      || !sameRect(witness.owner.getBoundingClientRect(), witness.ownerRect)
      || !sameRect(host.getBoundingClientRect(), witness.hostRect)
      || !sameRect(witness.clicked.getBoundingClientRect(), witness.clickedRect)) return refuse();
  const descendants = witness.owner.querySelectorAll('*');
  if (descendants.length > 2000 || [...descendants].filter(el => observation.editingSample(el,true)?.kind === 'public_edit_context').length !== 1) return refuse();
  const r = witness.ownerRect, h = witness.hostRect, {x,y} = witness.point;
  if (r.width <= 0 || r.height <= 0 || h.height <= 0 || h.width < 0 || h.x < r.x || h.x > r.x+r.width
      || h.y < r.y || h.y+h.height > r.y+r.height || x < r.x || x >= r.x+r.width || y < r.y || y >= r.y+r.height) return refuse();
  let hit = document.elementFromPoint(x,y), depth = 0;
  while (hit?.shadowRoot) {
    if (++depth > 100) return refuse();
    const nested = hit.shadowRoot.elementFromPoint(x,y);
    if (!nested || nested === hit) break;
    hit = nested;
  }
  if (hit !== witness.clicked || observation.sensitiveAncestor(hit)) return refuse();
  return { witness, rect:r, x,y, hit, id:witness.id };
}
function retainEditingFocusWitness(observationId, visualTargetId, point, binding) {
  globalThis.__workbenchEditingFocusWitness = null;
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId || observation.focusBinding !== binding) return { retained:false,reason:'focus_binding_changed' };
  const clicked = [...observation.visualElements].find(([,row]) => row.id === visualTargetId)?.[0];
  let host = document.activeElement;
  while (host?.shadowRoot?.activeElement) host = host.shadowRoot.activeElement;
  const sample = host && observation.editingSample(host, true), root = host?.getRootNode();
  if (!clicked || host !== observation.opaqueCheckedHost || !sample || sample.kind !== 'public_edit_context' || clicked.getRootNode() !== root
      || !observation.visualElements.has(host)) return { retained:false,reason:'public_edit_context_focus_not_observed' };
  // A named editing region is a candidate owner only after exact clicked-node
  // and genuine attached/focused-host evidence. BODY/HTML/common ancestry alone
  // never suffices, and multiple public editing hosts make the owner ambiguous.
  let owner = host.parentElement, depth = 0;
  for (; owner && ++depth <= 32; owner = owner.parentElement) {
    if (!['BODY','HTML'].includes(owner.tagName) && ['code','textbox'].includes(owner.getAttribute('role'))
        && owner.getRootNode() === root && owner.contains(clicked)) break;
  }
  if (!owner || depth > 32) return { retained:false,reason:'visible_editing_owner_unavailable' };
  const descendants = owner.querySelectorAll('*');
  if (descendants.length > 2000 || [...descendants].filter(el => observation.editingSample(el,true)?.kind === 'public_edit_context').length !== 1)
    return { retained:false,reason:'editing_owner_ambiguous' };
  const chain = element => {
    const rows = [];
    for (; element; element = element.assignedSlot || element.parentElement || element.getRootNode()?.host) {
      if (rows.length >= 100) return null;
      rows.push({element,root:element.getRootNode(),parent:element.parentElement,slot:element.assignedSlot});
    }
    return rows;
  };
  const hostChain = chain(host), clickedChain = chain(clicked);
  if (!hostChain || !clickedChain) return {retained:false,reason:'editing_owner_limit'};
  const rect = el => {const r=el.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height};};
  for (const row of [...hostChain,...clickedChain]) {
    const old = observation.visualElements.get(row.element);
    if (!old || old.root !== row.root || old.parent !== row.parent || old.slot !== row.slot
        || old.sensitive || old.disabled || old.aria_disabled === 'true' || !Array.isArray(old.styles)
        || old.styles[0] === 'none' || ['hidden','collapse'].includes(old.styles[1]) || Number(old.styles[3]) === 0)
      return {retained:false,reason:'focus_lineage_changed'};
  }
  const witness = { id:crypto.randomUUID().replaceAll('-',''),binding,host,context:sample.identity,root,clicked,owner,
    ownerRole:owner.getAttribute('role'),hostChain,clickedChain,point:{...point},ownerRect:rect(owner),hostRect:rect(host),clickedRect:rect(clicked) };
  // Original owner/clicked geometry and all identities remain fixed. A genuine
  // zero-width caret host may naturally move inside that unchanged owner as a
  // consequence of this click. Freeze its POST-click rectangle for later input;
  // this never changes the original pointer coordinates or recipient.
  for (const element of [host,clicked,owner]) {
    const old = observation.visualElements.get(element), now = rect(element);
    if (!old || old.root !== element.getRootNode() || old.parent !== element.parentElement || old.slot !== element.assignedSlot)
      return {retained:false,reason:'focus_lineage_changed'};
    if (element === owner && old.role !== witness.ownerRole) return {retained:false,reason:'focus_owner_changed'};
    const caretMotion = element === host && old.rect.width === 0 && now.width === 0 && old.rect.height > 0 && now.height > 0;
    if (!caretMotion && ['x','y','width','height'].some(k => old.rect[k] !== now[k])) return {retained:false,reason:'focus_lineage_changed'};
    if (element === host) {
      if (old.editingIdentity !== sample.identity) return {retained:false,reason:'focus_context_changed'};
      const r=witness.ownerRect,h=old.rect;
      if (h.x < r.x || h.x > r.x+r.width || h.y < r.y || h.y+h.height > r.y+r.height)
        return {retained:false,reason:'focus_host_outside_original_owner'};
    }
  }
  globalThis.__workbenchEditingFocusWitness = witness;
  const checked = observation.focusWitnessState(host, witness);
  return checked ? {retained:true,witness_id:witness.id,kind:'public_edit_context',owner_rect:checked.rect,
    point:{...point},scope:'post_click_public_focus_only_not_recipient_edit_effect'} : {retained:false,reason:'focus_lineage_unverified'};
}
async function guardEditingHostShadow(record, observation, targetId, current) {
  const group = 'workbench-editing-host:' + uuid();
  const composed = observation.composedEditingTargets?.includes(targetId) === true;
  try {
    current();
    const expression = '(() => { const o = globalThis.__workbenchObservation; if (!o || o.id !== '
      + JSON.stringify(observation.id) + ') return null; let el = '
      + (targetId == null ? 'document.activeElement; while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;'
        : 'o.targets.get(' + JSON.stringify(targetId) + ')?.element;')
      + ' o.opaqueCheckedHost = el; return el; })()';
    const resolved = await cdp(record,'Runtime.evaluate',{expression,uniqueContextId:observation.contextUniqueId,
      objectGroup:group,returnByValue:false,awaitPromise:false},observation.frame.session_id,current);
    current();
    if (resolved.exceptionDetails || !resolved.result?.objectId) throw fail('editing_host_shadow_unverified');
    const described = await cdp(record,'DOM.describeNode',{objectId:resolved.result.objectId,depth:composed?0:1,pierce:!composed},observation.frame.session_id,current);
    current();
    if (!described.node || described.node.nodeType !== 1) throw fail('editing_host_shadow_unverified');
    if (described.node.shadowRoots?.some(root => root.shadowRootType === 'closed')) throw fail('closed_shadow_editing_unsupported');
    if (composed) {
      const deadline=performance.now()+250,checked=()=>{current();if(performance.now()>=deadline)throw fail('editing_shadow_ancestor_timeout');};
      const prefix='(() => { const o=globalThis.__workbenchObservation; const item=o?.id==='
        +JSON.stringify(observation.id)+'?o.targets.get('+JSON.stringify(targetId)+'):null; const rows=item?.editing?.shadowLineage;';
      const meta=await cdp(record,'Runtime.evaluate',{expression:prefix+'return rows?.map(r=>!!r.ownShadow);})()',
        uniqueContextId:observation.contextUniqueId,returnByValue:true},observation.frame.session_id,current);
      checked();const expected=meta.result?.value;
      if(meta.exceptionDetails||!Array.isArray(expected)||!expected.length||expected.length>100||expected.some(v=>typeof v!=='boolean'))throw fail('editing_shadow_ancestor_unverified');
      for(let i=0;i<expected.length;i++){
        checked();const object=await cdp(record,'Runtime.evaluate',{expression:prefix+'return rows?.['+i+']?.element;})()',
          uniqueContextId:observation.contextUniqueId,objectGroup:group,returnByValue:false},observation.frame.session_id,current);
        checked();if(object.exceptionDetails||!object.result?.objectId)throw fail('editing_shadow_ancestor_unverified');
        // Metadata only. Closed root contents and unrepresented roots never
        // become public Selection authority via a null assignedSlot getter.
        const described=await cdp(record,'DOM.describeNode',{objectId:object.result.objectId,depth:0,pierce:false},observation.frame.session_id,current);
        checked();const roots=described.node?.shadowRoots||[];
        if(described.node?.nodeType!==1||!Array.isArray(roots)||roots.length!==(expected[i]?1:0)||roots.some(r=>r.shadowRootType!=='open'))throw fail('closed_shadow_editing_unsupported');
      }
    }
    if (described.node.attributes?.some((name,i) => i % 2 === 0 && name === 'contenteditable')) {
      const deadline = performance.now() + 250;
      const checked = () => { current(); if (performance.now() >= deadline) throw fail('editing_descendant_shadow_timeout'); };
      const prefix = '(() => { const o=globalThis.__workbenchObservation; const item=o?.id==='
        + JSON.stringify(observation.id) + '?o.targets.get(' + JSON.stringify(targetId) + '):null;'
        + 'const nodes=item?.editing?.kind==="public_dom_contenteditable"?item.editing.nodes.filter(r=>r.node.nodeType===1):[];';
      const count = await cdp(record,'Runtime.evaluate',{expression:prefix+'return nodes.length;})()',
        uniqueContextId:observation.contextUniqueId,returnByValue:true},observation.frame.session_id,current);
      checked(); const size=count.result?.value;
      if (!Number.isSafeInteger(size) || size < 0 || size > 256) throw fail('editing_descendant_shadow_unverified');
      // Public per-element depth-zero descriptions reveal closed roots without
      // reading their contents or requesting an unbounded hidden subtree.
      // Independent metadata reads share the original deadline. Bound their
      // concurrency so transport latency does not accumulate per descendant;
      // settle the whole batch before releasing remote references on refusal.
      for (let first=1;first<size;first+=8) {
        checked();
        const batch=await Promise.allSettled(Array.from({length:Math.min(8,size-first)},async (_,offset)=>{
          const i=first+offset;
          checked(); const child=await cdp(record,'Runtime.evaluate',{expression:prefix+'return nodes['+i+']?.node;})()',
            uniqueContextId:observation.contextUniqueId,objectGroup:group,returnByValue:false},observation.frame.session_id,current);
          checked(); if (!child.result?.objectId || child.exceptionDetails) throw fail('editing_descendant_shadow_unverified');
          const node=await cdp(record,'DOM.describeNode',{objectId:child.result.objectId,depth:0,...(composed?{pierce:false}:{})},observation.frame.session_id,current);
          checked(); if (!node.node || node.node.nodeType!==1 || node.node.shadowRoots?.length) throw fail('closed_shadow_editing_unsupported');
        }));
        for(const result of batch)if(result.status==='rejected')throw result.reason;
        checked();
      }
    }
  } finally {
    try { await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},observation.frame.session_id); }
    catch { /* An ended world releases its remote references. */ }
    current();
  }
}
function editingFocusBinding(record, observation) {
  return record.durable && !observation.frame.parent_id && !observation.frame.session_id ? JSON.stringify([
    record.id,record.claim_epoch,record.owner_session,record.runtime_generation,record.installation_id,record.peerId,
    record.target.target_generation,record.target.browser_target_id,record.generation,observation.frame.frame_id,
    observation.frame.loader_id,observation.contextUniqueId,record.editingFocusRevision || 0]) : null;
}

function observePage(observationId, captureGuard = false, paired = false, focusBinding = null) {
  const targets = new Map(), controls = [];
  const editingSample = (element, bounded = false, metadataOnly = false, navigation = false) => {
    const native = element.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
      : element.tagName === 'INPUT' && ['text','search','tel','url'].includes(element.type) ? HTMLInputElement.prototype : null;
    const get = (proto, key, object) => Object.getOwnPropertyDescriptor(proto, key)?.get?.call(object);
    if (native) {
      if (metadataOnly || navigation) return null; // A DOM witness must never read another recipient kind.
      const text = get(native, 'value', element), start = get(native, 'selectionStart', element), end = get(native, 'selectionEnd', element),
        direction = get(native, 'selectionDirection', element);
      return typeof text === 'string' && (bounded || text.length <= 4096) && Number.isInteger(start) && Number.isInteger(end)
        && start >= 0 && end >= start && end <= text.length ? { kind:'native_text_control', text:text.slice(0,4096), textLength:text.length, start, end,
          readOnly:get(native, 'readOnly', element), disabled:get(native, 'disabled', element),
          identity:null, ...(['forward','backward','none'].includes(direction)?{direction}:{}),
          maxLength:get(native, 'maxLength', element), scope:'complete_native_value' } : null;
    }
    if (typeof HTMLElement === 'undefined' || !(element instanceof HTMLElement)) return null;
    const context = typeof EditContext === 'undefined' ? null : get(HTMLElement.prototype, 'editContext', element);
    if ((metadataOnly || navigation) && context) return null;
    if (!context) {
      // Experimental open-root basis: composed StaticRange extent plus native
      // direction, explicitly distinct from the document raw-getter contract.
      const editorRoot = element.getRootNode(), shadow = editorRoot !== document;
      let shadowLineage = null, shadowRoots = null;
      if (shadow) {
        if (typeof ShadowRoot === 'undefined' || typeof Selection === 'undefined'
            || typeof AbstractRange === 'undefined' || typeof StaticRange === 'undefined') return null;
        shadowLineage = []; shadowRoots = [];
        let owner = element;
        while (owner) {
          if (shadowLineage.length >= 100 || !owner.isConnected || owner.assignedSlot
              || owner !== element && owner.isContentEditable) return null;
          const root = owner.getRootNode(), parent = owner.parentElement, ownShadow = owner.shadowRoot;
          if (root !== document) {
            if (!(root instanceof ShadowRoot) || get(ShadowRoot.prototype,'mode',root) !== 'open') return null;
            const host = get(ShadowRoot.prototype,'host',root);
            if (!host || host.shadowRoot !== root) return null;
            if (!shadowRoots.includes(root)) shadowRoots.push(root);
          }
          shadowLineage.push({element:owner,root,parent,slot:owner.assignedSlot,ownShadow});
          owner = parent || (root !== document ? get(ShadowRoot.prototype,'host',root) : null);
        }
        if (!shadowRoots.length || shadowLineage.at(-1)?.root !== document
            || shadowLineage.some(row => row.ownShadow && !shadowRoots.includes(row.ownShadow))) return null;
      }
      // Raw DOM text stays separate from explicit paragraph/BR structure.
      // No rendered-line serialization or hidden/protected editor islands.
      if (!element.isContentEditable || !['','true','plaintext-only'].includes(element.getAttribute('contenteditable'))
          || element.shadowRoot) return null;
      for (let owner = element.parentElement; owner; owner = owner.parentElement)
        if (owner.isContentEditable) return null;
      const nodes = [], byNode = new Map(); let text = '', textLength = 0, maxDepth = 0;
      const visit = (node, parent, depth) => {
        if (depth > 32 || nodes.length >= 256) return false;
        const type = get(Node.prototype, 'nodeType', node);
        const row = {node,parent,index:nodes.length,start:textLength,children:[],kind:type===Node.TEXT_NODE?'text':'inline'};
        maxDepth=Math.max(maxDepth,depth);nodes.push(row); byNode.set(node,row);
        if (type === Node.TEXT_NODE) {
          if (metadataOnly) {
            const length=get(CharacterData.prototype,'length',node);
            if (!Number.isSafeInteger(length) || length<0 || textLength+length>4096) return false;
            textLength+=length;
          } else {
            const value = get(Node.prototype, 'textContent', node);
            if (typeof value !== 'string' || textLength + value.length > 4096) return false;
            text += value; textLength+=value.length;
          }
        } else if (type === Node.ELEMENT_NODE) {
          if (sensitiveAncestor(node) || node.hidden || node.inert || node.disabled || !navigation && node.readOnly
              || node.getAttribute('aria-disabled') === 'true' || !navigation && node.getAttribute('aria-readonly') === 'true') return false;
          const style = getComputedStyle(node);
          if (style.display === 'none' || ['hidden','collapse'].includes(style.visibility) || Number(style.opacity) === 0) return false;
          row.tag=node.tagName.toLowerCase();
          const block=['P','DIV'].includes(node.tagName);
          if (node !== element && (!['SPAN','B','I','U','S','EM','STRONG','CODE','MARK','P','DIV','BR'].includes(node.tagName)
              || (block ? style.display!=='block' : style.display!=='inline')
              || node.hasAttribute('contenteditable') || !node.isContentEditable
              || node.shadowRoot || typeof EditContext !== 'undefined' && get(HTMLElement.prototype,'editContext',node))) return false;
          row.kind=node===element?'root':block?'paragraph':node.tagName==='BR'?'line_break':'inline';
          const children = get(Node.prototype,'childNodes',node);
          if (children.length > 256 - nodes.length) return false;
          row.children = Array.from(children);
          for (const child of row.children) if (!visit(child,node,depth+1)) return false;
        } else return false;
        row.end = textLength; return true;
      };
      if (!visit(element,null,0)) return null;
      if (navigation==='prepare') return {kind:'public_dom_contenteditable',identity:element,textLength,nodes,
        ...(shadow?{shadowLineage,shadowRoots}:{})};
      const selection = Document.prototype.getSelection.call(document);
      if (!selection || !shadow && get(Selection.prototype,'rangeCount',selection) !== 1) return null;
      const point = (node,offset) => {
        const row = byNode.get(node); if (!row || !Number.isInteger(offset) || offset < 0) return null;
        if (get(Node.prototype,'nodeType',node) === Node.TEXT_NODE) return offset <= row.end-row.start ? row.start+offset : null;
        return offset <= row.children.length ? (offset === row.children.length ? row.end : byNode.get(row.children[offset]).start) : null;
      };
      const ordered = (left,lo,right,ro) => {
        if (left === right) return lo <= ro;
        const childIndex = (parent,node) => {
          for (let child=node, row=byNode.get(node); row?.parent; child=row.parent,row=byNode.get(row.parent))
            if (row.parent === parent) return byNode.get(parent).children.indexOf(child);
          return -1;
        };
        const child=childIndex(left,right);if(child>=0)return lo<=child;
        const reverse=childIndex(right,left);if(reverse>=0)return reverse<ro;
        return byNode.get(left).index < byNode.get(right).index;
      };
      let anchor = get(Selection.prototype,'anchorNode',selection), focus = get(Selection.prototype,'focusNode',selection),
        anchorOffset = get(Selection.prototype,'anchorOffset',selection), focusOffset = get(Selection.prototype,'focusOffset',selection);
      let composedWitness = null;
      if (shadow) {
        try {
          if (typeof Selection.prototype.getComposedRanges !== 'function') return null;
          const ranges = Selection.prototype.getComposedRanges.call(selection,{shadowRoots});
          if (!Array.isArray(ranges) || ranges.length !== 1 || !(ranges[0] instanceof StaticRange)) return null;
          const range = ranges[0];
          // Platform layouts may place native node-returning accessors on an
          // intermediate prototype. Start at this realm's StaticRange prototype,
          // never the instance (own getters) or an assumed interface name.
          const rangeGet = key => {
            let prototype = StaticRange.prototype;
            for (let depth=0;depth<8 && prototype && prototype!==Object.prototype;depth++,prototype=Object.getPrototypeOf(prototype)) {
              const descriptor=Object.getOwnPropertyDescriptor(prototype,key);
              if (descriptor) {
                if ('value' in descriptor || typeof descriptor.get!=='function') throw Error('range_accessor_unavailable');
                return descriptor.get.call(range); // Native getter also enforces its receiver brand.
              }
            }
            throw Error('range_accessor_unavailable');
          };
          const startNode = rangeGet('startContainer'), endNode = rangeGet('endContainer'), startOffset = rangeGet('startOffset'),
            endOffset = rangeGet('endOffset'), collapsed = rangeGet('collapsed'),
            direction = get(Selection.prototype,'direction',selection), rawCollapsed = get(Selection.prototype,'isCollapsed',selection),
            rangeCount = get(Selection.prototype,'rangeCount',selection);
          if (!['none','forward','backward'].includes(direction) || !Number.isSafeInteger(anchorOffset) || anchorOffset < 0
              || !Number.isSafeInteger(focusOffset) || focusOffset < 0 || typeof collapsed !== 'boolean'
              || typeof rawCollapsed !== 'boolean' || rangeCount !== 1 || !collapsed && direction === 'none') return null;
          const start = point(startNode,startOffset), end = point(endNode,endOffset);
          if (start === null || end === null || start > end || !ordered(startNode,startOffset,endNode,endOffset) || startNode.getRootNode() !== editorRoot
              || endNode.getRootNode() !== editorRoot || collapsed !== (startNode === endNode && startOffset === endOffset)) return null;
          composedWitness = {startNode,endNode,startOffset,endOffset,collapsed,direction,
            rawAnchor:anchor,rawFocus:focus,rawAnchorOffset:anchorOffset,rawFocusOffset:focusOffset,rawCollapsed,rangeCount};
          // These oriented points are derived ONLY from the actual composed
          // extent and independently branded direction, never raw host offsets.
          const backward = !collapsed && direction === 'backward';
          anchor = backward ? endNode : startNode; focus = backward ? startNode : endNode;
          anchorOffset = backward ? endOffset : startOffset; focusOffset = backward ? startOffset : endOffset;
        } catch { return null; }
      }
      const a = point(anchor,anchorOffset), f = point(focus,focusOffset); if (a === null || f === null) return null;
      const start = Math.min(a,f), end = Math.max(a,f);
      if (!shadow && !metadataOnly) {
        const range = Selection.prototype.getRangeAt.call(selection,0);
        if (Range.prototype.toString.call(range) !== text.slice(start,end)) return null;
      }
      if (metadataOnly) return {kind:'public_dom_contenteditable',identity:element,textLength,start,end,nodes,anchor,focus,anchorOffset,focusOffset,
        ...(shadow?{shadowLineage,shadowRoots,composedWitness}:{})};
      const structure={basis:'DOM_nodes_and_boundaries_not_rendered_lines',node_count:nodes.length,max_depth:maxDepth,
        nodes:nodes.map(row=>({index:row.index,parent_index:row.parent===null?null:byNode.get(row.parent).index,
          kind:row.kind,...(row.tag?{tag:row.tag}:{}),text_start:row.start,text_end:row.end,child_count:row.children.length})),
        selection:shadow ? {basis:'public_composed_static_range_and_native_direction',is_collapsed:composedWitness.collapsed,
          native_direction:composedWitness.direction,orientation:'derived_from_native_direction_not_raw_getters',
          start_node_index:byNode.get(composedWitness.startNode).index,start_offset:composedWitness.startOffset,
          end_node_index:byNode.get(composedWitness.endNode).index,end_offset:composedWitness.endOffset,
          anchor_node_index:byNode.get(anchor).index,anchor_offset:anchorOffset,focus_node_index:byNode.get(focus).index,focus_offset:focusOffset,
          raw_getter_witness:{basis:'raw_native_Selection_getters',anchor_node_type:composedWitness.rawAnchor?get(Node.prototype,'nodeType',composedWitness.rawAnchor):null,
            focus_node_type:composedWitness.rawFocus?get(Node.prototype,'nodeType',composedWitness.rawFocus):null,anchor_inside_editor:byNode.has(composedWitness.rawAnchor),
            focus_inside_editor:byNode.has(composedWitness.rawFocus),anchor_offset:composedWitness.rawAnchorOffset,
            focus_offset:composedWitness.rawFocusOffset,is_collapsed:composedWitness.rawCollapsed,range_count:composedWitness.rangeCount,
            direction:composedWitness.direction}}
          : {basis:'exact_DOM_boundary_points',is_collapsed:get(Selection.prototype,'isCollapsed',selection),anchor_node_index:byNode.get(anchor).index,anchor_offset:anchorOffset,focus_node_index:byNode.get(focus).index,focus_offset:focusOffset}};
      return {kind:'public_dom_contenteditable',identity:element,text,textLength:text.length,start,end,nodes,anchor,focus,anchorOffset,focusOffset,structure,
        ...(shadow?{shadowLineage,shadowRoots,composedWitness}:{}),
        scope:shadow?'complete_bounded_open_shadow_DOM_textContent_with_composed_selection_not_rendered_text'
          :'complete_bounded_DOM_textContent_with_structural_boundaries_not_rendered_text'};
    }
    try {
      const attached = EditContext.prototype.attachedElements.call(context);
      if (attached.length !== 1 || attached[0] !== element) return null;
      const text = get(EditContext.prototype, 'text', context), start = get(EditContext.prototype, 'selectionStart', context), end = get(EditContext.prototype, 'selectionEnd', context);
      return typeof text === 'string' && (bounded || text.length <= 4096) && Number.isInteger(start) && Number.isInteger(end)
        && start >= 0 && start <= text.length && end >= 0 && end <= text.length ? { kind:'public_edit_context', text:text.slice(0,4096), textLength:text.length, start, end,
          identity:context, scope:'public_edit_context_only_not_entire_editor' } : null;
    } catch { return null; }
  };
  const selector = 'button,input,textarea,select,a,label,[role="button"],[role="checkbox"],[contenteditable="true"]';
  const sensitiveAncestor = (node, association = true) => {
    let element = node.nodeType === Node.TEXT_NODE ? node.assignedSlot || node.parentElement || node.getRootNode?.()?.host : node;
    while (element) {
      if (association && element.tagName === 'LABEL' && element.namespaceURI === 'http://www.w3.org/1999/xhtml'
          && element.control && sensitiveAncestor(element.control, false)) return true;
      if (element.type === 'password' || element.type === 'hidden'
          || /password|secret|token|session|authorization/i.test(element.name || element.getAttribute?.('name') || '')) return true;
      element = element.assignedSlot || element.parentElement || element.getRootNode?.()?.host;
    }
    return false;
  };
  const associatedLabels = element => {
    if (element.namespaceURI !== 'http://www.w3.org/1999/xhtml') return null;
    const prototype = ({ INPUT: globalThis.HTMLInputElement, BUTTON: globalThis.HTMLButtonElement,
      TEXTAREA: globalThis.HTMLTextAreaElement, SELECT: globalThis.HTMLSelectElement })[element.tagName]?.prototype;
    if (!['INPUT','BUTTON','TEXTAREA','SELECT'].includes(element.tagName)) return null;
    const unavailable = reason => ({ complete: false, count: null, rows: [], reason });
    try {
      const getter = prototype && Object.getOwnPropertyDescriptor(prototype, 'labels')?.get;
      if (!getter) return unavailable('native_labels_unavailable');
      const native = getter.call(element);
      if (native === null) return { complete: true, count: 0, rows: [] };
      if (!Number.isSafeInteger(native?.length) || native.length < 0) return unavailable('native_labels_unavailable');
      if (native.length > 16) return { ...unavailable('label_count_limit'), count: native.length };
      const rows = [], root = element.getRootNode();
      for (let index = 0; index < native.length; index++) {
        const label = native[index];
        if (!label?.isConnected || label.tagName !== 'LABEL' || label.namespaceURI !== 'http://www.w3.org/1999/xhtml'
            || label.getRootNode() !== root || label.control !== element || rows.some(row => row.element === label))
          return unavailable('native_label_binding_unavailable');
        rows.push({ element: label, root, control: label.control, htmlFor: label.htmlFor,
          parent: label.parentElement, sensitive: sensitiveAncestor(label) });
      }
      return { complete: true, count: rows.length, rows };
    } catch { return unavailable('native_labels_unavailable'); }
  };
  const labelText = (element, limit, budget) => {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let text = '', node = null;
    while (text.length < limit && budget.remaining > 0 && (node = walker.nextNode())) {
      budget.remaining--;
      if (!sensitiveAncestor(node) && !['SCRIPT','STYLE','NOSCRIPT'].includes(node.parentElement?.tagName))
        text += node.nodeValue.slice(0, limit - text.length);
    }
    return { text, truncated: !!node && (text.length >= limit || budget.remaining === 0) };
  };
  const semanticLabelInfo = (element, native = associatedLabels(element)) => {
    const metadata = { associated_labels_supported: native !== null, associated_label_count: native ? native.count : 0,
      associated_labels_complete: native?.complete ?? true,
      associated_labels_redacted: native?.rows.some(row => row.sensitive) || false,
      ...(native && !native.complete ? { label_association_reason: native.reason } : {}) };
    const finish = (label, source, truncated = false) => ({ label, label_source: source, label_truncated: truncated, ...metadata });
    // Privacy takes precedence over explicit labels and placeholders too.
    if (sensitiveAncestor(element)) return finish('', 'redacted');
    if (native && !native.complete) return finish('', 'unavailable');
    for (const [attribute, source] of [['aria-label','aria_label'],['placeholder','placeholder']]) {
      const explicit = element.getAttribute(attribute);
      if (explicit) return finish(explicit.slice(0, 180), source, explicit.length > 180);
    }
    if (native?.rows.length) {
      const budget = { remaining: 1000 }; let label = '', truncated = false;
      for (const row of native.rows) {
        if (row.sensitive) continue;
        const room = 180 - label.length - (label ? 1 : 0);
        if (room <= 0 || budget.remaining <= 0) { truncated = true; break; }
        const text = labelText(row.element, room, budget);
        const part = text.text.replace(/\s+/g, ' ').trim();
        if (part) label += (label ? ' ' : '') + part;
        truncated ||= text.truncated;
      }
      return finish(label, label ? 'native_labels' : metadata.associated_labels_redacted ? 'native_labels_redacted' : 'native_labels', truncated);
    }
    const text = labelText(element, 180, { remaining: 1000 });
    return finish(text.text, text.text ? 'descendant_text' : 'none', text.truncated);
  };
  const semanticLabel = element => semanticLabelInfo(element).label;
  const labelAssociation = element => {
    if (element.tagName !== 'LABEL' || element.namespaceURI !== 'http://www.w3.org/1999/xhtml') return null;
    const control = element.control;
    return { control, htmlFor: element.htmlFor, controlRoot: control?.getRootNode(),
      disabled: !!control && (!!control.disabled || control.matches(':disabled') || control.getAttribute('aria-disabled') === 'true'),
      readOnly: !!control && (!!control.readOnly || control.getAttribute('aria-readonly') === 'true'),
      sensitive: !!control && sensitiveAncestor(control), type: control?.type, name: control?.name };
  };
  const formGuard = element => {
    if (element.tagName === 'INPUT' && element.type === 'checkbox') return { checked: !!element.checked, indeterminate: !!element.indeterminate };
    if (element.tagName !== 'SELECT') return null;
    if (element.options.length > 1000) return { error: 'select_options_limit' };
    let bytes = 0;
    const options = [];
    for (const option of element.options) {
      const value = option.value, text = option.text;
      if (value.length > 4096 || text.length > 4096) return { error: 'select_options_limit' };
      const valueBytes = new TextEncoder().encode(value).length, textBytes = new TextEncoder().encode(text).length;
      bytes += valueBytes + textBytes;
      if (valueBytes > 4096 || textBytes > 4096 || bytes > 65536) return { error: 'select_options_limit' };
      options.push({ element: option, value, text, selected: !!option.selected,
        disabled: option.matches(':disabled'), hidden: optionEffectivelyHidden(option) });
    }
    return { multiple: !!element.multiple, options };
  };
  const roots = [{ root: document, depth: 0 }], captureElements = [], captureTextNodes = [], observers = [];
  globalThis.__workbenchObservation?.observers?.forEach(observer => observer.disconnect());
  // Keep exact DOM objects privately in the isolated world. A point picked
  // from an image must not silently bind to a newly exposed or moved element.
  const visualElements = new Map();
  const visualSample = element => {
    const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
    const properties = ['display','visibility','pointer-events','opacity','position','z-index','transform','transform-origin',
      'translate','rotate','scale','perspective','perspective-origin','clip','clip-path','overflow-x','overflow-y',
      'border-radius','contain','isolation','filter','offset-path','offset-distance','offset-rotate'];
    const values = properties.map(key => style.getPropertyValue(key));
    if (values.some(value => value.length > 4096) || [rect.x,rect.y,rect.width,rect.height].some(value => !Number.isFinite(value))) return null;
    return { root: element.getRootNode(), parent: element.parentElement, slot: element.assignedSlot,
      rect: { x:rect.x,y:rect.y,width:rect.width,height:rect.height }, styles: values,
      sensitive:sensitiveAncestor(element), role:element.getAttribute('role'), disabled: !!element.disabled, aria_disabled: element.getAttribute('aria-disabled'),
      input_type: element.type, checked: typeof element.checked === 'boolean' ? element.checked : null,
      editingIdentity: typeof HTMLElement !== 'undefined' && element instanceof HTMLElement
        ? Object.getOwnPropertyDescriptor(HTMLElement.prototype,'editContext')?.get?.call(element) : null };
  };
  const observation = { id: observationId, targets, semanticLabel, associatedLabels, sensitiveAncestor, revision: 0, observers, captureElements, captureTextNodes,
    visualElements, visualSample, labelAssociation, editingSample, focusBinding, visualMapComplete: true };
  observation.focusWitnessState = (host, expected) => editingFocusWitnessState(observation, host, expected);
  if (globalThis.__workbenchEditingFocusWitness?.binding !== focusBinding) globalThis.__workbenchEditingFocusWitness = null;
  globalThis.__workbenchObservation = observation;
  if (globalThis.__workbenchEditingFocusWitness) observation.focusWitnessState(globalThis.__workbenchEditingFocusWitness.host);
  const visualViewportState = () => globalThis.visualViewport ? { width:visualViewport.width,height:visualViewport.height,
    offset_x:visualViewport.offsetLeft,offset_y:visualViewport.offsetTop,page_x:visualViewport.pageLeft,page_y:visualViewport.pageTop,scale:visualViewport.scale } : null;
  observation.visualViewportState = visualViewportState;
  const scanViewport = { width: innerWidth, height: innerHeight, device_scale: devicePixelRatio, scroll_x: scrollX, scroll_y: scrollY,
    visual_viewport: visualViewportState() };
  let omitted = 0, text = '', omittedText = false, nodes = 0, rootsVisited = 0;
  for (let index = 0; index < roots.length && nodes < 10000; index++) {
    const { root, depth } = roots[index]; rootsVisited++;
    const observer = new MutationObserver(() => observation.revision++);
    observer.observe(root, { subtree: true, childList: true, attributes: true, characterData: true }); observers.push(observer);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    let node;
    while (nodes < 10000 && (node = walker.nextNode())) {
      nodes++;
      if (node.nodeType === Node.TEXT_NODE) {
        if (captureGuard && sensitiveAncestor(node) && !['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.parentElement?.tagName)) captureTextNodes.push(node);
        if (sensitiveAncestor(node) || ['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.parentElement?.tagName)) continue;
        const remaining = 1048576 - text.length;
        if (remaining <= 0) { omittedText = true; continue; }
        text += node.nodeValue.slice(0, Math.max(0, remaining - 1)) + '\n';
        if (node.nodeValue.length + 1 > remaining) omittedText = true;
        continue;
      }
      const element = node;
      if (element.shadowRoot) roots.push({ root: element.shadowRoot, depth: depth + 1 });
      if (captureGuard) {
        const sample = visualSample(element);
        if (!sample) observation.visualMapComplete = false;
        else visualElements.set(element, { ...sample, id: crypto.randomUUID().replaceAll('-', '') });
      }
      if (captureGuard && (sensitiveAncestor(element) || ['IFRAME', 'FRAME'].includes(element.tagName))) {
        const rect = element.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0 && getComputedStyle(element).visibility !== 'hidden')
          captureElements.push(element);
      }
      const editing = sensitiveAncestor(element) ? null : editingSample(element);
      if (!element.matches(selector) && !editing) continue;
      const r = element.getBoundingClientRect();
      const focusOwner = editing?.kind === 'public_edit_context' && observation.focusWitnessState(element);
      if ((r.width <= 0 || r.height <= 0) && !focusOwner || getComputedStyle(element).visibility === 'hidden') continue;
      if (controls.length >= 200) { omitted++; continue; }
      const sensitive = sensitiveAncestor(element);
      const nativeLabels = associatedLabels(element), labelInfo = semanticLabelInfo(element, nativeLabels);
      const id = crypto.randomUUID().replaceAll('-', '');
      const description = { target_id: id, tag: element.tagName.toLowerCase(), role: element.getAttribute('role'),
        ...labelInfo, dom_id: sensitive ? null : String(element.id || '').slice(0, 180),
        name: sensitive ? null : String(element.name || '').slice(0, 180),
        type: typeof element.type === 'string' ? element.type.slice(0, 32) : null,
        identity_attributes_truncated: !sensitive && (String(element.id || '').length > 180 || String(element.name || '').length > 180),
        disabled: !!element.disabled, sensitive, value: sensitive ? null : ('value' in element ? String(element.value).slice(0, 4096) : null),
        value_truncated: !sensitive && 'value' in element && String(element.value).length > 4096,
        checked: 'checked' in element ? !!element.checked : null, shadow_root_depth: depth,
        rect: { x: r.x, y: r.y, width: r.width, height: r.height } };
      if (focusOwner) description.editing_owner = { witness_id:focusOwner.id, rect:focusOwner.rect,
        point:{x:focusOwner.x,y:focusOwner.y}, keyboard_only:true, source:'settled_screenshot_click_then_public_focus_read' };
      if (editing) description.editing_context = { kind:editing.kind, text:editing.text,
        selection_start:editing.start, selection_end:editing.end, offset_units:'UTF-16 code units', scope:editing.scope, ...(editing.direction?{selection_direction:editing.direction}:{}),
        ...(editing.structure?{dom_structure:editing.structure}:{}) };
      // Native numeric ranges are observation data, never inferred from page text.
      if (!sensitive) {
        const proto = element.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
          : element.tagName === 'INPUT' && ['text','search','tel','url'].includes(element.type) ? HTMLInputElement.prototype : null;
        if (proto) {
          const start = Object.getOwnPropertyDescriptor(proto, 'selectionStart').get.call(element);
          const end = Object.getOwnPropertyDescriptor(proto, 'selectionEnd').get.call(element);
          if (Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end >= start) {
            description.selection_start = start; description.selection_length = end - start;
            description.selection_end = end; description.offset_units = 'UTF-16 code units';
            description.max_length = Object.getOwnPropertyDescriptor(proto, 'maxLength').get.call(element);
          }
        }
      }
      targets.set(id, { element, description, editing, focusWitness:focusOwner?.witness, associatedLabels: nativeLabels, domId: element.id ?? null,
        labelAssociation: labelAssociation(element), root: element.getRootNode(), inputType: element.type,
        name: element.name, anchorSource: element.tagName === 'A' && element.namespaceURI === 'http://www.w3.org/1999/xhtml'
          ? { href: Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href').get.call(element), download: element.getAttribute('download') } : null, readOnly: !!element.readOnly, ariaDisabled: element.getAttribute('aria-disabled'), ariaReadonly: element.getAttribute('aria-readonly'),
        contentEditable: element.contentEditable, isContentEditable: !!element.isContentEditable, formGuard: formGuard(element) });
      controls.push(description);
    }
  }
  observation.captureGuardComplete = nodes < 10000;
  observation.visualMapComplete = observation.visualMapComplete && nodes < 10000;
  observation.roots = roots.slice(0, rootsVisited).map(item => item.root);
  return { controls, controls_omitted: omitted, controls_incomplete: omitted > 0 || nodes >= 10000,
    text, text_incomplete: omittedText || nodes >= 10000, observation_nodes_scanned: nodes, open_shadow_roots_visited: rootsVisited - 1,
    dom_scope: 'Selected-frame document and open shadow roots; closed shadow roots and child-frame documents excluded',
    title: document.title.slice(0, 300), viewport: { width: innerWidth, height: innerHeight, device_scale: devicePixelRatio },
    ...(paired ? { _capture_anchor: { revision: observation.revision, root_count: rootsVisited, viewport: scanViewport } } : {}) };
}

function captureRefusal(record, stage, expected, actual, code = 'browser_observation_changed') {
  // Diagnose a refused capture without publishing page text, pixels, geometry
  // or another async SDK read that could change the measured interval.
  event(record, 'capture_refused', {
    reason: code, stage, expected_available: !!expected, actual_available: !!actual,
    dom_revision_changed: !!expected && !!actual && expected.revision !== actual.revision,
    root_count_changed: !!expected && !!actual && 'root_count' in expected && 'root_count' in actual
      && expected.root_count !== actual.root_count,
    viewport_changed: !!expected && !!actual && JSON.stringify(expected.viewport) !== JSON.stringify(actual.viewport),
    capture_regions_changed: !!expected && !!actual && 'capture_regions' in expected && 'capture_regions' in actual
      && JSON.stringify(expected.capture_regions) !== JSON.stringify(actual.capture_regions),
    state_error: actual?.error || null,
  });
  return fail(code);
}

function observationState(observationId) {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  // attachShadow does not trigger the document's MutationObserver. Compare
  // actual root identities as well as the mutation revision before any capture.
  const roots = [document]; let scanned = 0;
  for (let i = 0; i < roots.length; i++) {
    if (roots[i] !== observation.roots[i]) return { error: 'browser_observation_changed' };
    const walker = document.createTreeWalker(roots[i], NodeFilter.SHOW_ELEMENT); let element;
    while ((element = walker.nextNode())) {
      if (++scanned > 10000) return { error: 'screenshot_privacy_scan_incomplete' };
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  if (roots.length !== observation.roots.length) return { error: 'browser_observation_changed' };
  const regions = observation.captureElements.filter(element => element.isConnected).map(element => {
    const rect = element.getBoundingClientRect(); return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
  });
  let geometryComplete = true;
  for (const node of observation.captureTextNodes) {
    if (!node.isConnected) continue;
    try {
      const range = document.createRange(); range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (regions.length >= 10000) { geometryComplete = false; break; }
        if (rect.width > 0 && rect.height > 0) regions.push({ x: rect.x, y: rect.y, width: rect.width, height: rect.height });
      }
    } catch { geometryComplete = false; }
    if (!geometryComplete) break;
  }
  return { revision: observation.revision, viewport: { width: innerWidth, height: innerHeight, device_scale: devicePixelRatio,
    scroll_x: scrollX, scroll_y: scrollY, visual_viewport: observation.visualViewportState() }, root_count: roots.length, capture_regions: regions,
    capture_guard_complete: observation.captureGuardComplete && geometryComplete };
}

function visualPointInfo(observationId, x, y, anchor) {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId || !observation.visualMapComplete) return { error: 'visual_observation_unavailable' };
  globalThis.__workbenchEditingFocusWitness = null;
  const state = observationState(observationId);
  if (state.error) return state;
  const same = (a,b) => a === b || !!a && !!b && typeof a === 'object' && typeof b === 'object'
    && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(key => Object.hasOwn(b,key) && same(a[key],b[key]));
  if (state.revision !== anchor.revision || state.root_count !== anchor.root_count
      || !same(state.viewport,anchor.viewport)) return { error: 'visual_observation_changed' };
  const visual = state.viewport.visual_viewport;
  if (visual && (visual.scale !== 1 || visual.offset_x !== 0 || visual.offset_y !== 0)) return { error:'visual_viewport_transform_unsupported' };
  if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return { error:'invalid_image_point' };
  const covers = rect => x >= rect.x && y >= rect.y && x < rect.x + rect.width && y < rect.y + rect.height;
  // Check both old and current coverage. A layer moved away from the point
  // cannot expose a different target while passing only the final hit check.
  for (const [element, old] of observation.visualElements) {
    const now = element.isConnected ? observation.visualSample(element) : null;
    if (!now) return { error:'visual_observation_changed' };
    if (!covers(old.rect) && !covers(now.rect)) continue;
    if (now.root !== old.root || now.parent !== old.parent || now.slot !== old.slot
        || JSON.stringify(now.rect) !== JSON.stringify(old.rect) || JSON.stringify(now.styles) !== JSON.stringify(old.styles)
        || now.disabled !== old.disabled || now.aria_disabled !== old.aria_disabled
        || now.input_type !== old.input_type || now.checked !== old.checked) return { error:'visual_target_changed' };
  }
  let hit = document.elementFromPoint(x,y), depth = 0;
  while (hit?.shadowRoot) {
    if (depth++ >= 100) return { error:'shadow_hit_test_limit' };
    const nested = hit.shadowRoot.elementFromPoint(x,y);
    if (!nested) return { error:'target_obstructed' };
    if (nested === hit) break;
    hit = nested;
  }
  if (!hit || !observation.visualElements.has(hit)) return { error:'visual_target_unobserved' };
  if (['IFRAME','FRAME'].includes(hit.tagName)) return { error:'frame_pointer_input_unavailable' };
  if (observation.sensitiveAncestor(hit)) return { error:'local_sensitive_input_required' };
  if (hit.matches(':disabled') || hit.getAttribute('aria-disabled') === 'true') return { error:'target_disabled' };
  const old = observation.visualElements.get(hit);
  if (!covers(old.rect)) return { error:'visual_target_changed' };
  return { x,y,root_point:{x,y},rect:old.rect,visual_target_id:old.id,tag:hit.tagName.toLowerCase(),
    hit_matches_target:true,shadow_hit_depth:depth,content_frozen:false };
}

// CDP's real point node also sees author-closed shadow roots. Merely seeing
// shadowRoot === null in the page would mistake an opaque host for its child.
function visualResolvedHit(observationId, targetId) {
  const observation = globalThis.__workbenchObservation;
  const node = this.nodeType === Node.TEXT_NODE ? this.parentElement : this;
  if (!observation || observation.id !== observationId || !node?.isConnected) return false;
  return observation.visualElements.get(node)?.id === targetId;
}

// Images of a selected child are crops of the root surface. Only ordinary
// translation between viewport origins is admitted here; the more general
// homography used by semantic frame input is deliberately not image authority.
function visualFrameOffsets(bound) {
  if (bound.chain.some(row=>row.frame.allowed !== true)) throw fail('frame_grant_required');
  const offsets = new Map([[bound.chain[0].frame.frame_id,{x:0,y:0}]]);
  for (const boundary of bound.geometry.boundaries) {
    const q = boundary.content_quad_root_css, viewport = bound.geometry.viewports[boundary.child_frame_id];
    if (!viewport || !Array.isArray(q) || q.length !== 8 || q.some(n => !Number.isFinite(n))
        || ![q[2]-q[0]-viewport.width,q[4]-q[0]-viewport.width,q[6]-q[0],
          q[3]-q[1],q[5]-q[1]-viewport.height,q[7]-q[1]-viewport.height].every(n => Math.abs(n) < 1e-7))
      throw fail('frame_screenshot_transform_unsupported');
    offsets.set(boundary.child_frame_id,{x:q[0],y:q[1]});
  }
  if (offsets.size !== bound.chain.length) throw fail('frame_screenshot_unavailable');
  return offsets;
}
function visualFrameCrop(bound, clip) {
  const offsets = visualFrameOffsets(bound), selected = offsets.get(bound.chain.at(-1).frame.frame_id);
  const rootClip = {...clip,x:clip.x+selected.x,y:clip.y+selected.y};
  for (const row of bound.chain) {
    const offset = offsets.get(row.frame.frame_id), viewport = bound.geometry.viewports[row.frame.frame_id];
    const x = rootClip.x-offset.x, y = rootClip.y-offset.y;
    if (![x,y,viewport?.width,viewport?.height].every(Number.isFinite) || x < 0 || y < 0
        || x+clip.width > viewport.width || y+clip.height > viewport.height) throw fail('frame_screenshot_clipped');
  }
  return {offsets,rootClip};
}

// Runs on the exact frame owner in its parent's isolated world. A clear crop
// is stricter than a point hit: pointer-events:none overlays, generated content,
// sibling frames and ordinary text can paint into an otherwise valid hit path.
function visualFrameOwnerCrop(observationId, clip, anchor) {
  const o = globalThis.__workbenchObservation, owner = this;
  if (!o || o.id !== observationId || !o.visualMapComplete || !o.captureGuardComplete
      || o.visualElements.size > 128
      || !owner.isConnected || !['IFRAME','FRAME'].includes(owner.tagName) || !o.visualElements.has(owner))
    return {error:'frame_screenshot_owner_unobserved'};
  const state = observationState(observationId);
  if (state.error) return state;
  // CDP returnByValue can reorder object keys before they become arguments.
  // Compare the exact shape and values, never transport insertion order.
  const same = (a,b) => a === b || !!a && !!b && typeof a === 'object' && typeof b === 'object'
    && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(key=>Object.hasOwn(b,key) && same(a[key],b[key]));
  if (state.revision !== anchor.revision || state.root_count !== anchor.root_count
      || !same(state.viewport,anchor.viewport)) return {error:'visual_observation_changed'};
  if (!state.capture_guard_complete) return {error:'screenshot_privacy_scan_incomplete'};
  const overlaps = r => r.width > 0 && r.height > 0 && r.x < clip.x+clip.width && r.x+r.width > clip.x
    && r.y < clip.y+clip.height && r.y+r.height > clip.y;
  const lineage = new Set();
  for (let el=owner; el;) {
    if (lineage.size >= 100 || !o.visualElements.has(el) || el.assignedSlot || o.sensitiveAncestor(el))
      return {error:'frame_screenshot_owner_unobserved'};
    lineage.add(el);
    const root = el.getRootNode();
    if (root !== document && (!root.host || root.host.shadowRoot !== root)) return {error:'frame_screenshot_owner_unobserved'};
    el = el.parentElement || (root !== document ? root.host : null);
  }
  for (const [el,old] of o.visualElements) {
    const now = el.isConnected ? o.visualSample(el) : null;
    if (!now) return {error:'visual_observation_changed'};
    // Bounding boxes do not contain all paint. Refuse potentially unbounded
    // paint even on off-crop siblings, including pseudo-elements and SVG.
    const style = getComputedStyle(el);
    if (el.namespaceURI !== 'http://www.w3.org/1999/xhtml'
        || ['::before','::after','::marker','::backdrop'].some(pseudo => !['none','normal',''].includes(getComputedStyle(el,pseudo).content))
        || el.matches('dialog[open], :popover-open')
        || ['boxShadow','textShadow','filter','backdropFilter'].some(key => style[key] && style[key] !== 'none')
        || style.outlineStyle && style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) !== 0
        || style.borderImageOutset && style.borderImageOutset.split(/\s+/).some(n => parseFloat(n) !== 0)
        || style.listStyleType && style.listStyleType !== 'none' && style.display === 'list-item')
      return {error:'frame_screenshot_obstructed'};
    if (!overlaps(old.rect) && !overlaps(now.rect) && !lineage.has(el)) continue;
    if (now.root !== old.root || now.parent !== old.parent || now.slot !== old.slot
        || JSON.stringify(now.rect) !== JSON.stringify(old.rect) || JSON.stringify(now.styles) !== JSON.stringify(old.styles))
      return {error:'visual_target_changed'};
    if (!lineage.has(el)) return {error:'frame_screenshot_obstructed'};
    if (style.visibility !== 'visible' || style.display === 'none' || style.pointerEvents === 'none'
        || el.inert || el.getAttribute('aria-disabled') === 'true'
        || Number(style.opacity) !== 1 || !['1','normal'].includes(style.zoom || '1')
        || ['transform','translate','rotate','scale','perspective','filter','backdropFilter','clipPath','maskImage','offsetPath']
          .some(key => style[key] && style[key] !== 'none')
        || style.mixBlendMode && style.mixBlendMode !== 'normal' || style.clip && style.clip !== 'auto'
        || ['borderTopLeftRadius','borderTopRightRadius','borderBottomLeftRadius','borderBottomRightRadius']
          .some(key => style[key]?.split(/\s+/).some(n => parseFloat(n) !== 0)))
      return {error:'frame_screenshot_transform_unsupported'};
    const rect = now.rect;
    if (el !== owner && ['overflowX','overflowY'].some(key => style[key] && style[key] !== 'visible')
        && (clip.x < rect.x+el.clientLeft || clip.y < rect.y+el.clientTop
          || clip.x+clip.width > rect.x+el.clientLeft+el.clientWidth
          || clip.y+clip.height > rect.y+el.clientTop+el.clientHeight)) return {error:'frame_screenshot_clipped'};
  }
  let count = 0, rects = 0;
  for (const root of o.roots) {
    const walker = document.createTreeWalker(root,NodeFilter.SHOW_TEXT); let node;
    while ((node=walker.nextNode())) {
      if (++count > 10000) return {error:'screenshot_privacy_scan_incomplete'};
      if (!node.nodeValue.trim() || ['SCRIPT','STYLE','NOSCRIPT'].includes(node.parentElement?.tagName)) continue;
      const range = document.createRange(); range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (++rects > 10000) return {error:'screenshot_privacy_scan_incomplete'};
        if (overlaps(rect)) return {error:'frame_screenshot_obstructed'};
      }
    }
  }
  return {owner_visual_id:o.visualElements.get(owner).id,element_count:o.visualElements.size};
}

async function visualFrameCaptureGuard(record, bound, observationId, clip, anchors, checkpoint, inspectRoots = true) {
  const {offsets,rootClip} = visualFrameCrop(bound,clip), captured = anchors || [];
  const group = 'workbench-visual-frames:'+observationId;
  let total = 0;
  try {
    for (let i=0;i<bound.chain.length-1;i++) {
      const parent = bound.chain[i], boundary = bound.geometry.boundaries[i], offset = offsets.get(parent.frame.frame_id);
      checkpoint(); frameContextCurrent(record,parent);
      if (!anchors) {
        const scan = await frameValue(record,parent,'(() => { const editingFocusWitnessState='+editingFocusWitnessState.toString()
          +'; const optionEffectivelyHidden='+optionEffectivelyHidden.toString()+'; return ('+observePage.toString()+')('
          +JSON.stringify(observationId)+',true,true,null)._capture_anchor; })()',checkpoint);
        if (!scan) throw fail('frame_screenshot_owner_unobserved');
        captured.push(scan);
      }
      const resolved = await cdp(record,'DOM.resolveNode',{backendNodeId:boundary.owner_backend_node_id,
        executionContextId:parent.contextId,objectGroup:group},parent.frame.session_id,checkpoint);
      checkpoint(); frameContextCurrent(record,parent);
      if (!resolved.object?.objectId) throw fail('frame_screenshot_owner_unobserved');
      const checked = await cdp(record,'Runtime.callFunctionOn',{objectId:resolved.object.objectId,
        functionDeclaration:'function(...args){const observationState='+observationState.toString()+';return ('
          +visualFrameOwnerCrop.toString()+').apply(this,args);}',
        arguments:[{value:observationId},{value:{...clip,x:rootClip.x-offset.x,y:rootClip.y-offset.y}},{value:captured[i]}],
        returnByValue:true},parent.frame.session_id,checkpoint);
      checkpoint(); frameContextCurrent(record,parent);
      if (checked.exceptionDetails || checked.result?.value?.error || !checked.result?.value?.owner_visual_id)
        throw fail(checked.result?.value?.error || 'frame_screenshot_owner_unobserved');
      // The expensive opaque-root scan precedes the final selected recipient
      // proof. Only the light parent paint/hit fences follow that proof.
      if (!inspectRoots) continue;
      const count = checked.result.value.element_count;
      if (!Number.isSafeInteger(count) || count < 1 || count > 128 || (total+=count) > 256)
        throw fail('frame_screenshot_privacy_limit');
      // A closed root can paint outside its host's box and attachShadow does
      // not change a DOM mutation revision. Inspect root metadata on every
      // retained parent element on each guard; never request its subtree.
      const elements = await cdp(record,'Runtime.callFunctionOn',{objectId:resolved.object.objectId,
        functionDeclaration:'function(id){const o=globalThis.__workbenchObservation;return o?.id===id?[...o.visualElements.keys()]:null;}',
        arguments:[{value:observationId}],objectGroup:group,returnByValue:false},parent.frame.session_id,checkpoint);
      checkpoint(); frameContextCurrent(record,parent);
      if (elements.exceptionDetails || !elements.result?.objectId) throw fail('frame_screenshot_owner_unobserved');
      const properties = await cdp(record,'Runtime.getProperties',{objectId:elements.result.objectId,ownProperties:true,
        accessorPropertiesOnly:false,generatePreview:false},parent.frame.session_id,checkpoint);
      checkpoint(); frameContextCurrent(record,parent);
      const nodes = (properties.result || []).filter(row=>/^(0|[1-9]\d*)$/.test(row.name));
      if (properties.exceptionDetails || nodes.length !== count
          || nodes.some((row,i)=>row.name!==String(i) || !row.value?.objectId)) throw fail('frame_screenshot_owner_unobserved');
      for (let start=0;start<count;start+=8) {
        const described = await Promise.all(nodes.slice(start,start+8).map(row=>cdp(record,'DOM.describeNode',
          {objectId:row.value.objectId,depth:0,pierce:false},parent.frame.session_id,checkpoint)));
        checkpoint(); frameContextCurrent(record,parent);
        if (described.some(row=>row.node?.nodeType!==1 || !Array.isArray(row.node.shadowRoots || [])
            || row.node.shadowRoots?.some(root=>root.shadowRootType!=='open'))) throw fail('frame_screenshot_opaque_ancestor');
      }
      // Metadata replies may yield after the first style/privacy read.
      const final = await cdp(record,'Runtime.callFunctionOn',{objectId:resolved.object.objectId,
        functionDeclaration:'function(...args){const observationState='+observationState.toString()+';return ('
          +visualFrameOwnerCrop.toString()+').apply(this,args);}',
        arguments:[{value:observationId},{value:{...clip,x:rootClip.x-offset.x,y:rootClip.y-offset.y}},{value:captured[i]}],
        returnByValue:true},parent.frame.session_id,checkpoint);
      checkpoint(); frameContextCurrent(record,parent);
      if (final.exceptionDetails || final.result?.value?.error
          || final.result?.value?.owner_visual_id !== checked.result.value.owner_visual_id || final.result?.value?.element_count !== count)
        throw fail(final.result?.value?.error || 'frame_screenshot_owner_unobserved');
    }
  } finally {
    for (const session of new Set(bound.chain.slice(0,-1).map(row=>row.frame.session_id))) {
      try {await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},session,checkpoint);} catch { /* Ended worlds release their objects. */ }
      checkpoint();
    }
  }
  return {anchors:captured,rootClip};
}

async function visualClick(record, packet, observation, result) {
  const p = packet.parameters, intent = observation.imageIntent;
  if (!record.durable || (observation.frame.parent_id || observation.frame.session_id) && !intent?.frameCapture)
    throw fail('frame_screenshot_unavailable');
  if (!intent || intent.mapping.screenshot_sha256 !== p.screenshot_sha256) throw fail('stale_screenshot');
  const mapping = intent.mapping;
  if ([p.image_x,p.image_y].some(n => typeof n !== 'number' || !Number.isFinite(n) || n < 0)
      || p.image_x >= mapping.width || p.image_y >= mapping.height || p.target_id != null) throw fail('invalid_image_point');
  const point = { x:mapping.clip_css.x + p.image_x/mapping.pixel_per_css_x,
    y:mapping.clip_css.y + p.image_y/mapping.pixel_per_css_y };
  // The recipient lookup uses document CSS coordinates; native Input uses
  // viewport CSS coordinates. Keep both anchored to the original capture.
  const offsets = observation.frameChain ? visualFrameOffsets(observation.frameChain) : null;
  const offset = offsets?.get(observation.frame.frame_id) || {x:0,y:0};
  const rootPoint = {x:point.x+offset.x,y:point.y+offset.y};
  const renderer = observation.frameChain?.chain.find(row=>row.frame.frame_id===observation.frame.renderer_root_id);
  const rendererOffset = renderer ? offsets.get(renderer.frame.frame_id) : {x:0,y:0};
  const rendererViewport = renderer ? observation.frameChain.geometry.viewports[renderer.frame.frame_id] : intent.anchor.viewport;
  const queryPoint = {x:rootPoint.x-rendererOffset.x+rendererViewport.scroll_x,y:rootPoint.y-rendererOffset.y+rendererViewport.scroll_y};
  // DOM.getNodeForLocation accepts integer CSS coordinates. Do not query a
  // neighboring rounded pixel and then dispatch a different fractional point.
  if (![point.x,point.y,rootPoint.x,rootPoint.y,queryPoint.x,queryPoint.y].every(Number.isInteger)) throw fail('visual_fractional_css_point_unsupported');
  let held = null, closed = false, before = null, after = null, downAcknowledged = false;
  const current = () => {
    if (closed || performance.now() >= intent.deadline) throw fail('screenshot_intent_expired');
    requireTrust(packet); frameClaimCurrent(record,packet);
    if (!port || !record.debuggerAttached || leases.get(record.id) !== record || record.generation !== observation.generation
        || record.observations.get(p.observation_id) !== observation
        || observation.contextUniqueId !== record.contextUniqueIds.get((observation.frame.session_id || '') + ':' + observation.contextId)
        || intent.binding !== JSON.stringify([record.id,record.claim_epoch,record.owner_session,record.runtime_generation,
          record.installation_id,record.peerId,record.target.target_generation,record.target.browser_target_id])) throw fail('stale_screenshot');
    for (const row of observation.frameChain?.chain || []) frameContextCurrent(record,row);
    if (intent.frameCapture && (record.frameTopologyEpoch || 0) !== intent.frameCapture.topology) throw fail('stale_browser_frame');
  };
  const sample = async () => {
    current();
    const expression = '(() => {const observationState=' + observationState.toString() + ';return (' + visualPointInfo.toString()
      + ')(' + [JSON.stringify(p.observation_id),point.x,point.y,JSON.stringify(intent.anchor)].join(',') + ');})()';
    const hit = await value(record,expression,observation.contextId,observation.frame.session_id);
    current(); if (hit?.error) throw fail(hit.error);
    if (!hit?.hit_matches_target) throw fail('visual_target_unobserved');
    return {...hit,root_point:rootPoint};
  };
  const fresh = async () => {
    current();
    const selected = await live(record,packet.expected_generation,packet.expected_origin,observation.frame.frame_id,current);
    current();
    if (FRAME_IDENTITY_KEYS.some(k => selected.frame[k] !== observation.frame[k])) throw fail('stale_browser_frame');
    if (observation.frameChain) {
      frameChainCurrent(record,observation.frameChain.chain,selected.list,current);
      await visualFrameCaptureGuard(record,observation.frameChain,p.observation_id,mapping.clip_css,intent.frameCapture.anchors,current);
      const mapped = await frameInputGuard(record,packet,observation,point,false,current);
      if (mapped.root_point.x !== rootPoint.x || mapped.root_point.y !== rootPoint.y) throw fail('frame_transform_changed');
    }
    if (!await ownsActualTarget(record,current)) throw fail('browser_claim_owner_mismatch');
    current();
  };
  const realHit = async hit => {
    const group = 'workbench-visual:' + packet.request_id;
    try {
      current();
      const node = await cdp(record,'DOM.getNodeForLocation',{...queryPoint,includeUserAgentShadowDOM:true},observation.frame.session_id,current);
      current();
      if (node.frameId !== observation.frame.frame_id || !Number.isSafeInteger(node.backendNodeId)) throw fail('visual_recipient_unverified');
      const resolved = await cdp(record,'DOM.resolveNode',{backendNodeId:node.backendNodeId,executionContextId:observation.contextId,objectGroup:group},observation.frame.session_id,current);
      current();
      if (!resolved.object?.objectId) throw fail('visual_recipient_unverified');
      const checked = await cdp(record,'Runtime.callFunctionOn',{objectId:resolved.object.objectId,functionDeclaration:visualResolvedHit.toString(),
        arguments:[{value:p.observation_id},{value:hit.visual_target_id}],returnByValue:true},observation.frame.session_id,current);
      current();
      if (checked.exceptionDetails || checked.result?.value !== true) throw fail('visual_recipient_unverified');
      return node.backendNodeId;
    } finally {
      try {await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},observation.frame.session_id,current);} catch { /* Ended context releases its objects. */ }
      current();
    }
  };
  try {
    current();
    if (record.heldDrag?.pressAttempted && record.heldDrag.state !== 'acknowledged'
        || ['held','unverified'].includes(record.pointer_release_state)) throw fail('browser_drag_release_unverified');
    await fresh(); before = await sample(); const originalBackend = await realHit(before);
    held = { peer:record.peerId,owner:record.owner_session,runtime:record.runtime_generation,installation:record.installation_id,
      targetGeneration:record.target.target_generation,browserTarget:record.target.browser_target_id,epoch:record.claim_epoch,
      tabId:record.tabId,point:{...rootPoint},pressAttempted:false,releaseAttempted:false,state:'not_needed' };
    record.heldDrag = held; record.dragActive = true;
    // Abrupt worker loss after the send may lose live hold memory. Retain
    // conservative intent first; restored history is quarantined, never replayed.
    await bodyWait(persistTargets(),500,null,'browser_visual_intent_storage_timeout'); current(); state();
    // Node resolution and ownership checks yield. Finish with exact point
    // actionability, then a synchronous authority/deadline fence at the send.
    await fresh(); after = await sample();
    if (after.visual_target_id !== before.visual_target_id) throw fail('visual_target_changed');
    if (observation.frameChain) await verifyFrameGeometryForInput(record,packet,observation,current);
    const finalNode = await cdp(record,'DOM.getNodeForLocation',{...queryPoint,includeUserAgentShadowDOM:true},observation.frame.session_id,current);
    current();
    if (finalNode.frameId !== observation.frame.frame_id || finalNode.backendNodeId !== originalBackend) throw fail('visual_recipient_unverified');
    if (observation.frameChain) {
      await visualFrameCaptureGuard(record,observation.frameChain,p.observation_id,mapping.clip_css,intent.frameCapture.anchors,current,false);
      await frameInputGuard(record,packet,observation,point,false,current);
    }
    await bodyWait(cdp(record,'Input.dispatchMouseEvent',{type:'mousePressed',...rootPoint,button:'left',buttons:1,clickCount:1},null,() => {
      current(); held.pressAttempted = true; held.state = 'held'; record.pointer_release_state = 'held'; record.observations.clear();
    }),500,null,'browser_visual_click_timeout');
    downAcknowledged = true;
    await finishFramePointerHold(record,held,rootPoint);
    const focusBinding = editingFocusBinding(record,observation);
    const postCurrent = () => {
      requireTrust(packet); frameClaimCurrent(record,packet);
      if (performance.now() >= intent.deadline || !trust.control || !port || !record.debuggerAttached || leases.get(record.id) !== record
          || record.generation !== observation.generation || held.state !== 'acknowledged'
          || record.inputEligible === false || Date.now() >= record.expires
          || observation.contextUniqueId !== record.contextUniqueIds.get((observation.frame.session_id || '') + ':' + observation.contextId)
          || editingFocusBinding(record,observation) !== focusBinding) throw fail('editing_focus_binding_changed');
    };
    let focusWitness;
    try {
      postCurrent();
      if (observation.frameChain) throw fail('child_frame_editing_focus_unsupported');
      const focusFrame = await live(record,packet.expected_generation,packet.expected_origin,observation.frame.frame_id,postCurrent);
      if (['frame_id','loader_id','session_id'].some(k => focusFrame.frame[k] !== observation.frame[k])) throw fail('stale_browser_frame');
      if (!await ownsActualTarget(record,postCurrent)) throw fail('browser_claim_owner_mismatch');
      const focusObservation = {...observation,id:p.observation_id};
      await guardEditingHostShadow(record,focusObservation,null,postCurrent);
      focusWitness = await value(record,'(' + retainEditingFocusWitness.toString() + ')('
        + [JSON.stringify(p.observation_id),JSON.stringify(after.visual_target_id),JSON.stringify(point),JSON.stringify(focusBinding)].join(',')
        + ')',observation.contextId);
      postCurrent();
    } catch (error) {
      // Pointer release already settled outside this optional proof. Navigation,
      // world loss or unsupported focus cannot revoke that original click ACK.
      // Invalidate the proof binding locally: never enter a changed/ended world
      // just to clear renderer metadata, and never send another input/release.
      record.editingFocusRevision = (record.editingFocusRevision || 0) + 1;
      focusWitness = {retained:false,reason:error.code || 'post_click_focus_unavailable'};
    }
    return {...result,editing_focus_witness:focusWitness,...acknowledgedCdpInput(),
      effect_state:'unknown',effect_scope:'recipient_effect_not_established',task_completion:'not_established',mechanism:'cdp_screenshot_bound_click',
      screenshot_sha256:mapping.screenshot_sha256,image_point:{x:p.image_x,y:p.image_y},coordinate_units:'Original PNG pixels from top-left',
      dispatch_target:after,actionability_revalidated_before_dispatch:true,content_frozen:false,
      content_guard_scope:'Scan-retained DOM identities, covering geometry/styles and viewport; paint-only canvas/compositor changes are not detected',
      pointer_receipt:{down_attempted:true,down_acknowledged:downAcknowledged,up_attempted:held.releaseAttempted,
        up_acknowledged:held.releaseAcknowledged===true,pointer_release_state:held.state}};
  } catch (error) {
    const failure = fail(error.code || 'browser_visual_click_failed',held?.pressAttempted ? 'unknown' : 'none');
    if (held?.pressAttempted && !held.releaseAttempted) await releaseHeldDrag(record,'visual_click_interrupted');
    failure.pointer_receipt = {down_attempted:held?.pressAttempted===true,down_acknowledged:downAcknowledged,up_attempted:held?.releaseAttempted===true,
      up_acknowledged:held?.releaseAcknowledged===true,pointer_release_state:held?.state || 'not_needed'};
    throw failure;
  } finally {
    closed = true;
    if (held?.pressAttempted) record.observations.clear();
    if (held && record.heldDrag === held) {
      record.dragActive = false;
      if (!held.pressAttempted) {held.state = 'not_needed';record.pointer_release_state = 'not_needed';}
      try {await bodyWait(persistTargets(),500,null,'browser_visual_cleanup_storage_timeout');}
      catch { /* Conservative persisted intent remains quarantined. */ }
      state();
    }
  }
}

// Runs on a resolved backend DOM node in the observation's isolated world. Raw
// AX text, descriptions and source strings never enter the returned tree.
function axNodeSafety(observationId) {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId || !this.isConnected) return { sensitive: true };
  let sensitive = observation.sensitiveAncestor(this), count = 0;
  const roots = this.shadowRoot ? [this, this.shadowRoot] : [this];
  for (let i = 0; i < roots.length && !sensitive; i++) {
    const walker = document.createTreeWalker(roots[i], NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      if (++count > 1000 || observation.sensitiveAncestor(node)) { sensitive = true; break; }
      if (node.shadowRoot) roots.push(node.shadowRoot);
    }
  }
  let targetId = null;
  for (const [id, item] of observation.targets) if (item.element === this) { targetId = id; break; }
  return { sensitive, target_id: targetId };
}

function snapshotOptions(p) {
  for (const key of ['include_accessibility', 'include_screenshot']) if (p[key] != null && typeof p[key] !== 'boolean') throw fail('invalid_snapshot_options');
  const depth = p.ax_depth ?? 5, maxNodes = p.ax_max_nodes ?? 500, scale = p.screenshot_scale ?? 1;
  if (!Number.isInteger(depth) || depth < 1 || depth > 10 || !Number.isInteger(maxNodes) || maxNodes < 1 || maxNodes > 2000
      || typeof scale !== 'number' || !Number.isFinite(scale) || scale < 0.1 || scale > 1) throw fail('invalid_snapshot_options');
  const clip = p.screenshot_clip;
  if (clip != null && (typeof clip !== 'object' || Array.isArray(clip) || Object.keys(clip).sort().join(',') !== 'height,width,x,y'
      || ['x', 'y', 'width', 'height'].some(key => typeof clip[key] !== 'number' || !Number.isFinite(clip[key]))
      || clip.x < 0 || clip.y < 0 || clip.width <= 0 || clip.height <= 0)) throw fail('invalid_snapshot_options');
  return { accessibility: p.include_accessibility === true, screenshot: p.include_screenshot === true, depth, maxNodes, scale, clip };
}

async function accessibilitySnapshot(record, selected, contextId, observationId, options) {
  const tree = await cdp(record, 'Accessibility.getFullAXTree', { depth: options.depth, frameId: selected.frame_id }, selected.session_id);
  if (!Array.isArray(tree.nodes) || tree.nodes.length > options.maxNodes) throw fail('accessibility_node_limit');
  const group = 'workbench-ax-' + observationId, safety = new Map(), waiting = [];
  const parallelLimit = 16, uniqueReferenceLimit = 4096, valueReferenceLimit = 256, totalReferenceVisitLimit = 65536;
  let active = 0, maxActive = 0, referenceVisits = 0, closing = false;
  const pump = () => {
    while (active < parallelLimit && waiting.length) {
      const job = waiting.shift(); active++; maxActive = Math.max(maxActive, active);
      Promise.resolve().then(job.work).then(job.resolve, job.reject).finally(() => { active--; pump(); });
    }
  };
  const bounded = work => new Promise((resolve, reject) => { waiting.push({ work, resolve, reject }); pump(); });
  const check = async backendNodeId => {
    if (!Number.isSafeInteger(backendNodeId)) return { sensitive: true, target_id: null };
    if (!safety.has(backendNodeId)) {
      if (closing || safety.size >= uniqueReferenceLimit) throw fail('accessibility_reference_limit');
      safety.set(backendNodeId, bounded(async () => {
      try {
        const resolved = await cdp(record, 'DOM.resolveNode', { backendNodeId, executionContextId: contextId, objectGroup: group }, selected.session_id);
        if (!resolved.object?.objectId) return { sensitive: true, target_id: null };
        const evaluated = await cdp(record, 'Runtime.callFunctionOn', { objectId: resolved.object.objectId,
          functionDeclaration: axNodeSafety.toString(), arguments: [{ value: observationId }], returnByValue: true }, selected.session_id);
        return evaluated.exceptionDetails ? { sensitive: true, target_id: null } : evaluated.result?.value || { sensitive: true, target_id: null };
      } catch { return { sensitive: true, target_id: null }; }
      }));
    }
    return safety.get(backendNodeId);
  };
  const references = value => {
    const ids = new Set(), pending = [value]; let visits = 0;
    while (pending.length) {
      const item = pending.pop(); if (!item || typeof item !== 'object') continue;
      if (++visits > 2048 || ++referenceVisits > totalReferenceVisitLimit) throw fail('accessibility_reference_limit');
      if (item.backendDOMNodeId !== undefined) {
        ids.add(item.backendDOMNodeId);
        if (ids.size > valueReferenceLimit) throw fail('accessibility_reference_limit');
      }
      for (const child of Object.values(item)) if (Array.isArray(child)) {
        if (child.length > 2048) throw fail('accessibility_reference_limit');
        pending.push(...child);
      } else if (child && typeof child === 'object') pending.push(child);
      if (pending.length > 2048) throw fail('accessibility_reference_limit');
    }
    return [...ids];
  };
  try {
    const nodes = [];
    // Bound simultaneous protocol work while preserving the original tree order.
    for (let offset = 0; offset < tree.nodes.length; offset += 16) {
      nodes.push(...await Promise.all(tree.nodes.slice(offset, offset + 16).map(async node => {
        const dom = await check(node.backendDOMNodeId);
        const safeValue = async value => {
          if (!value || dom.sensitive || (await Promise.all(references(value).map(check))).some(row => row.sensitive)) return null;
          return ['string', 'computedString', 'number', 'integer', 'boolean'].includes(value.type)
            && ['string', 'number', 'boolean'].includes(typeof value.value) ? value.value : null;
        };
        const name = await safeValue(node.name), value = await safeValue(node.value);
        const properties = {};
        for (const prop of node.properties || []) if (['busy','disabled','focusable','focused','multiline','readonly','required','expanded','modal','selected','level'].includes(prop.name)
            && ['boolean','number'].includes(typeof prop.value?.value)) properties[prop.name] = prop.value.value;
        return { node_id: node.nodeId, parent_id: node.parentId || null, child_ids: node.childIds || [],
          backend_dom_node_id: node.backendDOMNodeId || null, dom_target_id: dom.target_id || null, ignored: !!node.ignored,
          role: node.role?.type === 'role' && typeof node.role.value === 'string' ? node.role.value : null,
          name, value, text_redacted: !!((node.name && name === null) || (node.value && value === null)), properties };
      })));
    }
    const ids = new Set(nodes.map(node => node.node_id));
    const omitted = nodes.reduce((n, node) => n + node.child_ids.filter(id => !ids.has(id)).length, 0);
    const result = { nodes, requested_depth: options.depth, max_nodes: options.maxNodes, boundary_child_references_omitted: omitted,
      depth_limited: true, tree_complete: false, scope: 'Selected-frame Chromium AX tree at requested depth',
      representation: 'privacy_filtered_chromium_ax_tree', suppressed_fields: ['description', 'sources', 'ignoredReasons', 'non_scalar_properties'],
      raw_unfiltered_tree_preserved: false, privacy_work: { unique_dom_references: safety.size, max_concurrent_checks: maxActive,
        concurrent_check_limit: parallelLimit, unique_reference_limit: uniqueReferenceLimit, per_value_reference_limit: valueReferenceLimit,
        reference_visits: referenceVisits, reference_visit_limit: totalReferenceVisitLimit } };
    if (encoder.encode(JSON.stringify(result)).length > 2097152) throw fail('accessibility_result_limit');
    return result;
  } finally {
    closing = true;
    await Promise.allSettled([...safety.values()]);
    try { await cdp(record, 'Runtime.releaseObjectGroup', { objectGroup: group }, selected.session_id); } catch { /* Ended context already released its objects. */ }
  }
}

function targetInfo(observationId, targetId, focus = false, requireFocus = false, inputAction = null) {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  const item = observation.targets.get(targetId), el = item?.element;
  if (!el?.isConnected) return { error: 'stale_target' };
  const r = el.getBoundingClientRect(), old = item.description;
  if (typeof observation.semanticLabel !== 'function' || typeof observation.sensitiveAncestor !== 'function') return { error: 'stale_observation' };
  if (item.associatedLabels) {
    if (typeof observation.associatedLabels !== 'function') return { error: 'stale_observation' };
    const original = item.associatedLabels, current = observation.associatedLabels(el);
    if (!original.complete) return { error: 'label_association_unavailable' };
    if (!current?.complete || current.count !== original.count || current.rows.length !== original.rows.length
        || original.rows.some((row, index) => ['element','root','control','htmlFor','parent','sensitive']
          .some(key => row[key] !== current.rows[index][key]))) return { error: 'target_changed' };
  }
  const association = item.labelAssociation;
  if (association) {
    if (typeof observation.labelAssociation !== 'function') return { error: 'stale_observation' };
    const current = observation.labelAssociation(el);
    if (!current || Object.keys(association).some(key => current[key] !== association[key])
        || current.control && !current.control.isConnected) return { error: 'target_changed' };
    if (current.sensitive) return { error: 'local_sensitive_input_required' };
    if (current.disabled) return { error: 'target_disabled' };
  }
  const label = observation.semanticLabel(el);
  if (observation.sensitiveAncestor(el) !== old.sensitive || el.getRootNode() !== item.root || el.tagName.toLowerCase() !== old.tag || el.getAttribute('role') !== old.role
      || label !== old.label || el.type !== item.inputType || el.name !== item.name
      || Object.hasOwn(item, 'domId') && (el.id ?? null) !== item.domId
      || !!el.readOnly !== item.readOnly || el.getAttribute('aria-disabled') !== item.ariaDisabled
      || el.getAttribute('aria-readonly') !== item.ariaReadonly || el.contentEditable !== item.contentEditable
      || !!el.isContentEditable !== item.isContentEditable) return { error: 'target_changed' };
  if (['fill','insert_text','undo','redo','press','check','select','select_text','replace_selection'].includes(inputAction)) {
    if (el.disabled || el.matches(':disabled') || el.getAttribute('aria-disabled') === 'true') return { error: 'target_disabled' };
    if (!['press','select_text'].includes(inputAction) && (el.readOnly || el.getAttribute('aria-readonly') === 'true')) return { error: 'target_readonly' };
    if (inputAction === 'fill' && (el.tagName !== 'TEXTAREA' && (el.tagName !== 'INPUT'
        || !['text','search','tel','url','email','number','password'].includes(el.type)))) return { error: 'invalid_input' };
  }
  if (old.value_truncated) return { error: 'target_value_exceeds_guard_limit' };
  const current = { x: r.x, y: r.y, width: r.width, height: r.height };
  if (['x', 'y', 'width', 'height'].some(k => Math.abs(current[k] - old.rect[k]) > 1)) return { error: 'target_moved' };
  if (!!el.disabled !== old.disabled || ('checked' in el && !!el.checked !== old.checked)
      || (!old.sensitive && 'value' in el && String(el.value).slice(0, 4096) !== old.value)) return { error: 'target_changed' };
  if (item.focusWitness && ['insert_text','undo','redo'].includes(inputAction)) {
    const owner = observation.focusWitnessState?.(el,item.focusWitness);
    if (!owner || focus) return {error:'editing_focus_witness_changed'};
    return {rect:owner.rect,x:owner.x,y:owner.y,sensitive:old.sensitive,tag:old.tag,hit_matches_target:true,
      focused:true,keyboard_only:true,editing_owner_witness_id:owner.id,shadow_hit_depth:0,
      hit_target:{tag:owner.hit.tagName.toLowerCase(),role:owner.hit.getAttribute('role')}};
  }
  const x = r.x + r.width / 2, y = r.y + r.height / 2;
  let hit = document.elementFromPoint(x, y), depth = 0;
  while (hit?.shadowRoot) {
    if (depth++ >= 100) return { error: 'shadow_hit_test_limit' };
    const nested = hit.shadowRoot.elementFromPoint(x, y);
    if (!nested) return { error: 'target_obstructed' };
    if (nested === hit) break;
    hit = nested;
  }
  let ancestor = hit;
  while (ancestor && ancestor !== el) ancestor = ancestor.assignedSlot || ancestor.parentElement || ancestor.getRootNode()?.host;
  if (!hit || ancestor !== el || el.disabled || el.getAttribute('aria-disabled') === 'true'
      || r.width <= 0 || r.height <= 0 || ['hidden', 'collapse'].includes(getComputedStyle(el).visibility)) return { error: 'target_obstructed' };
  // The admitted target can contain a different, sensitive hit recipient.
  // Check that recipient before focus or input, including through open shadows.
  if (observation.sensitiveAncestor(hit)) return { error: 'local_sensitive_input_required' };
  if (focus) el.focus();
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const focused = active === el;
  if (requireFocus && !focused) return { error: 'target_focus_changed' };
  return { rect: current, x, y, sensitive: old.sensitive, tag: old.tag, hit_matches_target: true, focused,
    shadow_hit_depth: depth, hit_target: { tag: hit.tagName.toLowerCase(), role: hit.getAttribute('role') } };
}
function readback(observationId, targetId, expectedText) {
  const observation = globalThis.__workbenchObservation?.id === observationId ? globalThis.__workbenchObservation : null;
  const item = observation?.targets.get(targetId);
  if (!item?.element.isConnected) return { connected: false };
  const el = item.element;
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const actual = item.description.sensitive || observation.sensitiveAncestor(el) ? null : ('value' in el ? String(el.value) : null);
  const result = { connected: true, value: actual === null ? null : actual.slice(0, 4096),
    value_truncated: actual !== null && actual.length > 4096,
    checked: 'checked' in el ? !!el.checked : null, focused: active === el };
  if (typeof expectedText === 'string') {
    result.desired_state_achieved = actual !== null && actual === expectedText;
    result.state_verified = actual !== null;
  }
  return result;
}

// Classification reads only public editable identity, even when privacy or
// structure made the retained editing sample unavailable. Unknown is refusal,
// never permission to take the generic focus-repair/activation route.
function editingKeyRecipient(observationId, targetId, navigationRequested = false) {
  const observation=globalThis.__workbenchObservation?.id===observationId?globalThis.__workbenchObservation:null;
  const item=observation?.targets.get(targetId),el=item?.element;
  if(!el?.isConnected||typeof item.isContentEditable!=='boolean')return {error:'editing_classification_unavailable'};
  if(['INPUT','TEXTAREA'].includes(el.tagName))return {contenteditable:false};
  if(typeof HTMLElement==='undefined')return {error:'editing_classification_unavailable'};
  const getter=Object.getOwnPropertyDescriptor(HTMLElement.prototype,'isContentEditable')?.get;
  if(typeof getter!=='function')return {error:'editing_classification_unavailable'};
  // Non-HTML activation cannot use the HTMLElement getter on itself. It also
  // cannot borrow a generic key route from an editable/context-owning ancestor.
  if(!(el instanceof HTMLElement)){
    if(item.isContentEditable)return {error:'editing_classification_unavailable'};
    const contextGetter=Object.getOwnPropertyDescriptor(HTMLElement.prototype,'editContext')?.get;
    if(typeof EditContext!=='undefined'&&typeof contextGetter!=='function')return {error:'editing_classification_unavailable'};
    let depth=0;
    for(let owner=el.assignedSlot||el.parentElement||el.getRootNode?.()?.host;owner;
        owner=owner.assignedSlot||owner.parentElement||owner.getRootNode?.()?.host){
      if(++depth>100)return {error:'editing_classification_unavailable'};
      if(owner instanceof HTMLElement){
        const editable=getter.call(owner);
        if(typeof editable!=='boolean'||editable||typeof contextGetter==='function'&&contextGetter.call(owner))
          return {error:'editing_classification_unavailable'};
      }
    }
    return {contenteditable:false};
  }
  const editable=getter.call(el);
  if(typeof editable!=='boolean')return {error:'editing_classification_unavailable'};
  const contenteditable=item.isContentEditable||editable;
  if(!navigationRequested||!contenteditable)return {contenteditable};
  const contextGetter=Object.getOwnPropertyDescriptor(HTMLElement.prototype,'editContext')?.get;
  if(typeof EditContext!=='undefined'&&typeof contextGetter!=='function')return {error:'editing_classification_unavailable'};
  const context=typeof EditContext==='undefined'?null:contextGetter.call(el);
  return {contenteditable,dom_navigation:!context&&item.editing?.kind!=='public_edit_context'};
}

// Literal keyboard intents retain the original public recipient and selection.
// A zero-size host additionally requires the retained exact visible-owner
// focus-point witness; ancestry alone never grants this keyboard-only route.
function literalEditingState(observationId, targetId, mode = 'verify') {
  const observation = globalThis.__workbenchObservation?.id === observationId ? globalThis.__workbenchObservation : null;
  const item = observation?.targets.get(targetId), el = item?.element;
  if (!el?.isConnected || !item.editing || typeof observation.editingSample !== 'function') return { error:'editing_recipient_unavailable' };
  if (observation.sensitiveAncestor(el)) return { error:'local_sensitive_input_required' };
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  if (active !== el) return { error:'target_focus_changed' };
  for (let owner = el, depth = 0; owner; owner = owner.assignedSlot || owner.parentElement || owner.getRootNode()?.host) {
    if (++depth > 100) return { error:'editing_owner_limit' };
    if (owner.readOnly || owner.getAttribute('aria-readonly') === 'true') return { error:'target_readonly' };
    const style = getComputedStyle(owner);
    if (owner.hidden || owner.inert || owner.disabled || owner.getAttribute('aria-disabled') === 'true'
        || style.display === 'none' || ['hidden','collapse'].includes(style.visibility) || Number(style.opacity) === 0)
      return { error:'target_obstructed' };
  }
  const r = el.getBoundingClientRect();
  if (item.focusWitness && !observation.focusWitnessState?.(el,item.focusWitness)) return {error:'editing_focus_witness_changed'};
  if ((r.width <= 0 || r.height <= 0) && !item.focusWitness) return { error:'editing_owner_geometry_unverified' };
  const metadataOnly=mode==='post_metadata';
  const reading = metadataOnly || mode==='readback' || mode==='selection_navigation_readback';
  const now = observation.editingSample(el, reading, metadataOnly), old = item.editing;
  if (now?.readOnly) return { error:'target_readonly' };
  if (now?.disabled) return { error:'target_disabled' };
  if (!now || now.identity !== old.identity || now.kind !== old.kind || el.getRootNode() !== item.root)
    return { error:'editing_recipient_changed' };
  if (old.shadowLineage) {
    if (!now.shadowLineage || now.shadowLineage.length !== old.shadowLineage.length
        || now.shadowLineage.some((row,i)=>['element','root','parent','slot','ownShadow'].some(k=>row[k]!==old.shadowLineage[i][k])))
      return {error:'editing_shadow_lineage_changed'};
  }
  if (metadataOnly) return now;
  if (mode==='selection_navigation_readback' && now.kind==='native_text_control'
      && !['forward','backward','none'].includes(now.direction)) return {error:'text_selection_direction_unavailable'};
  if (!reading) {
    if (now.text !== old.text || now.maxLength !== old.maxLength) return { error:'target_changed' };
    if (old.composedWitness && (!now.composedWitness || Object.keys(old.composedWitness).some(k=>now.composedWitness[k]!==old.composedWitness[k])))
      return {error:'editing_composed_selection_changed'};
    if (mode==='selection_navigation' && now.kind==='native_text_control'
        && (!['forward','backward','none'].includes(old.direction) || now.direction!==old.direction))
      return {error:'target_selection_direction_changed'};
    if (now.kind === 'public_dom_contenteditable') {
      if (now.nodes.length !== old.nodes.length || now.nodes.some((row,i) => row.node !== old.nodes[i].node
          || row.parent !== old.nodes[i].parent || row.children.length !== old.nodes[i].children.length
          || row.children.some((child,j) => child !== old.nodes[i].children[j]))) return {error:'editing_recipient_changed'};
      if (now.anchor !== old.anchor || now.focus !== old.focus || now.anchorOffset !== old.anchorOffset || now.focusOffset !== old.focusOffset)
        return {error:'target_selection_changed'};
    }
    if (now.start !== old.start || now.end !== old.end) return { error:'target_selection_changed' };
    const split = offset => offset > 0 && offset < now.text.length && /[\uD800-\uDBFF]/.test(now.text[offset-1]) && /[\uDC00-\uDFFF]/.test(now.text[offset]);
    if (split(now.start) || split(now.end)) return { error:'invalid_browser_text_range' };
  }
  return { connected:true, focused:true, kind:now.kind, text:now.text, text_length:now.textLength, text_truncated:now.textLength > now.text.length, selection_start:now.start,
    selection_end:now.end, offset_units:'UTF-16 code units', scope:now.scope,
    ...(now.structure?{dom_structure:now.structure}:{}),...(now.direction?{selection_direction:now.direction}:{}),
    state_verified:true, entire_editor_verified:false };
}


// Plain arrows acquire one explicit recipient focus, then retain a separate
// native Selection witness. Readonly is navigation permission, never editing.
function domNavigationState(observationId,targetId,prepare=false,publicReadback=false) {
  const o=globalThis.__workbenchObservation?.id===observationId?globalThis.__workbenchObservation:null;
  const item=o?.targets.get(targetId),el=item?.element;
  if(!el?.isConnected||el.getRootNode()!==item.root||typeof o.editingSample!=='function')return {error:'navigation_recipient_unavailable'};
  if(o.sensitiveAncestor(el))return {error:'local_sensitive_input_required'};
  if(!prepare){let active=document.activeElement;while(active?.shadowRoot?.activeElement)active=active.shadowRoot.activeElement;
    if(active!==el)return {error:'target_focus_changed'};}
  for(let owner=el,depth=0;owner;owner=owner.assignedSlot||owner.parentElement||owner.getRootNode()?.host){
    if(++depth>100)return {error:'editing_owner_limit'};
    if(owner.assignedSlot)return {error:'navigation_slot_unsupported'};
    const style=getComputedStyle(owner);
    if(owner.hidden||owner.inert||owner.disabled||owner.getAttribute('aria-disabled')==='true'
        ||style.display==='none'||['hidden','collapse'].includes(style.visibility)||Number(style.opacity)===0)return {error:'target_obstructed'};
  }
  const r=el.getBoundingClientRect();if(r.width<=0||r.height<=0)return {error:'editing_owner_geometry_unverified'};
  const sample=o.editingSample(el,true,!publicReadback,prepare?'prepare':'focused');
  if(sample?.kind!=='public_dom_contenteditable')return {error:'navigation_recipient_unavailable'};
  if(!publicReadback)return sample;
  return {connected:true,focused:true,kind:sample.kind,text:sample.text,text_length:sample.textLength,text_truncated:false,
    selection_start:sample.start,selection_end:sample.end,offset_units:'UTF-16 code units',scope:sample.scope,
    dom_structure:sample.structure,navigation_only:true,state_verified:true,entire_editor_verified:false};
}

// A separate, one-shot post-effect witness. Never rebase the pre-input intent.
// Capture uses only bounded public node metadata and native text-node lengths.
function domEditingPostState(observationId,targetId,token,phase,index=null,mode='readback') {
  const o=globalThis.__workbenchObservation;
  if (!o || o.id!==observationId) return {error:'editing_post_witness_unavailable'};
  const item=o.targets.get(targetId),navigation=mode.startsWith('navigation_'),prepare=mode==='navigation_prepare';
  if (phase==='discard') { if(o.postEditingWitness?.token===token)delete o.postEditingWitness;return null; }
  const capture=()=>{
    if(!navigation && item?.editing?.kind!=='public_dom_contenteditable')return null;
    const sample=navigation?domNavigationState(observationId,targetId,prepare):literalEditingState(observationId,targetId,'post_metadata');
    if(sample.error || !sample.nodes)return null;
    const lineage=[],refs=[],expected=[];
    for(let el=item.element;el;el=el.assignedSlot||el.parentElement||el.getRootNode()?.host){
      if(lineage.length>=100)return null;
      const root=el.getRootNode(),slot=el.assignedSlot,ownShadow=el.shadowRoot;
      if(root!==document && (!(root instanceof ShadowRoot)||root.mode!=='open'||root.host.shadowRoot!==root||!o.roots?.includes(root)))return null;
      if(ownShadow && (!o.roots?.includes(ownShadow)||ownShadow.mode!=='open'))return null;
      lineage.push({element:el,root,parent:el.parentElement,slot,ownShadow});
    }
    for(const row of sample.nodes){
      row.root=row.node.getRootNode();row.slot=row.node.assignedSlot||null;
      if(row.slot || row.root!==item.root)return null;
      if(row.node.nodeType===1){refs.push(row.node);expected.push(false);}
    }
    for(const row of lineage){const i=refs.indexOf(row.element);if(i<0){refs.push(row.element);expected.push(!!row.ownShadow);}else if(row.ownShadow)return null;}
    return {sample,lineage,refs,expected};
  };
  const same=(fresh,prior,selection=true)=>{
    const now=fresh?.sample,old=prior?.sample;
    const fields=['identity','textLength',...(selection?['start','end','anchor','focus','anchorOffset','focusOffset']:[])];
    return !!now&&!!old&&!fields.some(k=>now[k]!==old[k])&&now.nodes.length===old.nodes.length
      &&!now.nodes.some((r,i)=>['node','parent','root','slot','start','end','kind','tag'].some(k=>r[k]!==old.nodes[i][k])
        ||r.children.length!==old.nodes[i].children.length||r.children.some((v,j)=>v!==old.nodes[i].children[j]))
      &&fresh.lineage.length===prior.lineage.length&&!fresh.lineage.some((r,i)=>Object.keys(r).some(k=>r[k]!==prior.lineage[i][k]))
      &&fresh.refs.length===prior.refs.length&&!fresh.refs.some((r,i)=>r!==prior.refs[i])
      &&(!selection||!!now.composedWitness===!!old.composedWitness
        &&(!old.composedWitness||!Object.keys(old.composedWitness).some(k=>now.composedWitness[k]!==old.composedWitness[k])));
  };
  const nav=o.domNavigationWitness;
  const navigationCurrent=()=>nav&&nav.item===item&&nav.targetId===targetId&&nav.intent===item.editing&&performance.now()<nav.expires;
  if(phase==='capture'){
    delete o.postEditingWitness;
    if(navigation && !prepare && !navigationCurrent())return {error:'navigation_witness_unavailable'};
    const fresh=capture();if(!fresh)return {error:'editing_post_capture_unverified'};
    if(navigation && (mode==='navigation_capture'&&!same(fresh,nav.prepared,false)
        ||mode==='navigation_verify'&&(!nav.selected||!same(fresh,nav.selected))))return {error:'navigation_witness_changed'};
    o.postEditingWitness={...fresh,token,targetId,item,intent:item.editing,mode,expires:performance.now()+1000};
    return {count:fresh.refs.length,expected:fresh.expected};
  }
  const w=o.postEditingWitness;
  if(!w||w.token!==token||w.targetId!==targetId||w.item!==item||w.intent!==item?.editing||w.mode!==mode||performance.now()>=w.expires)
    return {error:'editing_post_witness_unavailable'};
  if(phase==='node')return Number.isInteger(index)&&index>=0&&index<w.refs.length?w.refs[index]:null;
  if(phase!=='finish')return {error:'editing_post_witness_unavailable'};
  delete o.postEditingWitness;
  const fresh=capture();if(!same(fresh,w))return {error:'editing_post_witness_changed'};
  if(navigation){
    if(prepare)o.domNavigationWitness={item,targetId,intent:item.editing,prepared:fresh,selected:null,expires:performance.now()+5000};
    else{
      if(!navigationCurrent())return {error:'navigation_witness_unavailable'};
      if(mode==='navigation_capture')nav.selected=fresh;
      else if(mode==='navigation_verify'&&(!nav.selected||!same(fresh,nav.selected)))return {error:'navigation_witness_changed'};
    }
    if(mode==='navigation_readback')return domNavigationState(observationId,targetId,false,true);
    return {connected:true,...(!prepare?{focused:true}:{}),navigation_witness_verified:true,state_verified:true,
      kind:'public_dom_contenteditable',scope:'bounded_public_DOM_native_navigation_only_no_text_readback'};
  }
  // Same renderer task: no await or public text serialization before revalidation.
  return literalEditingState(observationId,targetId,mode);
}

async function guardedDomEditingReadback(record,observation,targetId,current,mode) {
  const token=uuid(),group='workbench-post-editing:'+token,deadline=performance.now()+250;
  let failureStage='capture';
  const checked=()=>{current();if(performance.now()>=deadline)throw fail('editing_post_metadata_timeout');};
  const expression=(phase,index=null)=>'(()=>{const literalEditingState='+literalEditingState.toString()
    +';const domNavigationState='+domNavigationState.toString()+';return ('+domEditingPostState.toString()+')('+[observation.id,targetId,token,phase,index,mode].map(v=>JSON.stringify(v)).join(',')+');})()';
  const evaluate=async(phase,index=null,remote=false)=>{
    checked();const r=await cdp(record,'Runtime.evaluate',{expression:expression(phase,index),uniqueContextId:observation.contextUniqueId,
      ...(remote?{objectGroup:group}:{}),returnByValue:!remote,awaitPromise:false},observation.frame.session_id,current);
    checked();if(r.exceptionDetails)throw fail('editing_post_metadata_unverified');return remote?r.result:r.result?.value;
  };
  try{
    const meta=await evaluate('capture');
    if(!meta || meta.error || !Number.isSafeInteger(meta.count)||meta.count<1||meta.count>356
      ||!Array.isArray(meta.expected)||meta.expected.length!==meta.count||meta.expected.some(v=>typeof v!=='boolean'))throw fail('editing_post_metadata_unverified');
    // Fixed retained refs are independent metadata reads. Share the original
    // deadline in bounded batches; settle every launched pair before cleanup.
    failureStage='retained_metadata';
    for(let first=0;first<meta.count;first+=8){
      checked();
      const batch=await Promise.allSettled(Array.from({length:Math.min(8,meta.count-first)},async(_,offset)=>{
        const i=first+offset;
        const node=await evaluate('node',i,true);if(!node?.objectId)throw fail('editing_post_metadata_unverified');
        checked();const r=await cdp(record,'DOM.describeNode',{objectId:node.objectId,depth:0,pierce:false},observation.frame.session_id,current);
        checked();const roots=r.node?.shadowRoots||[];
        if(r.node?.nodeType!==1||!Array.isArray(roots)||roots.length!==(meta.expected[i]?1:0)||roots.some(v=>v.shadowRootType!=='open'))throw fail('closed_shadow_editing_unsupported');
      }));
      for(const result of batch)if(result.status==='rejected')throw result.reason;
      checked();
    }
    failureStage='finish';
    const after=await evaluate('finish');if(!after||after.error)throw fail(after?.error||'editing_post_metadata_unverified');return after;
  }catch(error){error.editing_readback_stage=failureStage;throw error;}finally{
    try{await cdp(record,'Runtime.evaluate',{expression:expression('discard'),uniqueContextId:observation.contextUniqueId,returnByValue:true},observation.frame.session_id);}catch{}
    try{await cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group},observation.frame.session_id);}catch{}
    try{current();}catch(error){error.editing_readback_stage='cleanup_guard';throw error;}
  }
}

// Read-only witness, in the observed field's exact isolated world. Do not
// substitute select-all acknowledgement for a sampled native selection.
function fillSelectionState(observationId, targetId, capabilityOnly = false) {
  const observation = globalThis.__workbenchObservation?.id === observationId ? globalThis.__workbenchObservation : null;
  const item = observation?.targets.get(targetId), el = item?.element;
  if (!el?.isConnected || observation.sensitiveAncestor(el)) return { error: 'fill_selection_unavailable' };
  if (el.disabled || el.matches(':disabled') || el.getAttribute('aria-disabled') === 'true') return { error: 'target_disabled' };
  if (el.readOnly || el.getAttribute('aria-readonly') === 'true') return { error: 'target_readonly' };
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const text = typeof el.value === 'string' ? el.value : null;
  if (active !== el || text === null || text !== item.description.value) return { error: 'target_changed' };
  const start = el.selectionStart, end = el.selectionEnd;
  if (Number.isInteger(start) && Number.isInteger(end)) return { start, end, text_length: text.length,
    selection_capable: true, selection_verified: start === 0 && end === text.length, mechanism: 'native_text_control_range' };
  if (el.tagName !== 'INPUT' || !['email', 'number'].includes(el.type)) return { error: 'fill_selection_capability_unverified' };
  if (el.disabled || el.readOnly || el.validity.badInput) return { error: 'target_changed' };
  // These controls expose null selection offsets. Native Selection.type and
  // a composed range can witness their UA-shadow selection without changing it.
  if (text.length === 0) return { selection_capable: true, selection_verified: true,
    native_selection_verified: false, mechanism: 'empty_value_no_replacement_required' };
  const selection = document.getSelection();
  const nativeType = Object.getOwnPropertyDescriptor(Selection.prototype, 'type')?.get;
  if (!selection || !nativeType || typeof Selection.prototype.getComposedRanges !== 'function') return { error: 'native_selection_witness_unavailable' };
  if (capabilityOnly) return { selection_capable: true, selection_verified: false, mechanism: 'native_composed_range_available' };
  if (nativeType.call(selection) !== 'Range' || Selection.prototype.toString.call(selection) !== text) return { error: 'fill_selection_unverified' };
  // Matching text alone could be selected elsewhere. Bind the single range to
  // this exact input's host boundaries, including every observed open shadow root.
  const roots = [];
  for (let root = el.getRootNode(); root?.host; root = root.host.getRootNode()) roots.push(root);
  const ranges = Selection.prototype.getComposedRanges.call(selection, { shadowRoots: roots });
  const parent = el.parentNode, index = Array.prototype.indexOf.call(parent.childNodes, el);
  const range = ranges.length === 1 ? ranges[0] : null;
  const matches = !!range && index >= 0 && range.startContainer === parent && range.endContainer === parent
    && range.startOffset === index && range.endOffset === index + 1;
  return { selection_capable: true, selection_verified: matches, native_selection_verified: matches,
    mechanism: 'native_select_all_with_composed_range_witness', range_matches_control: matches };
}


async function grantLocal(tabId, options) {
  await ensureConnection();
  const grantPort = port, grantPeer = peerId;
  const setup = reserveLocalSetup(grantPort);
  try {
  const connectionCurrent = () => setup.current() && port === grantPort && peerId === grantPeer && !!serverGeneration;
  const tab = await chrome.tabs.get(tabId), site = tab.url ? webOrigin(tab.url) : null;
  const resourceCurrent = () => requireCreationAdmission(tabId, tab.windowId);
  resourceCurrent();
  if (!connectionCurrent()) throw fail('workbench_not_connected');
  if (tab.incognito && (!chrome.extension.inIncognitoContext || !await chrome.extension.isAllowedIncognitoAccess())) throw fail('private_context_not_enabled');
  resourceCurrent();
  if (!connectionCurrent()) throw fail('workbench_not_connected');
  if (!Number.isInteger(options.seconds) || options.seconds < 60 || options.seconds > 900 || typeof options.control !== 'boolean' || typeof options.network !== 'boolean') throw fail('invalid_grant');
  for (const current of leases.values()) if (current.tabId === tabId && current.durable && (current.releasing || !['released', 'revoked', 'target_closed'].includes(current.state))) throw fail('browser_target_owned');
  for (const current of leases.values()) if (!current.durable && current.state === 'active' && current.tabId === tabId) await detach(current, 'local_grant_replaced');
  if ([...leases.values()].filter(r => !r.durable).length >= 32) {
    for (const [id, r] of leases) if (!r.durable && r.state !== 'active'
        && !['pending','unverified'].includes(r.cleanup_state)
        && !['prepared','held','unverified','not_recorded'].includes(r.heldKey?.state || r.keyboard_release_state)) {
      for (const row of r.requests.values()) releaseBody(row);
      leases.delete(id);
    }
    if ([...leases.values()].filter(r => !r.durable).length >= 32) throw fail('grant_limit');
  }
  if (!connectionCurrent()) throw fail('workbench_not_connected');
  resourceCurrent();
  const originalTarget = (await chrome.debugger.getTargets()).find(t => t.tabId === tabId && t.type === 'page');
  resourceCurrent();
  if (!originalTarget || !connectionCurrent()) throw fail('stale_browser_target');
  for (const row of leases.values()) if (!row.durable && row.browserTargetId === originalTarget.id
      && ['pending','unverified'].includes(row.cleanup_state)) throw fail('browser_cleanup_pending');
  for (const row of legacyKeyboardHistory.values()) if (row.browser_target_id === originalTarget.id)
    throw fail('browser_key_release_unverified');
  await chrome.debugger.attach({ tabId }, '1.3');
  if (!connectionCurrent()) {
    try { await chrome.debugger.detach({ targetId: originalTarget.id }); } catch { /* Original attachment was already lost. */ }
    throw fail('workbench_not_connected');
  }
  const record = { id: uuid(), tabId, windowId: tab.windowId, origin: site, generation: 1, expires: Date.now() + options.seconds * 1000,
    control: options.control, network: options.network, peerId: grantPeer, state: 'active', events: [], eventSequence: 0, eventsDropped: 0,
    observations: new Map(), children: new Map(), contextUniqueIds: new Map(), requests: new Map(), requestCounter: 0,
    browserTargetId: originalTarget.id, grantGeneration: uuid(), debuggerAttached: true,
    installation_id: installationId, runtime_generation: serverGeneration, initializing: true };
  leases.set(record.id, record);
  try {
    let waiting = true, timer;
    const deadline = performance.now() + 5000;
    const current = () => {
      if (!waiting || performance.now() >= deadline) throw fail('browser_document_readiness_timeout');
      resourceCurrent();
      if (!connectionCurrent() || record.state !== 'active' || record.inputEligible === false || leases.get(record.id) !== record) throw fail('workbench_not_connected');
    };
    try { await Promise.race([(async () => {
    await initializeRootInput(record, current); current();
    await (async () => {
      current(); await Promise.all([
        cdp(record, 'Page.enable').then(() => current()),
        cdp(record, 'Runtime.enable').then(() => current())
      ]); current();
    })(); current();
    const root = (await cdp(record, 'Page.getFrameTree')).frameTree.frame; current();
    const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === tabId && t.type === 'page'); current();
    if (actual?.id !== originalTarget.id) throw fail('stale_browser_target');
    const actualOrigin = webOrigin(root.securityOrigin || root.url);
    if (site && site !== actualOrigin) throw fail('selected_site_changed');
    record.origin = actualOrigin;
    record.loaderId = root.loaderId; record.mainFrameId = root.id;
    if (options.network) { await cdp(record, 'Network.enable', { maxTotalBufferSize: 8388608, maxResourceBufferSize: 2097152, maxPostDataSize: 0 }); current();
            await enableBodyCapture(record, undefined, current); current(); }
    try { await cdp(record, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true,
      filter: [{ type: 'iframe', exclude: false }, { type: 'worker', exclude: false }, { exclude: true }] }); }
    catch { event(record, 'coverage_gap', { reason: 'related_target_attachment_unavailable' }); }
    current();
    await invalidateCreationRetirement(tabId, originalTarget.id, current); current();
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(fail('browser_document_readiness_timeout')), 5000); })]);
    } finally { waiting = false; clearTimeout(timer); }
    resourceCurrent();
    record.initializing = false;
    event(record, 'attached', { pre_attach_network_gap: true, cookies_and_headers_captured: false }); state();
    await chrome.alarms.create('lease:' + record.id, { when: record.expires });
    resourceCurrent();
    if (!connectionCurrent() || record.state !== 'active') throw fail('workbench_not_connected');
    return publicLease(record);
  } catch (error) { event(record, 'setup_failed', { reason: error.code || 'browser_protocol_setup_failed', protocol_error_code: bodyProtocolError(error).code }); await detach(record, 'setup_failed'); throw fail('browser_attach_failed'); }
  } finally { setup.finish(); }
}

// Public control-range API only; no focus repair, selected content or key synthesis.
function textControlSelection(observationId, targetId, start, length, mode = 'verify') {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  const item = observation.targets.get(targetId), el = item?.element;
  if (!el?.isConnected) return { error: 'stale_target' };
  if (observation.sensitiveAncestor(el)) return { error: 'local_sensitive_input_required' };
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
    : el.tagName === 'INPUT' && ['text','search','tel','url'].includes(el.type) ? HTMLInputElement.prototype : null;
  if (!proto) return { error: 'unsupported_text_selection_control' };
  const target = targetInfo(observationId, targetId, false, false, 'select_text');
  if (target.error) return target;
  const text = Object.getOwnPropertyDescriptor(proto, 'value').get.call(el);
  if (text !== item.description.value) return { error: 'target_changed' };
  if (!Number.isInteger(start) || !Number.isInteger(length) || start < 0 || length < 0
      || start + length > text.length || start + length > 32768) return { error: 'invalid_browser_text_range' };
  const read = () => {
    const actualStart = Object.getOwnPropertyDescriptor(proto, 'selectionStart').get.call(el);
    const actualEnd = Object.getOwnPropertyDescriptor(proto, 'selectionEnd').get.call(el);
    if (!Number.isInteger(actualStart) || !Number.isInteger(actualEnd)) return { error: 'text_selection_readback_unavailable' };
    return { connected: true, selection_start: actualStart, selection_length: actualEnd - actualStart,
      selection_end: actualEnd, value_length: text.length, offset_units: 'UTF-16 code units',
      desired_state_achieved: actualStart === start && actualEnd === start + length, state_verified: true,
      focused: target.focused, value_unchanged: true, dispatched: false };
  };
  const before = read();
  if (before.error || mode !== 'apply' || before.desired_state_achieved) return before;
  const setter = proto.setSelectionRange;
  if (typeof setter !== 'function') return { error: 'text_selection_setter_unavailable' };
  setter.call(el, start, start + length, 'none');
  return { dispatched: true };
}

// A semantic DOM setter, without focus repair, keyboard synthesis or synthetic
// input/change events. The original value and range stay bound to the observation.
function textControlReplacement(observationId, targetId, replacement, mode = 'verify') {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  const item = observation.targets.get(targetId), el = item?.element, old = item?.description;
  if (!el?.isConnected) return { error: 'stale_target' };
  if (observation.sensitiveAncestor(el)) return { error: 'local_sensitive_input_required' };
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
    : el.tagName === 'INPUT' && ['text','search','tel','url'].includes(el.type) ? HTMLInputElement.prototype : null;
  if (!proto) return { error: 'unsupported_text_selection_control' };
  const start = old.selection_start, end = old.selection_end, original = old.value, maxLength = old.max_length;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start
      || typeof original !== 'string' || end > original.length || !Number.isInteger(maxLength) || maxLength < -1) return { error: 'text_selection_unavailable' };
  const splitsPair = offset => offset > 0 && offset < original.length
    && original.charCodeAt(offset - 1) >= 0xd800 && original.charCodeAt(offset - 1) <= 0xdbff
    && original.charCodeAt(offset) >= 0xdc00 && original.charCodeAt(offset) <= 0xdfff;
  if (splitsPair(start) || splitsPair(end)) return { error: 'invalid_browser_text_range' };
  if (typeof replacement !== 'string' || replacement.length > 4096) return { error: 'invalid_browser_replacement' };
  const expected = original.slice(0, start) + replacement + original.slice(end);
  if (expected.length > 4096) return { error: 'target_value_exceeds_guard_limit' };
  if (maxLength >= 0 && expected.length > maxLength) return { error: 'browser_text_limit_exceeded' };
  const noOp = expected === original;
  const read = () => {
    const value = Object.getOwnPropertyDescriptor(proto, 'value').get.call(el);
    const actualStart = Object.getOwnPropertyDescriptor(proto, 'selectionStart').get.call(el);
    const actualEnd = Object.getOwnPropertyDescriptor(proto, 'selectionEnd').get.call(el);
    const currentMaxLength = Object.getOwnPropertyDescriptor(proto, 'maxLength').get.call(el);
    if (value.length > 4096 || !Number.isInteger(actualStart) || !Number.isInteger(actualEnd)
        || actualStart < 0 || actualEnd < actualStart || actualEnd > value.length) return { error: 'text_replacement_readback_unavailable' };
    let active = document.activeElement;
    while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
    return { value, value_length: value.length, selection_start: actualStart, selection_end: actualEnd,
      selection_length: actualEnd - actualStart, focused: active === el, state_verified: true,
      max_length: currentMaxLength, field_limit_unchanged: currentMaxLength === maxLength,
      within_observed_field_limit: maxLength < 0 || value.length <= maxLength,
      literal_value_matches: value === expected,
      desired_state_achieved: currentMaxLength === maxLength && value === expected && actualStart === (noOp ? start : start + replacement.length)
        && actualEnd === (noOp ? end : start + replacement.length), dispatched: false };
  };
  if (mode !== 'readback') {
    const target = targetInfo(observationId, targetId, false, false, 'replace_selection');
    if (target.error) return target;
    const before = read();
    if (before.error) return before;
    if (before.value !== original) return { error: 'target_changed' };
    if (!before.field_limit_unchanged) return { error: 'target_field_limit_changed' };
    if (before.selection_start !== start || before.selection_end !== end) return { error: 'target_selection_changed' };
    if (mode !== 'apply' || noOp) return before;
    if (typeof proto.setRangeText !== 'function') return { error: 'text_replacement_setter_unavailable' };
    proto.setRangeText.call(el, replacement, start, end, 'end');
    // No Workbench normalization: native browser sanitization is sampled as-is.
    const after = read();
    if (after.error) throw Error(after.error);
    return { ...after, dispatched: true };
  }
  return read();
}

// targetInfo is injected in the same isolated evaluation. Option values/text
// stay in the private observation guard; results expose only indices/counts.
function formControl(observationId, targetId, kind, desired, mode = 'verify') {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  const item = observation.targets.get(targetId), el = item?.element, guard = item?.formGuard;
  if (!el?.isConnected) return { error: 'stale_target' };
  if (observation.sensitiveAncestor(el)) return { error: 'local_sensitive_input_required' };
  if (kind === 'check' && (el.tagName !== 'INPUT' || el.type !== 'checkbox')) return { error: 'unsupported_checkbox_control' };
  if (kind === 'select' && el.tagName !== 'SELECT') return { error: 'unsupported_select_control' };
  if (!guard || guard.error) return { error: guard?.error || 'stale_form_control' };
  if (mode !== 'readback') {
    const target = targetInfo(observationId, targetId, false, false, kind);
    if (target.error) return target;
    if (el.matches(':disabled')) return { error: 'target_disabled' };
  }
  if (kind === 'check') {
    if (mode !== 'readback' && (guard.checked !== !!el.checked || guard.indeterminate !== !!el.indeterminate)) return { error: 'target_changed' };
    if (el.indeterminate) return { error: 'unsupported_checkbox_state' };
    return { connected: true, checked: !!el.checked, desired_state_achieved: !!el.checked === desired, state_verified: true, dispatched: false };
  }
  if (el.multiple !== guard.multiple || el.options.length !== guard.options.length) return { error: 'select_options_changed' };
  for (let i = 0; i < guard.options.length; i++) {
    const option = el.options[i], old = guard.options[i];
    if (option !== old.element || option.value !== old.value || option.text !== old.text || option.matches(':disabled') !== old.disabled
        || optionEffectivelyHidden(option) !== old.hidden
        || mode !== 'readback' && !!option.selected !== old.selected) return { error: 'select_options_changed' };
    if (observation.sensitiveAncestor(option)) return { error: 'local_sensitive_input_required' };
  }
  if (!el.multiple && desired.length !== 1) return { error: 'invalid_select_options' };
  const indices = [];
  for (const value of desired) {
    const matches = guard.options.flatMap((option, index) => option.value === value ? [index] : []);
    if (!matches.length) return { error: 'select_option_not_found' };
    if (matches.length !== 1) return { error: 'ambiguous_select_option' };
    if (guard.options[matches[0]].disabled || guard.options[matches[0]].hidden) return { error: 'select_option_unavailable' };
    indices.push(matches[0]);
  }
  const current = Array.from(el.options).flatMap((option, index) => option.selected ? [index] : []);
  const achieved = current.length === indices.length && indices.every(index => current.includes(index));
  if (mode !== 'apply' || achieved) return { connected: true, selected_option_indexes: current, selected_count: current.length,
    desired_state_achieved: achieved, state_verified: true, dispatched: false };
  const setter = Object.getOwnPropertyDescriptor(HTMLOptionElement.prototype, 'selected')?.set;
  if (!setter) return { error: 'select_native_setter_unavailable' };
  for (let i = 0; i < el.options.length; i++) setter.call(el.options[i], indices.includes(i));
  el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return { dispatched: true };
}


function wheelTargetState(observationId, targetId, mode = 'prepare') {
  const observation = globalThis.__workbenchObservation, item = observation?.targets.get(targetId), el = item?.element;
  if (!observation || observation.id !== observationId || !el?.isConnected) return { error: 'stale_target' };
  if (el.getRootNode() !== item.root) return { error: 'target_changed' };
  if (observation.sensitiveAncestor(el)) return { error: 'local_sensitive_input_required' };
  const chain = () => {
    const nodes = []; let node = el;
    while (node) {
      if (nodes.length >= 32 || nodes.includes(node)) return null;
      nodes.push(node); node = node.assignedSlot || node.parentElement || node.getRootNode()?.host;
    }
    if (document.scrollingElement && !nodes.includes(document.scrollingElement)) {
      if (nodes.length >= 32) return null;
      nodes.push(document.scrollingElement);
    }
    return nodes;
  };
  const sample = nodes => {
    const rows = nodes.map((node, index) => ({ index, root_scroller: node === document.scrollingElement,
      scroll_left: node.scrollLeft, scroll_top: node.scrollTop, client_width: node.clientWidth, client_height: node.clientHeight,
      scroll_width: node.scrollWidth, scroll_height: node.scrollHeight }));
    if (rows.some(row => ['scroll_left','scroll_top','client_width','client_height','scroll_width','scroll_height']
        .some(key => typeof row[key] !== 'number' || !Number.isFinite(row[key])))) return { error: 'scroll_metrics_unavailable' };
    return { dom_revision: observation.revision, nodes: rows };
  };
  if (mode === 'prepare') {
    const checked = targetInfo(observationId, targetId);
    if (checked.error) return checked;
    if (el.matches(':disabled')) return { error: 'target_disabled' };
    const nodes = chain(); if (!nodes) return { error: 'scroll_ancestor_limit' };
    item.wheelGuard = { nodes };
    const metrics = sample(nodes); if (metrics.error) return metrics;
    return { dispatch_target: checked, sample: metrics, ancestor_limit: 32 };
  }
  const guard = item.wheelGuard;
  if (!guard) return { error: 'stale_scroll_observation' };
  const nodes = chain();
  if (!nodes || nodes.length !== guard.nodes.length || nodes.some((node, index) => node !== guard.nodes[index])) return { error: 'scroll_ancestors_changed' };
  return sample(nodes);
}

function dragTargets(observationId, startId, endId, mode, point) {
  const observation = globalThis.__workbenchObservation;
  if (!observation || observation.id !== observationId) return { error: 'stale_observation' };
  const start = observation.targets.get(startId), end = observation.targets.get(endId);
  if (!start?.element.isConnected || !end?.element.isConnected) return { error: 'stale_target' };
  for (const item of [start, end]) {
    const el = item.element;
    if (el.getRootNode() !== item.root || observation.sensitiveAncestor(el)) return { error: 'local_sensitive_input_required' };
    if (el.matches(':disabled') || el.getAttribute('aria-disabled') === 'true') return { error: 'target_disabled' };
    if (el.draggable) return { error: 'native_html_drag_payload_unsupported' };
  }
  if (mode === 'readback') {
    const source = readback(observationId, startId), destination = readback(observationId, endId);
    return { source, destination, dom_revision: observation.revision,
      control_state_changed: source.value !== start.description.value || source.checked !== start.description.checked
        || destination.value !== end.description.value || destination.checked !== end.description.checked };
  }
  const finish = targetInfo(observationId, endId);
  if (finish.error) return finish;
  let begin = null;
  if (mode === 'prepare') {
    begin = targetInfo(observationId, startId); if (begin.error) return begin;
    if (start.element.contains(end.element) || end.element.contains(start.element)
        || Math.abs(begin.x - finish.x) < 1 && Math.abs(begin.y - finish.y) < 1) return { error: 'drag_endpoints_ambiguous' };
  }
  if (point) {
    let hit = document.elementFromPoint(point.x, point.y), depth = 0;
    while (hit?.shadowRoot) { if (depth++ >= 100) return { error: 'shadow_hit_test_limit' }; hit = hit.shadowRoot.elementFromPoint(point.x, point.y); }
    if (!hit) return { error: 'drag_path_unavailable' };
    if (['iframe', 'frame'].includes(String(hit.tagName || '').toLowerCase())) return { error: 'frame_pointer_input_unavailable' };
    if (observation.sensitiveAncestor(hit)) return { error: 'local_sensitive_input_required' };
  }
  return { start: begin, end: finish, dom_revision: observation.revision };
}

// Optional diagnostic projection only. Never serialize SDK messages, paths,
// file contents, arbitrary error codes or exception descriptions.
function uploadDiagnosticError(error) {
  try {
    if (['browser_upload_timeout','upload_admission_timeout'].includes(error?.code))
      return { category: 'timeout', protocol_code: null };
    if (['upload_authority_changed','upload_authority_invalid','upload_input_not_empty','upload_input_unsupported',
      'upload_target_unavailable','upload_selection_unverified','upload_cleanup_unverified','local_sensitive_input_required',
      'stale_observation','stale_execution_context','stale_browser_frame','browser_file_upload_not_granted',
      'browser_upload_pending','workbench_not_connected','browser_evaluation_failed',
      'browser_local_file_access_not_enabled'].includes(error?.code))
      return { category: 'guard_refusal', protocol_code: null };
    let code = error?.code;
    if (typeof error?.message === 'string' && error.message.length <= 4096) {
      try { code = JSON.parse(error.message)?.code ?? code; } catch {}
    }
    if (Number.isInteger(code) && [-32700,-32600,-32601,-32602,-32603,-32000].includes(code))
      return { category: 'protocol_rejection', protocol_code: code };
    if (['TypeError','RangeError'].includes(error?.name))
      return { category: 'javascript_exception', protocol_code: null };
  } catch {} // Optional diagnostics must never replace the original failure.
  return { category: 'unclassified_error', protocol_code: null };
}
// Public read-only browser capability. Unknown is diagnostic only: older or
// unavailable APIs retain the existing guarded upload path. Never change consent.
async function uploadFileAccessReadiness(deadline) {
  const kind = contextKind();
  const unknown = reason => ({ allowed: null, reason, context_kind: kind });
  let method;
  try { method = chrome.extension?.isAllowedFileSchemeAccess; }
  catch { return unknown('api_failure'); }
  if (typeof method !== 'function') return unknown('api_unavailable');
  let timer;
  try {
    const result = await Promise.race([
      Promise.resolve().then(() => method.call(chrome.extension))
        .then(value => ({ type: 'value', value }), () => ({ type: 'failure' })),
      new Promise(resolve => { timer = setTimeout(() => resolve({ type: 'timeout' }),
        Math.max(0, Math.min(500, deadline - performance.now()))); })
    ]);
    if (contextKind() !== kind) return unknown('context_changed');
    if (result.type === 'timeout') return unknown('query_timeout');
    if (result.type === 'failure') return unknown('api_failure');
    return typeof result.value === 'boolean' ? { allowed: result.value, reason: 'observed', context_kind: kind }
      : unknown('invalid_response');
  } catch { return unknown('api_failure'); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
// Host-only content carrier: no public fallback and no arbitrary browser paths.
function uploadContentExchange(packet, nodeId, type, extra = {}) {
  const authority = packet.upload_authority, nonce = uuid(), currentPort = port, currentPeer = peerId;
  return new Promise((resolve, reject) => {
    if (uploadWaiters.size >= 4) { reject(fail('browser_upload_pending')); return; }
    const timer = setTimeout(() => { uploadWaiters.delete(nonce); reject(fail('upload_admission_timeout')); }, 5000);
    uploadWaiters.set(nonce, { resolve, reject, timer, port: currentPort, content: true,
      requestId: packet.request_id, peer: currentPeer,
      replyType: type === 'upload_content_read' ? 'upload_content_result' : 'upload_admission_result' });
    if (!sendNative(currentPort, { type, nonce, request_id: packet.request_id, peer_id: currentPeer,
        worker_generation: workerGeneration, carrier: 'supplied_content', token: authority.token,
        binding: authority.binding, backend_node_id: nodeId, ...extra })) {
      clearTimeout(timer); uploadWaiters.delete(nonce); reject(fail('workbench_not_connected'));
    }
  });
}

// Executed only in the already-bound isolated observation world, on its exact
// remote input object. Native prototype access avoids page-world File/getter/
// crypto overrides. Never read the contents of a preexisting/replacement File.
async function suppliedContentFile(encoded, filename, expectedSha, observationId, targetId, checkTarget) {
  const fileProperty = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'files');
  const readFiles = () => fileProperty.get.call(this);
  const bytes = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const file = new File([bytes], filename, { type: 'application/octet-stream', lastModified: 0 });
  bytes.fill(0);
  if (file.name !== filename) return { readback_started: false, error: 'upload_content_unsupported' };
  const transfer = new DataTransfer(); transfer.items.add(file);
  // No await between fresh target/empty checks and the one setter.
  const checked = checkTarget(observationId, targetId);
  if (checked.error) return { ...checked, readback_started: false };
  if (__workbenchObservation.targets.get(targetId)?.element !== this || checked.sensitive
      || this.tagName !== 'INPUT' || this.type !== 'file' || this.multiple) return { readback_started: false, error: 'upload_target_unavailable' };
  if (readFiles().length !== 0) return { readback_started: false, error: 'upload_input_not_empty' };
  fileProperty.set.call(this, transfer.files);
  if (readFiles().length !== 1 || readFiles()[0] !== file) return { readback_started: false, error: 'upload_selection_unverified' };
  this.dispatchEvent(new Event('input', { bubbles: true }));
  this.dispatchEvent(new Event('change', { bubbles: true }));
  if (!this.isConnected || readFiles().length !== 1 || readFiles()[0] !== file)
    return { readback_started: false, error: 'upload_selection_unverified' };
  const suppliedBytes = await Blob.prototype.arrayBuffer.call(file);
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', suppliedBytes)), b => b.toString(16).padStart(2, '0')).join('');
  if (!this.isConnected || readFiles().length !== 1 || readFiles()[0] !== file || digest !== expectedSha)
    return { readback_started: true, error: 'upload_selection_unverified' };
  return { readback_started: true, count: 1, files: [{ name: file.name, size: file.size, type: file.type, last_modified: file.lastModified }],
    selected_file_sha256: digest, selected_file_identity_verified: true, events_trusted: false };
}
async function uploadInput(record, packet, observation, frame) {
  const p = packet.parameters || {}, checking = packet.action === 'upload_clear_check';
  if (!record.durable || frame.parent_id || frame.session_id) throw fail('upload_frame_unsupported');
  if (!checking && trust?.file_upload !== true) throw fail('browser_file_upload_not_granted');
  const deadline = performance.now() + 8000, authority = packet.upload_authority;
  const content = authority?.carrier === 'supplied_content';
  let contentBytes = null;
  let attempted = false, acknowledged = false, readbackStarted = false, readbackReturned = false, closed = false;
  let phase = 'input_preflight';
  let fileAccess = { allowed: null, reason: 'not_checked', context_kind: contextKind() };
  const diagnostics = error => ({ version: content ? 2 : 1, phase, file_set_acknowledged: acknowledged,
    ...(content ? { readback_requested: attempted, renderer_phase_witnessed: attempted && readbackStarted !== null } : {}),
    readback_started: readbackStarted, readback_returned: readbackReturned, file_access: fileAccess,
    ...(error ? uploadDiagnosticError(error) : { category: 'none', protocol_code: null }) });
  if (!checking && record.uploadUnverified) throw fail('browser_upload_unverified');
  if (checking && record.uploadUnverified === packet.upload_cleanup?.stage_id) throw fail('upload_cleanup_unverified');
  const current = () => {
    if (closed || performance.now() >= deadline) throw fail('browser_upload_timeout');
    requireTrust(packet);
    if (record.state !== 'active' || record.peerId !== peerId || record.claim_epoch !== packet.claim_epoch
        || record.owner_session !== packet.owner_session || record.runtime_generation !== packet.runtime_generation
        || record.target.target_generation !== packet.target_generation || record.generation !== observation.generation
        || record.origin !== packet.expected_origin) throw fail('upload_authority_changed');
    if (!attempted && record.observations.get(p.observation_id) !== observation) throw fail('stale_observation');
    if (observation.contextUniqueId !== record.contextUniqueIds.get(':' + observation.contextId)) throw fail('stale_execution_context');
    if (!checking && trust.file_upload !== true) throw fail('browser_file_upload_not_granted');
    if (content && (!record.control || trust.control !== true || authority.worker_generation !== workerGeneration)) throw fail('upload_authority_changed');
  };
  const bounded = async work => {
    current(); let timer;
    try { return await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
      timer = setTimeout(() => { closed = true; reject(fail('browser_upload_timeout')); }, Math.max(0, Math.min(5000, deadline - performance.now())));
    })]); } finally { clearTimeout(timer); }
  };
  const fresh = async () => {
    current(); if (!await bounded(() => ownsActualTarget(record, current))) throw fail('upload_authority_changed');
    const selected = await bounded(() => live(record, packet.expected_generation, packet.expected_origin, frame.frame_id, current));
    if (['frame_id','loader_id','session_id'].some(k => selected.frame[k] !== observation.frame[k])) throw fail('stale_browser_frame');
    current();
  };
  const args = JSON.stringify(p.observation_id) + ',' + JSON.stringify(p.target_id);
  const check = async () => {
    await fresh();
    const expression = '(() => {const targetInfo=' + targetInfo.toString() + ';const checked=targetInfo(' + args + ');'
      + 'if(checked.error)return checked;const el=__workbenchObservation.targets.get(' + JSON.stringify(p.target_id) + ').element;'
      + 'if(el.tagName!=="INPUT"||el.type!=="file"||el.multiple)return {error:"upload_input_unsupported"};'
      + 'if(checked.sensitive)return {error:"local_sensitive_input_required"};'
      + 'return {empty:el.files.length===0};})()';
    const row = await bounded(() => value(record, expression, observation.contextId));
    current(); if (row?.error) throw fail(row.error);
    if (row?.empty !== true) throw fail(checking ? 'upload_cleanup_unverified' : 'upload_input_not_empty');
  };
  const group = 'workbench-upload-' + packet.request_id;
  try {
    await check();
    if (!checking) {
      phase = 'file_access_readiness';
      fileAccess = await uploadFileAccessReadiness(deadline);
      current(); // Identity/authority may have changed during the read-only query.
      if (fileAccess.reason === 'context_changed') throw fail('upload_authority_changed');
      if (fileAccess.allowed === false && !content) throw fail('browser_local_file_access_not_enabled');
    }
    phase = 'target_resolution';
    const remote = await bounded(() => cdp(record, 'Runtime.evaluate', {
      expression: '__workbenchObservation.targets.get(' + JSON.stringify(p.target_id) + ').element',
      contextId: observation.contextId, returnByValue: false, objectGroup: group }));
    current(); if (remote.exceptionDetails || !remote.result?.objectId) throw fail('upload_target_unavailable');
    phase = 'target_description';
    const node = await bounded(() => cdp(record, 'DOM.describeNode', { objectId: remote.result.objectId }));
    current(); if (node.node.nodeName !== 'INPUT') throw fail('upload_target_unavailable');
    if (checking) {
      phase = 'cleanup_verification';
      await check();
      if (node.node.backendNodeId !== packet.upload_cleanup.backend_node_id) throw fail('upload_cleanup_unverified');
      return { ok: true, upload_cleanup_proof: { condition: 'input_cleared', empty: true,
        input_backend_node_id: node.node.backendNodeId, stage_id: packet.upload_cleanup.stage_id } };
    }
    phase = 'stage_admission';
    if (!authority || typeof authority.token !== 'string' || !authority.binding || authority.stage_id !== authority.file?.stage_id) throw fail('upload_authority_invalid');
    await check();
    if (content) {
      if (authority.worker_generation !== workerGeneration || authority.chunk_bytes !== UPLOAD_CONTENT_CHUNK
          || !Number.isSafeInteger(authority.file.bytes) || authority.file.bytes < 0 || authority.file.bytes > UPLOAD_CONTENT_LIMIT
          || uploadContentBuffers.size >= 4) throw fail('upload_content_unsupported');
      contentBytes = new Uint8Array(authority.file.bytes); uploadContentBuffers.add(contentBytes);
      let offset = 0, done = false;
      phase = 'content_transfer';
      while (!done) {
        current();
        const chunk = await bounded(() => uploadContentExchange(packet, node.node.backendNodeId, 'upload_content_read', { offset }));
        current();
        if (chunk?.stage_id !== authority.stage_id || chunk.offset !== offset || chunk.bytes !== contentBytes.length
            || chunk.sha256 !== authority.file.sha256 || typeof chunk.data_base64 !== 'string'
            || chunk.data_base64.length > 43692 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(chunk.data_base64)) throw fail('upload_content_sequence');
        const bytes = decoded(chunk.data_base64), size = Math.min(UPLOAD_CONTENT_CHUNK, contentBytes.length - offset);
        if (bytes.length !== size || chunk.next_offset !== offset + size || chunk.eof !== (offset + size === contentBytes.length)) {
          bytes.fill(0); throw fail('upload_content_sequence');
        }
        contentBytes.set(bytes, offset); bytes.fill(0); offset += size; done = chunk.eof;
      }
      if (await bounded(() => hash(contentBytes)) !== authority.file.sha256) throw fail('upload_content_hash');
      current(); await check();
    }
    const nonce = uuid(), currentPort = port;
    const admitted = content ? await bounded(() => uploadContentExchange(packet, node.node.backendNodeId, 'upload_admission')) : await bounded(() => new Promise((resolve, reject) => {
      if (uploadWaiters.size >= 4) { reject(fail('browser_upload_pending')); return; }
      const timer = setTimeout(() => { uploadWaiters.delete(nonce); reject(fail('upload_admission_timeout')); }, 5000);
      uploadWaiters.set(nonce, { resolve, reject, timer, port: currentPort });
      if (!sendNative(currentPort, { type: 'upload_admission', nonce, request_id: packet.request_id,
          token: authority.token, binding: authority.binding, backend_node_id: node.node.backendNodeId })) {
        clearTimeout(timer); uploadWaiters.delete(nonce); reject(fail('workbench_not_connected'));
      }
    }));
    phase = 'dispatch_preflight';
    current(); await fresh();
    if (admitted?.stage_id !== authority.stage_id || admitted.filename !== authority.file.filename
        || admitted.sha256 !== authority.file.sha256 || admitted.bytes !== authority.file.bytes
        || (content ? admitted.carrier !== 'supplied_content' || admitted.worker_generation !== workerGeneration || Object.hasOwn(admitted, 'files')
          : !Array.isArray(admitted.files) || admitted.files.length !== 1)) throw fail('upload_authority_invalid');
    await check();
    if (content) {
      phase = 'content_file_selection_command';
      const remoteResult = await bounded(() => cdp(record, 'Runtime.callFunctionOn', {
        objectId: remote.result.objectId, returnByValue: true, awaitPromise: true,
        functionDeclaration: 'function(...args){const checkTarget=' + targetInfo.toString()
          + ';return (' + suppliedContentFile.toString() + ').call(this,...args,checkTarget);}',
        arguments: [b64(contentBytes), admitted.filename, admitted.sha256, p.observation_id, p.target_id].map(value => ({ value }))
      }, undefined, () => { current(); attempted = true; readbackStarted = null; record.uploadUnverified = authority.stage_id; record.observations.clear(); }));
      acknowledged = true; phase = 'content_selection_readback';
      if (remoteResult.exceptionDetails || !remoteResult.result?.value) throw fail('upload_selection_unverified');
      const selected = remoteResult.result.value;
      // A combined command reply witnesses only the phase reported by its renderer.
      // Missing/late ACKs cannot establish whether the renderer began reading.
      readbackStarted = typeof selected.readback_started === 'boolean' ? selected.readback_started : null;
      readbackReturned = readbackStarted === true;
      current(); await fresh();
      if (selected.error || selected.readback_started !== true || selected.selected_file_sha256 !== admitted.sha256 || selected.selected_file_identity_verified !== true
          || selected.events_trusted !== false || selected.count !== 1 || selected.files?.length !== 1
          || selected.files[0].name !== admitted.filename || selected.files[0].size !== admitted.bytes) throw fail(selected.error || 'upload_selection_unverified');
      record.uploadUnverified = null; phase = 'complete';
      return { ok: true, input_dispatched: false, native_input_dispatched: false, events_trusted: false,
        file_selection_dispatched: true, mechanism: 'supplied_content_file_list', carrier: 'supplied_content',
        effect_state: 'applied', dispatch_state: 'acknowledged', protocol_acknowledged: true,
        task_completion: 'not_established', website_upload_state: 'not_established', selected_files: selected.files,
        selected_file_sha256: selected.selected_file_sha256, selected_file_identity_verified: true,
        upload_receipt: { stage_id: authority.stage_id, carrier: 'supplied_content', file_set_attempted: true,
          source_sha256: admitted.sha256, source_bytes: admitted.bytes, filename: admitted.filename,
          selection_verified: true, selected_file_sha256: selected.selected_file_sha256, events_trusted: false,
          diagnostics: diagnostics() } };
    }
    phase = 'file_selection_command';
    await bounded(() => cdp(record, 'DOM.setFileInputFiles', { objectId: remote.result.objectId, files: admitted.files }, undefined, () => {
      current(); attempted = true; record.uploadUnverified = authority.stage_id; record.observations.clear();
    }));
    acknowledged = true; phase = 'post_selection_identity';
    current(); await fresh();
    phase = 'selection_readback';
    const selected = await bounded(() => {
      readbackStarted = true;
      return value(record, '(() => {const el=__workbenchObservation.targets.get('
        + JSON.stringify(p.target_id) + ').element;return {count:el.files.length,files:Array.from(el.files).slice(0,2).map(f=>'
        + '({name:f.name,size:f.size,type:f.type,last_modified:f.lastModified}))};})()', observation.contextId);
    });
    readbackReturned = true; phase = 'selection_verification';
    current();
    if (selected.count !== 1 || selected.files[0].name !== admitted.filename || selected.files[0].size !== admitted.bytes) throw fail('upload_selection_unverified');
    record.uploadUnverified = null; phase = 'complete';
    return { ok: true, input_dispatched: true, file_selection_dispatched: true, mechanism: 'cdp_file_input',
      effect_state: 'applied', dispatch_state: 'acknowledged', task_completion: 'not_established',
      website_upload_state: 'not_established', selected_files: selected.files,
      upload_receipt: { stage_id: authority.stage_id, file_set_attempted: true, source_sha256: admitted.sha256,
        source_bytes: admitted.bytes, filename: admitted.filename, selection_verified: true, diagnostics: diagnostics() } };
  } catch (error) {
    const failure = fail(error.code || 'browser_upload_failed', attempted ? 'unknown' : error.effect_state || 'none');
    failure.upload_receipt = { stage_id: authority?.stage_id || packet.upload_cleanup?.stage_id,
      file_set_attempted: attempted, selection_verified: false, diagnostics: diagnostics(error) };
    throw failure;
  } finally {
    closed = true;
    if (contentBytes) { contentBytes.fill(0); uploadContentBuffers.delete(contentBytes); }
    if (content) for (const [nonce, waiter] of uploadWaiters) {
      if (waiter.content && waiter.requestId === packet.request_id) {
        clearTimeout(waiter.timer); uploadWaiters.delete(nonce); waiter.reject(fail('browser_upload_timeout'));
      }
    }
    try { await Promise.race([(async () => { if (await ownsActualTarget(record)) await cdp(record, 'Runtime.releaseObjectGroup', { objectGroup: group }); })(),
      new Promise(resolve => setTimeout(resolve, 500))]); } catch {}
  }
}

function validateCaptureResponses(packet) {
  const capture = packet.parameters?.capture_responses;
  if (capture == null) return;
  if (typeof capture !== 'boolean' || !['create', 'acquire'].includes(packet.action)
      || packet.interaction_version !== INTERACTION_VERSION || packet.lease_id != null
      || packet.claim_id != null || packet.parameters?.diagnostic_scope != null)
    throw fail('invalid_browser_capture_policy');
  if (capture && trust?.network !== true) throw fail('network_capture_not_granted');
}

function validateClickCount(packet) {
  const p = packet.parameters || {};
  if (!Object.hasOwn(p, 'click_count')) return;
  if (packet.action !== 'click' || !Number.isInteger(p.click_count) || ![1, 2].includes(p.click_count))
    throw fail('invalid_browser_click_count');
}

async function execute(packet) {
  validateClickCount(packet);
  validateCaptureResponses(packet);
  const explicit = Object.hasOwn(packet.parameters || {}, 'click_count');
  const receipt = explicit ? { version: 1, requested_click_count: packet.parameters.click_count, clicks: [], completed_clicks: 0 } : null;
  try {
    const result = await executeAction(packet, receipt);
    return receipt ? { ...result, click_receipt: receipt } : result;
  } catch (error) {
    if (receipt) error.click_receipt = receipt;
    throw error;
  } finally {
    // executeAction's held-input cleanup has settled before accounting is published.
    if (receipt) receipt.completed_clicks = receipt.clicks.filter(row => row.down_acknowledged && row.up_acknowledged).length;
  }
}

async function executeAction(packet, clickReceipt = null) {
  const snapshotStarted = packet.action === 'snapshot' ? performance.now() : null;
  const record = leases.get(packet.lease_id);
  if (!record) throw fail('unknown_browser_lease');
  if (record.durable && packet.interaction_version !== INTERACTION_VERSION) throw fail('mixed_browser_authority');
  const p = packet.parameters || {};
  if (packet.action === 'press' && p.key === 'Redo' && !/Mac/.test(navigator.userAgent)) throw fail('browser_redo_platform_unsupported');
  if (p.click_count === 2 && !record.durable) throw fail('browser_claim_required');
  if (!record.durable) {
    const owner = packet.operation_owner;
    if (owner !== undefined && owner !== null && (typeof owner !== 'string' || !owner || encoder.encode(owner).length > 128))
      throw fail('browser_control_owner_mismatch');
    if (record.operationOwner !== undefined && record.operationOwner !== owner) throw fail('browser_control_owner_mismatch');
  }
  if (packet.action === 'detach' || packet.action === 'events') {
    if (record.peerId !== peerId || record.runtime_generation !== serverGeneration || record.installation_id !== installationId)
      throw fail('browser_lease_ended');
    const binding = packet.cleanup_binding;
    if (packet.action === 'detach' && (!binding || typeof binding !== 'object' ||
      ['lease_id','grant_generation','browser_target_id','installation_id','runtime_generation','peer_id',
      'profile_id','context_id','context_kind','tab_id'].some(key => binding[key] !== publicLease(record)[key])))
      throw fail('browser_control_owner_mismatch');
    if (packet.action === 'events') return { ok: true, ...publicLease(record), ...cachedEvents(record, p) };
    adoptLegacyOwner(record, packet.operation_owner);
    record.inputEligible = false;
    await detach(record, 'local_or_mcp_revoke');
    return { ok: true, ...publicLease(record), effect_state: record.keyboard_release_state === 'unverified'
      || record.cleanup_state === 'unverified' ? 'unknown' : 'applied' };
  }
  adoptLegacyOwner(record, packet.operation_owner);
  if (['evaluate','navigate','click','click_point','fill','insert_text','press','check','select','select_text','replace_selection','scroll','drag','upload','upload_clear_check'].includes(packet.action)
      && ['prepared','held','unverified','not_recorded'].includes(record.heldKey?.state || record.keyboard_release_state))
    throw fail('browser_key_release_unverified');
  if (packet.action === 'drag') {
    if (!record.durable) throw fail('browser_claim_required');
    const steps = Object.hasOwn(p, 'steps') ? p.steps : 8;
    if (typeof p.end_target_id !== 'string' || p.end_target_id === p.target_id
        || !Number.isInteger(steps) || steps < 2 || steps > 16) throw fail('invalid_drag_parameters');
  }
  if (packet.action === 'scroll') {
    if (!record.durable) throw fail('browser_claim_required');
    const dx = p.delta_x ?? 0, dy = p.delta_y ?? 0;
    if ([dx, dy].some(delta => typeof delta !== 'number' || !Number.isFinite(delta) || Math.abs(delta) > 2000)
        || dx === 0 && dy === 0 || p.delta_x === null || p.delta_y === null) throw fail('invalid_scroll_delta');
  }
  if (packet.action === 'select_text') {
    if (!record.durable) throw fail('browser_claim_required');
    if ([p.selection_start, p.selection_length].some(n => !Number.isInteger(n) || n < 0 || n > 32768)
        || p.selection_start + p.selection_length > 32768) throw fail('invalid_browser_text_range');
  }
  if (packet.action === 'replace_selection') {
    if (!record.durable) throw fail('browser_claim_required');
    if (typeof p.text !== 'string' || p.text.length > 4096 || encoder.encode(p.text).length > 32768
        || p.selection_start != null || p.selection_length != null) throw fail('invalid_browser_replacement');
  }
  if (packet.action === 'check' || packet.action === 'select') {
    if (!record.durable) throw fail('browser_claim_required');
    if (packet.action === 'check' && Object.hasOwn(p, 'checked') && typeof p.checked !== 'boolean') throw fail('invalid_checkbox_state');
    if (packet.action === 'select' && (!Array.isArray(p.selected_values) || p.selected_values.length > 100
        || p.selected_values.some(value => typeof value !== 'string' || encoder.encode(value).length > 4096)
        || new Set(p.selected_values).size !== p.selected_values.length
        || encoder.encode(JSON.stringify(p.selected_values)).length > 32768)) throw fail('invalid_select_options');
  }
  const selected = await live(record, packet.expected_generation, packet.expected_origin, p.frame_id);
  const browserFocus = await browserFocusSample(record, selected.browserTab);
  if (record.state !== 'active' || record.inputEligible === false || Date.now() >= record.expires
      || record.peerId !== peerId || record.runtime_generation !== serverGeneration) throw fail('browser_lease_ended');
  if (record.durable) frameClaimCurrent(record, packet);
  if (packet.expected_generation !== record.generation || packet.expected_origin !== record.origin) throw fail('stale_browser_document');
  const result = { ok: true, lease_id: record.id, document_generation: record.generation, origin: record.origin,
    browser_focus: browserFocus, frame_id: selected.frame.frame_id, loader_id: selected.frame.loader_id, frame_session_id: selected.frame.session_id,
    browser_scope: record.durable ? 'Claimed tab and ordinary HTTP(S) descendant frames' : 'Explicit selected tab and same-origin frames' };
  if (packet.action === 'inspect') return { ...result, ...publicLease(record), frames: selected.list, frames_incomplete: false, frame_limit: 100,
    worker_generation: workerGeneration, extension_version: chrome.runtime.getManifest().version,
    input_initialization: record.inputInitialization || { state: 'unverified' },
    network_pre_attach_gap: true, event_omissions: record.eventsDropped, related_targets: [...record.children.values()].map(({ready, ...row}) => row) };
  if (packet.action === 'detach') { await detach(record, 'local_or_mcp_revoke'); return { ...result, state: 'detached', effect_state: 'applied' }; }
  if (packet.action === 'events') {
    const after = p.after_sequence ?? 0, limit = p.limit ?? 20;
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1 || limit > 100) throw fail('invalid_event_cursor');
    const rows = record.events.filter(e => e.sequence > after).slice(0, limit);
    return { ...result, events: rows, retained_first: record.events[0]?.sequence ?? null, dropped: record.eventsDropped,
      gap_before_cursor: !!record.events.length && after < record.events[0].sequence - 1,
      next_sequence: rows.at(-1)?.sequence ?? after, pre_attach_gap: true,
      scope: 'Bounded network metadata and console argument types; secret headers and console values were not collected.' };
  }
  if (packet.action === 'body' || packet.action === 'document') {
    if (!record.network) throw fail('network_capture_not_granted');
    let request = packet.action === 'document'
      ? [...record.requests.values()].reverse().find(r => r.type === 'Document' && r.frameId === selected.frame.frame_id && r.loaderId === selected.frame.loader_id)
      : record.requests.get(p.request_key);
    if (!request) throw fail('original_body_not_captured');
    if (request.redirected) throw fail('redirect_body_unavailable');
    if (request.streamPromise) await request.streamPromise;
    if (completeRawBody(record, request)) {
      const bytes = new Uint8Array(request.bodyBytes); let offset = 0;
      for (const chunk of request.bodyChunks) { bytes.set(chunk, offset); offset += chunk.length; }
      return { ...result, request_key: request.key, body_base64: b64(bytes), body_sha256: await hash(bytes),
        representation: 'browser_response_entity_bytes', wire_bytes_claimed: false, fresh_fetch_performed: false,
        status: request.status ?? null, mime_type: request.mimeType ?? null };
    }
    if (!request.bodyGap && request.streamReady && !request.finished) throw fail('response_body_still_streaming');
    let body;
    try { body = await cdp(record, 'Network.getResponseBody', { requestId: request.requestId }, request.sessionId); }
    catch { throw fail('response_body_evicted_or_unavailable'); }
    const bytes = body.base64Encoded ? decoded(body.body) : encoder.encode(body.body);
    if (bytes.length > 2097152) throw fail('response_body_limit');
    return { ...result, request_key: request.key, body_base64: b64(bytes), body_sha256: await hash(bytes),
      representation: body.base64Encoded ? 'browser_binary_response_body' : 'browser_decoded_response_body_utf8',
      wire_bytes_claimed: false, fresh_fetch_performed: false, status: request.status ?? null, mime_type: request.mimeType ?? null };
  }
  if (packet.action === 'navigate') {
    if (!record.control) throw fail('browser_control_not_granted');
    if (typeof p.url !== 'string' || p.url.length > 8192) throw fail('invalid_url');
    webOrigin(p.url);
    const frame = selected.frame;
    const frameSession = frame.session_id ? record.children.get(frame.session_id) : null;
    const navigationCurrent = () => {
      if (record.durable) { requireTrust(packet); frameClaimCurrent(record, packet); }
      if (record.generation !== packet.expected_generation || record.origin !== packet.expected_origin)
        throw fail('stale_browser_document');
      if (frame.session_id && (!frameSession || record.children.get(frame.session_id) !== frameSession
          || frameSession.target_id !== frame.renderer_root_id || frameSession.session_epoch !== frame.session_epoch))
        throw fail('stale_browser_frame');
    };
    const confirmed = await live(record, packet.expected_generation, packet.expected_origin, p.frame_id, navigationCurrent);
    if (['frame_id', 'parent_id', 'loader_id', 'session_id', 'session_epoch', 'renderer_root_id']
        .some(key => confirmed.frame[key] !== frame[key])) throw fail('stale_browser_frame');
    const navigated = await navigateWithLifetime(record, { url: p.url, frameId: confirmed.frame.frame_id },
      confirmed.frame.session_id, navigationCurrent,
      confirmed.list.find(row => row.frame_id === confirmed.frame.parent_id)?.session_id);
    return { ...result, navigation_dispatched: true, effect_state: navigated.errorText ? 'unknown' : 'applied',
      task_completion: 'not_established', destination_origin: webOrigin(p.url) };
  }
  const contextId = await world(record, selected.frame);
  if (packet.action === 'snapshot') {
    const options = snapshotOptions(p);
    const imageStarted = options.screenshot ? snapshotStarted : null;
    if ((options.accessibility || options.screenshot) && !record.durable) throw fail('browser_claim_required');
    const observationId = uuid();
    const contextUniqueId = record.contextUniqueIds?.get((selected.frame.session_id || '') + ':' + contextId);
    const captureCurrent = () => {
      if (!options.screenshot) return;
      if (performance.now() >= imageStarted+30000) throw fail('screenshot_intent_expired');
      requireTrust(packet); frameClaimCurrent(record,packet);
      if (!port || !record.debuggerAttached || leases.get(record.id) !== record || record.generation !== packet.expected_generation
          || record.contextUniqueIds.get((selected.frame.session_id || '')+':'+contextId) !== contextUniqueId)
        throw fail('stale_screenshot');
    };
    // Bind the chain before pixels are acquired; never build image authority
    // from a convenient post-capture geometry or replacement renderer.
    let frameChain = options.screenshot ? await captureFrameChain(record,selected.frame,selected.list,contextId,captureCurrent) : null;
    let frameCapture = null;
    const paired = options.accessibility || options.screenshot;
    const snapshot = await value(record, '(() => { const editingFocusWitnessState = ' + editingFocusWitnessState.toString() + '; const optionEffectivelyHidden = ' + optionEffectivelyHidden.toString() + '; return ('
      + observePage.toString() + ')(' + JSON.stringify(observationId) + ',' + options.screenshot + ',' + paired + ','
      + JSON.stringify(editingFocusBinding(record,{frame:selected.frame,contextUniqueId})) + '); })()', contextId, selected.frame.session_id);
    const anchor = snapshot._capture_anchor; delete snapshot._capture_anchor;
    const stateExpression = '(' + observationState.toString() + ')(' + JSON.stringify(observationId) + ')';
    const before = paired ? await value(record, stateExpression, contextId, selected.frame.session_id) : null;
    if (before?.error) throw captureRefusal(record, 'scan_recheck', anchor, before, before.error);
    if (paired && (!anchor || anchor.revision !== before.revision || anchor.root_count !== before.root_count
        || JSON.stringify(anchor.viewport) !== JSON.stringify(before.viewport))) throw captureRefusal(record, 'scan_recheck', anchor, before);
    const accessibility = options.accessibility ? await accessibilitySnapshot(record, selected.frame, contextId, observationId, options) : null;
    let screenshot = null;
    if (options.screenshot) {
      if (!before.capture_guard_complete) throw fail('screenshot_privacy_scan_incomplete');
      const viewport = before.viewport, clip = options.clip || { x: 0, y: 0, width: viewport.width, height: viewport.height };
      if (clip.x + clip.width > viewport.width || clip.y + clip.height > viewport.height
          || clip.width * clip.height * (viewport.device_scale * options.scale) ** 2 > 4194304) throw fail('screenshot_pixel_limit');
      if (before.capture_regions.some(rect => rect.x < clip.x + clip.width && rect.x + rect.width > clip.x
          && rect.y < clip.y + clip.height && rect.y + rect.height > clip.y)) throw fail('screenshot_sensitive_region');
      let surfaceClip = {...clip,x:viewport.scroll_x+clip.x,y:viewport.scroll_y+clip.y};
      if (frameChain) {
        const topology = record.frameTopologyEpoch || 0;
        frameCapture = {...await visualFrameCaptureGuard(record,frameChain,observationId,clip,null,captureCurrent),topology};
        if (frameCapture.anchors.some(row=>row.viewport.device_scale !== viewport.device_scale)) throw fail('frame_screenshot_transform_unsupported');
        await verifyFrameGeometryForInput(record,packet,{frameChain},captureCurrent);
        frameChainCurrent(record,frameChain.chain,await frames(record,captureCurrent),captureCurrent);
        if ((record.frameTopologyEpoch || 0) !== topology) throw fail('stale_browser_frame');
        const rootViewport = frameCapture.anchors[0].viewport;
        surfaceClip = {...frameCapture.rootClip,x:frameCapture.rootClip.x+rootViewport.scroll_x,y:frameCapture.rootClip.y+rootViewport.scroll_y};
      }
      const captured = await cdp(record, 'Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false,
        clip: {...surfaceClip,scale:options.scale} },null,captureCurrent);
      captureCurrent();
      const bytes = decoded(captured.data);
      if (bytes.length > 2097152) throw fail('screenshot_result_limit');
      if (bytes.length < 24 || bytes[0] !== 137 || String.fromCharCode(...bytes.subarray(1, 4)) !== 'PNG') throw fail('screenshot_invalid');
      const header = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), width = header.getUint32(16), height = header.getUint32(20);
      if (!width || !height || width * height > 4194304) throw fail('screenshot_pixel_limit');
      screenshot = { screenshot_base64: captured.data, screenshot_sha256: await hash(bytes), screenshot_bytes: bytes.length,
        mime_type: 'image/png', width, height, clip_css: clip, document_clip_css: { ...clip, x: viewport.scroll_x + clip.x, y: viewport.scroll_y + clip.y },
        ...(frameCapture ? {root_clip_css:frameCapture.rootClip,root_document_clip_css:surfaceClip} : {}),
        requested_scale: options.scale, pixel_per_css_x: width / clip.width, pixel_per_css_y: height / clip.height,
        scope: frameCapture ? 'Selected child-frame viewport crop of root surface; clear ordinary ancestor path, known sensitive regions and descendant-frame pixels refused'
          : 'Selected main-frame viewport crop; known sensitive regions and child-frame pixels refused',
        representation: 'chromium_surface_png', potentially_sensitive: true };
    }
    const confirmed = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
    if (['frame_id', 'loader_id', 'session_id'].some(k => selected.frame[k] !== confirmed.frame[k])) throw fail('stale_browser_frame');
    if (record.durable && (!contextUniqueId || contextUniqueId !== record.contextUniqueIds.get((selected.frame.session_id || '') + ':' + contextId))) throw fail('stale_execution_context');
    const after = paired ? await value(record, stateExpression, contextId, selected.frame.session_id) : null;
    if (options.screenshot && !after?.capture_guard_complete) throw fail('screenshot_privacy_scan_incomplete');
    if (paired && (after?.error || before.revision !== after.revision || JSON.stringify(before.viewport) !== JSON.stringify(after.viewport)
        || options.screenshot && JSON.stringify(before.capture_regions) !== JSON.stringify(after.capture_regions))) throw captureRefusal(record, 'post_capture', before, after);
    if (!frameChain) frameChain = await captureFrameChain(record, selected.frame, confirmed.list, contextId);
    if (frameCapture) {
      await visualFrameCaptureGuard(record,frameChain,observationId,screenshot.clip_css,frameCapture.anchors,captureCurrent);
      await verifyFrameGeometryForInput(record,packet,{frameChain},captureCurrent);
      if ((record.frameTopologyEpoch || 0) !== frameCapture.topology) throw fail('stale_browser_frame');
    }
    const finalSelection = frameChain ? await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id) : confirmed;
    if (frameChain) frameChainCurrent(record, frameChain.chain, finalSelection.list);
    if (frameChain && paired) {
      const published = await value(record, stateExpression, contextId, selected.frame.session_id);
      if (published?.error || before.revision !== published.revision || JSON.stringify(before.viewport) !== JSON.stringify(published.viewport)) throw captureRefusal(record, 'publication_recheck', before, published);
    }
    if (contextUniqueId !== record.contextUniqueIds.get((selected.frame.session_id || '') + ':' + contextId)) throw fail('stale_execution_context');
    const imageIntent = screenshot ? { mapping:Object.fromEntries(Object.entries(screenshot).filter(([key]) => key !== 'screenshot_base64')),
      anchor:structuredClone(before),deadline:imageStarted+30000,
      ...(frameCapture ? {frameCapture} : {}),
      binding:JSON.stringify([record.id,record.claim_epoch,record.owner_session,record.runtime_generation,record.installation_id,
        record.peerId,record.target.target_generation,record.target.browser_target_id]) } : null;
    const domEditingTargets=snapshot.controls.filter(c=>c.editing_context?.kind==='public_dom_contenteditable').map(c=>c.target_id);
    const composedEditingTargets=snapshot.controls.filter(c=>c.editing_context?.dom_structure?.selection?.basis==='public_composed_static_range_and_native_direction').map(c=>c.target_id);
    record.observations.clear(); record.observations.set(observationId, { frame: selected.frame, contextId, generation: record.generation,
      contextUniqueId, frameChain, imageIntent, ...(domEditingTargets.length?{domEditingTargets}:{}), ...(composedEditingTargets.length?{composedEditingTargets}:{}) });
    return { ...result, ...snapshot, observation_id: observationId, coordinate_units: 'Selected-frame CSS viewport pixels',
      ...(frameChain ? { observation_identity: { observation_id: observationId, document_generation: record.generation, frame_id: selected.frame.frame_id, loader_id: selected.frame.loader_id, frame_session_id: selected.frame.session_id, execution_context_unique_id: contextUniqueId || null }, frame_chain: { identities: frameChain.chain.map(row => ({ ...row.frame, execution_context_unique_id: row.contextUniqueId })), geometry: frameChain.geometry } } : {}),
      execution_context_unique_id: record.contextUniqueIds?.get((selected.frame.session_id || '') + ':' + contextId) || null,
      ...(paired ? { observation_identity: { observation_id: observationId, document_generation: record.generation,
        frame_id: selected.frame.frame_id, loader_id: selected.frame.loader_id, frame_session_id: selected.frame.session_id,
        execution_context_unique_id: contextUniqueId || null }, capture_consistency: { dom_revision_at_scan: anchor.revision,
          viewport_at_scan: anchor.viewport, observed_root_count_at_scan: anchor.root_count, root_topology_verified: true,
          dom_revision_before: before.revision, dom_revision_after: after.revision,
          viewport_before: before.viewport, viewport_after: after.viewport,
          guarantee: 'Same frame, loader, execution context, scan-anchored DOM mutation revision, observed open-root topology and viewport across sequential captures; compositor-only animation is not frozen' } } : {}),
      ...(accessibility ? { accessibility } : {}), ...(screenshot ? { screenshot,
        visual_input:{action:'click_point',coordinate_units:'Original PNG pixels from top-left',max_age_ms:30000,
          remaining_ms:Math.max(0,imageIntent.deadline-performance.now()),age_scope:'Worker snapshot execution start; not network transfer or compositor frame age',
          content_frozen:false,scope:frameCapture ? 'Selected child crop; opaque/transformed/overlapped/partially clipped ancestor paths and descendant-frame pixels refuse'
            : 'Main-frame crop only; opaque, child-frame and transformed visual-viewport paths refuse'} } : {}),
      source: 'Current DOM observation; not original server HTML' };
  }
  if (!record.control) throw fail('browser_control_not_granted');
  if (packet.action === 'evaluate') {
    if (typeof p.expression !== 'string' || encoder.encode(p.expression).length > 65536) throw fail('invalid_expression');
    await live(record, packet.expected_generation, packet.expected_origin, p.frame_id);
    const evaluated = await cdp(record, 'Runtime.evaluate', { expression: p.expression, contextId, returnByValue: true, awaitPromise: true, timeout: 5000 }, selected.frame.session_id);
    if (evaluated.exceptionDetails) throw fail('browser_evaluation_failed', 'unknown');
    return { ...result, value: evaluated.result?.value ?? null, remote_type: evaluated.result?.type,
      execution_world: 'Selected-frame isolated world; DOM shared, page-script globals unavailable', task_completion: 'not_established' };
  }
  const observation = record.observations.get(p.observation_id);
  const verifyObservation = currentFrame => {
    if (!observation || record.observations.get(p.observation_id) !== observation || observation.generation !== record.generation
        || ['frame_id', 'loader_id', 'session_id'].some(k => observation.frame[k] !== currentFrame[k])) throw fail('stale_observation');
    if (observation.contextUniqueId !== record.contextUniqueIds.get((currentFrame.session_id || '') + ':' + observation.contextId)) throw fail('stale_execution_context');
  };
  verifyObservation(selected.frame);
  if (packet.action === 'click_point') return visualClick(record,packet,observation,result);
  const args = JSON.stringify(p.observation_id) + ',' + JSON.stringify(p.target_id);
  const editingAction = packet.action === 'press' && ['Undo','Redo'].includes(p.key) ? p.key.toLowerCase() : packet.action;
  const actionable = async (currentFrame, focus = false, requireFocus = false, checkpoint = () => {}) => {
    const pointer = ['click','drag'].includes(packet.action);
    const current = () => {
      checkpoint(); verifyObservation(currentFrame);
      if (pointer && observation.frameChain) {
        frameClaimCurrent(record, packet);
        for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
      }
    };
    current();
    const checked = await value(record, '(' + targetInfo.toString() + ')(' + args + ',' + focus + ',' + requireFocus + ',' + JSON.stringify(editingAction) + ')', observation.contextId, currentFrame.session_id);
    current();
    if (checked?.error) throw fail(checked.error);
    if (!checked?.hit_matches_target) throw fail('target_actionability_unavailable');
    if (requireFocus && checked.focused !== true) throw fail('target_focus_changed');
    const mapped = await frameInputGuard(record, packet, observation, checked, requireFocus, current);
    current();
    if (observation.frameChain) {
      const topology = record.frameTopologyEpoch || 0;
      const final = await value(record, '(' + targetInfo.toString() + ')(' + args + ',false,' + requireFocus + ',' + JSON.stringify(editingAction) + ')', observation.contextId, currentFrame.session_id);
      current();
      if (final?.error) throw fail(final.error);
      if (!final?.hit_matches_target || final.x !== checked.x || final.y !== checked.y) throw fail('target_moved');
      if (requireFocus && final.focused !== true) throw fail('target_focus_changed');
      await verifyFrameGeometryForInput(record, packet, observation, current);
      if (pointer) {
        await freshFrameInputIdentity(record, packet, observation, current);
        const recipient = await value(record, '(' + targetInfo.toString() + ')(' + args + ',false,' + requireFocus + ',' + JSON.stringify(editingAction) + ')', observation.contextId, currentFrame.session_id);
        current();
        if (recipient?.error) throw fail(recipient.error);
        if (!recipient?.hit_matches_target || recipient.x !== checked.x || recipient.y !== checked.y) throw fail('target_moved');
        if ((record.frameTopologyEpoch || 0) !== topology) throw fail('stale_browser_frame');
      }
    }
    current(); return { ...checked, ...mapped };
  };
  if (!record.durable && ['click','check','scroll','drag'].includes(packet.action) && (selected.frame.parent_id || selected.frame.session_id)) throw fail('frame_pointer_input_unavailable');
  if (['fill','insert_text'].includes(packet.action) && (typeof p.text !== 'string' || encoder.encode(p.text).length > 32768)) throw fail('invalid_input');
  const before = await actionable(selected.frame);
  if (before?.sensitive) throw fail('local_sensitive_input_required');
  if (packet.action === 'upload' || packet.action === 'upload_clear_check') {
    return { ...await uploadInput(record, packet, observation, selected.frame), browser_focus: browserFocus };
  }
  if (['click','fill','insert_text','press','check','select','select_text','replace_selection','scroll','drag'].includes(packet.action)
      && (record.heldDrag?.pressAttempted && record.heldDrag.state !== 'acknowledged'
        || ['held','unverified'].includes(record.pointer_release_state))) throw fail('browser_drag_release_unverified');
  if (packet.action === 'drag') {
    const deadline = performance.now() + 5000;
    let closed = false, stageDeadline = null, held = null;
    const current = () => {
      if (closed || performance.now() >= (stageDeadline ?? deadline)) throw fail('browser_drag_timeout');
      if (record.state !== 'active' || record.peerId !== peerId || record.owner_session !== packet.owner_session
          || record.claim_epoch !== packet.claim_epoch || record.runtime_generation !== packet.runtime_generation
          || record.target.target_generation !== packet.target_generation) throw fail('browser_claim_owner_mismatch');
      if (!observation || observation.generation !== record.generation
          || !held?.pressAttempted && record.observations.get(p.observation_id) !== observation) throw fail('stale_observation');
      if (observation.contextUniqueId !== record.contextUniqueIds.get((observation.frame.session_id || '') + ':' + observation.contextId)) throw fail('stale_execution_context');
      if (observation.frameChain) for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
    };
    const fresh = async () => {
      current();
      if (observation.frameChain) for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
      const selectedNow = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
      if (['frame_id','loader_id','session_id'].some(key => selectedNow.frame[key] !== observation.frame[key])) throw fail('stale_browser_frame');
      if (observation.frameChain) frameChainCurrent(record, observation.frameChain.chain, selectedNow.list, current);
      if (!await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
      return selectedNow.frame;
    };
    const dragState = async (mode, point = null) => {
      const frame = await fresh();
      const expression = '(() => { const targetInfo = ' + targetInfo.toString() + '; const readback = ' + readback.toString()
        + '; return (' + dragTargets.toString() + ')(' + JSON.stringify(p.observation_id) + ',' + JSON.stringify(p.target_id) + ','
        + JSON.stringify(p.end_target_id) + ',' + JSON.stringify(mode) + ',' + JSON.stringify(point) + '); })()';
      const result = await value(record, expression, observation.contextId, frame.session_id);
      current(); if (result?.error) throw fail(result.error);
      await fresh();
      if (mode === 'prepare' || mode === 'moving') {
        // Metadata awaits can outlive the geometry read. Check the exact controls
        // again after those waits; do not dispatch from an earlier actionability read.
        const ready = await value(record, expression, observation.contextId, frame.session_id);
        current(); if (ready?.error) throw fail(ready.error);
        const startMap = await frameInputGuard(record, packet, observation, mode === 'prepare' ? ready.start : point, false, current);
        const endMap = mode === 'prepare' ? await frameInputGuard(record, packet, observation, ready.end, false, current) : null;
        if (observation.frameChain) {
          const topology = record.frameTopologyEpoch || 0;
          const final = await value(record, expression, observation.contextId, frame.session_id);
          current(); if (final?.error) throw fail(final.error);
          await verifyFrameGeometryForInput(record, packet, observation, current);
          await freshFrameInputIdentity(record, packet, observation, current);
          const recipient = await value(record, expression, observation.contextId, frame.session_id);
          current(); if (recipient?.error) throw fail(recipient.error);
          // Preparation binds both original endpoints. During a held gesture
          // the source may legitimately move; only the destination and current
          // path point are revalidated by dragTargets('moving').
          for (const key of mode === 'prepare' ? ['start','end'] : ['end']) {
            if (recipient[key].x !== ready[key].x || recipient[key].y !== ready[key].y) throw fail('target_moved');
          }
          if ((record.frameTopologyEpoch || 0) !== topology) throw fail('stale_browser_frame');
        }
        return { ...ready, root_point: startMap.root_point, ...(endMap ? { root_end: endMap.root_point } : {}) };
      }
      return result;
    };
    const bounded = async (work, limit = 500) => {
      current(); stageDeadline = Math.min(deadline, performance.now() + limit);
      let timer;
      try {
        const result = await Promise.race([Promise.resolve().then(() => { current(); return work(); }), new Promise((_, reject) => {
          timer = setTimeout(() => { closed = true; reject(fail('browser_drag_timeout')); }, stageDeadline - performance.now());
        })]); current(); return result;
      } finally { clearTimeout(timer); stageDeadline = null; }
    };
    const counts = { down_attempted: false, down_acknowledged: false, moves_attempted: 0, moves_acknowledged: 0 };
    record.dragActive = true; state();
    try {
      // No button is held during preparation. Allow cold CDP reads while keeping
      // the total operation and all held-input stages tightly bounded.
      const prepared = await bounded(() => dragState('prepare'), 2000);
      held = { peer: record.peerId, owner: record.owner_session, runtime: record.runtime_generation, installation: record.installation_id,
        targetGeneration: record.target.target_generation, browserTarget: record.target.browser_target_id, epoch: record.claim_epoch,
        tabId: record.tabId, point: prepared.root_point, localPoint: { x: prepared.start.x, y: prepared.start.y }, pressAttempted: false, releaseAttempted: false, state: 'not_needed' };
      record.heldDrag = held;
      await bounded(() => cdp(record, 'Input.dispatchMouseEvent', { type: 'mousePressed', ...held.point, button: 'left', buttons: 1, clickCount: 1 }, null, () => {
        current(); counts.down_attempted = true; held.pressAttempted = true; held.state = 'held'; record.observations.clear();
      })); counts.down_acknowledged = true;
      const steps = Object.hasOwn(p, 'steps') ? p.steps : 8;
      for (let step = 1; step <= steps; step++) {
        const point = { x: prepared.start.x + (prepared.end.x - prepared.start.x) * step / steps,
          y: prepared.start.y + (prepared.end.y - prepared.start.y) * step / steps };
        await bounded(async () => {
          const mapped = await dragState('moving', point);
          await cdp(record, 'Input.dispatchMouseEvent', { type: 'mouseMoved', ...mapped.root_point, button: 'left', buttons: 1 }, null,
            () => { current(); held.point = mapped.root_point; held.localPoint = point; counts.moves_attempted++; });
          current(); counts.moves_acknowledged++;
        });
        await bounded(() => new Promise(resolve => setTimeout(resolve, 16)));
      }
      await bounded(() => dragState('moving', held.localPoint));
      const release = await releaseHeldDrag(record, 'drag_complete');
      if (release !== 'acknowledged') throw fail('browser_drag_release_unverified');
      const after = await bounded(() => dragState('readback'));
      return { ...result, ...acknowledgedCdpInput(after.control_state_changed || after.dom_revision !== prepared.dom_revision ? 'changed' : 'unchanged'),
        mechanism: 'cdp_native_pointer_drag', effect_state: 'unknown', effect_scope: 'recipient_effect_not_established', task_completion: 'not_established',
        drag_receipt: { ...counts, release_attempted: held.releaseAttempted, pointer_release_state: held.state, steps },
        readback: after, application_change_observed: after.control_state_changed || after.dom_revision !== prepared.dom_revision,
        coordinate_units: 'CSS viewport pixels', actionability_revalidated_before_dispatch: true };
    } catch (error) {
      const release = held ? await releaseHeldDrag(record, 'drag_interrupted') : 'not_needed';
      const failure = fail(error.code || 'browser_drag_failed', held?.pressAttempted ? 'unknown' : error.effect_state || 'none');
      failure.drag_receipt = { ...counts, release_attempted: held?.releaseAttempted === true, pointer_release_state: release };
      throw failure;
    } finally { closed = true; record.dragActive = false; if (held?.pressAttempted) record.observations.clear(); state(); }
  }
  if (packet.action === 'scroll') {
    let attempted = false, cancelled = false, started = null, deadline = null, stageDeadline = null;
    const sameOwner = () => record.state === 'active' && record.peerId === peerId && record.owner_session === packet.owner_session
      && record.runtime_generation === packet.runtime_generation && record.claim_epoch === packet.claim_epoch
      && record.target.target_generation === packet.target_generation;
    const current = () => {
      const cutoff = stageDeadline ?? deadline;
      if (cancelled || cutoff !== null && performance.now() >= cutoff) { cancelled = true; throw fail('scroll_readback_timeout'); }
      if (!sameOwner()) throw fail('browser_claim_owner_mismatch');
      if (!observation || observation.generation !== record.generation
          || !attempted && record.observations.get(p.observation_id) !== observation) throw fail('stale_observation');
      if (observation.contextUniqueId !== record.contextUniqueIds.get((observation.frame.session_id || '') + ':' + observation.contextId)) throw fail('stale_execution_context');
      if (observation.frameChain) for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
    };
    const verifyFrame = frame => {
      current();
      if (['frame_id', 'loader_id', 'session_id'].some(key => observation.frame[key] !== frame[key])) throw fail('stale_browser_frame');
    };
    const freshGuard = async () => {
      current();
      const fresh = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
      verifyFrame(fresh.frame);
      if (observation.frameChain) frameChainCurrent(record, observation.frameChain.chain, fresh.list, current);
      const stillOwned = await ownsActualTarget(record, current);
      verifyFrame(fresh.frame);
      if (!stillOwned) throw fail('browser_claim_owner_mismatch');
      return fresh.frame;
    };
    const state = async (frame, mode) => {
      verifyFrame(frame);
      const expression = '(() => { const targetInfo = ' + targetInfo.toString() + '; return (' + wheelTargetState.toString() + ')('
        + args + ',' + JSON.stringify(mode) + '); })()';
      const result = await value(record, expression, observation.contextId, frame.session_id);
      verifyFrame(frame);
      if (result?.error) throw fail(result.error);
      return result;
    };
    const bounded = async (work, limit) => {
      current();
      stageDeadline = Math.min(deadline, performance.now() + limit);
      const remaining = stageDeadline - performance.now();
      if (remaining <= 0) { cancelled = true; throw fail('scroll_readback_timeout'); }
      let timer;
      try {
        const result = await Promise.race([Promise.resolve().then(() => { current(); return work(); }), new Promise((_, reject) => {
          timer = setTimeout(() => { cancelled = true; reject(fail('scroll_readback_timeout')); }, remaining);
        })]);
        current();
        return result;
      } finally { clearTimeout(timer); stageDeadline = null; }
    };
    let prepared, finalPrepared, mappedWheel;
    try {
    prepared = await state(await freshGuard(), 'prepare');
    // The final preparation can itself yield while the browser target changes.
    // Query actual target/frame/context again before the single native send.
    finalPrepared = await state(await freshGuard(), 'prepare');
    mappedWheel = await frameInputGuard(record, packet, observation, finalPrepared.dispatch_target, false, current);
    if (observation.frameChain) {
      const topology = record.frameTopologyEpoch || 0;
      await state(observation.frame, 'prepare');
      await verifyFrameGeometryForInput(record, packet, observation, current);
      // Parent geometry queries yield across renderers. Recheck the exact
      // local recipient after those reads before using the earlier root point.
      const final = await state(await freshGuard(), 'prepare');
      if (final.dispatch_target.x !== finalPrepared.dispatch_target.x
          || final.dispatch_target.y !== finalPrepared.dispatch_target.y) throw fail('target_moved');
      if ((record.frameTopologyEpoch || 0) !== topology) throw fail('stale_browser_frame');
    }
    } catch (error) {
      cancelled = true;
      throw fail(error.code || 'browser_scroll_prepare_failed', 'none');
    }
    try {
      current();
      attempted = true;
      record.observations.clear();
      await cdp(record, 'Input.dispatchMouseEvent', { type: 'mouseWheel', x: mappedWheel.root_point.x, y: mappedWheel.root_point.y,
        deltaX: p.delta_x ?? 0, deltaY: p.delta_y ?? 0, button: 'none', buttons: 0, modifiers: 0, pointerType: 'mouse' }, null);
      started = performance.now(); deadline = started + 1000;
      const sampleBudget = Math.min(1000, 250 * new Set(observation.frameChain?.chain.map(row => row.frame.session_id) || [selected.frame.session_id]).size);
      let last = null, stable = 0, after, samples = 0;
      for (; samples < 16;) {
        after = await bounded(async () => {
          const frame = await freshGuard();
          const sample = await state(frame, 'readback');
          await freshGuard();
          return sample;
        }, sampleBudget);
        samples++;
        const signature = JSON.stringify(after);
        stable = signature === last ? stable + 1 : 0; last = signature;
        if (samples >= 3 && stable >= 2) break;
        await bounded(() => new Promise(resolve => setTimeout(resolve, 25)), 1000);
      }
      await bounded(freshGuard, 1000);
      current();
      const elapsed = performance.now() - started;
      if (elapsed >= 1000) { cancelled = true; throw fail('scroll_readback_timeout'); }
      after = { ...after, stable_in_window: stable >= 2, sample_count: samples, sample_limit: 16,
        elapsed_ms: elapsed, sampling_time_limit_ms: 1000, final_outcome_established: false,
        scope: 'Numeric offsets and DOM revision of the exact target composed ancestor chain; bounded sequential readback, causality and final outcome not established' };
      const offsetsChanged = after.nodes.some((node, index) => node.scroll_left !== prepared.sample.nodes[index].scroll_left
        || node.scroll_top !== prepared.sample.nodes[index].scroll_top);
      current();
      return { ...result, before: prepared.sample, readback: after, dispatch_target: { ...finalPrepared.dispatch_target, ...mappedWheel },
        ...acknowledgedCdpInput(offsetsChanged ? 'changed' : 'unchanged'),
        effect_state: after.stable_in_window && offsetsChanged ? 'applied' : 'unknown', scroll_offsets_changed: offsetsChanged,
        effect_scope: 'sampled_scroll_offsets',
        observed_content_revision_changed: after.dom_revision !== prepared.sample.dom_revision,
        actionability_revalidated_before_dispatch: true, mechanism: 'cdp_native_mouse_wheel',
        coordinate_units: 'CSS viewport pixels', delta_units: 'CSS pixels', held_input_introduced: false, task_completion: 'not_established' };
    } catch (error) { if (attempted) throw fail(error.code || 'browser_scroll_failed', 'unknown'); throw error; }
    finally { cancelled = true; if (attempted) record.observations.clear(); }
  }
  if (packet.action === 'select_text' || packet.action === 'replace_selection') {
    const replacing = packet.action === 'replace_selection';
    const timeoutCode = replacing ? 'browser_text_replacement_timeout' : 'browser_text_selection_timeout';
    const deadline = performance.now() + 5000;
    let closed = false, attempted = false, dispatched = false, completed = false, timer;
    const current = () => {
      if (closed || performance.now() >= deadline) throw fail(timeoutCode);
      requireTrust(packet);
      frameClaimCurrent(record, packet);
      if (!port || record.installation_id !== installationId || Date.now() >= record.expires
          || leases.get(record.id) !== record) throw fail('browser_claim_owner_mismatch');
      verifyObservation(selected.frame);
      if (observation.frameChain) for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
    };
    const fresh = async () => {
      current();
      const now = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
      current(); verifyObservation(now.frame);
      if (observation.frameChain) frameChainCurrent(record, observation.frameChain.chain, now.list, current);
      if (!await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
      current(); return now.frame;
    };
    const state = async (frame, mode) => {
      current(); verifyObservation(frame);
      const expression = '(() => { const targetInfo = ' + targetInfo.toString() + '; return ('
        + (replacing ? textControlReplacement : textControlSelection).toString() + ')(' + args + ','
        + (replacing ? JSON.stringify(p.text) : p.selection_start + ',' + p.selection_length) + ','
        + JSON.stringify(mode) + '); })()';
      const sampled = await cdp(record, 'Runtime.evaluate', { expression, uniqueContextId: observation.contextUniqueId,
        returnByValue: true, awaitPromise: false, timeout: Math.max(1, Math.floor(deadline - performance.now())) },
        frame.session_id, () => { current(); if (mode === 'apply') attempted = true; });
      current();
      if (sampled.exceptionDetails) throw fail('browser_evaluation_failed');
      const value = sampled.result?.value;
      if (value?.error) {
        // This helper returns errors only before its synchronous setter call.
        if (mode === 'apply') attempted = false;
        throw fail(value.error);
      }
      if (!value || typeof value.dispatched !== 'boolean') throw fail('text_selection_readback_unavailable');
      return value;
    };
    try {
      return await Promise.race([(async () => {
        const initial = await state(await fresh(), 'verify');
        const dispatchTarget = await actionable(await fresh(), false, false, current);
        const applied = await state(selected.frame, 'apply');
        dispatched = applied.dispatched; attempted = dispatched;
        // Read after metadata awaits; never repair or repeat a setter after reversion.
        await fresh();
        const after = await state(selected.frame, 'readback');
        current();
        delete initial.dispatched; delete after.dispatched; completed = true;
        if (replacing) {
          const setterReadback = { ...applied }; delete setterReadback.dispatched;
          return { ...result, before: initial, setter_readback: setterReadback, readback: after, dispatch_target: dispatchTarget,
            requested_text: p.text, observed_max_length: initial.max_length, field_limit_verified: after.field_limit_unchanged,
            original_selection: { selection_start: initial.selection_start, selection_length: initial.selection_length },
            desired_state_achieved: after.desired_state_achieved, exact_requested_state: after.desired_state_achieved,
            state_verified: after.state_verified, replacement_dispatched: dispatched,
            input_dispatched: false, native_input_dispatched: false, actionability_revalidated_before_dispatch: true,
            dispatch_state: dispatched ? 'acknowledged' : 'not_needed', dispatch_effect_state: dispatched ? 'applied' : 'none',
            effect_state: after.desired_state_achieved ? dispatched ? 'applied' : 'none' : 'unknown',
            mechanism: dispatched ? 'public_text_control_set_range_text' : 'verified_state_no_op',
            normalization_policy: 'Native browser text-control sanitization may normalize line endings or strip input newlines; actual setter and later readbacks are returned',
            workbench_normalization_performed: false, setter_literal_value_matches: setterReadback.literal_value_matches,
            events_dispatched: false, offset_units: 'UTF-16 code units', task_completion: 'not_established' };
        }
        return { ...result, before: initial, readback: after, dispatch_target: dispatchTarget,
          requested_selection: { selection_start: p.selection_start, selection_length: p.selection_length },
          desired_state_achieved: after.desired_state_achieved, exact_requested_state: after.desired_state_achieved,
          state_verified: after.state_verified, selection_dispatched: dispatched,
          input_dispatched: false, native_input_dispatched: false, actionability_revalidated_before_dispatch: true,
          dispatch_state: dispatched ? 'acknowledged' : 'not_needed', dispatch_effect_state: dispatched ? 'applied' : 'none',
          effect_state: after.desired_state_achieved ? dispatched ? 'applied' : 'none' : 'unknown',
          mechanism: dispatched ? 'public_text_control_set_selection_range' : 'verified_state_no_op',
          offset_units: 'UTF-16 code units', selected_contents_returned: false, task_completion: 'not_established' };
      })(), new Promise((_, reject) => {
        timer = setTimeout(() => { closed = true; reject(fail(timeoutCode)); }, 5000);
      })]);
    } catch (error) { throw fail(error.code || (replacing ? 'browser_text_replacement_failed' : 'browser_text_selection_failed'), attempted || dispatched ? 'unknown' : 'none'); }
    finally { closed = true; clearTimeout(timer); if (attempted || dispatched || completed) record.observations.clear(); }
  }
  if (packet.action === 'check' || packet.action === 'select') {
    const desired = packet.action === 'check' ? p.checked ?? true : p.selected_values;
    const expression = mode => '(() => { const targetInfo = ' + targetInfo.toString() + '; const optionEffectivelyHidden = '
      + optionEffectivelyHidden.toString() + '; return (' + formControl.toString() + ')('
      + args + ',' + JSON.stringify(packet.action) + ',' + JSON.stringify(desired) + ',' + JSON.stringify(mode) + '); })()';
    const state = async (frame, mode) => {
      verifyObservation(frame);
      if (mode === 'apply') await actionable(frame);
      const result = await value(record, expression(mode), observation.contextId, frame.session_id);
      verifyObservation(frame);
      if (result?.error) {
        const refusal = fail(result.error);
        if (mode === 'apply') refusal.form_pre_dispatch_refusal = true;
        throw refusal;
      }
      return result;
    };
    const initial = await state(selected.frame, 'verify');
    const dispatchSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
    let dispatchTarget, heldPointer = null, dispatched = false, potentialDispatch = false, pressed = false, releaseAttempted = false, released = false;
    try {
      dispatchTarget = await actionable(dispatchSelection.frame);
      const final = await state(dispatchSelection.frame, 'verify');
      if (!final.desired_state_achieved) {
        if (packet.action === 'check') {
          dispatchTarget = await actionable(dispatchSelection.frame);
          potentialDispatch = true; pressed = true;
          await cdp(record, 'Input.dispatchMouseEvent', { type: 'mousePressed', x: dispatchTarget.root_point.x, y: dispatchTarget.root_point.y, button: 'left', clickCount: 1 }, null, () => { heldPointer = startFramePointerHold(record, packet, dispatchTarget.root_point); });
          dispatched = true;
          await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
          releaseAttempted = true;
          await frameInputGuard(record, packet, observation, dispatchTarget);
          await finishFramePointerHold(record, heldPointer, dispatchTarget.root_point);
          released = true;
        } else {
          potentialDispatch = true;
          const applied = await state(dispatchSelection.frame, 'apply');
          dispatched = applied.dispatched === true; potentialDispatch = dispatched;
        }
      }
      const confirmed = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
      const after = await state(confirmed.frame, 'readback');
      if (!dispatched && !after.desired_state_achieved) throw fail('target_changed');
      delete initial.dispatched; delete after.dispatched;
      record.observations.clear();
      return { ...result, before: initial, dispatch_target: dispatchTarget, actionability_revalidated_before_dispatch: true,
        readback: after, desired_state_achieved: after.desired_state_achieved, state_verified: after.state_verified,
        input_dispatched: dispatched, native_input_dispatched: dispatched && packet.action === 'check',
        dispatch_state: dispatched ? 'acknowledged' : 'not_needed', dispatch_effect_state: dispatched ? 'applied' : 'none',
        effect_state: dispatched && after.desired_state_achieved ? 'applied' : 'none',
        mechanism: !dispatched ? 'verified_state_no_op' : packet.action === 'check' ? 'cdp_native_checkbox_click' : 'native_select_setter_and_programmatic_events',
        events_trusted: dispatched ? packet.action === 'check' : null,
        programmatic_events: dispatched && packet.action === 'select' ? ['input', 'change'] : [],
        pointer_release_state: pressed ? released ? 'acknowledged' : 'unverified' : 'not_needed', task_completion: 'not_established' };
    } catch (error) {
      if (error.form_pre_dispatch_refusal && !dispatched) throw error;
      if (potentialDispatch || dispatched) throw fail(error.code || 'browser_action_failed', 'unknown'); throw error;
    }
    finally {
      if (heldPointer?.pressAttempted && !heldPointer.releaseAttempted) await releaseHeldDrag(record, 'pointer_interrupted');
    }
  }
  const dispatchSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
  // Only two fixed native selection intents; never parse arbitrary chords or
  // mutate the original packet key/operation identity used by durable receipts.
  const selectionKey = packet.action==='press' && p.key==='Shift+ArrowLeft' ? 'ArrowLeft'
    : packet.action==='press' && p.key==='Shift+ArrowRight' ? 'ArrowRight' : null;
  let dispatched = false, heldPointer = null, heldKey = null, strictDomEditingKey = false, plainDomNavigation = false, postEditingCurrent = null;
  let dispatchTarget, insertReceipt = null;
  try {
    if (packet.action === 'click' && (p.click_count ?? 1) === 1) {
      // Preserve the existing single-click waits and admission behavior. Only
      // the new two-click gesture needs a sequence-wide deadline and fences.
      dispatchTarget = await actionable(dispatchSelection.frame);
      const row = clickReceipt ? { click_count: 1, down_attempted: false, down_acknowledged: false,
        up_attempted: false, up_acknowledged: false } : null;
      await cdp(record, 'Input.dispatchMouseEvent', { type: 'mousePressed', ...dispatchTarget.root_point, button: 'left', clickCount: 1 }, null, () => {
        heldPointer = startFramePointerHold(record, packet, dispatchTarget.root_point, 1, row);
        if (row) { row.down_attempted = true; clickReceipt.clicks.push(row); }
      });
      dispatched = true;
      if (row) row.down_acknowledged = true;
      await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id);
      await frameInputGuard(record, packet, observation, dispatchTarget);
      if (row && !heldPointer) row.up_attempted = true;
      await finishFramePointerHold(record, heldPointer, dispatchTarget.root_point);
      if (row && !heldPointer) row.up_acknowledged = true;
    } else if (packet.action === 'click') {
      const count = p.click_count ?? 1, deadline = performance.now() + 5000;
      const current = () => {
        if (performance.now() >= deadline || !port || record.peerId !== peerId || record.state !== 'active'
            || record.inputEligible === false || Date.now() >= record.expires || leases.get(record.id) !== record
            || record.installation_id !== installationId || record.runtime_generation !== serverGeneration) throw fail('browser_lease_ended');
        if (record.durable) { requireTrust(packet); if (!trust.control) throw fail('browser_control_not_granted'); frameClaimCurrent(record, packet); }
        verifyObservation(selected.frame);
      };
      // Every press retains the original observed recipient and coordinates.
      // A first click may mutate the page; it never earns a rebased second click.
      dispatchTarget = await actionable(dispatchSelection.frame, false, false, current);
      const original = dispatchTarget;
      for (let clickCount = 1; clickCount <= count; clickCount++) {
        current();
        const selection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        if (record.durable && !await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
        const checked = await actionable(selection.frame, false, false, current);
        if (checked.sensitive) throw fail('local_sensitive_input_required');
        if (['x','y'].some(key => checked[key] !== original[key] || checked.root_point[key] !== original.root_point[key])) throw fail('target_moved');
        const row = clickReceipt ? { click_count: clickCount, down_attempted: false, down_acknowledged: false,
          up_attempted: false, up_acknowledged: false } : null;
        await cdp(record, 'Input.dispatchMouseEvent', { type: 'mousePressed', ...original.root_point, button: 'left', clickCount }, null, () => {
          current();
          heldPointer = startFramePointerHold(record, packet, original.root_point, clickCount, row);
          if (row) { row.down_attempted = true; clickReceipt.clicks.push(row); }
          dispatched = true;
        });
        if (row) row.down_acknowledged = true;
        current();
        await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        await frameInputGuard(record, packet, observation, original, false, current);
        if (row && !heldPointer) row.up_attempted = true;
        await finishFramePointerHold(record, heldPointer, original.root_point);
        if (row && !heldPointer) { row.up_attempted = true; row.up_acknowledged = true; }
      }
    } else if (['fill','insert_text','press'].includes(packet.action)) {
      const current = () => {
        if (!port || record.peerId !== peerId || record.state !== 'active' || record.inputEligible === false
            || Date.now() >= record.expires || leases.get(record.id) !== record
            || record.installation_id !== installationId || record.runtime_generation !== serverGeneration) throw fail('browser_lease_ended');
        if (record.durable) {
          requireTrust(packet); if (!trust.control) throw fail('browser_control_not_granted');
          frameClaimCurrent(record, packet);
          if (observation.frameChain) for (const row of observation.frameChain.chain) frameContextCurrent(record, row);
        }
        verifyObservation(selected.frame);
      };
      const history = packet.action === 'press' && ['Undo','Redo'].includes(p.key);
      if(packet.action==='press'&&['Enter','Space','Backspace','Delete','ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(p.key)) {
        current();
        const classified=await value(record,'('+editingKeyRecipient.toString()+')('+args+','+JSON.stringify(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(p.key))+')',observation.contextId,selected.frame.session_id);
        current();
        if(classified?.error||typeof classified?.contenteditable!=='boolean')throw fail(classified?.error||'editing_classification_unavailable');
        plainDomNavigation=classified.contenteditable&&classified.dom_navigation===true&&['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(p.key);
        strictDomEditingKey=classified.contenteditable&&!plainDomNavigation;
      }
      const literal = packet.action === 'insert_text' || history || strictDomEditingKey || selectionKey!==null;
      if (literal && observation.domEditingTargets?.includes(p.target_id)) postEditingCurrent = current;
      if ((literal||plainDomNavigation) && !record.durable) throw fail('browser_claim_required');
      if(plainDomNavigation){
        postEditingCurrent=current;
        await guardedDomEditingReadback(record,{...observation,id:p.observation_id},p.target_id,current,'navigation_prepare');
      }
      const literalState = async (mode = selectionKey!==null ? 'selection_navigation' : 'verify') => {
        current();
        const state = await value(record, '(() => { const targetInfo = ' + targetInfo.toString()
          + '; const target = targetInfo(' + args + ',false,true,' + JSON.stringify(editingAction) + ');'
          + ' if (target.error) return target; return { ...target, ...(' + literalEditingState.toString() + ')('
          + args + ',' + JSON.stringify(mode) + ') }; })()', observation.contextId, selected.frame.session_id);
        current();
        if (state?.error || state?.state_verified !== true) throw fail(state?.error || 'editing_recipient_unavailable');
        if (packet.action === 'insert_text' && state.kind === 'public_dom_contenteditable') {
          if (state.text_length - (state.selection_end-state.selection_start) + p.text.length > 4096) throw fail('dom_editing_text_limit');
          const breaks=(p.text.match(/\r\n|[\r\n\u2028\u2029]/g)||[]).length;
          if (!state.dom_structure || state.dom_structure.node_count + breaks*(state.dom_structure.max_depth+2)*2 > 256)
            throw fail('dom_editing_structure_limit');
        }
        return state;
      };
      if (literal) {
        await guardEditingHostShadow(record,{...observation,id:p.observation_id},p.target_id,current);
        await literalState();
      }
      await actionable(dispatchSelection.frame, !literal, literal, current);
      const focus = await value(record, '(' + readback.toString() + ')(' + args + ')', observation.contextId, selected.frame.session_id);
      current();
      if (!focus?.focused) throw fail('target_focus_failed');
      const focusedSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
      dispatchTarget = await actionable(focusedSelection.frame, false, true, current);
      if(plainDomNavigation)await guardedDomEditingReadback(record,{...observation,id:p.observation_id},p.target_id,current,'navigation_capture');
      if (packet.action === 'insert_text') {
        const insertSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        if (!await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
        dispatchTarget = await actionable(insertSelection.frame, false, true, current);
        await guardEditingHostShadow(record,{...observation,id:p.observation_id},p.target_id,current);
        await literalState();
        // Capture the original authority before dispatch. An attempted command
        // is not an ACK, and an ACK is not recipient or task verification.
        insertReceipt = {version:1,action:'insert_text',operation_request_id:packet.operation_request_id||packet.request_id,
          transport_request_id:packet.request_id,observation_id:p.observation_id,target_id:p.target_id,
          attempted:false,protocol_acknowledged:false,recipient_observed:'not_established',state_observed:'not_established',
          task_verified:false,retry_allowed:false,
          browser_target_id:record.target.browser_target_id,frame_id:selected.frame.frame_id,loader_id:selected.frame.loader_id,
          frame_session_id:selected.frame.session_id||null,execution_context_unique_id:observation.contextUniqueId,
          binding:{installation_id:record.installation_id,runtime_generation:record.runtime_generation,peer_id:record.peerId,
            owner_session:record.owner_session,claim_id:record.id,claim_epoch:record.claim_epoch,
            target_generation:record.target.target_generation,document_generation:record.generation,
            profile_id:record.target.profile_id,context_id:record.target.context_id,context_kind:record.target.context_kind}};
        await cdp(record, 'Input.insertText', { text:p.text }, selected.frame.session_id,
          () => { current(); dispatched = true; insertReceipt.attempted = true; });
        insertReceipt.protocol_acknowledged = true;
      } else if (packet.action === 'fill') {
        const selectionState = async capabilityOnly => {
          current();
          const state = await value(record, '(' + fillSelectionState.toString() + ')(' + args + ',' + capabilityOnly + ')', observation.contextId, selected.frame.session_id);
          current();
          if (state?.error || (capabilityOnly ? state?.selection_capable : state?.selection_verified) !== true) throw fail(state?.error || 'fill_selection_unverified');
          return state;
        };
        // Refuse unsupported selection before any key event. Supported range
        // mechanisms are qualified separately; null ranges are never assumed full.
        await selectionState(true);
        const ready = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        dispatchTarget = await actionable(ready.frame, false, true, current);
        const mac = /Mac/.test(navigator.userAgent);
        const key = { key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, modifiers: mac ? 4 : 2 };
        heldKey = await prepareHeldKey(record, packet, observation, selected.frame, key, current);
        const downSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        dispatchTarget = await actionable(downSelection.frame, false, true, current);
        await selectionState(true);
        await cdp(record, 'Input.dispatchKeyEvent', { type: 'keyDown', ...key, commands: ['selectAll'] }, selected.frame.session_id,
          () => { current(); heldKey.downAttempted = true; heldKey.state = 'held'; dispatched = true; });
        heldKey.downAcknowledged = true;
        if (await releaseHeldKey(record, 'key_complete') !== 'acknowledged') throw fail('browser_key_release_unverified', 'unknown');
        await selectionState(false);
        const insertSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        if (record.durable && !await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
        dispatchTarget = await actionable(insertSelection.frame, false, true, current);
        // Re-read the exact local hit/focus/value and full native range after
        // metadata/ancestor waits. No refocus or selection mutation repairs a
        // failed fence. Separate renderer samples cannot freeze the compositor.
        const final = await value(record, '(() => { const targetInfo = ' + targetInfo.toString()
          + '; const target = targetInfo(' + args + ',false,true,"fill"); if (target.error) return target;'
          + ' return { ...target, ...(' + fillSelectionState.toString() + ')(' + args + ') }; })()',
          observation.contextId, selected.frame.session_id);
        current();
        if (final?.error || final?.selection_verified !== true) throw fail(final?.error || 'fill_selection_unverified');
        if (!final.hit_matches_target || final.x !== dispatchTarget.x || final.y !== dispatchTarget.y) throw fail('target_moved');
        await cdp(record, 'Input.insertText', { text: p.text }, selected.frame.session_id, current);
      } else {
        const allowed = { Enter: 13, Tab: 9, Escape: 27, Space: 32, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Backspace: 8, Delete: 46, Undo: 90, Redo: 90 };
        const nativeKey = selectionKey || p.key;
        if (!Object.hasOwn(allowed, nativeKey)) throw fail('unsupported_key');
        const key = history ? (p.key === 'Redo' ? 'Z' : 'z') : nativeKey === 'Space' ? ' ' : nativeKey;
        const heldParams = { key, code: history ? 'KeyZ' : nativeKey, windowsVirtualKeyCode: allowed[nativeKey],
          ...(selectionKey ? {modifiers:8} : history ? { modifiers: p.key === 'Redo' ? 12 : /Mac/.test(navigator.userAgent) ? 4 : 2 } : {}) };
        heldKey = await prepareHeldKey(record, packet, observation, selected.frame, heldParams, current);
        const downSelection = await live(record, packet.expected_generation, packet.expected_origin, selected.frame.frame_id, current);
        dispatchTarget = await actionable(downSelection.frame, false, true, current);
        if(plainDomNavigation){
          if(!await ownsActualTarget(record,current))throw fail('browser_claim_owner_mismatch');
          await guardedDomEditingReadback(record,{...observation,id:p.observation_id},p.target_id,current,'navigation_verify');
        }
        if (literal) {
          if (!await ownsActualTarget(record, current)) throw fail('browser_claim_owner_mismatch');
          await guardEditingHostShadow(record,{...observation,id:p.observation_id},p.target_id,current);
          await literalState();
        }
        await cdp(record, 'Input.dispatchKeyEvent', { type: 'keyDown', ...heldParams,
          ...(history && /Mac/.test(navigator.userAgent) ? { commands: [p.key.toLowerCase()] } : {}),
          ...(p.key === 'Enter' ? { text: '\r', unmodifiedText: '\r' } : p.key === 'Space' ? { text: ' ', unmodifiedText: ' ' } : {}) },
          selected.frame.session_id, () => { current(); heldKey.downAttempted = true; heldKey.state = 'held'; dispatched = true; });
        heldKey.downAcknowledged = true;
        if (await releaseHeldKey(record, 'key_complete') !== 'acknowledged') throw fail('browser_key_release_unverified', 'unknown');
      }
    } else throw fail('unsupported_action');
    const readbackArgs = packet.action === 'fill' ? args + ',' + JSON.stringify(p.text) : args;
    const strictEditing = packet.action === 'insert_text' || strictDomEditingKey || selectionKey!==null || packet.action === 'press' && ['Undo','Redo'].includes(p.key);
    // Fresh fixed-node metadata is required for shared DOM readback, including
    // descendants created by native editing. Original intent remains untouched.
    const after = plainDomNavigation
      ? await guardedDomEditingReadback(record,{...observation,id:p.observation_id},p.target_id,postEditingCurrent,'navigation_readback')
      : strictEditing && postEditingCurrent
      ? await guardedDomEditingReadback(record,{...observation,id:p.observation_id},p.target_id,postEditingCurrent,
          selectionKey!==null?'selection_navigation_readback':'readback')
      : await value(record, '(' + (strictEditing ? literalEditingState : readback).toString() + ')('
        + (strictEditing ? args + ',' + JSON.stringify(selectionKey!==null?'selection_navigation_readback':'readback') : readbackArgs) + ')', observation.contextId, selected.frame.session_id);
    record.observations.clear();
    return { ...result, before, dispatch_target: dispatchTarget, actionability_revalidated_before_dispatch: true,
      readback: after, effect_state: packet.action === 'fill' && after.desired_state_achieved !== true ? 'unknown' : 'applied',
      ...(packet.action === 'fill' ? { dispatch_effect_state: 'applied', desired_state_achieved: after.desired_state_achieved === true, state_verified: after.state_verified === true } : {}),
      ...(['click', 'press', 'insert_text'].includes(packet.action) ? { ...acknowledgedCdpInput(),
        effect_state: 'unknown', effect_scope: 'recipient_effect_not_established' } : {}),
      ...(heldKey ? { keyboard_receipt: keyboardReceipt(heldKey) } : {}),
      ...(selectionKey ? {selection_navigation:{intent:p.key,native_key:selectionKey,modifiers:8,
        scope:'native_selection_change_not_guaranteed_UTF16_distance'}} : {}),
      task_completion: 'not_established' };
  } catch (error) {
    const failure = dispatched || heldPointer?.pressAttempted ? fail(error.code || 'browser_action_failed', 'unknown') : error;
    if(insertReceipt?.attempted){
      const acknowledged=insertReceipt.protocol_acknowledged;
      failure.input_error_receipt={...insertReceipt,readback:{state:acknowledged?'unavailable':'not_started',
        stage:acknowledged?error.editing_readback_stage||'post_readback':'insert_command',
        reason:acknowledged?'guarded_readback_unavailable':'command_response_unavailable'}};
    }
    throw failure;
  }
  finally {
    if (heldPointer?.pressAttempted && !heldPointer.releaseAttempted) await releaseHeldDrag(record, 'pointer_interrupted');
    if (heldKey?.downAttempted && !heldKey.releaseAttempted) await releaseHeldKey(record, 'key_interrupted');
    if (heldKey && !heldKey.downAttempted) { heldKey.state = 'not_needed'; record.keyboard_release_state = 'not_needed'; }
    if (heldKey) {
      const originalBinding = !record.durable || record.owner_session === packet.owner_session
        && record.runtime_generation === packet.runtime_generation && record.target.target_generation === packet.target_generation
        && (record.claim_epoch === packet.claim_epoch || record.state !== 'active' && record.claim_epoch === packet.claim_epoch + 1);
      if (originalBinding) {
        try { if (record.durable) await persistTargets(); else await persistLegacyKeyboard(record); }
        catch { /* Persisted conservative intent remains quarantined. */ }
        state();
      }
    }
  }
}

async function respond(requestId, result, replyPort) {
  if (!port || port !== replyPort) return;
  const bytes = encoder.encode(JSON.stringify(result));
  if (bytes.length <= 65536) { sendNative(replyPort, { type: 'response', request_id: requestId, result }); return; }
  if (bytes.length > 8388608) { sendNative(replyPort, { type: 'response', request_id: requestId, result: { ok: false, error: { code: 'browser_result_limit', effect_state: 'unknown' } } }); return; }
  const transferId = uuid();
  const digest = await hash(bytes);
  if (port !== replyPort) return;
  if (!sendNative(replyPort, { type: 'transfer_begin', request_id: requestId, transfer_id: transferId, total_bytes: bytes.length, sha256: digest })) return;
  for (let offset = 0; offset < bytes.length; offset += 32768) if (!sendNative(replyPort, { type: 'transfer_chunk', transfer_id: transferId, offset, data: b64(bytes.subarray(offset, offset + 32768)) })) return;
  sendNative(replyPort, { type: 'transfer_end', transfer_id: transferId });
}
async function command(packet) {
  const replyPort = port;
  if (packet.action?.startsWith('managed_download_')) {
    try { return await respond(packet.request_id, await managedOperation(packet), replyPort); }
    catch (error) { return await respond(packet.request_id, { ok: false,
      error: { code: error.code || 'managed_download_failed', effect_state: error.effect_state || 'unknown' } }, replyPort); }
  }
  const record = leases.get(packet.claim_id || packet.lease_id);
  const control = record && (record.durable ? packet.interaction_version === INTERACTION_VERSION
    && (['stop','release','claim_status','events','dialog_read','dialog_handle'].includes(packet.action) || packet.action === 'cleanup' && !packet.upload_cleanup)
    : ['detach','events'].includes(packet.action));
  const previousHeld = record?.heldKey;
  const keyboardAdmission = record ? { id: record.id, peer: record.peerId, installation: record.installation_id,
    runtime: record.runtime_generation, owner: record.durable ? record.owner_session : packet.operation_owner ?? null,
    epoch: record.claim_epoch, generation: record.generation, browserTarget: record.durable ? record.target.browser_target_id : record.browserTargetId,
    targetGeneration: record.target?.target_generation, grant: record.grantGeneration,
    keyboardUnsettled: ['prepared','held','unverified'].includes(previousHeld?.state || record.keyboard_release_state) } : null;
  const token = uuid();
  if (record?.busy && !control) return respond(packet.request_id, { ok: false, error: { code: 'browser_operation_pending', effect_state: 'none' } }, replyPort);
  if (record && !control) { record.busy = true; record.busyToken = token;
    record.lifecycleAction = LIFECYCLE_ACTIONS.has(packet.action) ? packet.action : null; }
  try { await respond(packet.request_id, await (packet.interaction_version === INTERACTION_VERSION ? executeDurable(packet) : execute(packet)), replyPort); }
  catch (error) { await respond(packet.request_id, { ok: false, error: { code: error.code || 'browser_operation_failed', effect_state: error.effect_state || 'unknown',
    ...(error.acquisition_failure ? { acquisition_failure: error.acquisition_failure } : {}),
    ...(error.drag_receipt ? { drag_receipt: error.drag_receipt } : {}),
    ...(error.click_receipt ? { click_receipt: error.click_receipt } : {}),
    ...(error.upload_receipt ? { upload_receipt: error.upload_receipt } : {}),
    ...(error.dialog_receipt ? { dialog_receipt: error.dialog_receipt } : {}),
    ...(error.pointer_receipt ? { pointer_receipt:error.pointer_receipt } : {}),
    ...(error.input_error_receipt ? { input_error_receipt:error.input_error_receipt } : {}),
    ...keyboardErrorMetadata(record, packet, keyboardAdmission, previousHeld) } }, replyPort); }
  finally {
    if (record && !control && record.busyToken === token) {
      if (packet.action === 'drag') record.dragPending = false;
      if (packet.action === 'upload') record.uploadPending = false;
      record.busy = false; record.busyToken = undefined; record.lifecycleAction = null;
    }
  }
}

chrome.debugger.onDetach.addListener((source, reason) => {
  for (const record of leases.values()) if (record.tabId === source.tabId || source.targetId && source.targetId === (record.target?.browser_target_id || record.browserTargetId)) {
    lifecycleEvent(record, source, 'debugger_detach', {}, reason);
    fenceBodyCapture(record, 'body_attachment_ended'); settleBodyCapture(record, 'detached');
    record.debuggerAttached = false;
    if (record.state === 'active') void detach(record, reason, false);
  }
});
chrome.tabs.onRemoved.addListener(tabId => { for (const r of leases.values()) if (r.tabId === tabId) void detach(r, 'tab_closed'); });
chrome.tabs.onUpdated.addListener((tabId, change) => {
  for (const r of leases.values()) if (r.tabId === tabId && r.state === 'active' && change.url) {
    if (r.initializing) { r.initializationNavigation++; continue; }
    try { if (webOrigin(change.url) !== r.origin) {
      if (r.durable) { endChildNavigation(r); r.origin = webOrigin(change.url); r.generation++; r.observations.clear(); state(); }
      else void detach(r, 'origin_changed');
    } } catch { void detach(r, 'unsupported_origin'); }
  }
});
chrome.alarms.onAlarm.addListener(alarm => { const r = leases.get(alarm.name.replace('lease:', '')); if (r && Date.now() >= r.expires) void detach(r, 'expired'); });
chrome.debugger.onEvent.addListener((source, method, params) => {
  if (method === 'Page.downloadWillBegin') { pageDownloadEvent(source, params); return; }
  const identityEvent = ['Page.frameNavigated','Page.navigatedWithinDocument','Page.frameDetached','Target.detachedFromTarget',
    'Runtime.executionContextCreated','Runtime.executionContextDestroyed','Runtime.executionContextsCleared','Page.javascriptDialogClosed'].includes(method);
  const record = [...leases.values()].find(r => (r.tabId === source.tabId || source.targetId && source.targetId === (r.target?.browser_target_id || r.browserTargetId))
    && (r.state === 'active' || identityEvent && (r.releasing || r.dialogOperation || r.pendingDialog || ['prepared','held','unverified'].includes(r.heldKey?.state))));
  if (!record) return;
  if (method === 'Target.attachedToTarget' || method === 'Target.detachedFromTarget')
    lifecycleEvent(record, source, method === 'Target.attachedToTarget' ? 'related_attach' : 'related_detach', params);
  if (record.diagnosticOnly) {
    try { diagnosticEvent(record, source, method, params); } catch { diagnosticEnd(record, 'event_collection_failed'); }
    if (!method.startsWith('Page.') && !method.startsWith('Runtime.executionContext')) return;
  }
  if (method === 'Fetch.requestPaused') {
    void handleBodyPause(record, source, params).catch(() => {
      record.cleanup_state = 'unverified'; void detach(record, 'response_capture_unverified');
    }); return;
  }
  if (method === 'Page.javascriptDialogOpening') {
    // Diagnostic publication excludes message and prompt contents. An explicit
    // resolver needs a separately authorized public invocation; Stop does not accept.
    record.modal = { sequence: (record.modalSequence = (record.modalSequence || 0) + 1), type: params.type,
      has_browser_handler: params.hasBrowserHandler === true, opened_at: Date.now() / 1000,
      browser_target_id: record.target?.browser_target_id || record.browserTargetId,
      document_generation: record.generation, frame_session_id: source.sessionId || null,
      frame_id: typeof params.frameId === 'string' && params.frameId.length > 0 && params.frameId.length <= 256 ? params.frameId : null };
    // Retain the first unresolved noncontent identity independently of a
    // resolver. A later opening never erases an earlier unverified close gap.
    if (record.durable) {
      record.pendingDialog ||= { ...record.modal };
      if (record.dialog_resolution_state !== 'unverified') record.dialog_resolution_state = 'pending';
    }
    const message = boundedDialogText(params.message), prompt = boundedDialogText(params.defaultPrompt);
    record.dialogDetails = { sequence: record.modal.sequence, message: message.text, message_truncated: message.truncated,
      default_prompt: prompt.text, default_prompt_truncated: prompt.truncated };
    const { sequence: dialogSequence, ...metadata } = record.modal;
    event(record, 'javascript_dialog_opened', { ...metadata, dialog_sequence: dialogSequence });
    if (record.durable) void persistTargets().catch(() => { record.cleanup_state = 'unverified'; state(); });
    state(); return;
  }
  if (method === 'Page.javascriptDialogClosed') {
    const currentModal = record.modal || record.pendingDialog;
    const closeSession = source.sessionId || null;
    const closeFrame = typeof params.frameId === 'string' ? params.frameId : null;
    if (!currentModal || closeSession !== currentModal.frame_session_id
        || currentModal.frame_id && closeFrame && closeFrame !== currentModal.frame_id) {
      event(record,'javascript_dialog_close_identity_gap',{dialog_sequence:currentModal?.sequence || null});
      return;
    }
    const pending = record.dialogOperation;
    const identityVerified = currentModal.frame_id != null && closeFrame === currentModal.frame_id;
    if (pending && currentModal.sequence === pending.sequence) {
      pending.close = { accepted: params.result === true,
        identityVerified,
        promptMatch: pending.promptText == null ? null : params.userInput === pending.promptText };
      pending.closed?.();
    }
    if (identityVerified && record.pendingDialog?.sequence === currentModal.sequence
        && record.pendingDialog.frame_id === closeFrame && record.pendingDialog.frame_session_id === closeSession) {
      record.pendingDialog = null;
      if (!pending && !record.dialog_receipt?.dispatch_attempted) record.dialog_resolution_state = 'not_needed';
    } else if (record.pendingDialog) record.dialog_resolution_state = 'unverified';
    event(record, 'javascript_dialog_closed', { dialog_sequence: currentModal.sequence, accepted: params.result === true });
    record.modal = null; record.dialogDetails = undefined;
    if (record.durable) void persistTargets().catch(() => { record.cleanup_state = 'unverified'; state(); });
    state(); return;
  }
  if (record.state === 'active' && Date.now() >= record.expires) { void detach(record, 'expired'); return; }
  if (method === 'Page.frameDetached') endRemovedFrameNavigation(record, source, params);
  if (record.heldKey && (method === 'Page.frameNavigated' && params.frame.id === record.heldKey.frame.frame_id
      && params.frame.loaderId !== record.heldKey.frame.loader_id
      || method === 'Page.frameDetached' && params.frameId === record.heldKey.frame.frame_id)) record.heldKey.contextInvalidated = true;
  if (['Target.attachedToTarget','Target.detachedFromTarget','Page.frameAttached','Page.frameNavigated','Page.frameDetached','Runtime.executionContextDestroyed','Runtime.executionContextsCleared'].includes(method)) record.frameTopologyEpoch = (record.frameTopologyEpoch || 0) + 1;
  if (record.initializing && !source.sessionId && (method === 'Page.frameNavigated' && !params.frame.parentId
      || method === 'Page.navigatedWithinDocument')) {
    record.initializationNavigation++; return;
  }
  if (!source.sessionId && (method === 'Page.frameNavigated' && !params.frame.parentId
      || method === 'Page.navigatedWithinDocument' || method === 'Runtime.executionContextsCleared'))
    fencePageDownloads(record, 'document_changed');
  if (method === 'Page.frameNavigated' && record.origin && !source.sessionId && !params.frame.parentId) {
    try { if (webOrigin(params.frame.securityOrigin || params.frame.url) !== record.origin) {
      if (record.durable) { endChildNavigation(record); record.origin = webOrigin(params.frame.securityOrigin || params.frame.url); }
      else { void detach(record, 'origin_changed'); return; }
    } } catch { void detach(record, 'origin_changed'); return; }
    if (record.loaderId !== params.frame.loaderId) { endChildNavigation(record); record.loaderId = params.frame.loaderId; record.generation++; record.observations.clear(); event(record, 'document_changed'); state(); }
  } else if (method === 'Page.navigatedWithinDocument') {
    if (!source.sessionId && params.frameId === record.mainFrameId) endChildNavigation(record);
    record.generation++; record.observations.clear(); event(record, 'same_document_navigation'); state();
  } else if (method === 'Runtime.executionContextCreated' && record.contextUniqueIds) {
    if (params.context.uniqueId) {
      const key = (source.sessionId || '') + ':' + params.context.id;
      record.contextUniqueIds.set(key, params.context.uniqueId);
      (record.contextFrames ||= new Map()).set(key, params.context.auxData?.frameId || null);
    }
  } else if (method === 'Runtime.executionContextDestroyed' && record.contextUniqueIds) {
    const prefix = (source.sessionId || '') + ':';
    const hasId = Number.isSafeInteger(params.executionContextId);
    const uniqueId = typeof params.executionContextUniqueId === 'string' && params.executionContextUniqueId ? params.executionContextUniqueId : null;
    if (hasId) {
      const key = prefix + params.executionContextId;
      if (!uniqueId || record.contextUniqueIds.get(key) === uniqueId) { record.contextUniqueIds.delete(key); record.contextFrames?.delete(key); }
    }
    else for (const [key, currentUniqueId] of record.contextUniqueIds) {
      if (key.startsWith(prefix) && (!uniqueId || currentUniqueId === uniqueId)) { record.contextUniqueIds.delete(key); record.contextFrames?.delete(key); }
    }
    for (const [id, observation] of record.observations) {
      const contexts = observation.frameChain?.chain || [{ frame: observation.frame, contextId: observation.contextId, contextUniqueId: observation.contextUniqueId }];
      if (contexts.some(row => (row.frame.session_id || '') === (source.sessionId || '')
          && (!hasId || row.contextId === params.executionContextId)
          && (!uniqueId || row.contextUniqueId === uniqueId))) record.observations.delete(id);
    }
    event(record, 'context_invalidated', { reason: method });
  } else if ((method === 'Runtime.executionContextsCleared' || method === 'Page.frameDetached') && record.contextUniqueIds) {
    const session=source.sessionId||'',prefix=session+':';
    for(const key of record.contextUniqueIds.keys()) {
      if(method==='Runtime.executionContextsCleared' ? key.startsWith(prefix) : record.contextFrames?.get(key)===params.frameId) {
        record.contextUniqueIds.delete(key);record.contextFrames?.delete(key);
      }
    }
    for(const [id,observation]of record.observations) {
      const rows=observation.frameChain?.chain||[{frame:observation.frame}];
      if(rows.some(row=>method==='Runtime.executionContextsCleared' ? (row.frame.session_id||'')===session : row.frame.frame_id===params.frameId))
        record.observations.delete(id);
    }
    event(record, 'context_invalidated', { reason: method });
  } else if (method === 'Target.attachedToTarget') {
    if (record.durable) record.observations.clear();
    const child = { type: params.targetInfo.type, target_id: params.targetInfo.targetId, url: safeURL(params.targetInfo.url),
      parent_session_id: source.sessionId || null, session_epoch: (record.frameSessionEpoch = (record.frameSessionEpoch || 0) + 1) };
    record.children.set(params.sessionId, child);
    child.ready = (async () => {
      try {
        await cdp(record, 'Runtime.enable', {}, params.sessionId);
        if (params.targetInfo.type === 'iframe') {
          await cdp(record, 'Page.enable', {}, params.sessionId);
          await cdp(record, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true,
            filter: [{ type: 'iframe', exclude: false }, { type: 'worker', exclude: false }, { exclude: true }] }, params.sessionId);
        }
        if (record.network) {
          await cdp(record, 'Network.enable', { maxTotalBufferSize: 2097152, maxResourceBufferSize: 1048576, maxPostDataSize: 0 }, params.sessionId);
          await enableBodyCapture(record, params.sessionId);
        }
      } catch (error) { child.readiness_error = error.code || 'related_target_unavailable'; event(record, 'coverage_gap', { reason: 'related_target_unavailable' }); throw error; }
    })();
    child.ready.catch(() => {});
  } else if (method === 'Target.detachedFromTarget') {
    if (typeof params.sessionId === 'string') endNavigation(record, params.sessionId);
    if (record.contextUniqueIds) for (const key of record.contextUniqueIds.keys()) if (key.startsWith(params.sessionId + ':')) { record.contextUniqueIds.delete(key); record.contextFrames?.delete(key); }
    fenceBodyCapture(record, 'body_child_ended', params.sessionId); settleBodyCapture(record, 'session_gone', params.sessionId);
    record.bodyCaptureSessions?.delete(bodySessionKey(params.sessionId));
    record.children.delete(params.sessionId); record.observations.clear(); event(record, 'related_target_detached');
  } else if (method === 'Network.requestWillBeSent' && record.network) {
    const previous = [...record.requests.values()].reverse().find(r => r.requestId === params.requestId && r.sessionId === source.sessionId);
    if (params.redirectResponse && previous) { previous.redirected = true; event(record, 'redirect', { request_key: previous.key, status: params.redirectResponse.status }); }
    const key = uuid();
    const row = { key, requestId: params.requestId, sessionId: source.sessionId, frameId: params.frameId, loaderId: params.loaderId, type: params.type, observedBodyBytes: 0, observedBodyEvents: 0, bodyLengthKnown: true };
    record.requests.set(key, row);
    if (!record.bodyCaptureSessions?.get(bodySessionKey(source.sessionId))) row.streamPromise = streamBody(record, row);
    if (record.requests.size > 200) { const first = record.requests.keys().next().value; releaseBody(record.requests.get(first)); record.requests.delete(first); event(record, 'coverage_gap', { reason: 'request_metadata_evicted' }); }
    event(record, 'request', { request_key: key, url: safeURL(params.request.url), method: params.request.method, type: params.type, frame_id: params.frameId,
      has_post_data: !!params.request.hasPostData, secret_headers_collected: false, child_session: source.sessionId || null });
  } else if (method === 'Network.responseReceived' && record.network) {
    const row = [...record.requests.values()].reverse().find(r => r.requestId === params.requestId && r.sessionId === source.sessionId);
    if (row) {
      row.status = params.response.status; row.mimeType = params.response.mimeType;
      if (!record.bodyCaptureSessions?.get(bodySessionKey(source.sessionId))) row.streamPromise = (async () => {
        const initial = row.streamPromise;
        if (initial) await initial;
        if (row.bodyGap === 'raw_stream_unavailable') {
          row.bodyGap = undefined;
          await streamBody(record, row);
        }
      })();
    }
    event(record, 'response', { request_key: row?.key ?? null, status: params.response.status, mime_type: params.response.mimeType, from_service_worker: !!params.response.fromServiceWorker,
      url: safeURL(params.response.url), secret_headers_collected: false });
  } else if (method === 'Network.dataReceived') {
    const row = [...record.requests.values()].reverse().find(r => r.requestId === params.requestId && r.sessionId === source.sessionId);
    if (row) {
      row.observedBodyEvents++;
      if (Number.isSafeInteger(params.dataLength) && params.dataLength >= 0
          && Number.isSafeInteger(row.observedBodyBytes + params.dataLength)) row.observedBodyBytes += params.dataLength;
      else row.bodyLengthKnown = false;
      if (params.data && row.streamPromise) retainBody(record, row, decoded(params.data));
    }
  } else if (method === 'Network.loadingFinished') {
    const row = [...record.requests.values()].reverse().find(r => r.requestId === params.requestId && r.sessionId === source.sessionId);
    if (row) row.finished = true;
  } else if (method === 'Network.loadingFailed') {
    const row = [...record.requests.values()].reverse().find(r => r.requestId === params.requestId && r.sessionId === source.sessionId);
    if (row) { releaseBody(row); row.bodyGap = 'response_failed'; row.failed = true; row.canceled = params.canceled === true; }
    event(record, 'request_failed', { request_key: row?.key || null, reason: params.canceled ? 'canceled' : 'network_failure' });
  }
  else if (method === 'Runtime.consoleAPICalled') event(record, 'console', { level: params.type, argument_types: (params.args || []).slice(0, 10).map(a => a.type), values_collected: false });
  else if (method === 'Runtime.exceptionThrown') event(record, 'runtime_exception', { text_collected: false });
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('popup.html'))) return false;
  void (async () => {
    if (message.action === 'status') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return { ok: true, connected: !!serverGeneration, worker_generation: workerGeneration, connection_diagnostic: connectionDiagnostic(), current_tab_id: tab?.id,
        leases: [...leases.values()].filter(r => !r.durable).map(publicLease), private_context: chrome.extension.inIncognitoContext,
        trust, claims: [...claims.values()].map(publicClaim), current_target_stopped: stoppedTargets.has(targets.get(tab?.id)?.target_id) };
    }
    if (message.action === 'setup') return { ok: true, trust: await localSetup(message.options) };
    if (message.action === 'revoke_setup') {
      if (trust) {
        fencePageDownloads(null, 'local_setup_revoked');
        trust = { ...trust, enabled: false };
        await chrome.storage.local.set({ ['workbenchTrust:' + contextKind()]: trust });
        await managedRevoke();
        sendNative(port, { type: 'local_revoke', interaction_version: INTERACTION_VERSION, trust_id: trust.trust_id });
        for (const record of claims.values()) if (!['released', 'revoked', 'target_closed'].includes(record.state)) await finishClaim(record, 'revoked', 'local_setup_revoked');
      }
      state(); return { ok: true };
    }
    if (message.action === 'stop_target' || message.action === 'resume_target') {
      await ensureConnection();
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id !== message.tab_id) throw fail('selected_tab_changed');
      const actual = (await chrome.debugger.getTargets()).find(t => t.tabId === tab?.id && t.type === 'page');
      const target = targets.get(tab?.id);
      if (!target || actual?.id !== target.browser_target_id) throw fail('stale_browser_target');
      if (message.action === 'resume_target') stoppedTargets.delete(target.target_id);
      else { stoppedTargets.add(target.target_id);
        for (const record of claims.values()) if (record.target.target_id === target.target_id && !['released', 'revoked', 'target_closed'].includes(record.state)) await finishClaim(record, 'revoked', 'local_stop');
      }
      await persistTargets(); state(); return { ok: true };
    }
    if (message.action === 'grant') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id !== message.tab_id) throw fail('selected_tab_changed');
      return { ok: true, lease: await grantLocal(tab.id, message.options) };
    }
    if (message.action === 'revoke') {
      const record = leases.get(message.lease_id);
      if (!record) throw fail('unknown_browser_lease');
      await detach(record, 'local_revoke'); return { ok: true };
    }
    throw fail('unsupported_local_action');
  })().then(reply, e => reply({ ok: false, error: { code: e.code || 'local_action_failed' } }));
  return true;
});

// Managed requests are profile-scoped, not debugger/tab or document actions.
const managedDownloads = new Map();
let managedLoaded;
let managedPersistence = Promise.resolve();
const CANCEL_EVIDENCE_CALLERS = new Set(['explicit_command','arm_expiry','context_fence','permission_revoke','ambiguity','page_event','filename_event','api_start','blob_start','unspecified']);
const CANCEL_EVIDENCE_REASONS = new Set(['explicit_or_host_control','arm_expired','native_connection_lost','workbench_shutdown','idle_disconnect','connection_timeout','connection_setup_failed','document_changed','trust_generation_changed','local_setup_revoked','permission_reduced','permission_removed','authority_or_capture_ended','ambiguity_barrier','current_admission_ended','cancel_already_requested','blob_current_ended','post_start_guard_ended','unspecified']);
function newProducerCancelEvidence(id) {
  return { version:1, coverage:'new_producer_best_effort', producer_id:id, entries:[], total_requests:0, omitted:false };
}
function cancelEvidenceProjection(value, row) {
  const empty = () => ({version:1,coverage:'not_recorded',producer_id:row.download_id,entries:[],total_requests:null,omitted:true});
  try {
    const integer = v => Number.isSafeInteger(v) && v >= 0, clock = v => v === null || integer(v);
    const id = v => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
    if (!value || Object.keys(value).sort().join(',') !== 'coverage,entries,omitted,producer_id,total_requests,version'
        || value.version !== 1 || value.producer_id !== row.download_id || !id(row.download_id) || !['ordinary','private'].includes(row.context_kind)
        || typeof value.omitted !== 'boolean' || !Array.isArray(value.entries) || value.entries.length > 8) return empty();
    if (value.coverage === 'not_recorded') return value.entries.length === 0 && value.total_requests === null ? {...empty(),omitted:value.omitted} : empty();
    if (value.coverage !== 'new_producer_best_effort' || !integer(value.total_requests)
        || value.total_requests > value.entries.length && !value.omitted) return empty();
    const entries=[];let sequence=0;
    for (const item of value.entries) {
      if (!item || Object.keys(item).sort().join(',') !== 'acknowledged,attempted,caller,command_id,context_kind,error_class,error_stage,native_id,protocol_code,reason,returned_monotonic_ms,sequence,started_monotonic_ms,started_wall_ms,worker_generation'
          || !integer(item.sequence) || item.sequence <= sequence || item.sequence > value.total_requests || !id(item.worker_generation)
          || item.context_kind !== row.context_kind || !['ordinary','private'].includes(item.context_kind)
          || item.native_id !== null && (!Number.isInteger(item.native_id) || item.native_id < 0 || item.native_id > 2147483647 || item.native_id !== row.browser_download_id)
          || !CANCEL_EVIDENCE_CALLERS.has(item.caller) || !CANCEL_EVIDENCE_REASONS.has(item.reason)
          || item.command_id !== null && !id(item.command_id)
          || ![item.started_wall_ms,item.started_monotonic_ms,item.returned_monotonic_ms].every(clock)
          || item.started_monotonic_ms !== null && item.returned_monotonic_ms !== null && item.returned_monotonic_ms < item.started_monotonic_ms
          || typeof item.attempted !== 'boolean' || typeof item.acknowledged !== 'boolean'
          || item.attempted !== (item.native_id !== null) || item.acknowledged && !item.attempted
          || !['none','no_native_id','native_cancel','state_refresh'].includes(item.error_stage)
          || !['none','timeout','protocol_rejection','javascript_exception','unclassified_error'].includes(item.error_class)
          || item.protocol_code !== null && ![-32700,-32600,-32601,-32602,-32603,-32000].includes(item.protocol_code)
          || (item.error_class === 'protocol_rejection') !== (item.protocol_code !== null)) return empty();
      sequence=item.sequence;entries.push({...item});
    }
    return {...value,entries};
  } catch { return empty(); }
}
function normalizeCancelEvidence(row) {
  if (!Object.hasOwn(row,'producer_cancel_evidence')) return;
  row.producer_cancel_evidence=cancelEvidenceProjection(row.producer_cancel_evidence,row);
  if (encoder.encode(JSON.stringify(row)).length > 32768) delete row.producer_cancel_evidence;
}
function cancelEvidenceClock(wall=false) {
  try { const value=Math.floor(wall ? Date.now() : performance.now()); return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  catch { return null; }
}
function beginCancelEvidence(row,caller,reason,nativeId,commandId) {
  try {
    if (!Object.hasOwn(row,'producer_cancel_evidence')) return null; // No old-history backfill.
    const data=cancelEvidenceProjection(row.producer_cancel_evidence,row);
    row.producer_cancel_evidence=data;
    if (data.coverage !== 'new_producer_best_effort') return null;
    if (data.total_requests === Number.MAX_SAFE_INTEGER) { data.omitted=true;return null; }
    const item={sequence:++data.total_requests,worker_generation:workerGeneration,context_kind:contextKind(),native_id:nativeId,
      caller:CANCEL_EVIDENCE_CALLERS.has(caller)?caller:'unspecified',reason:CANCEL_EVIDENCE_REASONS.has(reason)?reason:'unspecified',
      command_id:typeof commandId==='string'&&/^[a-f0-9]{32}$/.test(commandId)?commandId:null,
      started_wall_ms:cancelEvidenceClock(true),started_monotonic_ms:cancelEvidenceClock(),returned_monotonic_ms:null,
      attempted:nativeId!==null,acknowledged:false,error_stage:nativeId===null?'no_native_id':'none',error_class:'none',protocol_code:null};
    data.entries.push(item);
    if (data.entries.length > 8) {
      const firstNative=data.entries.find(entry=>entry.attempted);
      const index=data.entries.findIndex((entry,index)=>index!==0 && entry!==firstNative);
      data.entries.splice(index,1);data.omitted=true;
    }
    const handle={row,sequence:item.sequence,worker_generation:workerGeneration};
    if(nativeId===null)finishCancelEvidence(handle,false);
    return handle;
  } catch { return null; }
}
function finishCancelEvidence(handle,acknowledged,error=null,stage='none') {
  if(!handle)return;
  try {
    const item=handle.row.producer_cancel_evidence?.entries.find(row=>row.sequence===handle.sequence&&row.worker_generation===handle.worker_generation);
    if(!item)return; // Eviction/lost diagnostics never change original cleanup.
    item.acknowledged=acknowledged;
    if(item.returned_monotonic_ms===null){const value=cancelEvidenceClock();item.returned_monotonic_ms=value!==null&&(item.started_monotonic_ms===null||value>=item.started_monotonic_ms)?value:null;}
    if(error){const safe=responseDiagnosticError(error);item.error_class=safe.error_class;item.protocol_code=safe.protocol_code;item.error_stage=stage;}
  } catch {} // Evidence never changes original SDK/control flow.
}
function cancelFenceReason(reason) { return CANCEL_EVIDENCE_REASONS.has(reason)?reason:'authority_or_capture_ended'; }
async function managedPermission() {
  return !!chrome.downloads && !!chrome.permissions && await chrome.permissions.contains({ permissions: ['downloads'] });
}
function managedGetFilenameValid(identifier, filename) {
  // Existing receipts keep their original names. New GET staging names have
  // no extension, so Chrome's MIME safety correction cannot replace it.
  return filename === 'LocalWorkbench/' + identifier
    || filename === 'LocalWorkbench/' + identifier + '.download';
}
function managedPublic(row) {
  preservePageAmbiguity(row);
  const { busy, operation, admission_diagnostics, producer_cancel_evidence, ...result } = row;
  if (admission_diagnostics) {
    result.admission_diagnostics = responseDiagnosticProjection(admission_diagnostics, 4);
    if (JSON.stringify(result).length > 32768)
      delete result.admission_diagnostics;
  }
  if (producer_cancel_evidence !== undefined) {
    result.producer_cancel_evidence=cancelEvidenceProjection(producer_cancel_evidence,row);
    if(encoder.encode(JSON.stringify(result)).length>32768)delete result.producer_cancel_evidence;
  }
  return result;
}
function managedHistoryLocation() {
  if (contextKind() === 'ordinary') return { area:chrome.storage.local, key:'workbenchManaged:ordinary' };
  if (!/^[0-9a-f]{32}$/.test(profileId || '') || !/^[0-9a-f]{32}$/.test(contextId || ''))
    throw fail('download_context_unavailable');
  // Private receipt contents have browser-session lifetime, never local/sync.
  return { area:chrome.storage.session, key:'workbenchManaged:private:' + profileId + ':' + contextId };
}
async function managedSave() {
  const snapshot = JSON.parse(JSON.stringify([...managedDownloads.values()].map(managedPublic)));
  const location = managedHistoryLocation();
  if (contextKind() === 'private' && snapshot.some(row => row.route !== 'page_response'
      || row.context_kind !== 'private' || row.private !== true || row.profile_id !== profileId || row.context_id !== contextId
      || row.installation_id !== installationId || !validPageHistory(row))) throw fail('download_history_schema');
  const next = managedPersistence.then(() => location.area.set({ [location.key]: snapshot }));
  managedPersistence = next.catch(() => {});
  await next;
}
async function managedLoad() {
  const location = managedHistoryLocation();
  if (!managedLoaded) managedLoaded = (async () => {
    const stored = (await location.area.get(location.key))[location.key] || [];
    if (!Array.isArray(stored) || stored.length > 1000) throw fail('download_history_limit');
    for (const row of stored) {
      if (!row || typeof row !== 'object' || !/^[0-9a-f]{32}$/.test(row.download_id)
          || managedDownloads.has(row.download_id) || row.context_kind !== contextKind()
          || ['installation_id','profile_id','context_id','nonce'].some(key=>typeof row[key] !== 'string' || !/^[0-9a-f]{32}$/.test(row[key]))
          || typeof row.owner_session !== 'string' || !row.owner_session.length || row.owner_session.length > 128
          || typeof row.original_request_id !== 'string' || !row.original_request_id.length || row.original_request_id.length > 128
          || row.route === 'page_response' && row.relative_filename !== 'LocalWorkbench/' + row.download_id + '.download'
          || row.route !== 'page_response' && row.route !== 'profile_api_blob' && !managedGetFilenameValid(row.download_id, row.relative_filename)
          || !['intent','attempted','unknown','in_progress','complete','interrupted','gone'].includes(row.producer_state)
          || row.browser_download_id != null && (!Number.isInteger(row.browser_download_id) || row.browser_download_id < 0 || row.browser_download_id > 2147483647)
          || ['in_progress','complete','interrupted'].includes(row.producer_state) && row.browser_download_id == null) throw fail('download_history_schema');
      if (contextKind() === 'private' && (row.route !== 'page_response' || row.private !== true || row.profile_id !== profileId
          || row.context_id !== contextId || row.installation_id !== installationId)) throw fail('download_history_schema');
      normalizeCancelEvidence(row);
      if (row.download_persistence !== undefined && !['saved','unknown'].includes(row.download_persistence)) throw fail('download_history_schema');
      if (row.route !== undefined && !['profile_api_get','page_response','profile_api_blob'].includes(row.route)) throw fail('download_history_schema');
      if (row.route === 'profile_api_blob') {
        if (!validBlobHistory(row)) throw fail('download_history_schema');
        if (row.worker_generation !== workerGeneration && !['complete','interrupted','gone'].includes(row.producer_state)) {
          row.cancel_requested = true; row.producer_state = 'unknown';
        }
      }
      if (row.route === 'page_response') {
        if (!validPageHistory(row)) throw fail('download_history_schema');
        preservePageAmbiguity(row);
        // Cold startup has no original event/session authority. Known IDs permit
        // cleanup; no response, GUID or new ID may bind in this new worker.
        if (row.worker_generation !== workerGeneration && !['complete','interrupted','gone'].includes(row.producer_state)) {
          row.cancel_requested = true;
          if (!pageAmbiguity(row)) row.observation_state = 'cold_worker_unknown';
          row.producer_state = 'unknown';
        }
      }
      if (['intent','attempted'].includes(row.producer_state)) row.producer_state = 'unknown';
      managedDownloads.set(row.download_id, row);
    }
  })();
  return managedLoaded;
}
function managedPublish(row) {
  if (port && serverGeneration) sendNative(port, { type: 'managed_download_state', managed_download_version: 1,
    download: managedPublic(row) });
}
async function managedPersistReceipt(row) {
  // Persistence is not cleanup authority. A failed/stalled normal store cannot
  // prevent cancellation of the original exact native ID already returned.
  row.download_persistence = 'saved';
  try { await bodyWait(managedSave(),350,null,'download_storage_timeout'); return true; }
  catch { row.download_persistence = 'unknown'; managedPublish(row); return false; }
}
function previousUnusedClaimTerminal(row) {
  const b = row.page_binding, record = claims.get(b?.claim_id);
  if (!record?.durable || record.debuggerAttached !== false || record.inputEligible !== false) return false;
  const claim = publicClaim(record);
  return ['released','revoked','target_closed'].includes(claim.state)
    && ['completed','target_gone'].includes(claim.cleanup_state) && claim.debuggerAttached === false
    && claim.input_eligible === false && claim.claim_epoch > b.claim_epoch
    && ['owner_session','installation_id','runtime_generation'].every(k => claim[k] === b[k])
    // Local durableTarget receipts omit origin for privacy. Only this terminal
    // cleanup predicate permits omission; any retained origin must still match.
    && (!Object.prototype.hasOwnProperty.call(claim.target,'origin') || claim.target.origin === b.origin)
    && ['target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind',
      'connection_generation','frame_id','loader_id','document_epoch'].every(k => claim.target[k] === b[k]);
}
async function persistPreviousObserverRetirement(row) {
  // Do not expose saved until the witness itself is durable. A failed first
  // write leaves unknown; a cold restore can retry this metadata write only.
  row.download_persistence = 'unknown';
  try { await bodyWait(managedSave(),350,null,'download_storage_timeout'); }
  catch { managedPublish(row); return; }
  await managedPersistReceipt(row); managedPublish(row);
}
async function managedRefresh(row) {
  if (row.browser_download_id == null) {
    // A fresh read can reconcile an old unused observer only from its durable
    // exact cancellation fence. The old worker cannot consume another response;
    // cold workers never bind new page IDs. This says nothing about HTTP effects.
    if (row.route === 'page_response' && row.observer_retirement === undefined
        && row.runtime_generation !== serverGeneration && /^[0-9a-f]{32}$/.test(serverGeneration || '')
        && row.worker_generation !== workerGeneration && previousUnusedClaimTerminal(row) && row.cancel_requested === true
        && row.producer_state === 'gone' && row.observation_state === 'cancelled_before_response'
        && row.download_persistence === 'saved' && row.cleanup_state === 'pending'
        && row.response == null && row.token_filename == null && !pageAmbiguity(row)) {
      row.observer_retirement = 'cancelled_before_worker_restart';
      row.observer_retirement_worker_generation = workerGeneration;
      row.cleanup_state = 'settled';
      await persistPreviousObserverRetirement(row);
    } else if (row.observer_retirement === 'cancelled_before_worker_restart' && row.download_persistence === 'unknown') {
      await persistPreviousObserverRetirement(row);
    }
    return;
  }
  const found = await chrome.downloads.search({ id: row.browser_download_id });
  if (!found.length) { row.producer_state = 'gone'; row.filename = null; }
  else {
    const item = found[0];
    if (row.route === 'page_response' && pageAmbiguity(row)) {
      row.producer_state = 'unknown'; await managedPersistReceipt(row); managedPublish(row); return;
    }
    if (found.length !== 1 || item.id !== row.browser_download_id || row.route !== 'page_response' && item.byExtensionId !== chrome.runtime.id
        || item.incognito !== (row.context_kind === 'private')
        || ['page_response','profile_api_blob'].includes(row.route) && item.url !== row.url) throw fail('download_identity_changed');
    row.producer_state = item.state; row.filename = item.filename || null;
    row.by_extension_id = item.byExtensionId; row.private = item.incognito;
    row.bytes_received = item.bytesReceived; row.file_size = item.fileSize; row.total_bytes = item.totalBytes;
    row.error_code = typeof item.error === 'string' ? item.error.slice(0, 80) : null;
  }
  if (row.cancel_requested && ['complete','interrupted','gone'].includes(row.producer_state)) row.cleanup_state = 'settled';
  await managedPersistReceipt(row); managedPublish(row);
}
function retireUnusedPageObserver(row) {
  // This synchronous witness retires only our response observer. Response-stage
  // observation cannot establish whether an HTTP request was submitted.
  if (row.route === 'page_response' && row.worker_generation === workerGeneration
      && row.observation_state === 'armed' && !row.response && row.token_filename == null
      && row.browser_download_id == null && !pageAmbiguity(row))
    row.observer_retirement = 'cancelled_while_armed';
}
async function managedCancel(row, caller = 'unspecified', reason = 'unspecified', commandId) {
  retireUnusedPageObserver(row);
  row.cancel_requested = true; row.cleanup_state = 'pending';
  if (row.route === 'page_response' && (!row.response || row.response.continuation_state === 'not_attempted')) {
    row.producer_state = 'gone';
    if (!row.response) row.observation_state = 'cancelled_before_response';
  }
  managedPublish(row);
  if (row.browser_download_id == null) {
    beginCancelEvidence(row,caller,reason,null,commandId);
    // Keep the exact tombstone. Only a validated unused-observer witness
    // settles it; consumed/legacy/unknown rows without proof stay fenced.
    if (['cancelled_while_armed','cancelled_before_worker_restart'].includes(row.observer_retirement)) row.cleanup_state = 'settled';
    await managedPersistReceipt(row); managedPublish(row); return; // Retain exact original late-ID cancellation intent.
  }
  // Retained returned-ID or page-token authority permits original cleanup even
  // when storage is unavailable. Neither admission nor ID guessing occurs here.
  let evidence, cancelAcknowledged=false;
  try {
    // Preserve SDK callee/argument evaluation order; evidence returns the same ID.
    const argument=nativeId=>{evidence=beginCancelEvidence(row,caller,reason,nativeId,commandId);return nativeId;};
    await chrome.downloads.cancel(argument(row.browser_download_id));
    cancelAcknowledged=true; finishCancelEvidence(evidence,true);
    await managedRefresh(row); // ACK alone never establishes terminal state.
  } catch (error) {
    finishCancelEvidence(evidence,cancelAcknowledged,error,cancelAcknowledged?'state_refresh':'native_cancel');
    row.cleanup_state = 'unknown';
    try { await managedPersistReceipt(row); }
    catch { row.download_persistence = 'unknown'; }
    // Retain the original row even if recovery persistence or publication
    // fails; neither can turn an attempted cancellation into no effect.
    try { managedPublish(row); } catch { /* Original custody remains pinned. */ }
    // The cancel API was invoked, including synchronous SDK failures. A lost
    // ACK or later identity/refresh failure cannot establish no effect.
    throw fail(error?.code || 'managed_download_failed', 'unknown');
  }
}
async function managedOperation(packet) {
  // Fence any already loaded original before permission/storage waits.
  if (packet.action === 'managed_download_cancel') {
    const original = managedDownloads.get(packet.download_id);
    if (original && ['owner_session','nonce','original_request_id','installation_id','profile_id','context_id','context_kind'].every(k => original[k] === packet[k]))
      original.cancel_requested = true;
  }
  if (contextKind() === 'private' && packet.private_page_download_version !== 1
      && packet.action !== 'managed_download_start' && packet.action !== 'managed_download_start_blob')
    throw fail('download_private_bridge_unavailable');
  await managedLoad();
  const cleanup = packet.action === 'managed_download_cancel';
  if (!cleanup) requireTrust(packet);
  else if (packet.context_id !== contextId || packet.profile_id !== profileId || packet.context_kind !== contextKind()
      || packet.runtime_generation !== serverGeneration) throw fail('download_owner_mismatch');
  if (packet.managed_download_version !== 1 || packet.installation_id !== installationId
      || !cleanup && !trust.file_download || !await managedPermission()) throw fail('browser_download_not_granted');
  if (!/^[0-9a-f]{32}$/.test(packet.download_id) || !/^[0-9a-f]{32}$/.test(packet.nonce)
      || typeof packet.owner_session !== 'string' || packet.owner_session.length > 128
      || typeof packet.original_request_id !== 'string' || packet.original_request_id.length > 128) throw fail('download_identity_required');
  const kind = packet.action.slice('managed_download_'.length);
  let row = managedDownloads.get(packet.download_id);
  if (row && ['owner_session','installation_id','profile_id','context_id','context_kind','nonce','original_request_id']
      .some(key => row[key] !== packet[key])) throw fail('download_owner_mismatch');
  if (!row && kind === 'cancel') {
    // Cancellation can overtake an admitted but not-yet-delivered start. Keep
    // a fenced unknown intent; absence of a returned ID is not absence proof.
    if (contextKind() === 'private') {
      row = pageArmRecord(packet, true);
      row.observation_state = 'cold_worker_unknown'; row.producer_state = 'unknown'; row.cancel_requested = true;
    } else row = { download_id: packet.download_id, owner_session: packet.owner_session,
      installation_id: installationId, profile_id: profileId, context_id: contextId, context_kind: contextKind(),
      nonce: packet.nonce, original_request_id: packet.original_request_id,
      relative_filename: managedGetFilenameValid(packet.download_id, packet.relative_filename)
        ? packet.relative_filename : 'LocalWorkbench/' + packet.download_id, producer_state: 'unknown',
      browser_download_id: null, filename: null, private: contextKind() === 'private',
      bytes_received: 0, file_size: -1, total_bytes: -1, cancel_requested: true };
    managedDownloads.set(row.download_id, row); await managedSave();
  }
  if (kind === 'start_blob') {
    if (row) return {ok:true,download:managedPublic(row),original_request_not_repeated:true};
    row = await startBlobDownload(packet);
  } else if (kind === 'arm') {
    if (row) return { ok: true, download: managedPublic(row), original_request_not_repeated: true };
    row = pageArmRecord(packet);
    if (!await managedPermission() || !pageDownloadCurrent(row)) throw fail('download_claim_changed');
    if (contextKind() === 'private') {
      if (!await chrome.extension.isAllowedIncognitoAccess()) throw fail('private_context_not_enabled');
      const tab = await chrome.tabs.get(row.page_binding.tab_id);
      if (!tab || tab.incognito !== true || !pageDownloadCurrent(row)) throw fail('download_claim_changed');
    }
    if ([...managedDownloads.values()].filter(r => !['complete','interrupted','gone'].includes(r.producer_state)).length >= 32
        || managedDownloads.size >= 1000) throw fail('download_resource_limit');
    if ([...managedDownloads.values()].some(r => r.route === 'page_response' && r.page_binding.claim_id === row.page_binding.claim_id
        && !['complete','interrupted','gone'].includes(r.producer_state))) throw fail('download_arm_pending');
    managedDownloads.set(row.download_id, row); await managedSave();
    if (!pageDownloadCurrent(row)) { row.cancel_requested = true; row.producer_state = 'gone'; await managedSave(); throw fail('download_claim_changed'); }
    setTimeout(() => { if (row.observation_state === 'armed') {
      // Expiry has the same synchronous unused-observer proof as explicit cancel.
      void managedCancel(row,'arm_expiry','arm_expired').catch(() => { row.cleanup_state = 'unknown'; managedPublish(row); }); } },
      Math.max(1, row.expires_at * 1000 - Date.now()));
  } else if (kind === 'start') {
    if (row) return { ok: true, download: managedPublic(row), original_request_not_repeated: true };
    if (contextKind() === 'private') throw fail('private_download_unverified');
    if (!trust.control || !managedGetFilenameValid(packet.download_id, packet.relative_filename)) throw fail('download_admission_stopped');
    webOrigin(packet.url);
    if (typeof packet.url !== 'string' || encoder.encode(packet.url).length > 8192) throw fail('invalid_download_url');
    const live = [...managedDownloads.values()].filter(r => !['complete','interrupted','gone'].includes(r.producer_state));
    if (live.length >= 32 || managedDownloads.size >= 1000) throw fail('download_resource_limit');
    row = { download_id: packet.download_id, owner_session: packet.owner_session,
      installation_id: installationId, profile_id: profileId, context_id: contextId, context_kind: contextKind(),
      nonce: packet.nonce, original_request_id: packet.original_request_id, relative_filename: packet.relative_filename,
      producer_state: 'intent', browser_download_id: null, filename: null, private: contextKind() === 'private',
      bytes_received: 0, file_size: -1, total_bytes: -1, cancel_requested: false,
      producer_cancel_evidence:newProducerCancelEvidence(packet.download_id) };
    managedDownloads.set(row.download_id, row);
    await managedSave();
    // No await between the last lifetime/capability check and original invocation.
    requireTrust(packet);
    if (!trust.file_download || row.cancel_requested) throw fail('download_admission_stopped');
    row.producer_state = 'attempted'; await managedSave(); requireTrust(packet);
    if (!trust.file_download || row.cancel_requested) throw fail('download_admission_stopped');
    try {
      row.operation = chrome.downloads.download({ url: packet.url, filename: row.relative_filename,
        conflictAction: 'uniquify', saveAs: false });
      const id = await row.operation;
      if (!Number.isSafeInteger(id) || id < 0) throw fail('download_id_unverified');
      row.browser_download_id = id; row.by_extension_id = chrome.runtime.id;
      row.producer_state = 'in_progress'; row.download_persistence = 'unknown'; managedPublish(row);
      if (row.cancel_requested || !trust?.enabled || !trust.file_download) await managedCancel(row,'api_start','post_start_guard_ended');
      else {
        await managedPersistReceipt(row);
        if (row.cancel_requested || !trust?.enabled || !trust.file_download) await managedCancel(row,'api_start','post_start_guard_ended');
        else await managedRefresh(row);
      }
    } catch (error) {
      if (row.browser_download_id == null) row.producer_state = 'unknown';
      await managedPersistReceipt(row); managedPublish(row); throw fail(error.code || 'download_start_unverified', 'unknown');
    }
  } else {
    if (!row) throw fail('download_unknown_intent');
    if (kind === 'state') await managedRefresh(row);
    else if (kind === 'cancel') await managedCancel(row,'explicit_command','explicit_or_host_control',packet.request_id);
    else throw fail('invalid_download_action');
  }
  return { ok: true, download: managedPublic(row), bytes_captured: false };
}
async function managedRevoke() {
  fencePageDownloads(null, 'permission_reduced');
  await managedLoad();
  for (const row of managedDownloads.values()) if (!['complete','interrupted','gone'].includes(row.producer_state)) row.cancel_requested = true;
  // Flags are synchronous; native cleanup must not queue behind this store.
  for (const row of managedDownloads.values()) if (!['complete','interrupted','gone'].includes(row.producer_state)) {
    row.cancel_requested = true;
    try { await managedCancel(row,'permission_revoke','permission_reduced'); } catch { row.cleanup_state = 'unknown'; await managedPersistReceipt(row); managedPublish(row); }
  }
}
let managedEventsInstalled = false;
function managedAttachEvents() {
  if (managedEventsInstalled || !chrome.downloads?.onChanged) return;
  managedEventsInstalled = true;
  chrome.downloads.onDeterminingFilename?.addListener(pageDetermineFilename);
  chrome.downloads.onChanged.addListener(delta => {
    void managedLoad().then(async () => {
      const row = [...managedDownloads.values()].find(item => item.browser_download_id === delta.id);
      if (row) await managedRefresh(row);
    }).catch(() => {});
  });
}
managedAttachEvents();
chrome.permissions?.onAdded?.addListener(managedAttachEvents);
chrome.permissions?.onRemoved?.addListener(permissions => {
  if (permissions.permissions?.includes('downloads')) {
    fencePageDownloads(null, 'permission_removed');
    void managedLoad().then(async () => {
      for (const row of managedDownloads.values()) if (!['complete','interrupted','gone'].includes(row.producer_state)) {
        row.cancel_requested = true; row.cleanup_state = 'unknown'; managedPublish(row);
      }
      await managedSave();
    }).catch(() => {});
  }
});

// Original HTTP response observation uses only an existing owned root Fetch session.
const pageObservationWaiters = new Map();
function safeAttachmentName(headers) {
  if (!Array.isArray(headers) || headers.length > 256) return null;
  const dispositions = headers.filter(h => typeof h?.name === 'string' && h.name.toLowerCase() === 'content-disposition');
  if (dispositions.length !== 1 || typeof dispositions[0].value !== 'string') return null;
  const value = dispositions[0].value;
  if (value.length > 4096 || /[\x00-\x1f\x7f]/.test(value)) return null;
  // Support one UTF8 extended name and its optional ASCII fallback. Duplicate
  // names and unknown/malformed parameters are unsupported, passed unchanged.
  const parts = value.split(';');
  if (!/^attachment\s*$/i.test(parts.shift()) || parts.length < 1 || parts.length > 2) return null;
  const names = new Map();
  for (const part of parts) {
    const match = /^\s*(filename\*|filename)\s*=\s*(.*?)\s*$/i.exec(part);
    if (!match || names.has(match[1].toLowerCase())) return null;
    const key = match[1].toLowerCase();
    let decoded;
    if (key === 'filename*') {
      const encoded = /^UTF-8''([A-Za-z0-9!#$&+.^_`|~%*-]+)$/i.exec(match[2]);
      if (!encoded) return null;
      try { decoded = decodeURIComponent(encoded[1]); } catch { return null; }
    } else {
      const quoted = /^"([^"\\]*)"$/.exec(match[2]);
      decoded = quoted ? quoted[1] : /^[A-Za-z0-9!#$&+.^_`|~-]+$/.test(match[2]) ? match[2] : null;
      if (!decoded || /[^\x20-\x7e]/.test(decoded) || /[\/\\\x00-\x1f\x7f]/.test(decoded)) return null;
    }
    names.set(key, decoded);
  }
  const name = names.get('filename*') || names.get('filename');
  if (!name || encoder.encode(name).length > 240 || /[\/\\<>:"|?*\x00-\x1f\x7f]/.test(name)
      || /^\s|\s$|^\.|[. ]$/.test(name) || /[\u202a-\u202e\u2066-\u2069]/.test(name)
      || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) return null;
  const ext = /\.[A-Za-z0-9]{1,16}$/.exec(name);
  return ext ? { name, extension: ext[0] } : null;
}
function pageDownloadCurrent(row, trace) {
  const b = row.page_binding, record = claims.get(b?.claim_id);
  const capture = record?.bodyCaptureSessions?.get('');
  return responseDiagnosticMark(trace, 'route', row.route === 'page_response')
    && responseDiagnosticMark(trace, 'cancel_requested', !row.cancel_requested)
    && responseDiagnosticMark(trace, 'ambiguity', !pageAmbiguity(row))
    && responseDiagnosticMark(trace, 'worker_generation', row.worker_generation === workerGeneration)
    && responseDiagnosticMark(trace, 'runtime_generation', row.runtime_generation === serverGeneration)
    && responseDiagnosticMark(trace, 'installation', row.installation_id === installationId)
    && responseDiagnosticMark(trace, 'profile', row.profile_id === profileId)
    && responseDiagnosticMark(trace, 'context', row.context_id === contextId)
    && responseDiagnosticMark(trace, 'context_kind', row.context_kind === contextKind())
    && responseDiagnosticMark(trace, 'binding_context_kind', b.context_kind === contextKind())
    && responseDiagnosticMark(trace, 'claim_context_kind', record?.target.context_kind === contextKind())
    && responseDiagnosticMark(trace, 'response_or_unexpired_arm', (row.response || Date.now() < row.expires_at * 1000))
    && responseDiagnosticMark(trace, 'trust_enabled', trust?.enabled)
    && responseDiagnosticMark(trace, 'trust_control', trust.control)
    && responseDiagnosticMark(trace, 'trust_network', trust.network)
    && responseDiagnosticMark(trace, 'trust_file_download', trust.file_download)
    && responseDiagnosticMark(trace, 'trust_identity', trust.trust_id === b.trust_id)
    && responseDiagnosticMark(trace, 'peer_identity', peerId === b.peer_id)
    && responseDiagnosticMark(trace, 'durable_claim', record?.durable)
    && responseDiagnosticMark(trace, 'owner_identity', record.owner_session === row.owner_session)
    && responseDiagnosticMark(trace, 'claim_epoch', record.claim_epoch === b.claim_epoch)
    && responseDiagnosticMark(trace, 'target_generation', record.target.target_generation === b.target_generation)
    && responseDiagnosticMark(trace, 'browser_target', record.target.browser_target_id === b.browser_target_id)
    && responseDiagnosticMark(trace, 'main_frame', record.mainFrameId === b.frame_id)
    && responseDiagnosticMark(trace, 'loader', record.loaderId === b.loader_id)
    && responseDiagnosticMark(trace, 'document_epoch', record.generation === b.document_epoch)
    && responseDiagnosticMark(trace, 'origin', record.origin === b.origin)
    && responseDiagnosticMark(trace, 'claim_network', record.network)
    && responseDiagnosticMark(trace, 'claim_control', record.control)
    && responseDiagnosticMark(trace, 'capture_enabled', capture?.enabled)
    && responseDiagnosticMark(trace, 'capture_current', bodyCaptureCurrent(capture, trace));
}
function fencePageDownloads(record, reason) {
  // Synchronous revocation precedes every await in claim/transport/permission cleanup.
  for (const row of managedDownloads.values()) if (['page_response','profile_api_blob'].includes(row.route)
      && (!record || (row.page_binding || row.source_binding).claim_id === record.id) && !['complete','interrupted','gone'].includes(row.producer_state)) {
    retireUnusedPageObserver(row);
    row.cancel_requested = true; row.observation_state = reason;
    if (row.route === 'page_response' && (!row.response || row.response.continuation_state === 'not_attempted')) row.producer_state = 'gone';
    void managedCancel(row,'context_fence',cancelFenceReason(reason)).catch(() => { row.cleanup_state = 'unknown'; managedPublish(row); });
  }
}
async function pageObservationAck(row, messageType = 'managed_download_observation') {
  if (!port || !serverGeneration || pageObservationWaiters.size >= 32) throw fail('download_host_unavailable');
  const ackNonce = uuid(), currentPort = port;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pageObservationWaiters.delete(ackNonce); reject(fail('download_observation_timeout')); }, 500);
    pageObservationWaiters.set(ackNonce, { port: currentPort, timer, resolve, reject });
    try { sendNative(currentPort, { type: messageType, managed_download_version: 1,
      ack_nonce: ackNonce, download: managedPublic(row) }); }
    catch (error) { clearTimeout(timer); pageObservationWaiters.delete(ackNonce); reject(error); }
  });
}
function pageDownloadPauseCandidate(record, source, params) {
  if (source.sessionId || !record.durable) return null;
  return [...managedDownloads.values()].find(r => r.route === 'page_response' && r.observation_state === 'armed'
    && r.page_binding.claim_id === record.id && r.page_binding.frame_id === params.frameId
    && r.url === params.request?.url && r.method === params.request?.method);
}
async function handlePageDownloadPause(record, source, params) {
  const row = pageDownloadPauseCandidate(record, source, params);
  if (!row) return false;
  // Candidate lookup and this reservation have no intervening await, including
  // the handleBodyPause caller. Cancellation can never see armed after selection.
  // Consume synchronously: no second response can share this original intent.
  row.observation_state = 'response_observed';
  const capture = record.bodyCaptureSessions?.get('');
  if (!capture || !bodyCaptureOwned(capture)) { row.producer_state = 'unknown'; await managedSave(); return true; }
  const address = { targetId: capture.target };
  const initialTrace = { failed: null };
  // Fetch.requestPaused.networkId exists only when Network emitted a matching
  // event. The original Fetch ID still addresses this exact paused response.
  // Present malformed values never become omitted-property authority.
  const fetchOnly = !('networkId' in params);
  const validIdentity = responseDiagnosticMark(initialTrace, 'fetch_request_id_type', Object.hasOwn(params, 'requestId') && typeof params.requestId === 'string')
    && responseDiagnosticMark(initialTrace, 'fetch_request_id_empty', params.requestId.length > 0)
    && responseDiagnosticMark(initialTrace, 'fetch_request_id_length', params.requestId.length <= 256)
    && (fetchOnly || responseDiagnosticMark(initialTrace, 'network_request_id_type', Object.hasOwn(params, 'networkId') && typeof params.networkId === 'string')
    && responseDiagnosticMark(initialTrace, 'network_request_id_empty', params.networkId.length > 0)
    && responseDiagnosticMark(initialTrace, 'network_request_id_length', params.networkId.length <= 256));
  const parsed = safeAttachmentName(params.responseHeaders);
  const status = params.responseStatusCode;
  // Let generic body handling retain its original pause receipts while explicitly
  // excluding this response from raw body capture. It alone owns continuation.
  const phase = { binding: capture, fetchId: params.requestId, continuation: 'not_attempted', captureClosed: true,
    state: 'pending', phaseKey: capture.generation + ':' + params.requestId + ':'
      + (params.responseErrorReason ? 'error:' + params.responseErrorReason : 'response:' + status) };
  const networkRow = fetchOnly ? undefined : [...record.requests.values()].find(r => r.requestId === params.networkId && r.frameId === params.frameId && !r.sessionId);
  phase.row = networkRow;
  if (networkRow) { releaseBody(networkRow); networkRow.bodyGap = 'original_attachment_download'; }
  if (record.bodyPauses.size >= 32 || record.bodyPhaseHistory.size >= 256) {
    const oldest = [...record.bodyPhaseHistory.keys()].find(key => !record.bodyPauses.has(key));
    if (oldest !== undefined) record.bodyPhaseHistory.delete(oldest);
    else { row.observation_state = 'history_limit'; }
  }
  record.bodyPhaseHistory.set(phase.phaseKey, phase);
  record.bodyPauses.set(phase.phaseKey, phase);
  if (!recordBodyReceipt(record, phase)) { row.observation_state = 'history_limit'; }
  let rewrite = false, diagnosticPhase = 'initial_response_admission', currentTrace = initialTrace;
  try {
    if (validIdentity && responseDiagnosticMark(initialTrace, 'attachment_supported', parsed)
        && responseDiagnosticMark(initialTrace, 'document_resource_type', params.resourceType === 'Document')
        && responseDiagnosticMark(initialTrace, 'status_integer', Number.isInteger(status))
        && responseDiagnosticMark(initialTrace, 'status_minimum_200', status >= 200)
        && responseDiagnosticMark(initialTrace, 'status_maximum_299', status <= 299)
        && responseDiagnosticMark(initialTrace, 'history_capacity', row.observation_state !== 'history_limit') && pageDownloadCurrent(row, initialTrace)) {
      putResponseDiagnostic(row, 'admission_diagnostics', 4, diagnosticPhase, initialTrace, phase);
      diagnosticPhase = 'post_observation_ack';
      row.response = { fetch_request_id: params.requestId, network_request_id: fetchOnly ? null : params.networkId,
        frame_id: params.frameId, session_id: null, status_code: status, resource_type: 'Document', original_filename: parsed.name,
        page_guid: null, continuation_state: 'not_attempted', id_observed: false,
        ...(fetchOnly ? { request_binding: 'fetch_response_only_v1' } : {}) };
      row.token_filename = row.response_token + parsed.extension;
      await bodyWait(managedSave(), 400, null, 'download_storage_timeout');
      await pageObservationAck(row);
      currentTrace = { failed: null };
      rewrite = pageDownloadCurrent(row, currentTrace) && responseDiagnosticMark(currentTrace, 'capture_owned', bodyCaptureOwned(capture, currentTrace));
      putResponseDiagnostic(row, 'admission_diagnostics', 4, diagnosticPhase, currentTrace, phase);
    } else {
      row.observation_state = !parsed ? 'unsupported_content_disposition'
        : params.resourceType !== 'Document' ? 'unsupported_resource_type' : 'admission_ended';
      putResponseDiagnostic(row, 'admission_diagnostics', 4, diagnosticPhase, initialTrace, phase);
    }
  } catch (error) {
    putResponseDiagnostic(row, 'admission_diagnostics', 4, diagnosticPhase, currentTrace, phase, 'none', error);
    row.observation_state = error.code || 'download_observation_unknown'; row.producer_state = 'unknown';
  }
  const postAdmissionTrace = { failed: null };
  if (!bodyCaptureOwned(capture, postAdmissionTrace)) {
    putResponseDiagnostic(row, 'admission_diagnostics', 4, 'final_capture_ownership', postAdmissionTrace, phase);
    row.producer_state = 'unknown'; await managedSave(); managedPublish(row); return true;
  }
  if (rewrite) {
    row.producer_state = 'attempted'; row.response.continuation_state = 'attempted';
    // This attempted phase is durable on both sides before invocation. A stale
    // ACK cannot cross the final synchronous admission fence.
    try { await bodyWait(managedSave(), 400, null, 'download_storage_timeout'); await pageObservationAck(row); }
    catch (error) {
      putResponseDiagnostic(row, 'admission_diagnostics', 4, 'post_attempt_ack', null, phase, 'none', error);
      rewrite = false; row.producer_state = 'unknown';
    }
    const finalTrace = { failed: null };
    rewrite = rewrite && pageDownloadCurrent(row, finalTrace) && responseDiagnosticMark(finalTrace, 'capture_owned', bodyCaptureOwned(capture, finalTrace));
    if (rewrite || finalTrace.failed !== null)
      putResponseDiagnostic(row, 'admission_diagnostics', 4, 'post_attempt_ack', finalTrace, phase);
  }
  const ownershipTrace = { failed: null };
  if (!bodyCaptureOwned(capture, ownershipTrace)) {
    putResponseDiagnostic(row, 'admission_diagnostics', 4, 'final_capture_ownership', ownershipTrace, phase);
    row.producer_state = 'unknown'; await managedSave(); managedPublish(row); return true;
  }
  const command = { requestId: params.requestId };
  if (rewrite) {
    command.responseCode = status;
    if (typeof params.responseStatusText === 'string') command.responsePhrase = params.responseStatusText;
    command.responseHeaders = params.responseHeaders.map(header => header.name.toLowerCase() === 'content-disposition'
      ? { ...header, value: 'attachment; filename="' + row.token_filename + '"' } : { ...header });
  } else if (row.response) row.response.continuation_state = 'unmodified';
  phase.continuation = 'attempted'; publishBodyReceipt(phase);
  // No await between final fence, header construction and original invocation.
  try {
    await bodyWait(chrome.debugger.sendCommand(address, params.responseErrorReason ? 'Fetch.continueRequest' : 'Fetch.continueResponse', command),
      500, null, 'download_continue_timeout');
    phase.continuation = 'acknowledged'; phase.state = 'completed'; phase.cleanup = 'continued';
    if (rewrite) { row.response.continuation_state = 'acknowledged'; row.observation_state = 'awaiting_download'; }
    else { row.producer_state = 'gone'; }
  } catch (error) {
    putResponseDiagnostic(record, 'response_capture_diagnostics', 32, 'continuation_wait', null, phase,
      params.responseErrorReason ? 'continue_request' : 'continue_response', error);
    phase.continuation = 'unverified'; row.producer_state = 'unknown';
    if (rewrite) row.response.continuation_state = 'unknown';
    bodyRecovery(record, phase, 'response_continuation_unverified');
  }
  publishBodyReceipt(phase);
  if (phase.cleanup) record.bodyPauses.delete(phase.phaseKey);
  await managedSave(); managedPublish(row);
  return true;
}
function pageAmbiguity(row) {
  if (row.route !== 'page_response') return null;
  return row.ambiguity_reason || (/^ambiguous_/.test(row.observation_state || '') ? row.observation_state : null);
}
function preservePageAmbiguity(row, reason) {
  const barrier = pageAmbiguity(row) || reason;
  if (!barrier) return;
  // Once recorded, this original cannot regain publication/admission authority.
  row.ambiguity_reason = barrier; row.observation_state = barrier; row.cancel_requested = true;
}
function persistPageAmbiguity(row) {
  managedPublish(row);
  if (row.browser_download_id != null) void managedCancel(row,'ambiguity','ambiguity_barrier').catch(() => {});
  else void managedPersistReceipt(row).then(() => managedPublish(row));
}
function pageDownloadEvent(source, params) {
  const matches = [...managedDownloads.values()].filter(row => row.route === 'page_response' && row.worker_generation === workerGeneration
    && row.response && ['attempted','acknowledged','unknown'].includes(row.response.continuation_state)
    && !source.sessionId && (source.targetId === row.page_binding.browser_target_id || source.tabId === row.page_binding.tab_id)
    && params.frameId === row.page_binding.frame_id && params.suggestedFilename === row.token_filename);
  if (matches.length !== 1 || typeof params.guid !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(params.guid)) return;
  const row = matches[0];
  if (pageAmbiguity(row)) { preservePageAmbiguity(row); persistPageAmbiguity(row); return; }
  if (row.response.page_guid && row.response.page_guid !== params.guid
      || [...managedDownloads.values()].some(other => other !== row && other.response?.page_guid === params.guid)) {
    row.producer_state = 'unknown'; preservePageAmbiguity(row, 'ambiguous_page_guid');
  } else {
    row.response.page_guid = params.guid;
    if (!pageDownloadCurrent(row)) row.cancel_requested = true;
  }
  managedPublish(row);
  if (row.cancel_requested && row.browser_download_id != null) void managedCancel(row,'page_event','cancel_already_requested').catch(() => {});
  else void managedPersistReceipt(row).then(() => managedPublish(row));
}
function suggestManagedApiFilename(item, suggest) {
  const original = () => [...managedDownloads.values()].find(row => row.route !== 'page_response'
    && row.browser_download_id === item.id && row.context_kind === (item.incognito ? 'private' : 'ordinary')
    && row.context_kind === contextKind() && row.profile_id === profileId && row.context_id === contextId && row.installation_id === installationId);
  const apply = () => {
    const row = original();
    if (row?.relative_filename && !row.cancel_requested) suggest({ filename: row.relative_filename });
    else suggest();
  };
  if (original()) { apply(); return; }
  const pending = [...managedDownloads.values()].filter(row => row.route !== 'page_response'
    && row.browser_download_id == null && row.operation).map(row => row.operation);
  if (!pending.length) { suggest(); return; }
  // Native returned-ID ownership alone grants naming authority. This waits for
  // originals already issued by our API, never joins URL/time or invokes again.
  const ready = new Promise(resolve => {
    const check = () => { if (original()) resolve(); };
    // Each original can establish its own returned ID independently. An
    // unrelated stalled SDK promise must not delay an already-known owner.
    for (const operation of pending) void Promise.resolve(operation).then(check, check);
    check();
  });
  void bodyWait(ready,500,null,'download_filename_id_timeout').then(apply,() => suggest());
  return true;
}
function pageDetermineFilename(item, suggest) {
  if (item.byExtensionId === chrome.runtime.id && Number.isInteger(item.id) && item.id >= 0 && item.id <= 2147483647
      && typeof item.incognito === 'boolean') return suggestManagedApiFilename(item, suggest);
  const basename = item.filename?.split(/[\\/]/).pop();
  const matches = [...managedDownloads.values()].filter(row => row.route === 'page_response' && row.worker_generation === workerGeneration
    && row.response && ['attempted','acknowledged','unknown'].includes(row.response.continuation_state)
    && row.context_kind === contextKind() && row.profile_id === profileId && row.context_id === contextId
    && row.token_filename === basename && typeof item.incognito === 'boolean'
    && item.incognito === (row.context_kind === 'private') && item.url === row.url);
  if (matches.length !== 1 || !Number.isInteger(item.id) || item.id < 0 || item.id > 2147483647) { suggest(); return; }
  const row = matches[0];
  if (pageAmbiguity(row)) { preservePageAmbiguity(row); suggest(); persistPageAmbiguity(row); return; }
  if (row.browser_download_id != null && row.browser_download_id !== item.id
      || [...managedDownloads.values()].some(other => other !== row && other.browser_download_id === item.id)) {
    preservePageAmbiguity(row, 'ambiguous_download_id'); row.producer_state = 'unknown'; suggest();
    persistPageAmbiguity(row); return;
  }
  // Exact opaque filename establishes this observed ID even if Page GUID is
  // delivered later. Capture still requires both; cancellation need not wait.
  const current = pageDownloadCurrent(row);
  if (!current) row.cancel_requested = true;
  row.browser_download_id = item.id; row.response.id_observed = true; row.private = item.incognito;
  row.producer_state = 'in_progress'; row.observation_state = 'id_observed';
  const name = row.response.original_filename;
  // Preserve native default collision policy: no conflictAction override.
  suggest({ filename: name });
  row.download_persistence = 'unknown'; managedPublish(row);
  void (async () => {
    if (row.cancel_requested) await managedCancel(row,'filename_event','cancel_already_requested');
    else { await managedPersistReceipt(row); if (row.cancel_requested) await managedCancel(row,'filename_event','cancel_already_requested'); else await managedRefresh(row); }
  })().catch(() => { row.cleanup_state = 'unknown'; managedPublish(row); });
}

function validPageHistory(row) {
  normalizeCancelEvidence(row);
  if (row.admission_diagnostics) {
    row.admission_diagnostics = responseDiagnosticProjection(row.admission_diagnostics, 4);
    if (JSON.stringify(row).length > 32768) delete row.admission_diagnostics;
  }
  const b = row.page_binding;
  const keys = ['claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id',
    'target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind',
    'connection_generation','frame_id','loader_id','document_epoch','origin','worker_generation','trust_id'];
  if (!b || typeof b !== 'object' || Object.keys(b).length !== keys.length || keys.some(k => !(k in b))
      || keys.filter(k => !['claim_epoch','tab_id','document_epoch'].includes(k)).some(k => typeof b[k] !== 'string' || !b[k].length || b[k].length > 256)
      || !Number.isSafeInteger(b.claim_epoch) || b.claim_epoch < 1 || !Number.isSafeInteger(b.document_epoch) || b.document_epoch < 1
      || !Number.isInteger(b.tab_id) || b.tab_id < 0 || !['ordinary','private'].includes(row.context_kind) || b.context_kind !== row.context_kind
      || ['owner_session','installation_id','runtime_generation','profile_id','context_id'].some(k => b[k] !== row[k])
      || !['GET','POST'].includes(row.method) || typeof row.url !== 'string' || encoder.encode(row.url).length > 8192
      || !/^workbench-owned-[0-9a-f]{32}$/.test(row.response_token) || row.worker_generation !== b.worker_generation
      || !Number.isFinite(row.expires_at) || row.expires_at <= 0 || row.expires_at >= 1e12
      || row.ambiguity_reason != null && !['ambiguous_page_guid','ambiguous_download_id'].includes(row.ambiguity_reason)
      || JSON.stringify(row).length > 32768) return false;
  try { webOrigin(row.url); } catch { return false; }
  if (row.observer_retirement_worker_generation !== undefined && (row.observer_retirement !== 'cancelled_before_worker_restart'
      || !/^[0-9a-f]{32}$/.test(row.observer_retirement_worker_generation)
      || row.observer_retirement_worker_generation === row.worker_generation)) return false;
  if (row.observer_retirement === 'cancelled_before_worker_restart' && row.observer_retirement_worker_generation === undefined) return false;
  if (row.observer_retirement !== undefined && (!['cancelled_while_armed','cancelled_before_worker_restart'].includes(row.observer_retirement)
      || row.cancel_requested !== true || row.producer_state !== 'gone' || row.response != null
      || row.token_filename != null || row.browser_download_id != null || pageAmbiguity(row)
      || row.observation_state !== 'cancelled_before_response')) return false;
  const r = row.response;
  if (!r) return row.browser_download_id == null;
  const fetchOnly = r?.request_binding === 'fetch_response_only_v1';
  const responseKeys = ['fetch_request_id','network_request_id','frame_id','session_id','status_code','resource_type','original_filename','page_guid','continuation_state','id_observed',
    ...(fetchOnly ? ['request_binding'] : [])];
  const name = safeAttachmentName([{name:'Content-Disposition',value:"attachment; filename*=UTF-8''" + encodeURIComponent(r.original_filename || '').replace(/'/g, '%27')}]);
  return typeof r === 'object' && Object.keys(r).length === responseKeys.length && responseKeys.every(k => k in r)
    && ['fetch_request_id','frame_id'].every(k => typeof r[k] === 'string' && r[k].length > 0 && r[k].length <= 256)
    && (fetchOnly ? r.network_request_id === null : typeof r.network_request_id === 'string' && r.network_request_id.length > 0 && r.network_request_id.length <= 256)
    && r.frame_id === b.frame_id && r.session_id === null && Number.isInteger(r.status_code) && r.status_code >= 200 && r.status_code <= 299
    && r.resource_type === 'Document' && name?.name === r.original_filename && row.token_filename === row.response_token + name.extension
    && (r.page_guid === null || typeof r.page_guid === 'string' && /^[0-9a-fA-F-]{36}$/.test(r.page_guid))
    && ['not_attempted','attempted','acknowledged','unknown','unmodified'].includes(r.continuation_state)
    && typeof r.id_observed === 'boolean' && (row.browser_download_id == null || r.id_observed && ['attempted','acknowledged','unknown'].includes(r.continuation_state));
}
function pageArmRecord(packet, cleanupOnly = false) {
  const b = packet.page_binding;
  if (!b || typeof b !== 'object') throw fail('invalid_download_arm');
  const row = { download_id: packet.download_id, owner_session: packet.owner_session,
    installation_id: installationId, profile_id: profileId, context_id: contextId, context_kind: contextKind(),
    runtime_generation: cleanupOnly ? b.runtime_generation : serverGeneration, worker_generation: cleanupOnly ? b.worker_generation : workerGeneration, nonce: packet.nonce,
    original_request_id: packet.original_request_id, relative_filename: 'LocalWorkbench/' + packet.download_id + '.download',
    route: 'page_response', page_binding: b, response_token: packet.response_token, url: packet.url, method: packet.method,
    expires_at: packet.expires_at, source_root: packet.source_root, observation_state: 'armed',
    producer_state: 'intent', browser_download_id: null, filename: null, private: contextKind() === 'private',
    bytes_received: 0, file_size: -1, total_bytes: -1, cancel_requested: false,
    ...(!cleanupOnly?{producer_cancel_evidence:newProducerCancelEvidence(packet.download_id)}:{}) };
  if (!validPageHistory(row) || packet.route !== 'page_response' || !cleanupOnly && (b.worker_generation !== workerGeneration
      || row.expires_at * 1000 > Date.now() + 31000) || !b.trust_id || !row.source_root
      || typeof row.source_root.workspace !== 'string' || !Number.isSafeInteger(row.source_root.dev)
      || !Number.isSafeInteger(row.source_root.inode)) throw fail('invalid_download_arm');
  return row;
}
function safeBlobFilename(name) {
  return typeof name === 'string' && encoder.encode(name).length > 0 && encoder.encode(name).length <= 240
    && name.trim() === name && !/^\.|[.]$/.test(name) && !/[\/\\<>:"|?*\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(name)
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name);
}
// Isolated-world read of the same observed, actionable HTML anchor. No click,
// Blob body read, URL creation or creator attribution occurs here.
function blobAnchorDescriptor(observationId, targetId, expectedOrigin) {
  const checked = targetInfo(observationId, targetId);
  if (checked.error) return checked;
  if (checked.sensitive) return { error: 'local_sensitive_input_required' };
  const item = __workbenchObservation.targets.get(targetId), el = item.element;
  if (el.tagName !== 'A' || el.namespaceURI !== 'http://www.w3.org/1999/xhtml' || !item.anchorSource)
    return { error: 'blob_anchor_required' };
  const href = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href').get.call(el);
  const download = el.getAttribute('download');
  if (href !== item.anchorSource.href || download !== item.anchorSource.download)
    return { error: 'target_changed' };
  let source;
  try { source = new URL(href); } catch { return { error: 'invalid_blob_source' }; }
  if (location.origin !== expectedOrigin || source.protocol !== 'blob:' || source.origin !== expectedOrigin
      || !/^https?:\/\//.test(source.origin) || new TextEncoder().encode(href).length > 8192)
    return { error: 'blob_origin_mismatch' };
  return { href, download_attribute: download };
}
function blobDownloadCurrent(row) {
  const b = row.source_binding, record = claims.get(b?.claim_id);
  return row.route === 'profile_api_blob' && !row.cancel_requested && row.worker_generation === workerGeneration
    && row.runtime_generation === serverGeneration && row.installation_id === installationId
    && row.profile_id === profileId && row.context_id === contextId && contextKind() === 'ordinary'
    && trust?.enabled && trust.control && trust.file_download && trust.trust_id === b.trust_id && peerId === b.peer_id
    && record?.durable && record.debuggerAttached === true && !record.releasing && publicInputEligible(record)
    && Date.now() < record.expires && ownsTarget(record) && !stoppedTargets.has(record.target.target_id)
    && record.owner_session === row.owner_session && record.claim_epoch === b.claim_epoch
    && record.target.target_generation === b.target_generation && record.target.browser_target_id === b.browser_target_id
    && record.mainFrameId === b.frame_id && record.loaderId === b.loader_id && record.generation === b.document_epoch
    && record.origin === b.origin && record.control;
}
function validBlobHistory(row) {
  normalizeCancelEvidence(row);
  const b = row.source_binding;
  const keys = ['claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id','target_id','target_generation',
    'browser_target_id','tab_id','profile_id','context_id','context_kind','connection_generation','frame_id','loader_id','document_epoch','origin','worker_generation','trust_id'];
  const root = row.source_root;
  if (!b || Object.keys(b).length !== keys.length || keys.some(k => !(k in b))
      || keys.filter(k => !['claim_epoch','tab_id','document_epoch'].includes(k)).some(k => typeof b[k] !== 'string' || !b[k].length || b[k].length > 256)
      || ['claim_epoch','document_epoch'].some(k => !Number.isSafeInteger(b[k]) || b[k] < 1)
      || !Number.isInteger(b.tab_id) || b.tab_id < 0 || b.context_kind !== 'ordinary' || row.context_kind !== 'ordinary'
      || ['owner_session','installation_id','runtime_generation','profile_id','context_id'].some(k => b[k] !== row[k])
      || row.worker_generation !== b.worker_generation || !/^[0-9a-f]{32}$/.test(row.observation_id) || !/^[0-9a-f]{32}$/.test(row.target_id)
      || row.intended_filename != null && !safeBlobFilename(row.intended_filename)
      || !root || Object.keys(root).sort().join(',') !== 'dev,inode,workspace' || typeof root.workspace !== 'string' || !root.workspace.length || root.workspace.length > 128
      || ['dev','inode'].some(k => !Number.isSafeInteger(root[k]) || root[k] < 0) || JSON.stringify(row).length > 32768) return false;
  const s = row.blob_source;
  if (!s) return row.relative_filename === null && row.browser_download_id == null && row.url == null;
  const sourceKeys = ['observation_id','target_id','frame_id','loader_id','document_generation','execution_context_unique_id','backend_node_id','href','download_attribute','filename'];
  let source; try { source = new URL(s.href); } catch { return false; }
  return Object.keys(s).length === sourceKeys.length && sourceKeys.every(k => k in s)
    && ['observation_id','target_id'].every(k => s[k] === row[k]) && ['frame_id','loader_id'].every(k => s[k] === b[k])
    && s.document_generation === b.document_epoch && Number.isSafeInteger(s.backend_node_id) && s.backend_node_id > 0
    && typeof s.execution_context_unique_id === 'string' && s.execution_context_unique_id.length > 0 && s.execution_context_unique_id.length <= 256
    && source.protocol === 'blob:' && source.origin === b.origin && /^https?:\/\//.test(source.origin) && encoder.encode(s.href).length <= 8192
    && (s.download_attribute === null || typeof s.download_attribute === 'string') && safeBlobFilename(s.filename)
    && (s.download_attribute || row.intended_filename) === s.filename && row.url === s.href
    && row.relative_filename === 'LocalWorkbench/' + row.download_id + '/' + s.filename;
}
async function startBlobDownload(packet) {
  const b = packet.source_binding;
  const row = { download_id:packet.download_id,owner_session:packet.owner_session,installation_id:installationId,
    profile_id:profileId,context_id:contextId,context_kind:contextKind(),runtime_generation:serverGeneration,worker_generation:workerGeneration,
    nonce:packet.nonce,original_request_id:packet.original_request_id,route:'profile_api_blob',source_binding:b,
    observation_id:packet.observation_id,target_id:packet.target_id,intended_filename:packet.intended_filename,
    source_root:packet.source_root,blob_source:null,relative_filename:null,url:null,
    producer_state:'intent',browser_download_id:null,filename:null,private:false,bytes_received:0,file_size:-1,total_bytes:-1,cancel_requested:false,producer_cancel_evidence:newProducerCancelEvidence(packet.download_id) };
  if (packet.blob_download_version !== 1 || packet.route !== 'profile_api_blob' || !validBlobHistory(row) || !blobDownloadCurrent(row))
    throw fail('invalid_blob_source');
  if ([...managedDownloads.values()].filter(r=>!['complete','interrupted','gone'].includes(r.producer_state)).length >= 32 || managedDownloads.size >= 1000)
    throw fail('download_resource_limit');
  const record = claims.get(b.claim_id), observation = record.observations.get(row.observation_id);
  const deadline = performance.now() + 8000, group = 'workbench-blob-' + row.download_id;
  let closed = false, attempted = false;
  const current = () => {
    if (closed || performance.now() >= deadline || !blobDownloadCurrent(row)) throw fail('download_claim_changed');
    if (!observation || record.observations.get(row.observation_id) !== observation || observation.generation !== record.generation
        || observation.frame.parent_id || observation.frame.session_id || observation.frame.frame_id !== b.frame_id
        || observation.frame.loader_id !== b.loader_id || observation.contextUniqueId !== record.contextUniqueIds.get(':' + observation.contextId))
      throw fail('stale_observation');
  };
  const bounded = async work => {
    current(); const result = await bodyWait(Promise.resolve().then(work), Math.max(1,Math.min(1200,deadline-performance.now())),null,'blob_source_timeout');
    current(); return result;
  };
  const readSource = async () => {
    current();
    if (!await bounded(()=>ownsActualTarget(record,current))) throw fail('download_claim_changed');
    const selected = await bounded(()=>live(record,b.document_epoch,b.origin,b.frame_id,current));
    if (['frame_id','loader_id','session_id'].some(k=>selected.frame[k] !== observation.frame[k])) throw fail('stale_browser_frame');
    const expression = '(()=>{const targetInfo=' + targetInfo.toString() + ';return (' + blobAnchorDescriptor.toString() + ')('
      + JSON.stringify(row.observation_id) + ',' + JSON.stringify(row.target_id) + ',' + JSON.stringify(b.origin) + ');})()';
    const source = await bounded(()=>value(record,expression,observation.contextId));
    if (source?.error) throw fail(source.error);
    if (!source || !source.href || source.download_attribute !== null && typeof source.download_attribute !== 'string') throw fail('invalid_blob_source');
    const filename = source.download_attribute || row.intended_filename;
    if (!safeBlobFilename(filename) || source.download_attribute && row.intended_filename && row.intended_filename !== filename) throw fail('invalid_blob_filename');
    return { ...source, filename };
  };
  managedDownloads.set(row.download_id,row);
  try {
    current(); await bounded(()=>managedSave());
    const source = await readSource();
    const remote = await bounded(()=>cdp(record,'Runtime.evaluate',{expression:'__workbenchObservation.targets.get('+JSON.stringify(row.target_id)+').element',
      contextId:observation.contextId,objectGroup:group}));
    if (remote.exceptionDetails || !remote.result?.objectId) throw fail('blob_anchor_required');
    const node = await bounded(()=>cdp(record,'DOM.describeNode',{objectId:remote.result.objectId}));
    if (node.node?.nodeName !== 'A' || !Number.isSafeInteger(node.node.backendNodeId) || node.node.backendNodeId < 1) throw fail('blob_anchor_required');
    row.blob_source = { observation_id:row.observation_id,target_id:row.target_id,frame_id:b.frame_id,loader_id:b.loader_id,
      document_generation:b.document_epoch,execution_context_unique_id:observation.contextUniqueId,backend_node_id:node.node.backendNodeId,
      href:source.href,download_attribute:source.download_attribute,filename:source.filename };
    row.url = source.href; row.relative_filename = 'LocalWorkbench/' + row.download_id + '/' + source.filename;
    if (!validBlobHistory(row)) throw fail('invalid_blob_source');
    await bounded(()=>managedSave()); await bounded(()=>pageObservationAck(row,'managed_download_blob_admission'));
    row.producer_state = 'attempted'; await bounded(()=>managedSave());
    await bounded(()=>pageObservationAck(row,'managed_download_blob_admission'));
    const final = await readSource();
    if (JSON.stringify(final) !== JSON.stringify(source)) throw fail('target_changed');
    // The precise original descriptor is durable in extension and host. No await
    // separates this final lifetime check from the original native invocation.
    current(); attempted = true;
    row.operation = chrome.downloads.download({url:row.url,filename:row.relative_filename,conflictAction:'uniquify',saveAs:false});
    const id = await row.operation;
    if (!Number.isInteger(id) || id < 0 || id > 2147483647) throw fail('download_id_unverified');
    row.browser_download_id = id; row.by_extension_id = chrome.runtime.id; row.producer_state = 'in_progress';
    row.download_persistence = 'unknown'; managedPublish(row);
    if (!blobDownloadCurrent(row)) await managedCancel(row,'blob_start','blob_current_ended');
    else {
      await managedPersistReceipt(row);
      if (!blobDownloadCurrent(row)) await managedCancel(row,'blob_start','blob_current_ended'); else await managedRefresh(row);
    }
  } catch (error) {
    if (row.browser_download_id == null) row.producer_state = attempted ? 'unknown' : 'gone';
    await managedPersistReceipt(row); managedPublish(row);
    throw fail(error.code || 'download_start_unverified', attempted ? 'unknown' : 'none');
  } finally {
    closed = true;
    // Releasing this helper group neither repeats a Blob nor grants new input.
    try { await bodyWait(cdp(record,'Runtime.releaseObjectGroup',{objectGroup:group}),500,null,'blob_group_cleanup_timeout'); } catch {}
  }
  return row;
}

// Available only to this extension's service-worker developer context; web
// pages have no external-message receiver or content-script bridge.
globalThis.WorkbenchSelectedTabs = { grantLocal, detach, leases, claims, targets, localSetup, executeDurable, ensureConnection, workerGeneration, managedOperation };
setInterval(() => { if (port && serverGeneration) sendNative(port, { type: 'heartbeat' }); }, 10000);
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'workbench:reconnect') void ensureConnection().catch(() => {}); });
// Durable setup may reconnect autonomously; it never upgrades an old tab grant.
void (async () => {
  // Attempt zero is bootstrap only; no ensureConnection attempt exists yet.
  const receipt = connectionPhaseReporter(0);
  receipt('bootstrap_trust_storage_read');
  const saved = await chrome.storage?.local?.get('workbenchTrust:' + contextKind());
  if (!saved?.['workbenchTrust:' + contextKind()]?.enabled) return;
  receipt('bootstrap_alarm');
  await chrome.alarms.create('workbench:reconnect', { periodInMinutes: 1 });
  await ensureConnection();
})().catch(() => {});

// Opt-in passive diagnostics: no Fetch interception, input, logical focus or replay.
function diagnosticProjectChat(value) {
  try { const u=new URL(value);
    if(u.origin!=='https://chatgpt.com'||u.username||u.password||u.search||u.hash||value!==u.origin+u.pathname)return null;
    const match=/^\/g\/g-p-[a-f0-9]{32}(?:-[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?)?\/c\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\/?$/i.exec(u.pathname);
    return match?{chat_url:'https://chatgpt.com/c/'+match[1].toLowerCase(),observed_url:u.origin+u.pathname}:null;
  }catch{return null;}
}
function diagnosticChat(value) {
  try { const u = new URL(value); return u.protocol === 'https:' && u.host === 'chatgpt.com'
    && !u.username && !u.password && !u.search && !u.hash && (u.pathname === '/' || /^\/c\/[a-f0-9-]{36}\/?$/i.test(u.pathname))
    ? u.origin + (u.pathname === '/' ? '/' : u.pathname.replace(/\/$/, '')) : diagnosticProjectChat(value)?.chat_url || null; } catch { return null; }
}
function diagnosticRedact(value, depth = 0) {
  if (depth > 20) return '[depth limit]';
  if (Array.isArray(value)) return value.map(v => diagnosticRedact(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) =>
    [k, /^token$|authorization|cookie|password|secret|access.?token|refresh.?token|id.?token|api.?key|csrf|credential|session.?token|headers$/i.test(k)
      ? '[redacted]' : diagnosticRedact(v, depth + 1)]));
  if (typeof value === 'string' && /^\s*[\[{]/.test(value)) {
    // Public tool-result strings can themselves be JSON. Redact their values
    // before URL normalization can consume an escaped quote boundary.
    let nested;
    try { nested = JSON.parse(value); } catch { /* Keep the text fallback. */ }
    if (nested && typeof nested === 'object') return JSON.stringify(diagnosticRedact(nested, depth + 1));
  }
  return typeof value === 'string' ? value.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]').replace(/https?:\/\/[^\s<>"']+/gi, diagnosticURL) : value;
}
function diagnosticURL(value) {
  try { const u = new URL(value); for (const key of [...u.searchParams.keys()])
    if (/^(?:sig|googleaccessid|policy)$|token|key|auth|secret|password|cookie|signature|credential|csrf/i.test(key)) u.searchParams.set(key, '[redacted]');
    u.username = ''; u.password = ''; u.hash = ''; return u.href; } catch { return '[invalid URL]'; }
}
function diagnosticWakeCredit(record, available) {
  for(const waiter of record.diagnostics?.creditWaiters || [])waiter.finish(available);
}
function diagnosticWaitCredit(record, request, deadline) {
  const d=record.diagnostics;
  if(!diagnosticBodyCurrent(record,request))return Promise.resolve(false);
  if(d.creditWaiters.size>=2){diagnosticEnd(record,'native_transport_credit_wait_limit');return Promise.resolve(false);}
  const remaining=deadline-performance.now();if(remaining<=0)return Promise.resolve(false);
  return new Promise(resolve=>{
    let timer,done=false;
    const waiter={request,finish:available=>{if(done)return;done=true;clearTimeout(timer);d.creditWaiters.delete(waiter);resolve(available);}};
    d.creditWaiters.add(waiter);timer=setTimeout(()=>waiter.finish(false),remaining);
  });
}
async function diagnosticEmitBody(record, request, data) {
  const d=record.diagnostics,deadline=performance.now()+5000;
  // Keep the existing2MiB/4096-frame hard cap. Bodies cooperate at1MiB,
  // reserving one maximum frame and metadata headroom; no packet queue/copy.
  while(diagnosticBodyCurrent(record,request)){
    if(d.unackedBytes+120000<=1048576&&d.unacked.size<2048)return diagnosticEmit(record,data);
    const available=await diagnosticWaitCredit(record,request,deadline);
    if(!available){if(diagnosticBodyCurrent(record,request))diagnosticEnd(record,'native_transport_credit_timeout');return false;}
  }
  return false;
}
function diagnosticEmit(record, data) {
  const d = record.diagnostics;
  if (!d?.active || record.peerId !== peerId || record.state !== 'active') return false;
  if(!diagnosticScopeCurrent(record)){diagnosticEnd(record,'scope_binding_changed');return false;}
  const event = diagnosticRedact({ ...data, sequence: ++d.sequence, at: Date.now()/1000,
    document: data.document || diagnosticScopeDocument(record), linkage: 'observed_opted_in_tab_flow_not_proven_chat_causality' });
  const packet = { type: 'browser_diagnostic_event', record_id: d.id, owner_session: record.owner_session,
    claim_id: record.id, event };
  if (encoder.encode(JSON.stringify(packet)).length > 120000) {
    return diagnosticEmit(record, { kind: 'gap', reason: 'event_frame_limit', original_kind: data.kind });
  }
  if (d.maxBytes != null && d.bytes + encoder.encode(JSON.stringify(packet)).length > d.maxBytes - 4096) {
    diagnosticEmitFinal(record, 'worker_byte_limit'); return false;
  }
  const size=encoder.encode(JSON.stringify(packet)).length;
  if(d.unackedBytes+size>2097152 || d.unacked.size>=4096){diagnosticEmitFinal(record,'native_transport_backpressure');return false;}
  d.bytes+=size;d.unacked.set(event.sequence,size);d.unackedBytes+=size;
  if(!sendNative(port,packet)){diagnosticEnd(record,'native_transport_unavailable');return false;}return true;
}
function diagnosticEmitFinal(record, reason) {
  const d = record.diagnostics; if (!d?.active) return;
  sendNative(port, { type:'browser_diagnostic_event', record_id:d.id, owner_session:record.owner_session, claim_id:record.id,
    event:{ sequence:++d.sequence,at:Date.now()/1000,kind:'gap',reason,capture_ended:true,
      scope_stage:d.scopeStage,observed_url:d.observedURL,canonical_confirmed:d.scopeStage==='canonical',
      document_revalidation_pending:!!d.reload,pending_stream_count:d.streams?.size || 0,retained_stream_prefix_bytes:[...(d.streams || [])].reduce((n,s)=>n+s.used,0),
      pending_request_count:d.requests.size,pending_body_count:(d.pendingBodies || 0)+(d.bodyQueue?.length || 0) } });
  diagnosticWakeCredit(record,false);
  for(const stream of d.streams || []){stream.closed=true;stream.buffer=null;}d.streams?.clear();
  if(d.reload)clearTimeout(d.reload.timer);d.reload=null;
  d.active = false; d.requests.clear(); d.assets?.clear(); if(d.bodyQueue)d.bodyQueue.length=0;
}
function diagnosticEnd(record, reason) { if (record.diagnostics?.active) diagnosticEmitFinal(record, reason); }
async function diagnosticDigest(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function diagnosticBodyCurrent(record, request) {
  const d=record.diagnostics;
  return !!d?.active&&!d.reload&&!request.bodyIdentityRetired&&(request.captureEpoch || 0)===(d.captureEpoch || 0)&&diagnosticScopeCurrent(record);
}
async function diagnosticBody(record, request, direction, body, encoded = false) {
  const d = record.diagnostics; if (!diagnosticBodyCurrent(record,request)) return;
  // Binary/HTML are never retained as text. Digests describe returned CDP bytes.
  if (encoded) { diagnosticEmit(record,{kind:'body_gap',request_id:request.id,direction,reason:'base64_or_binary_body'}); return; }
  const raw = request.streamRawBytes || encoder.encode(body), sha = await diagnosticDigest(raw);
  if (!diagnosticBodyCurrent(record,request)) return;
  const html = /html/i.test(request.mime || '');
  if (d.bodyBytes != null && raw.length > d.bodyBytes || html) {
    diagnosticEmit(record,{kind:'body_gap',request_id:request.id,direction,reason:html?'html_metadata_only':'body_byte_limit',raw_bytes:raw.length,raw_sha256:sha}); return;
  }
  let value; try { value = JSON.stringify(diagnosticRedact(JSON.parse(body))); }
  catch { value = request.streamEvidence ? diagnosticStreamVariant(body,request.streamEvidence) : body.split('\n').map(line => {
    const prefix=line.startsWith('data:')?'data:':'';
    try { return prefix+JSON.stringify(diagnosticRedact(JSON.parse(prefix?line.slice(5):line))); }
    catch { return diagnosticRedact(line).replace(/((?:token|access_token|refresh_token|id_token|api_key|password|secret|authorization|cookie)[\"']?\s*[=:]\s*)[\"']?[^\s,;\"']+[\"']?/gi,'$1[redacted]'); }
  }).join('\n'); }
  const bytes = encoder.encode(value), bodyId = uuid(), chunks = Math.ceil(bytes.length/16384);
  const variantDigest=await diagnosticDigest(bytes);
  if(!diagnosticBodyCurrent(record,request))return;
  if(!await diagnosticEmitBody(record,request,{kind:'body_begin',body_id:bodyId,request_id:request.id,direction,document:request.document,raw_digest_scope:request.streamEvidence?.body_coverage==='observed_stream_prefix'?'cdp_observed_stream_prefix_bytes_not_http_wire_bytes':'cdp_decoded_utf8_not_http_wire_bytes',...(request.streamEvidence || {}),method:request.method,url:request.url,redirect_hop:request.hop,frame_id:request.frame_id,loader_id:request.loader_id,raw_sha256:sha,raw_bytes:raw.length,
    variant_sha256:variantDigest,variant_bytes:bytes.length,chunks,representation:'credential_redacted_utf8',original_request_outcome:request.outcome || 'request_observed'}))return;
  for (let i=0; i<chunks && diagnosticBodyCurrent(record,request); i++) {
    // UTF-8 bytes, not JavaScript character slices; native frame stays bounded.
    const part=bytes.slice(i*16384,(i+1)*16384); let binary=''; for (const b of part) binary+=String.fromCharCode(b);
    if(!await diagnosticEmitBody(record,request,{kind:'body_chunk',body_id:bodyId,index:i,data:btoa(binary)}))return;
    if(i%16===15)await new Promise(resolve=>setTimeout(resolve,0));
  }
  if(diagnosticBodyCurrent(record,request))await diagnosticEmitBody(record,request,{kind:'body_end',body_id:bodyId,request_id:request.id});
}
// Fixed, bounded public-DOM sampler. No form values, hidden stores or arbitrary evaluation.
const DIAGNOSTIC_DOM = `(()=>{
 const started=performance.now();
 const coverage={partial:true,basis:'rendered_public_dom_not_occlusion_or_viewport',nodes:0,
  node_limit:3000,depth_limit:64,time_limit_ms:150,text_byte_limit:32768,text_bytes:0,source_text_character_limit:16384,
  item_text_byte_limits:{rendered_text:12288,status:1024,region:2048,metadata:256},semantic_limits:{messages:200,statuses:20,regions:8},
  byte_counts:'sampled_before_credential_filter',
  root_basis:'body',text_order:'semantic_status_priority_then_document',priority_status_nodes:0,
  node_counts:'checks_including_repeated_priority_ancestors',
  truncated:false,hidden_subtrees:0,protected_subtrees:0,semantic_limit_reached:false,
  reasons:[],phase:'root_selection',phase_progress:{root_selection:'not_started',priority_scan:'not_started',traversal:'not_started',metadata:'not_started'},
  elapsed_ms:0,walk_finished:false,max_depth_checked:0};
 const reason=(code)=>{if(coverage.reasons.indexOf(code)<0)coverage.reasons.push(code);coverage.truncated=true;
  coverage.phase_progress[coverage.phase]='limited';
  if(!coverage.first_limit_phase)coverage.first_limit_phase=coverage.phase;};
 const phase=name=>{coverage.phase=name;coverage.phase_progress[name]='started';};
 // Native DOM/style/layout calls cannot be interrupted. Check their elapsed
 // cost before completing the producing phase or assigning work to the next.
 const finishPhase=(progress='finished')=>{
  coverage.elapsed_ms=Math.max(0,performance.now()-started);
  if(coverage.elapsed_ms>=coverage.time_limit_ms)reason('time_limit');
  if(coverage.phase_progress[coverage.phase]!=='limited')coverage.phase_progress[coverage.phase]=progress;
 };
 const messages=[],statuses=[],regions=[],visible_errors=[],priorityNodes=[];
 const text={text:'',bytes:0,truncated:false};
 const append=(out,value,limit)=>{
  const source=value.slice(0,16384).replace(/\\s+/g,' ').trim();
  if(!source)return;
  let piece='', added=0, steps=0, separator=out.text?' ':'';
  for(let i=0;i<source.length;i++){
   const code=source.charCodeAt(i),pair=code>=55296&&code<=56319&&i+1<source.length&&source.charCodeAt(i+1)>=56320&&source.charCodeAt(i+1)<=57343;
   const ch=pair?source.slice(i,i+2):source[i],size=separator.length+(pair?4:code<128?1:code<2048?2:3);
   if(out.bytes+added+size>limit||coverage.text_bytes+added+size>coverage.text_byte_limit){out.truncated=true;
    reason(coverage.text_bytes+added+size>coverage.text_byte_limit?'text_byte_limit':'item_text_byte_limit');break;}
   piece+=separator+ch;separator='';added+=size;
   if(pair)i++;
   if(++steps%64===0&&performance.now()-started>=coverage.time_limit_ms){out.truncated=true;reason('time_limit');break;}
  }
  out.text+=piece;out.bytes+=added;coverage.text_bytes+=added;
  if(value.length>16384){out.truncated=true;reason('source_text_character_limit');}
 };
 const item=(role,label)=>({text:'',bytes:0,truncated:false,role,label});
 const metadata=value=>{const out=item();append(out,value,256);return out.text;};
 const budget=()=>{
  let ok=true;
  if(coverage.nodes>=coverage.node_limit){reason('node_limit');ok=false;}
  if(performance.now()-started>=coverage.time_limit_ms){reason('time_limit');ok=false;}return ok;
 };
 const admitted=(node,count=true)=>{
  const tag=node.tagName.toLowerCase(),attr=k=>node.getAttribute(k)||'';
  if(['script','style','noscript','template','input','textarea','select','option'].includes(tag)
   ||node.isContentEditable||attr('role')==='textbox'||/password|secret|token|session|authorization|credential/i.test(attr('name')+' '+attr('autocomplete'))){if(count)coverage.protected_subtrees++;return false;}
  const style=getComputedStyle(node);
  if(node.hidden||attr('aria-hidden').trim().toLowerCase()==='true'||style.display==='none'||style.visibility==='hidden'||style.visibility==='collapse'||style.opacity==='0'){
   if(count)coverage.hidden_subtrees++;return false;}
  return true;
 };
 const visit=(node,depth,active)=>{
  if(!budget())return false;
  coverage.nodes++;
  coverage.max_depth_checked=Math.max(coverage.max_depth_checked,depth);
  if(depth>coverage.depth_limit){reason('depth_limit');return true;}
  if(node.nodeType===3){append(text,node.nodeValue||'',12288);for(let i=0;i<active.length;i++)append(active[i],node.nodeValue||'',active[i].role?1024:2048);return true;}
  if(node.nodeType!==1||!admitted(node))return true;
  const attr=k=>node.getAttribute(k)||'';
  // display:contents wrappers have no box, but may contain rendered descendants.
  const rendered=node.offsetWidth>0||node.offsetHeight>0;
  if(rendered){
   if(attr('data-message-id')){if(messages.length<200)messages.push({id:metadata(attr('data-message-id')),role:metadata(attr('data-message-author-role'))});else {coverage.semantic_limit_reached=true;reason('semantic_limit');}}
   const role=attr('role');
   if(role==='status'||role==='alert'){
    if(statuses.length<20){const out=item(role);statuses.push(out);active=active.concat(out);}else {coverage.semantic_limit_reached=true;reason('semantic_limit');}
   }
   if(role==='region'){
    if(regions.length<8){const out=item(undefined,metadata(attr('aria-label')));regions.push(out);active=active.concat(out);}else {coverage.semantic_limit_reached=true;reason('semantic_limit');}
   }
  }
  if(priorityNodes.length){
   const first=[];
   for(let i=0;i<priorityNodes.length;i++){if(!budget())return false;if(priorityNodes[i].parentElement===node)first.push(priorityNodes[i]);}
   for(let i=0;i<first.length;i++)if(!visit(first[i],depth+1,active))return false;
   for(let child=node.firstChild;child;child=child.nextSibling){
    if(!budget())return false;
    if(first.indexOf(child)<0&&!visit(child,depth+1,active))return false;
   }
  }else for(let child=node.firstChild;child;child=child.nextSibling)if(!visit(child,depth+1,active))return false;
  return true;
 };
 phase('root_selection');
 if(document.body){
  const main=document.querySelector('main,[role="main"]'),region=main?null:document.querySelector('[role="region"]');
  const candidate=main||region;let root=document.body,rootDepth=0;
  if(candidate&&candidate!==document.body){
   let node=candidate,depth=0,valid=true;
   while(node&&node!==document.body){
    if(!budget()){valid=false;break;}
    if(depth>=coverage.depth_limit){valid=false;reason('depth_limit');break;}
    coverage.nodes++;if(!admitted(node,false)){valid=false;break;}
    node=node.parentElement;depth++;
   }
   if(valid&&node===document.body&&budget()){
    coverage.nodes++;valid=admitted(document.body,false);
    if(valid){root=candidate;rootDepth=depth;coverage.root_basis=main?'main':'region';}
   }
  }
  finishPhase();phase('priority_scan');
  if(budget()){
   const candidates=root.querySelectorAll('[role="status"],[role="alert"]');
   if(candidates.length>20){coverage.semantic_limit_reached=true;reason('semantic_limit');}
   for(let i=0;i<candidates.length&&i<20&&budget();i++){
    const path=[];let node=candidates[i],depth=rootDepth;
    while(node&&node!==root&&depth<coverage.depth_limit&&budget()){
     coverage.nodes++;path.push(node);node=node.parentElement;depth++;
    }
    if(node!==root&&depth>=coverage.depth_limit)reason('depth_limit');
    if(node===root){coverage.priority_status_nodes++;for(let j=0;j<path.length;j++)if(priorityNodes.indexOf(path[j])<0)priorityNodes.push(path[j]);}
   }
   const priorityBudget=budget();
   finishPhase(priorityBudget?'finished':'interrupted');
   phase('traversal');coverage.walk_finished=visit(root,rootDepth,[]);
   finishPhase(coverage.walk_finished?'finished':'interrupted');
  }else finishPhase('interrupted');
 }else {reason('no_body');coverage.phase_progress.root_selection='no_body';finishPhase('no_body');}
 phase('metadata');
 for(let i=0;i<statuses.length;i++){const out=statuses[i];out.error_observed=out.role==='alert'||/couldn[’']?t load|failed|error|unable to|something went wrong/i.test(out.text);
  out.error_classification=out.role==='alert'?'alert_role':'text_heuristic';
  if(out.error_observed)visible_errors.push(out.text);}
 const href=location.href,title=metadata(document.title),ready_state=document.readyState;
 finishPhase();
 if(!coverage.reasons.length)coverage.reasons.push('sampled_root_walk_finished');
 coverage.phase='finished';coverage.partial=true;
 return {href,title,ready_state,messages,visible_errors,
  rendered_text:text,statuses,regions,coverage};
})()`;
function diagnosticDOMRedact(value) {
  const redact = v => Array.isArray(v) ? v.map(redact) : v && typeof v==='object'
    ? Object.fromEntries(Object.entries(v).map(([k,item])=>[k,redact(item)]))
    : typeof v==='string' ? v.replace(/((?:token|access_token|refresh_token|id_token|api_key|password|secret|authorization|cookie)[\"']?\s*[=:]\s*)(?:"(?:\\[\s\S]|[^"\\])*(?:"|\\?$)|'(?:\\[\s\S]|[^'\\])*(?:'|\\?$)|[^\s,;\"']+)/gi,'$1[redacted]') : v;
  return redact(diagnosticRedact(value));
}
async function diagnosticMark(record, label, ids) {
  if(record.diagnostics?.reload)throw fail('diagnostic_document_revalidation_pending');
  const d=record.diagnostics,epoch=d?.captureEpoch,generation=record.generation,loader=record.loaderId;
  const current=()=>record.diagnostics===d&&diagnosticBodyCurrent(record,{captureEpoch:epoch})
    &&record.generation===generation&&record.loaderId===loader;
  const frame = (await cdp(record,'Page.getFrameTree')).frameTree?.frame;
  if(!current())throw fail('diagnostic_document_changed');
  if (!diagnosticScopeCurrent(record) || frame?.id!==record.mainFrameId || frame?.loaderId!==record.loaderId || !diagnosticScopeObserved(record,frame?.url)) { diagnosticEnd(record,'scope_navigation'); throw fail('diagnostic_document_mismatch'); }
  const result = await cdp(record,'Runtime.evaluate',{expression:DIAGNOSTIC_DOM,returnByValue:true,awaitPromise:false,throwOnSideEffect:true});
  if (!record.diagnostics?.active) throw fail('diagnostic_capture_ended');
  if(!current())throw fail('diagnostic_document_changed');
  if (!diagnosticScopeObserved(record,result.result?.value?.href)) throw fail('diagnostic_document_mismatch');
  diagnosticEmit(record,{kind:'mark',label,mcp_ids:ids,visible_dom:diagnosticDOMRedact(result.result.value)});
}
async function diagnosticControl(record, packet) {
  requireTrust(packet);
  if (!record.diagnosticOnly || record.control || !record.network || !trust.network || record.target.context_kind !== 'ordinary'
      || record.state !== 'active' || record.releasing || !ownsTarget(record)) throw fail('diagnostic_authority');
  const p=packet.parameters || {};
  if (packet.action === 'diagnostics_begin') {
    if (record.diagnostics || !/^[a-f0-9]{32}$/.test(p.record_id) || (p.max_bytes != null && (!Number.isSafeInteger(p.max_bytes) || p.max_bytes<1048576))
        || !Number.isSafeInteger(p.body_bytes) || p.body_bytes<4096
        || p.stream_buffer_bytes !== undefined && (!diagnosticStreamBudgetValid(p.stream_buffer_bytes)
          || p.stream_buffer_bytes!==record.diagnosticScope.stream_buffer_bytes)
        || record.diagnosticScope.stream_buffer_bytes !== undefined && p.stream_buffer_bytes!==record.diagnosticScope.stream_buffer_bytes) throw fail('diagnostic_parameters');
    record.diagnostics={id:p.record_id,active:true,sequence:0,bytes:0,pendingBodies:0,bodyQueue:[],unacked:new Map(),unackedBytes:0,maxBytes:p.max_bytes,bodyBytes:p.body_bytes,streamBufferBytes:p.stream_buffer_bytes ?? 2097152,requests:new Map(),assets:new Map(),streams:new Set(),captureEpoch:0,creditWaiters:new Set(),bodyWork:new Set(),bodyURLs:new WeakMap()};
    record.diagnostics.scopeBinding=diagnosticScopeBinding(record);
    record.diagnostics.observedURL=record.diagnosticScope.observed_document_url || record.diagnosticScope.chat_url;
    record.diagnostics.scopeStage=record.diagnosticScope.chat_url==='https://chatgpt.com/'?'root':'canonical';
    await diagnosticMark(record,'before',[]);
  } else if (!record.diagnostics && packet.action === 'diagnostics_stop') {
    return {ok:true,record_id:p.record_id,active:false,capture_never_initialized:true,claim:publicClaim(record)};
  } else if (p.record_id !== record.diagnostics?.id) throw fail('diagnostic_record_mismatch');
  if (packet.action === 'diagnostics_mark') await diagnosticMark(record,p.label,p.mcp_ids);
  if (packet.action === 'diagnostics_stop') {
    if(record.diagnostics.active&&!record.diagnostics.reload) {
      try { await diagnosticMark(record,'after',[]); }
      catch { diagnosticEmit(record,{kind:'gap',reason:'after_dom_unavailable'}); }
    }
    diagnosticEnd(record,'explicit_capture_stop');
  }
  return {ok:true,record_id:record.diagnostics.id,active:record.diagnostics.active,sequence:record.diagnostics.sequence,stream_limits:diagnosticStreamLimits(record.diagnostics),claim:publicClaim(record)};
}
// Provisional routes are observed document locations, never canonical chat IDs.
// Only a root-started recorder can traverse one provisional route then bind once.
function diagnosticProvisional(value) {
  try {
    const u=new URL(value);
    if(u.origin!=='https://chatgpt.com'||u.username||u.password||u.search||u.hash)return null;
    const path=decodeURIComponent(u.pathname),match=/^\/c\/local-chatgpt:([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\/?$/i.exec(path);
    return match?'https://chatgpt.com/c/local-chatgpt%3A'+match[1].toLowerCase():null;
  }catch{return null;}
}
function diagnosticScopeBinding(record) {
  return {claim_id:record.id,owner_session:record.owner_session,peer_id:record.peerId,
    installation_id:record.installation_id,runtime_generation:record.runtime_generation,
    tab_id:record.tabId,target_tab_id:record.target.tab_id,target_id:record.target.target_id,
    browser_target_id:record.target.browser_target_id,target_generation:record.target.target_generation,
    connection_generation:record.target.connection_generation,
    profile_id:record.target.profile_id,context_id:record.target.context_id,context_kind:record.target.context_kind,
    frame_id:record.mainFrameId,loader_id:record.loaderId,origin:record.origin};
}
function diagnosticScopeAuthorityCurrent(record) {
  const d=record.diagnostics,b=d?.scopeBinding,current=diagnosticScopeBinding(record);
  return !!b&&claims.get(record.id)===record&&record.peerId===peerId&&record.state==='active'
    &&record.diagnosticOnly===true&&record.control===false&&record.inputEligible===false&&record.network===true&&trust?.enabled&&trust.network
    &&Object.keys(b).every(key=>key==='loader_id'||b[key]===current[key]);
}
function diagnosticScopeCurrent(record) {
  return !record.diagnostics?.reload&&diagnosticScopeAuthorityCurrent(record)
    &&record.diagnostics.scopeBinding.loader_id===record.loaderId;
}
function diagnosticScopeDocument(record) {
  const d=record.diagnostics;
  return {frame_id:record.mainFrameId,loader_id:record.loaderId,epoch:record.generation,
    chat_url:record.diagnosticScope.chat_url,observed_url:d?.observedURL||record.diagnosticScope.chat_url,
    scope_stage:d?.scopeStage||'unconfirmed',canonical_confirmed:d?.scopeStage==='canonical'};
}
function diagnosticScopeObserved(record, url, transition = false) {
  const d=record.diagnostics;
  if(!diagnosticScopeCurrent(record))return false;
  const project=diagnosticProjectChat(url);
  if(project&&!record.diagnosticScope.observed_document_url)return false;
  const canonical=diagnosticChat(url),provisional=diagnosticProvisional(url),observed=project?.observed_url||canonical||provisional;
  if(observed===d.observedURL)return true;
  if(!transition||!d.postWitness||!['root','provisional'].includes(d.scopeStage))return false;
  if(provisional&&d.scopeStage==='root') {
    d.observedURL=provisional;d.scopeStage='provisional';
    diagnosticEmit(record,{kind:'conversation_provisional',observed_url:provisional,canonical_confirmed:false,
      post_witness:d.postWitness,reason:'first_provisional_route_observed_after_post',causality:'not_established'});
    return true;
  }
  if(canonical&&canonical!=='https://chatgpt.com/') {
    const previous=d.observedURL,previousStage=d.scopeStage;
    d.observedURL=canonical;d.scopeStage='canonical';record.diagnosticScope.chat_url=canonical;
    diagnosticEmit(record,{kind:'conversation_bound',previous_chat_url:previous,previous_scope_stage:previousStage,
      chat_url:canonical,post_witness:d.postWitness,canonical_confirmed:true,
      reason:'first_canonical_route_observed_after_post',causality:'not_established'});
    return true;
  }
  return false;
}
// Complete SSE events are parsed only after bounded aggregation, so escaped
// credential keys and values split across transport chunks remain redactable.
function diagnosticStreamVariant(body, evidence) {
  body=body.replace(/\r\n?/g,'\n'); // Redacted parsing view only; raw digest/bytes stay original.
  let end=0;for(const match of body.matchAll(/\r?\n\r?\n/g))end=match.index+match[0].length;
  if(end<body.length)evidence.stream_gaps.push('stream_incomplete_sse_tail_omitted');
  return body.slice(0,end).split(/\r?\n\r?\n/).map(frame=>{
    if(!frame)return '';
    const lines=frame.split(/\r?\n/),data=lines.filter(line=>line.startsWith('data:')).map(line=>line.slice(5).replace(/^ /,'')).join('\n');
    const metadata=lines.filter(line=>!line.startsWith('data:')).map(line=>diagnosticDOMRedact(line));
    if(!lines.some(line=>line.startsWith('data:')))return metadata.join('\n');
    let value;
    try{value=JSON.stringify(diagnosticRedact(JSON.parse(data)));}
    catch{
      if(/^[\s]*[\[{]/.test(data)&&data.trim()!=='[DONE]'){
        if(!evidence.stream_gaps.includes('stream_unparseable_json_event_omitted'))evidence.stream_gaps.push('stream_unparseable_json_event_omitted');value='[unparseable JSON event omitted]';
      }else value=diagnosticDOMRedact(data);
    }
    return [...metadata,'data: '+value].join('\n');
  }).join('\n\n');
}
// Two fixed collector slots include finalization/credit waits. An explicit
// aggregate budget is divided equally so one stream cannot starve the other.
// Limits describe retained raw prefix arrays, not decoding/redaction copies or
// whole-process RAM. Defaults preserve two 1 MiB slots; no network effects.
function diagnosticStreamBudgetValid(value) {
  return Number.isSafeInteger(value)&&value>=8192&&value<=67108864;
}
function diagnosticStreamLimits(d) {
  const budget=d.streamBufferBytes ?? 2097152,perStream=Math.min(d.bodyBytes,Math.floor(budget/2));
  return {stream_buffer_bytes:budget,stream_prefix_byte_limit:perStream,
    stream_retained_raw_budget_bytes:2*perStream,stream_collector_limit:2,
    stream_budget_scope:'retained_raw_prefix_arrays_including_finalization_not_process_ram'};
}
function diagnosticStreamData(record, stream, data, prepend=false, expectedLength) {
  if(stream.closed || !record.diagnostics?.active || typeof data!=='string')return;
  if(data.length%4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data)){
    stream.gaps.add('stream_base64_invalid');stream.prefixBroken=true;
    if(prepend){stream.enableFailed=true;stream.used=0;}return;
  }
  const count=Math.floor(data.length*3/4)-(data.endsWith('==')?2:data.endsWith('=')?1:0);
  if(!prepend&&(!Number.isSafeInteger(expectedLength)||expectedLength<0||expectedLength!==count)){
    stream.gaps.add('stream_data_length_mismatch');stream.prefixBroken=true;return;
  }
  if(count<0 || !Number.isSafeInteger(stream.observed+count)){stream.gaps.add('stream_byte_count_invalid');stream.prefixBroken=true;return;}
  stream.observed+=count;
  if(stream.prefixBroken&&!prepend)return;
  const capacity=prepend?stream.buffer.length:stream.buffer.length-stream.used;
  const take=Math.min(count,capacity);
  if(take<count)stream.gaps.add('stream_prefix_byte_limit');
  if(!take)return;
  try {
    const text=atob(data.slice(0,Math.ceil(take/3)*4));
    if(text.length<take)throw fail('stream_base64_invalid');
    if(prepend){
      const kept=Math.min(stream.used,stream.buffer.length-take);
      if(kept<stream.used)stream.gaps.add('stream_prefix_byte_limit');
      stream.buffer.copyWithin(take,0,kept);stream.used=kept+take;
      for(let i=0;i<take;i++)stream.buffer[i]=text.charCodeAt(i);
    }else{for(let i=0;i<take;i++)stream.buffer[stream.used++]=text.charCodeAt(i);}
  }catch{stream.gaps.add('stream_base64_invalid');stream.prefixBroken=true;if(prepend){stream.enableFailed=true;stream.used=0;}}
}
function diagnosticStartStream(record, request) {
  const d=record.diagnostics;
  if(request.hop>0){diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_redirect_prefix_unavailable'});return;}
  if(d.streams.size>=2){diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_working_buffer_limit',
    ...diagnosticStreamLimits(d),stream_reserved_raw_bytes:[...d.streams].reduce((n,s)=>n+(s.buffer?.length || 0),0)});return;}
  const limits=diagnosticStreamLimits(d);let buffer;
  try{buffer=new Uint8Array(limits.stream_prefix_byte_limit);}
  catch{diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_buffer_allocation_failed',...limits});return;}
  const stream={buffer,limits,used:0,observed:0,gaps:new Set(),closed:false};
  stream.request=request;request.stream=stream;d.streams.add(stream);
  let timer;
  stream.ready=Promise.race([
    cdp(record,'Network.streamResourceContent',{requestId:request.id}),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('stream_enable_timeout')),1000);})
  ]).then(result=>{
    if(!stream.closed){if(typeof result.bufferedData==='string')diagnosticStreamData(record,stream,result.bufferedData,true);
      else {stream.enableFailed=true;stream.gaps.add('stream_buffered_data_missing');}stream.enabled=true;}
  }).catch(()=>{stream.enableFailed=true;stream.gaps.add('stream_enable_unavailable');})
    .finally(()=>clearTimeout(timer));
}
function diagnosticFinishStream(record, request, terminal) {
  const d=record.diagnostics,stream=request.stream;
  if(!stream || stream.closed)return;
  if(!['loading_finished','loading_failed'].includes(terminal)){
    // A reused request ID can now denote another response/origin. Neither a
    // late activation ACK nor getResponseBody may inherit the old authority.
    const retained=stream.used;stream.closed=true;stream.buffer=null;
    if(!stream.processing)d.streams.delete(stream);
    diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_request_identity_changed',
      stream_terminal:terminal,discarded_stream_prefix_bytes:retained});return;
  }
  if(stream.finishing)return;
  stream.finishing=true;
  void (async()=>{
    await stream.ready;
    if(stream.closed || !d.active)return;
    if(stream.enableFailed){
      diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_enable_unavailable'});
    }
    if(d.pendingBodies>=2){diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_finalize_work_limit'});return;}
    d.pendingBodies++;stream.processing=true;
    if(terminal==='loading_finished'||stream.enableFailed){
      // Keep the configured complete-body path for successful responses. The
      // additional bounded prefix is fallback evidence, not a new retention cap.
      try {
        const full=await cdp(record,'Network.getResponseBody',{requestId:request.id});
        if(stream.closed || !d.active)return;
        if(typeof full.body==='string'&&!full.base64Encoded&&encoder.encode(full.body).length<=d.bodyBytes){
          await diagnosticBody(record,{...request,streamRawBytes:null,streamEvidence:{
            body_coverage:'original_response_body',...stream.limits,stream_terminal:terminal,stream_enable:stream.enableFailed?'unverified':'acknowledged',stream_gaps:[]}},'response',full.body);return;
        }
        stream.gaps.add('stream_complete_body_working_limit');
      }catch{stream.gaps.add('stream_complete_body_unavailable');}
      if(stream.closed || !d.active)return;
      if(stream.enableFailed){diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'original_body_unavailable_no_refetch'});return;}
    }
    request.streamEvidence={body_coverage:'observed_stream_prefix',...stream.limits,stream_terminal:terminal,
      observed_stream_bytes:stream.observed,retained_stream_bytes:stream.used,
      stream_gaps:[...stream.gaps],stream_enable:stream.enableFailed?'unverified':'acknowledged',
      stream_byte_count_basis:'validated_base64_data'};
    if(terminal!=='loading_finished')request.streamEvidence.stream_gaps.push('stream_request_failed_or_interrupted');
    request.streamRawBytes=stream.buffer.subarray(0,stream.used);
    let text;
    try{text=new TextDecoder('utf-8',{fatal:true}).decode(request.streamRawBytes);}
    catch{text=new TextDecoder().decode(request.streamRawBytes);request.streamEvidence.stream_gaps.push('stream_utf8_replacement');}
    await diagnosticBody(record,request,'response',text);
  })().catch(()=>diagnosticBodyCurrent(record,request)&&!stream.closed&&diagnosticEmit(record,{kind:'body_gap',request_id:request.id,reason:'stream_prefix_processing_failed'}))
    .finally(()=>{stream.closed=true;stream.buffer=null;delete request.streamRawBytes;d.streams.delete(stream);
      if(stream.processing){d.pendingBodies--;if(d.active&&d.bodyQueue.length)diagnosticQueueBody(record,d.bodyQueue.shift(),'response');}});
}
function diagnosticBodyURLIdentity(value) {
  // Private transient correlation only; never attach credential-bearing URLs
  // to request rows, emitted events, receipts or durable storage.
  if(typeof value!=='string'||value.length>16384)return null;
  try {const url=new URL(value);return ['http:','https:'].includes(url.protocol)&&url.href.length<=16384?url.href:null;}
  catch{return null;}
}
function diagnosticRetireBodyWork(record, id, reason) {
  const d=record.diagnostics;
  // Only existing bounded work: two active bodies, 32 queued rows, two streams.
  const rows=new Set([...d.bodyWork,...d.bodyQueue,...[...d.streams].map(s=>s.request)]);
  let retired=0;
  for(const row of rows)if(row?.id===id&&!row.bodyIdentityRetired){row.bodyIdentityRetired=true;retired++;}
  d.bodyQueue=d.bodyQueue.filter(row=>row.id!==id);
  for(const waiter of d.creditWaiters)if(waiter.request?.id===id)waiter.finish(false);
  for(const stream of d.streams)if(stream.request?.id===id)diagnosticFinishStream(record,stream.request,reason);
  if(retired)diagnosticEmit(record,{kind:'body_gap',request_id:id,reason,retired_body_work:retired});
}
function diagnosticQueueBody(record, request, direction, body, encoded) {
  const d=record.diagnostics;
  if (!diagnosticBodyCurrent(record,request)) return;
  // Request strings are already allocated by CDP; do not retain them in a queue.
  if (d.pendingBodies >= 2) {
    if (direction === 'response' && d.bodyQueue.length < 32) d.bodyQueue.push(request);
    else diagnosticEmit(record,{kind:'body_gap',request_id:request.id,direction,reason:'body_work_queue_limit'});
    return;
  }
  d.pendingBodies++;d.bodyWork.add(request);
  void (async()=>{
    const v=direction==='response' ? await cdp(record,'Network.getResponseBody',{requestId:request.id}) : {body,base64Encoded:encoded};
    await diagnosticBody(record,request,direction,v.body || '',v.base64Encoded);
  })().catch(e=>diagnosticBodyCurrent(record,request)&&diagnosticEmit(record,{kind:'body_gap',request_id:request.id,direction,
    reason:'original_body_unavailable_no_refetch',code:e.code || 'cdp_body_unavailable'})).finally(()=>{
      d.bodyWork.delete(request);d.pendingBodies--;
      if (d.active && d.bodyQueue.length) diagnosticQueueBody(record,d.bodyQueue.shift(),'response');
    });
}
function diagnosticReload(record, frame) {
  const d=record.diagnostics;
  // An exact canonical conversation opt-in survives no URL/context/target
  // switch. Loader replacement is suspended until fresh public frame proof.
  if(d.scopeStage!=='canonical'||frame.id!==record.mainFrameId||frame.url!==d.observedURL
      ||diagnosticChat(frame.url)!==record.diagnosticScope.chat_url||typeof frame.loaderId!=='string'
      ||!frame.loaderId.length||frame.loaderId.length>256
      ||frame.securityOrigin!=null&&frame.securityOrigin!=='https://chatgpt.com')return false;
  const previous=diagnosticScopeDocument(record),oldEpoch=record.generation;
  diagnosticEmit(record,{kind:'gap',reason:'same_chat_document_revalidation',document:previous,
    discarded_request_count:d.requests.size,discarded_body_queue_count:d.bodyQueue.length,
    pending_body_count:d.pendingBodies,discarded_stream_prefix_bytes:[...d.streams].reduce((n,s)=>n+s.used,0)});
  if(!d.active)return true;
  for(const stream of [...d.streams])diagnosticFinishStream(record,stream.request,'document_changed');
  if(!d.active)return true;
  d.requests.clear();d.assets.clear();d.bodyQueue.length=0;d.captureEpoch++;diagnosticWakeCredit(record,false);
  const pending={frame:frame.id,loader:frame.loaderId,url:frame.url,oldEpoch,ignored:0,timer:null};d.reload=pending;
  void Promise.race([
    cdp(record,'Page.getFrameTree'),
    new Promise((_,reject)=>{pending.timer=setTimeout(()=>reject(fail('diagnostic_revalidation_timeout')),1000);})
  ]).then(result=>{
    if(!d.active||d.reload!==pending)return;
    const observed=result.frameTree?.frame;
    if(!diagnosticScopeAuthorityCurrent(record)||record.loaderId!==pending.loader||record.generation!==oldEpoch+1
        ||observed?.id!==pending.frame||observed?.loaderId!==pending.loader||observed?.url!==pending.url
        ||observed.securityOrigin!=null&&observed.securityOrigin!=='https://chatgpt.com'){
      diagnosticEnd(record,'scope_document_revalidation_failed');return;
    }
    // Rebind only the verified document field, never original authority.
    d.scopeBinding={...d.scopeBinding,loader_id:pending.loader};d.reload=null;
    diagnosticEmit(record,{kind:'document_revalidated',previous_document:previous,
      ignored_unverified_events:pending.ignored,reason:'same_exact_canonical_chat_new_document',coverage:'gap_during_revalidation',causality:'not_established'});
  }).catch(()=>{if(d.active&&d.reload===pending)diagnosticEnd(record,'scope_document_revalidation_failed');})
    .finally(()=>clearTimeout(pending.timer));
  return true;
}
function diagnosticEvent(record, source, method, p) {
  const d=record.diagnostics; if (!d?.active || source.sessionId) return;
  if(source.tabId!=null&&source.tabId!==record.tabId||source.targetId!=null&&source.targetId!==record.target.browser_target_id)return;
  if(method==='Page.frameDetached'&&p.frameId===record.mainFrameId){diagnosticEnd(record,'scope_document_detached');return;}
  if(d.reload){
    if(!diagnosticScopeAuthorityCurrent(record)){diagnosticEnd(record,'scope_binding_changed');return;}
    if(method==='Page.frameNavigated'&&!p.frame?.parentId){diagnosticEnd(record,'scope_reload_superseded');return;}
    if(method==='Page.navigatedWithinDocument'&&p.frameId===record.mainFrameId&&p.url!==d.reload.url){diagnosticEnd(record,'scope_navigation');return;}
    d.reload.ignored=Math.min(d.reload.ignored+1,1000000);return;
  }
  if(!diagnosticScopeCurrent(record)){diagnosticEnd(record,'scope_binding_changed');return;}
  if(method==='Page.frameNavigated'&&!p.frame?.parentId
      &&(p.frame?.id!==record.mainFrameId||p.frame?.loaderId!==record.loaderId)){
    if(!diagnosticReload(record,p.frame))diagnosticEnd(record,'scope_document_changed');return;
  }
  if ((method==='Page.frameNavigated' && p.frame?.id===record.mainFrameId && !diagnosticScopeObserved(record,p.frame.url,true))
      || method==='Page.navigatedWithinDocument' && p.frameId===record.mainFrameId && !diagnosticScopeObserved(record,p.url,true)) {
    diagnosticEnd(record,'scope_navigation'); return;
  }
  if (method==='Network.requestWillBeSent') {
    diagnosticRetireBodyWork(record,p.requestId,'request_body_identity_changed');
    // Terminal requests leave the metadata map while their bounded body work
    // can still be pending. Fence those two retained collectors on ID reuse too.
    for(const pending of d.streams)if(pending.request?.id===p.requestId)diagnosticFinishStream(record,pending.request,'request_replaced');
    const r=p.request || {}, sameDocument=diagnosticScopeObserved(record,p.documentURL);
    // No headers or arbitrary console values are copied. Asset metadata cannot evict API requests.
    if (!sameDocument || p.frameId!==record.mainFrameId) {
      const previous=d.requests.get(p.requestId);
      if(previous?.stream)diagnosticFinishStream(record,previous,'request_lineage_lost');
      d.requests.delete(p.requestId);d.assets.delete(p.requestId);
      return;
    }
    if (p.loaderId!==record.loaderId) {
      // Missing lineage is not the pinned document. Discard an earlier redirect
      // hop with this ID too, so a later response cannot inherit its body authority.
      if(d.requests.get(p.requestId)?.stream)diagnosticFinishStream(record,d.requests.get(p.requestId),'request_lineage_lost');
      d.requests.delete(p.requestId);d.assets.delete(p.requestId);
      diagnosticEmit(record,{kind:'gap',reason:'request_document_loader_unverified',request_id:p.requestId,
        method:r.method,url:diagnosticURL(r.url),capture_scope_stage:d.scopeStage,
        document:{frame_id:p.frameId,loader_id:typeof p.loaderId==='string'?p.loaderId:null,
          linkage:'unverified_request_document'}});
      return;
    }
    if (d.scopeStage==='root' && p.loaderId===record.loaderId && typeof p.requestId==='string' && p.requestId.length>0 && p.requestId.length<=256 && r.method==='POST' && ['Fetch','XHR'].includes(p.type)
        && (()=>{try{return new URL(r.url).origin==='https://chatgpt.com'}catch{return false}})()) {
      d.postWitness={request_id:p.requestId,sequence:d.sequence+1,frame_id:p.frameId,loader_id:p.loaderId,
        document_url:d.observedURL,request_url:diagnosticURL(r.url)};
    }
    // Body authority follows the admitted root document, not its destinations.
    // The frame/document/loader checks above exclude unrelated browsing/workers.
    const textual=['Fetch','XHR','Document'].includes(p.type), bodyScheme=(()=>{try{return ['http:','https:'].includes(new URL(r.url).protocol)}catch{return false}})();
    const bodyURL=diagnosticBodyURLIdentity(r.url);
    const previous=d.requests.get(p.requestId);if(previous?.stream)diagnosticFinishStream(record,previous,'request_replaced');
    const row={id:p.requestId,captureEpoch:d.captureEpoch,document:diagnosticScopeDocument(record),mime:'',bodyEligible:textual&&bodyScheme&&bodyURL!==null,frame_id:p.frameId,loader_id:p.loaderId,
      method:r.method,url:diagnosticURL(r.url),hop:(d.requests.get(p.requestId)?.hop ?? -1)+1};
    if(row.bodyEligible)d.bodyURLs.set(row,bodyURL);
    diagnosticEmit(record,{kind:'request',request_id:p.requestId,method:r.method,url:diagnosticURL(r.url),resource_type:p.type,redirect_hop:row.hop,
      frame_id:p.frameId,loader_id:p.loaderId,cdp_timestamp:p.timestamp,redirect_status:p.redirectResponse?.status,
      category:textual?'api_document':'asset',request_body_present:r.hasPostData===true});
    if (!textual) {
      if (d.assets.size<8192) d.assets.set(p.requestId,row);
      else diagnosticEmit(record,{kind:'gap',reason:'asset_tracking_limit'});
    }
    if (textual) {
      if (d.requests.size>=1024 && !d.requests.has(p.requestId)) { diagnosticEmit(record,{kind:'body_gap',request_id:p.requestId,reason:'request_tracking_limit'}); return; }
      d.requests.set(p.requestId,row);
      if(bodyScheme&&bodyURL===null)diagnosticEmit(record,{kind:'body_gap',request_id:p.requestId,reason:'request_body_url_identity_limit'});
      const contentType=Object.entries(r.headers || {}).find(([k])=>k.toLowerCase()==='content-type')?.[1] || '';
      const textualPost=/json|text|event-stream/i.test(contentType) || !contentType && /^[\s]*[\[{]/.test(r.postData || '');
      if(row.bodyEligible && textualPost && typeof r.postData==='string') {
        const requestRow={...row,mime:contentType};d.bodyURLs.set(requestRow,bodyURL);
        diagnosticQueueBody(record,requestRow,'request',r.postData);
      } else if(r.hasPostData) diagnosticEmit(record,{kind:'body_gap',request_id:p.requestId,direction:'request',
        reason:!bodyScheme?'request_body_scheme_excluded':bodyURL===null?'request_body_url_identity_limit':typeof r.postData!=='string'?'request_body_event_missing':'request_body_nontextual'});
    }
  } else if (method==='Network.responseReceived') {
    const bodyURL=diagnosticBodyURLIdentity(p.response?.url);
    const r=d.requests.get(p.requestId) || d.assets.get(p.requestId);
    if(!r){
      const pending=[...d.bodyWork,...d.bodyQueue,...[...d.streams].map(s=>s.request)].find(row=>row.id===p.requestId&&!row.bodyIdentityRetired);
      if(pending&&d.bodyURLs.get(pending)!==bodyURL)diagnosticRetireBodyWork(record,p.requestId,'response_request_url_unverified');
      return;
    }
    r.mime=p.response?.mimeType;
    // Redirects must replace the request row. Compare private canonical URLs,
    // not credential-redacted metadata that can collapse distinct resources.
    r.bodyEligible = r.bodyEligible && bodyURL!==null && bodyURL===d.bodyURLs.get(r);
    if(!r.bodyEligible){
      diagnosticRetireBodyWork(record,p.requestId,'response_request_url_unverified');
      if(r.stream)diagnosticFinishStream(record,r,'response_request_url_unverified');
      if(d.requests.has(p.requestId))diagnosticEmit(record,{kind:'body_gap',request_id:p.requestId,direction:'response',reason:'response_request_url_unverified'});
    }
    if(r.bodyEligible && /event-stream/i.test(r.mime || '') && !r.stream)diagnosticStartStream(record,r);
    diagnosticEmit(record,{kind:'response',request_id:p.requestId,status:p.response?.status,mime:r.mime,
      url:diagnosticURL(p.response?.url),protocol:p.response?.protocol,from_cache:p.response?.fromDiskCache===true});
  } else if(method==='Network.dataReceived') {
    const r=d.requests.get(p.requestId);if(r?.stream&&r.bodyEligible&&!r.stream.closed){
      if(typeof p.data==='string')diagnosticStreamData(record,r.stream,p.data,false,p.dataLength);
      else if(r.stream.enabled&&p.dataLength>0){r.stream.gaps.add('stream_data_event_missing');r.stream.prefixBroken=true;}
    }
  } else if (method==='Network.loadingFinished' || method==='Network.loadingFailed') {
    const r=d.requests.get(p.requestId) || d.assets.get(p.requestId); if(!r)return;d.requests.delete(p.requestId);d.assets.delete(p.requestId);
    diagnosticEmit(record,{kind:method==='Network.loadingFailed'?'loading_failed':'loading_finished',request_id:p.requestId,
      error:p.errorText,canceled:p.canceled,encoded_bytes:p.encodedDataLength});
    if (r.bodyEligible && /json|text|event-stream|javascript|xml/i.test(r.mime || '')) {
      r.outcome=method==='Network.loadingFailed'?'failed_or_partial':'completed';
      if(r.stream)diagnosticFinishStream(record,r,method==='Network.loadingFailed'?'loading_failed':'loading_finished');
      else diagnosticQueueBody(record,r,'response');
    } else if(r.bodyEligible) diagnosticEmit(record,{kind:'body_gap',request_id:p.requestId,reason:'nontext_or_html_response'});
  } else if(method==='Runtime.consoleAPICalled') diagnosticEmit(record,{kind:'console',level:p.type,argument_count:p.args?.length || 0});
  else if(method==='Runtime.exceptionThrown') diagnosticEmit(record,{kind:'exception',line:p.exceptionDetails?.lineNumber,
    column:p.exceptionDetails?.columnNumber,script_url:diagnosticURL(p.exceptionDetails?.url),description_omitted:true});
}

function diagnosticCdp(record, method, params, sessionId, willSend) {
  const allowed=['Page.enable','Page.getFrameTree','Runtime.enable','Network.enable','Network.getResponseBody','Network.streamResourceContent'];
  if (record.state!=='active' || record.releasing || record.peerId!==peerId || !ownsTarget(record)
      || record.control!==false || record.inputEligible!==false || !trust?.enabled || !trust.network
      || sessionId || !(allowed.includes(method) || method==='Runtime.evaluate' && params.expression===DIAGNOSTIC_DOM))
    throw fail('diagnostic_read_only');
  if(method==='Network.streamResourceContent' && (!record.diagnostics?.active || !record.diagnostics.requests.get(params.requestId)?.stream
      || !record.diagnostics.requests.get(params.requestId)?.bodyEligible || !/event-stream/i.test(record.diagnostics.requests.get(params.requestId)?.mime || '')))throw fail('diagnostic_read_only');
  if (method==='Network.getResponseBody' && !record.diagnostics?.active) throw fail('diagnostic_capture_ended');
  willSend();return chrome.debugger.sendCommand({targetId:record.target.browser_target_id},method,params);
}
