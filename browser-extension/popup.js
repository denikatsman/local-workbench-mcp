const status = document.querySelector('#status'), grant = document.querySelector('#grant'), revoke = document.querySelector('#revoke');
let tabId, leaseId;
let connectionWorkerGeneration;
// This same extension page can live in a normal window while Chrome prompts.
// Its URL carries visible choices, never an instruction to grant access.
const setupParameters = new URL(window.location.href).searchParams;
const setupWindow = setupParameters.has('setup_options');
let validSetupWindow = true;
if (setupWindow) {
  try {
    const options = JSON.parse(setupParameters.get('setup_options'));
    const fields = ['control', 'network', 'file_upload', 'file_download', 'private_context'];
    if (!options || Object.keys(options).length !== fields.length || fields.some(k => typeof options[k] !== 'boolean')
        || options.private_context !== (chrome.extension.inIncognitoContext === true)) throw new Error('Wrong browser context');
    for (const key of fields.slice(0, 4)) document.querySelector('#setup-' + key.replaceAll('_', '-')).checked = options[key];
  } catch {
    validSetupWindow = false;
  }
  document.querySelector('#setup-guidance').hidden = false;
  document.querySelector('#setup-guidance').textContent = validSetupWindow
    ? 'Review these choices, then update browser access. This window stays open while Chrome asks about incoming downloads.'
    : 'This setup window does not match its browser context. Close it and reopen setup from the extension.';
  for (const element of document.querySelectorAll('[data-popup-only]')) element.hidden = true;
}
const setup = document.querySelector('#setup'), revokeSetup = document.querySelector('#revoke-setup');
const stopTarget = document.querySelector('#stop-target'), resumeTarget = document.querySelector('#resume-target');
async function refresh() {
  try {
    const state = await chrome.runtime.sendMessage({ action: 'status' });
    connectionWorkerGeneration = state.worker_generation;
    tabId = state.current_tab_id;
    const lease = state.leases.find(r => r.tab_id === tabId && r.state === 'active' && r.expires_at > Date.now() / 1000);
    leaseId = lease?.lease_id;
    const enabled = state.trust?.enabled === true;
    status.textContent = enabled ? `Browser access is enabled for ${state.private_context ? 'private' : 'ordinary'} browsing. ${state.connected ? 'Workbench is connected.' : 'Waiting for Workbench to connect.'}`
      : lease ? `Sharing ${lease.origin}. Access expires at ${new Date(lease.expires_at * 1000).toLocaleTimeString()}.`
        : 'Enable this browser context once. Local Workbench must be running.';
    const diagnostic = document.querySelector('#connection-diagnostic');
    const failure = state.connection_diagnostic?.last_failure;
    const explanations = {
      native_host_not_found: 'Chrome could not find the Workbench browser helper.',
      native_host_forbidden: 'Chrome refused access to the Workbench browser helper.',
      native_host_start_failed: 'Chrome could not start the Workbench browser helper.',
      native_host_exited: 'The Workbench browser helper exited.',
      native_host_io_failed: 'Chrome could not communicate with the Workbench browser helper.',
      native_connection_lost: 'The connection to the Workbench browser helper ended.',
      connection_timeout: 'The Workbench browser connection did not become ready in time.',
    };
    const historyFailure = ['browser_key_history_limit', 'browser_key_history_unavailable',
      'browser_target_history_limit', 'browser_claim_history_limit', 'browser_session_storage_unavailable'].includes(failure?.code);
    diagnostic.hidden = state.connected || !failure;
    diagnostic.textContent = diagnostic.hidden ? '' : historyFailure
      ? 'Workbench could not restore saved browser history. Existing records were kept.'
      : Object.hasOwn(explanations, failure.code) ? explanations[failure.code]
        : 'The Workbench browser connection could not be initialized.';
    setup.hidden = false; setup.textContent = enabled ? 'Update browser access' : 'Enable browser access'; revokeSetup.hidden = setupWindow || !enabled;
    if (enabled && !setupWindow) {
      document.querySelector('#setup-control').checked = state.trust.control === true;
      document.querySelector('#setup-network').checked = state.trust.network === true;
      document.querySelector('#setup-file-upload').checked = state.trust.file_upload === true;
      document.querySelector('#setup-file-download').checked = state.trust.file_download === true;
    }
    const claim = state.claims?.find(r => r.target.tab_id === tabId && !['released', 'target_closed'].includes(r.state));
    stopTarget.hidden = setupWindow || !enabled || !claim || claim.state === 'revoked';
    resumeTarget.hidden = setupWindow || !enabled || !state.current_target_stopped;
    revoke.hidden = setupWindow || !lease;
    if (setupWindow && (!validSetupWindow || state.private_context !== (chrome.extension.inIncognitoContext === true))) {
      validSetupWindow = false; setup.disabled = true;
      status.textContent = 'This setup window could not verify its browser context. Close it and reopen setup from the extension.';
    }
  } catch { status.textContent = 'The extension could not check this tab. Reopen it and try again.'; }
}
grant.addEventListener('click', async () => {
  grant.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ action: 'grant', tab_id: tabId,
      options: { seconds: Number(document.querySelector('#seconds').value), control: document.querySelector('#control').checked, network: document.querySelector('#network').checked } });
    if (!result.ok) {
      const code = result.error?.code;
      status.textContent = code === 'workbench_not_connected' ? 'Workbench is not connected. Start the app and complete browser-bridge setup, then try again.'
        : code === 'private_context_not_enabled' ? 'Enable this extension for private browsing in Chrome before sharing a private tab.'
          : code === 'selected_tab_changed' ? 'The selected tab changed. Reopen this window on the tab you want to share.' : 'Chrome could not share this tab. It may be a restricted page or already open in DevTools.';
    } else await refresh();
  } finally { grant.disabled = false; }
});
revoke.addEventListener('click', async () => { await chrome.runtime.sendMessage({ action: 'revoke', lease_id: leaseId }); await refresh(); });
async function localAction(action, options) {
  try {
    const result = await chrome.runtime.sendMessage({ action, tab_id: tabId, options });
    if (!result.ok) {
      status.textContent = result.error?.code === 'private_context_not_enabled'
        ? 'Enable this extension for private browsing in Chrome before setting up private access.'
        : result.error?.code === 'selected_tab_changed' ? 'The selected tab changed. Reopen this popup.'
          : 'Browser access could not be updated. Start Workbench and try again.';
      return;
    }
    await refresh();
  } catch { status.textContent = 'Browser access could not be updated. Reopen this popup and try again.'; }
}
setup.addEventListener('click', async () => {
  if (setupWindow && !validSetupWindow) return;
  const options = { control: document.querySelector('#setup-control').checked,
    network: document.querySelector('#setup-network').checked,
    file_upload: document.querySelector('#setup-file-upload').checked,
    file_download: document.querySelector('#setup-file-download').checked };
  const fields = Object.keys(options).map(key => document.querySelector('#setup-' + key.replaceAll('_', '-')));
  setup.disabled = true; fields.forEach(field => { field.disabled = true; });
  try {
    if (options.file_download) {
      if (setupWindow) {
        // Request directly from this page's explicit click, before any await.
        if (!await chrome.permissions.request({ permissions: ['downloads'] })) {
          status.textContent = 'Chrome did not allow incoming downloads. Existing access remains available.'; return;
        }
      } else if (!await chrome.permissions.contains({ permissions: ['downloads'] })) {
        const url = new URL(chrome.runtime.getURL('popup.html'));
        url.searchParams.set('setup_options', JSON.stringify({ ...options,
          private_context: chrome.extension.inIncognitoContext === true }));
        await chrome.windows.create({ url: url.href, type: 'popup', width: 380, height: 660,
          incognito: chrome.extension.inIncognitoContext === true });
        status.textContent = 'Continue in the browser access window to confirm these choices.';
        return;
      }
    }
    await localAction('setup', options);
  } catch {
    status.textContent = 'Browser access could not be updated. Existing access remains available. Reopen setup and try again.';
  } finally {
    setup.disabled = setupWindow && !validSetupWindow;
    fields.forEach(field => { field.disabled = false; });
  }
});
revokeSetup.addEventListener('click', () => localAction('revoke_setup'));
stopTarget.addEventListener('click', () => localAction('stop_target'));
resumeTarget.addEventListener('click', () => localAction('resume_target'));
void refresh();

// Independent of runtime.sendMessage and the native connection. A stuck worker
// status request never prevents reading the extension page's session store.
const connectionDetails = document.querySelector('#connection-details');
let connectionReadBusy = false;
function connectionSnapshotText(snapshot, readAt) {
  const fail = () => { throw new Error('invalid diagnostic snapshot'); };
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const time = value => value === null || integer(value);
  const kind = chrome.extension.inIncognitoContext === true ? 'private' : 'ordinary';
  const fields = ['version','worker_generation','context_kind','extension_version','captured_at_ms',
    'update_sequence','omitted_history','persistence_failures','history_before_worker','persistence','rows'];
  if (!snapshot || Object.keys(snapshot).length !== fields.length || fields.some(k => !Object.hasOwn(snapshot,k))
      || snapshot.version !== 1 || typeof snapshot.worker_generation !== 'string' || !/^[a-f0-9]{32}$/.test(snapshot.worker_generation)
      || snapshot.context_kind !== kind || typeof snapshot.extension_version !== 'string' || snapshot.extension_version.length > 32 || !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(snapshot.extension_version)
      || !time(snapshot.captured_at_ms) || !integer(snapshot.update_sequence) || !integer(snapshot.omitted_history)
      || !integer(snapshot.persistence_failures) || snapshot.history_before_worker !== 'unavailable'
      || snapshot.persistence !== 'best_effort' || !Array.isArray(snapshot.rows) || snapshot.rows.length > 32) fail();
  const phases = new Set(['bootstrap_trust_storage_read','bootstrap_alarm','attempt_started','profile_storage_read',
    'profile_storage_write','context_storage_read','context_storage_write','foundations','keyboard_history_read',
    'trust_storage_read','session_history_read','durable_history_read','manifest_fetch','manifest_body','manifest_hash',
    'native_port','native_hello','native_ready','trust_restore','trust_ready','connected','disconnected','setup_failed']);
  const lines = [], sequences = new Map();
  for (const row of snapshot.rows) {
    const keys = ['version','worker_generation','connection_attempt','sequence','phase','elapsed_ms','received_at_ms'];
    if (!row || Object.keys(row).length !== keys.length || keys.some(k => !Object.hasOwn(row,k))
        || row.version !== 1 || row.worker_generation !== snapshot.worker_generation
        || !integer(row.connection_attempt) || !integer(row.sequence) || row.sequence < 1
        || !phases.has(row.phase) || !time(row.elapsed_ms) || !time(row.received_at_ms)) fail();
    const previous = sequences.get(row.connection_attempt);
    if (previous !== undefined && row.sequence <= previous) fail();
    sequences.set(row.connection_attempt,row.sequence);
    lines.push(`Attempt ${row.connection_attempt}, sequence ${row.sequence}: ${row.phase}; elapsed ${row.elapsed_ms === null ? 'unknown' : row.elapsed_ms + ' ms'}; received wall time ${row.received_at_ms ?? 'unknown'}`);
  }
  let version;
  try { version = chrome.runtime.getManifest().version; } catch {}
  const match = connectionWorkerGeneration === snapshot.worker_generation && version === snapshot.extension_version;
  return [`${kind} browsing — ${match ? 'Matches last responding worker; current readiness unknown.' : 'Historical / current worker unverified.'}`,
    `Worker ${snapshot.worker_generation}; extension ${snapshot.extension_version}`,
    `Snapshot capture wall time ${snapshot.captured_at_ms ?? 'unknown'}; display read wall time ${readAt}`,
    `Omitted older entries: ${snapshot.omitted_history}; observed persistence failures: ${snapshot.persistence_failures}.`,
    'Best effort: later/unwritten entries, storage failures and previous-worker history may be missing. Phase gaps do not prove a worker or phase never started.',
    ...lines].join('\n');
}
async function readConnectionDetails() {
  if (!connectionDetails || connectionReadBusy) return;
  connectionReadBusy = true;
  let timer, readStarted = false;
  try {
    const kind = chrome.extension.inIncognitoContext === true ? 'private' : 'ordinary';
    const key = 'workbenchConnectionPhases:' + kind;
    const pending = Promise.resolve(chrome.storage.session.get(key));
    readStarted = true;
    // A timed-out read remains the sole in-flight read until storage settles.
    // Repeated clicks must not accumulate indefinitely pending storage calls.
    const observed = pending.finally(() => { connectionReadBusy = false; });
    const result = await Promise.race([observed, new Promise((_,reject) => {
      timer = setTimeout(() => reject(new Error('diagnostic read timeout')), 750);
    })]);
    connectionDetails.textContent = result?.[key] ? connectionSnapshotText(result[key],Date.now())
      : 'No saved connection details. Storage may be unavailable or no snapshot was written; worker readiness is unknown.';
  } catch {
    connectionDetails.textContent = 'Saved connection details are unavailable or invalid. Worker readiness and the reason are unknown. Browser access controls are unchanged.';
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (!readStarted) connectionReadBusy = false;
  }
}
document.querySelector('#connection-read')?.addEventListener('click', readConnectionDetails);
void readConnectionDetails();
