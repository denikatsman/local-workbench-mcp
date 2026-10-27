"""Task-owned original profile downloads; incoming bytes use existing folder authority."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
import uuid

from .browser_wire import ProtocolError, read_private_json, MAX_FRAME
from .context import work_context
from .errors import WorkbenchError
from .persistence import atomic_json
from .response_diagnostics import projection as diagnostic_projection
from .download_cancel_evidence import projection as cancel_projection, normalize as normalize_cancel_evidence, merge as merge_cancel_evidence


class SelectedDownloads:
    VERSION = 1
    LIMIT = 32
    HISTORY_LIMIT = 1000

    def __init__(self, broker, files):
        self.broker, self.files = broker, files
        self.path = broker.root / 'managed-downloads.json'
        self.lock = threading.RLock()
        self.records = {}
        self.fences = set()
        if self.path.exists():
            document = read_private_json(self.path)
            if type(document.get('version')) is not int or document['version'] != self.VERSION or not isinstance(document.get('records'), dict):
                raise WorkbenchError('download_history_schema', 'Managed download history requires reconciliation.')
            self.records = document['records']
            owners = document.get('stopped_owners', [])
            if (len(self.records) > self.HISTORY_LIMIT or not isinstance(owners, list)
                    or len(owners) > self.HISTORY_LIMIT
                    or any(not isinstance(owner, str) or not 0 < len(owner) <= 128 for owner in owners)):
                raise WorkbenchError('download_history_schema', 'Managed download history requires reconciliation.')
            self.fences = set(owners)
        for row in self.records.values():
            if (not isinstance(row, dict) or not isinstance(row.get('owner_session'), str)
                    or not 0 < len(row['owner_session']) <= 128
                    or not isinstance(row.get('download_id'), str)
                    or not re.fullmatch('[0-9a-f]{32}', row['download_id'])
                    or self.records.get(row['download_id']) is not row
                    or row.get('producer_state') not in ('intent', 'attempted', 'unknown', 'in_progress', 'complete', 'interrupted', 'gone')
                    or row.get('capture_state') not in ('not_attempted', 'finalizing', 'unknown', 'verified')
                    or row.get('download_persistence') not in (None,'saved','unknown')
                    or row.get('cleanup_state') not in (None,'pending','unknown','settled')):
                raise WorkbenchError('download_history_schema', 'Managed download history requires reconciliation.')
            normalize_cancel_evidence(row)
            if row.get('route', 'profile_api_get') not in ('profile_api_get', 'page_response', 'profile_api_blob'):
                raise WorkbenchError('download_history_schema', 'Unknown download provenance route.')
            if row.get('route') == 'page_response':
                self._validate_page_history(row)
            if row.get('route') == 'profile_api_blob':
                self._validate_blob_history(row)
            if row.get('capture_state') == 'finalizing':
                row['capture_state'] = 'unknown'
        self.finalizing = set()

    @staticmethod
    def _validate_page_history(row):
        normalize_cancel_evidence(row)
        if 'admission_diagnostics' in row:
            row['admission_diagnostics'] = diagnostic_projection(row['admission_diagnostics'], 4)
            if len(json.dumps(row).encode()) > 32768:
                row.pop('admission_diagnostics')
        binding = row.get('page_binding')
        if (not isinstance(binding, dict) or len(json.dumps(row).encode()) > 32768
                or set(binding) != {'claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id',
                    'target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind',
                    'connection_generation','frame_id','loader_id','document_epoch','origin','worker_generation','trust_id'}
                or any(not isinstance(binding[k], str) or not 0 < len(binding[k]) <= 256 for k in binding
                       if k not in ('claim_epoch','tab_id','document_epoch'))
                or any(type(binding[k]) is not int or binding[k] < 1 for k in ('claim_epoch','document_epoch'))
                or type(binding['tab_id']) is not int or binding['tab_id'] < 0
                or binding['context_kind'] not in ('ordinary','private') or row.get('context_kind') != binding['context_kind']
                or any(binding[k] != row.get(k) for k in ('owner_session','installation_id','runtime_generation','profile_id','context_id'))
                or row.get('method') not in ('GET','POST')
                or not isinstance(row.get('response_token'), str) or not re.fullmatch('workbench-owned-[0-9a-f]{32}', row['response_token'])
                or type(row.get('expires_at')) not in (int,float) or not 0 < row['expires_at'] < 1e12):
            raise WorkbenchError('download_history_schema', 'Page response history requires reconciliation.')
        root = row.get('source_root')
        if (not isinstance(root, dict) or set(root) != {'workspace','dev','inode'}
                or not isinstance(root['workspace'], str) or not 0 < len(root['workspace']) <= 128
                or any(type(root[k]) is not int or root[k] < 0 for k in ('dev','inode'))
                or row.get('browser_download_id') is not None and (type(row['browser_download_id']) is not int
                    or not 0 <= row['browser_download_id'] <= 2**31-1)):
            raise WorkbenchError('download_history_schema', 'Invalid retained original root or DownloadItem ID.')
        SelectedDownloads._accept_page(row, {**row, 'original_request_id': row['request_id']})

    def _save(self):
        document = {'version': self.VERSION, 'records': self.records, 'stopped_owners': sorted(self.fences)}
        if len(json.dumps(document, ensure_ascii=True, separators=(',', ':')).encode()) > MAX_FRAME:
            # New optional bytes must not make a previously readable history
            # unreadable. Keep every original authoritative record unchanged.
            document = {**document, 'records': {key: {k: v for k, v in row.items()
                if k != 'producer_cancel_evidence'} for key, row in self.records.items()}}
        atomic_json(self.path, document)

    @staticmethod
    def page_ambiguity(row):
        if row.get('route') != 'page_response': return None
        return row.get('ambiguity_reason') or (row.get('observation_state')
            if row.get('observation_state', '').startswith('ambiguous_') else None)

    @staticmethod
    def unsettled(row):
        return (SelectedDownloads.page_ambiguity(row) or row.get('producer_state') not in ('complete', 'interrupted', 'gone')
                or row.get('download_persistence') == 'unknown' or row.get('cleanup_state') in ('pending','unknown')
                or row.get('capture_state') in ('finalizing', 'unknown') or row.get('cancel_state') in ('pending', 'unknown'))

    def active_ids(self, owner=None):
        with self.lock:
            return [key for key, row in self.records.items()
                    if (self.unsettled(row) or key in self.finalizing)
                    and (owner is None or row['owner_session'] == owner)]

    def fence_claim(self, claim_id):
        # Called in the broker control reservation, before transport awaits.
        with self.lock:
            changed = False
            for row in self.records.values():
                if row.get('route') in ('page_response','profile_api_blob') and (row.get('page_binding') or row.get('source_binding'))['claim_id'] == claim_id and self.unsettled(row):
                    row['cancel_requested'] = True; row['cancel_state'] = 'pending'; changed = True
            if changed: self._save()

    def _record(self, identifier, owner):
        row = self.records.get(identifier)
        if not row or row['owner_session'] != owner:
            raise WorkbenchError('download_owner_mismatch', 'Use this task’s original download ID.', effect_state='none')
        return row

    def _peer(self, profile, context, kind, *, starting=False, cleanup=False):
        with self.broker.lock:
            candidates = [p for p in self.broker.peers.values() if p.connected
                and p.identity.get('profile_id') == profile and p.identity.get('context_id') == context
                and p.identity.get('private_context') is (kind == 'private')]
            if len(candidates) != 1:
                raise WorkbenchError('download_profile_unavailable', 'Reconnect the original browser context.', effect_state='none')
            peer = candidates[0]
            trust = self.broker.trust_records.get(peer.trust_key, {})
            if type(peer.identity.get('managed_download_version')) is not int or peer.identity['managed_download_version'] != self.VERSION:
                raise WorkbenchError('download_bridge_unavailable', 'Update and reload the browser bridge locally.', effect_state='none')
            if not cleanup and (not trust.get('enabled') or trust.get('file_download') is not True):
                raise WorkbenchError('browser_download_not_granted', 'Enable incoming downloads once in the local browser popup.', effect_state='none')
            if starting and not trust.get('control'):
                raise WorkbenchError('download_admission_stopped', 'This browser context is stopped for downloads.', effect_state='none')
            return peer, copy.deepcopy(trust)

    def _page_current(self, row):
        """Broker lock precedes download lock; callers never hold download lock here."""
        binding = row['page_binding']
        with self.broker.lock:
            claim = self.broker.claims.get(binding['claim_id'])
            peer = self.broker.peers.get(binding['peer_id'])
            trust = self.broker.trust_records.get(getattr(peer, 'trust_key', None), {})
            if peer and (type(peer.identity.get('page_download_version')) is not int or peer.identity['page_download_version'] != 1):
                raise WorkbenchError('download_page_bridge_unavailable', 'Reload the bridge candidate with original page download support.', effect_state='none')
            kind = binding['context_kind']
            if kind == 'private' and (not peer or type(peer.identity.get('private_page_download_version')) is not int
                    or peer.identity['private_page_download_version'] != 1):
                raise WorkbenchError('download_private_bridge_unavailable', 'Reload the bridge with private page-download support.', effect_state='none')
            if (kind not in ('ordinary','private') or not claim or not peer
                    or peer.identity.get('private_context') is not (kind == 'private')
                    or not peer.connected or peer.identity.get('worker_generation') != binding['worker_generation']
                    or self.broker._binding(claim) != {k: v for k, v in binding.items() if k not in ('worker_generation', 'trust_id')}
                    or not trust.get('enabled') or not all(trust.get(k) is True for k in ('control', 'network', 'file_download'))
                    or trust.get('trust_id') != binding['trust_id'] or not claim.get('control') or not claim.get('network')):
                raise WorkbenchError('download_claim_changed', 'The exact claim, document or incoming grant changed.', effect_state='none')
            self.broker._normal_guard(binding['claim_id'], self.broker._binding(claim))

    def _blob_current(self, row):
        binding = row['source_binding']
        with self.broker.lock:
            claim = self.broker.claims.get(binding['claim_id'])
            peer = self.broker.peers.get(binding['peer_id'])
            trust = self.broker.trust_records.get(getattr(peer, 'trust_key', None), {})
            if peer and (type(peer.identity.get('blob_download_version')) is not int or peer.identity['blob_download_version'] != 1):
                raise WorkbenchError('download_blob_bridge_unavailable', 'Reload the bridge with observed Blob-anchor support.', effect_state='none')
            if (not claim or not peer or not peer.connected or peer.identity.get('worker_generation') != binding['worker_generation']
                    or self.broker._binding(claim) != {k:v for k,v in binding.items() if k not in ('worker_generation','trust_id')}
                    or not trust.get('enabled') or not trust.get('control') or not trust.get('file_download')
                    or trust.get('trust_id') != binding['trust_id'] or not claim.get('control')):
                raise WorkbenchError('download_claim_changed', 'The exact Blob source claim, document or grant changed.', effect_state='none')
            self.broker._normal_guard(binding['claim_id'], self.broker._binding(claim))

    @staticmethod
    def _safe_blob_filename(name):
        return (isinstance(name, str) and 0 < len(name.encode()) <= 240 and name.strip() == name
                and not name.startswith('.') and not name.endswith('.')
                and not any(c in name for c in '/\\<>:"|?*')
                and not any(ord(c) < 32 or ord(c) == 127 or 0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in name)
                and not re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', name))

    @staticmethod
    def _accept_blob(row, data):
        from .selected_tabs import origin
        for key in ('route','source_binding','source_root','observation_id','target_id','intended_filename'):
            if data.get(key) != row.get(key): raise ProtocolError('download_blob_binding')
        source = data.get('blob_source')
        if source is None:
            if row.get('blob_source') or data.get('browser_download_id') is not None or data.get('relative_filename') is not None:
                raise ProtocolError('download_blob_source_required')
            return
        keys = {'observation_id','target_id','frame_id','loader_id','document_generation',
                'execution_context_unique_id','backend_node_id','href','download_attribute','filename'}
        binding = row['source_binding']
        if (not isinstance(source, dict) or set(source) != keys
                or any(source[k] != row[k] for k in ('observation_id','target_id'))
                or any(source[k] != binding[k] for k in ('frame_id','loader_id'))
                or type(source['document_generation']) is not int or source['document_generation'] != binding['document_epoch']
                or not isinstance(source['execution_context_unique_id'], str) or not 0 < len(source['execution_context_unique_id']) <= 256
                or type(source['backend_node_id']) is not int or not 1 <= source['backend_node_id'] <= 2**53-1
                or not isinstance(source['href'], str) or not source['href'].startswith('blob:') or len(source['href'].encode()) > 8192
                or source['download_attribute'] is not None and not isinstance(source['download_attribute'], str)
                or not SelectedDownloads._safe_blob_filename(source['filename'])):
            raise ProtocolError('download_blob_source')
        try:
            if origin(source['href'][5:]) != binding['origin']: raise ProtocolError('download_blob_origin')
        except (ValueError, ProtocolError) as error: raise ProtocolError('download_blob_origin') from error
        wanted = source['download_attribute'] or row['intended_filename']
        if wanted != source['filename'] or not SelectedDownloads._safe_blob_filename(wanted):
            raise ProtocolError('download_blob_filename')
        relative = 'LocalWorkbench/' + row['download_id'] + '/' + source['filename']
        if data.get('relative_filename') != relative or data.get('url') != source['href']:
            raise ProtocolError('download_blob_routing')
        if row.get('blob_source') is not None and row['blob_source'] != source:
            raise ProtocolError('download_blob_source_changed')
        row.update(blob_source=copy.deepcopy(source), relative_filename=relative, url=source['href'])

    @staticmethod
    def _validate_blob_history(row):
        normalize_cancel_evidence(row)
        b = row.get('source_binding')
        keys = {'claim_id','claim_epoch','owner_session','installation_id','runtime_generation','peer_id',
                'target_id','target_generation','browser_target_id','tab_id','profile_id','context_id','context_kind',
                'connection_generation','frame_id','loader_id','document_epoch','origin','worker_generation','trust_id'}
        root = row.get('source_root')
        if (not isinstance(b, dict) or set(b) != keys or len(json.dumps(row).encode()) > 32768
                or any(not isinstance(b[k], str) or not 0 < len(b[k]) <= 256 for k in keys - {'claim_epoch','tab_id','document_epoch'})
                or any(type(b[k]) is not int or b[k] < 1 for k in ('claim_epoch','document_epoch'))
                or type(b['tab_id']) is not int or b['tab_id'] < 0 or b['context_kind'] != 'ordinary' or row.get('context_kind') != 'ordinary'
                or any(b[k] != row.get(k) for k in ('owner_session','installation_id','runtime_generation','profile_id','context_id'))
                or any(not isinstance(row.get(k), str) or not re.fullmatch('[0-9a-f]{32}', row[k]) for k in ('observation_id','target_id'))
                or row.get('intended_filename') is not None and not SelectedDownloads._safe_blob_filename(row['intended_filename'])
                or not isinstance(root, dict) or set(root) != {'workspace','dev','inode'}
                or not isinstance(root['workspace'], str) or not 0 < len(root['workspace']) <= 128
                or any(type(root[k]) is not int or root[k] < 0 for k in ('dev','inode'))
                or row.get('browser_download_id') is not None and (type(row['browser_download_id']) is not int or not 0 <= row['browser_download_id'] <= 2**31-1)):
            raise WorkbenchError('download_history_schema', 'Blob source history requires reconciliation.')
        SelectedDownloads._accept_blob(row, row)

    def observe_blob(self, peer, packet):
        nonce = packet.get('ack_nonce')
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce): raise ProtocolError('download_observation_shape')
        try:
            self.message(peer, packet)
            row = self.records[packet['download']['download_id']]
            self._blob_current(row)
            with self.lock:
                if row.get('cancel_requested') or row['owner_session'] in self.fences:
                    raise WorkbenchError('download_admission_stopped', 'Original Blob initiation ended.', effect_state='none')
            peer.send({'type':'managed_download_observation_result','ack_nonce':nonce,'ok':True})
        except (WorkbenchError, OSError, ProtocolError) as error:
            peer.send({'type':'managed_download_observation_result','ack_nonce':nonce,'ok':False,
                       'error':{'code':getattr(error,'code','download_observation_unsaved')}})

    def _start_blob(self, workspace, owner, request_id, *, claim_id, claim_epoch, target_generation,
                    expected_generation, expected_origin, frame_id, observation_id, target_id,
                    intended_filename, source_workspace):
        from .selected_tabs import valid_id
        if (not all(valid_id(v) for v in (claim_id, observation_id, target_id))
                or type(claim_epoch) is not int or type(expected_generation) is not int
                or intended_filename is not None and not self._safe_blob_filename(intended_filename)):
            raise WorkbenchError('invalid_blob_source', 'Use a fresh observed root anchor and a safe optional basename.', effect_state='none')
        self.broker.journal.validate_id(request_id)
        identifier = hashlib.sha256(('selected-download:' + owner + ':' + request_id).encode()).hexdigest()[:32]
        caller = {'claim_id':claim_id,'claim_epoch':claim_epoch,'target_generation':target_generation,
                  'document_epoch':expected_generation,'origin':expected_origin,'frame_id':frame_id}
        with self.lock: admitted = copy.deepcopy(self.records.get(identifier))
        if admitted:
            b = admitted.get('source_binding', {})
            if (admitted.get('route') != 'profile_api_blob' or admitted['workspace'] != workspace
                    or any(b.get(k) != v for k,v in caller.items()) or admitted['observation_id'] != observation_id
                    or admitted['target_id'] != target_id or admitted['intended_filename'] != intended_filename
                    or admitted['source_root']['workspace'] != source_workspace):
                raise WorkbenchError('request_conflict', 'Original Blob request arguments differ.', effect_state='none')
        else:
            with self.broker.lock:
                claim = self.broker.claims.get(claim_id)
                if not claim or claim['owner_session'] != owner:
                    raise WorkbenchError('download_claim_changed', 'Use this task’s current durable ordinary claim.', effect_state='none')
                b = copy.deepcopy(self.broker._binding(claim))
                peer = self.broker.peers.get(b['peer_id'])
                trust = self.broker.trust_records.get(getattr(peer,'trust_key',None), {})
                if any(b.get(k) != v for k,v in caller.items()) or b['context_kind'] != 'ordinary':
                    raise WorkbenchError('download_claim_changed', 'Use the current ordinary root frame and document.', effect_state='none')
                b.update(worker_generation=peer.identity.get('worker_generation') if peer else None, trust_id=trust.get('trust_id'))
            self._blob_current({'source_binding':b})
        payload = {'tool':'selected_download','workspace':workspace,'owner':owner,'action':'start_blob',
                   'source_binding':b,'observation_id':observation_id,'target_id':target_id,
                   'intended_filename':intended_filename,'source_workspace':source_workspace}
        def start():
            if admitted: raise WorkbenchError('download_admission_unknown', 'Recover the original Blob intent; never reissue it.', effect_state='unknown')
            if not self.files or not source_workspace:
                raise WorkbenchError('download_folder_access_required', 'Select an already approved incoming workspace.', effect_state='none')
            descriptor = self.files._root_descriptor(source_workspace)
            try: stat = os.fstat(descriptor)
            finally: os.close(descriptor)
            self._blob_current({'source_binding':b})
            with self.lock:
                if owner in self.fences: raise WorkbenchError('download_admission_stopped', 'Task downloads were stopped.', effect_state='none')
                if len(self.active_ids()) >= self.LIMIT or len(self.records) >= self.HISTORY_LIMIT:
                    raise WorkbenchError('download_resource_limit', 'Reconcile pending downloads first.', effect_state='none')
                row = {'download_id':identifier,'owner_session':owner,'workspace':workspace,'request_id':request_id,
                    'installation_id':self.broker.install_id,'runtime_generation':self.broker.instance_id,
                    'profile_id':b['profile_id'],'context_id':b['context_id'],'context_kind':'ordinary','nonce':uuid.uuid4().hex,
                    'route':'profile_api_blob','source_binding':b,'observation_id':observation_id,'target_id':target_id,
                    'intended_filename':intended_filename,'blob_source':None,'relative_filename':None,'url':None,
                    'source_root':{'workspace':source_workspace,'dev':stat.st_dev,'inode':stat.st_ino},
                    'producer_state':'intent','browser_download_id':None,'capture_state':'not_attempted',
                    'cancel_state':'not_requested','created_at':time.time()}
                self.records[identifier] = row; self._save()
            try:
                result = self._command(row, 'start_blob', peer=peer, trust=trust)
                with self.lock: self._accept(row, result)
            except BaseException:
                with self.lock:
                    if row['producer_state'] == 'intent': row['producer_state'] = 'unknown'
                    self._save()
                raise
            return {'ok':True,'download':self._public(row),'bytes_captured':False,
                    'scope':'initial_task_owned_original_observed_blob_api_download','page_click_recovery':False,'creator_attribution':False}
        return self.broker.journal.run(request_id, payload, start, resource='managed-blob:' + claim_id,
            initial_checkpoint={'download_id':identifier,'effect_state':'unknown','phase':'before_blob_source_resolution'})

    def guard(self, action, packet):
        if action not in ('managed_download_start', 'managed_download_arm', 'managed_download_start_blob'): return
        if action == 'managed_download_arm':
            self._page_current(self.records[packet['download_id']])
        if action == 'managed_download_start_blob': self._blob_current(self.records[packet['download_id']])
        with self.lock:
            row = self._record(packet['download_id'], packet['owner_session'])
            if row['owner_session'] in self.fences or row.get('cancel_requested'):
                raise WorkbenchError('download_admission_stopped', 'Original admission was stopped before send.', effect_state='none')

    def _command(self, row, action, *, peer=None, trust=None, timeout=2):
        if peer is None:
            peer, trust = self._peer(row['profile_id'], row['context_id'], row['context_kind'], cleanup=action == 'cancel')
        private_page = row.get('route') == 'page_response' and row['context_kind'] == 'private'
        if private_page and (type(peer.identity.get('private_page_download_version')) is not int
                or peer.identity['private_page_download_version'] != 1):
            raise WorkbenchError('download_private_bridge_unavailable', 'The original private page-download bridge is unavailable.', effect_state='none')
        return self.broker._rpc(peer, 'managed_download_' + action, {
            **({'private_page_download_version':1} if private_page else {}),
            'interaction_version': 1, 'managed_download_version': 1,
            'runtime_generation': self.broker.instance_id, 'installation_id': self.broker.install_id,
            'profile_id': row['profile_id'], 'context_id': row['context_id'],
            'context_kind': row['context_kind'], 'trust_id': trust['trust_id'],
            'owner_session': row['owner_session'], 'download_id': row['download_id'],
            'original_request_id': row['request_id'], 'nonce': row['nonce'], 'relative_filename': row['relative_filename'],
            **({'url': row['url'], 'relative_filename': row['relative_filename']} if action == 'start' else {}),
            **({k: copy.deepcopy(row[k]) for k in ('route', 'page_binding', 'response_token', 'url', 'method', 'expires_at', 'source_root')}
               if row.get('route') == 'page_response' else {}),
            **({'blob_download_version':1, **{k:copy.deepcopy(row[k]) for k in ('route','source_binding','observation_id','target_id','intended_filename','source_root')}}
               if row.get('route') == 'profile_api_blob' else {})
        }, timeout=timeout if action in ('state', 'cancel') else 10)

    def _previous_claim_terminal(self, row):
        binding = row.get('page_binding') or {}
        with self.broker.lock:
            claim = getattr(self.broker, 'claims', {}).get(binding.get('claim_id'))
            if not claim: return False
            terminal = self.broker._binding(claim)
            return (claim.get('state') in ('released','revoked','target_closed')
                and claim.get('cleanup_state') in ('completed','target_gone')
                and claim.get('debuggerAttached') is False and claim.get('input_eligible') is False
                and type(terminal.get('claim_epoch')) is int and terminal['claim_epoch'] > binding['claim_epoch']
                # durableTarget intentionally omits origin. This predicate only
                # retires a terminal observer; original page bindings still match
                # in full, and no input or fresh admission authority is restored.
                and ('origin' not in claim['target'] or claim['target']['origin'] == binding['origin'])
                and all(terminal.get(k) == value for k, value in binding.items()
                    if k not in ('peer_id','worker_generation','trust_id','claim_epoch','origin')))

    def _accept(self, row, result, *, persist=True, worker_generation=None, terminal_claim=False):
        data = result.get('download')
        if not isinstance(data, dict):
            raise ProtocolError('download_record_required')
        for key in ('download_id', 'owner_session', 'installation_id', 'profile_id', 'context_id',
                    'context_kind', 'nonce', 'original_request_id', 'relative_filename'):
            wanted = row['request_id'] if key == 'original_request_id' else row[key]
            if key == 'relative_filename' and row.get('route') == 'profile_api_blob': continue
            if data.get(key) != wanted:
                raise ProtocolError('download_record_binding')
        identifier = data.get('browser_download_id')
        if identifier is not None and (type(identifier) is not int or not 0 <= identifier <= 2**31 - 1):
            raise ProtocolError('download_browser_id')
        if row.get('browser_download_id') is not None and identifier != row['browser_download_id']:
            raise ProtocolError('download_browser_id_changed')
        state = data.get('producer_state')
        if state not in ('intent', 'attempted', 'unknown', 'in_progress', 'complete', 'interrupted', 'gone'):
            raise ProtocolError('download_state')
        if state in ('in_progress', 'complete', 'interrupted') and identifier is None:
            raise ProtocolError('download_missing_returned_id')
        for key in ('bytes_received', 'file_size', 'total_bytes'):
            value = data.get(key, -1)
            if type(value) is not int or not -1 <= value <= 2**53 - 1:
                raise ProtocolError('download_byte_metadata')
        filename = data.get('filename')
        if filename is not None and (not isinstance(filename, str) or len(filename.encode()) > 8192 or '\0' in filename):
            raise ProtocolError('download_filename')
        if identifier is not None:
            if row.get('route', 'profile_api_get') != 'page_response' and data.get('by_extension_id') != self.broker.expected['extension_id']:
                raise ProtocolError('download_extension_binding')
            if type(data.get('private')) is not bool or data['private'] != (row['context_kind'] == 'private'):
                raise ProtocolError('download_private_binding')
        if row.get('route') == 'page_response':
            if row['context_kind'] == 'private' and data.get('private') is not True:
                raise ProtocolError('download_private_binding')
            guid = (data.get('response') or {}).get('page_guid') if isinstance(data.get('response'), dict) else None
            if any(other['download_id'] != row['download_id'] and ((identifier is not None and other.get('browser_download_id') == identifier)
                    or guid is not None and other.get('response', {}).get('page_guid') == guid) for other in self.records.values()):
                raise ProtocolError('download_page_identity_reused')
            if (data.get('observer_retirement') == 'cancelled_before_worker_restart'
                    and row.get('observer_retirement') is None
                    and (not terminal_claim or row['runtime_generation'] == self.broker.instance_id
                        or data.get('observer_retirement_worker_generation') != worker_generation
                        or worker_generation == row['page_binding']['worker_generation']
                        or row.get('cancel_requested') is not True
                        or row.get('producer_state') != 'gone'
                        or row.get('observation_state') != 'cancelled_before_response'
                        or row.get('download_persistence') != 'saved'
                        or row.get('cleanup_state') != 'pending'
                        or row.get('capture_state') != 'not_attempted')):
                raise ProtocolError('download_observer_reconciliation')
            self._accept_page(row, data)
        if row.get('route') == 'profile_api_blob': self._accept_blob(row, data)
        error_code = data.get('error_code')
        if error_code is not None and (not isinstance(error_code,str) or len(error_code) > 80): raise ProtocolError('download_error_metadata')
        persistence = data.get('download_persistence')
        cleanup = data.get('cleanup_state')
        if persistence is not None and persistence not in ('saved','unknown'): raise ProtocolError('download_persistence_metadata')
        if cleanup is not None and cleanup not in ('pending','unknown','settled'): raise ProtocolError('download_cleanup_metadata')
        if 'producer_cancel_evidence' in data:
            row['producer_cancel_evidence']=merge_cancel_evidence(row.get('producer_cancel_evidence'),data['producer_cancel_evidence'],row['download_id'],row['context_kind'],identifier)
        if persistence is not None: row['download_persistence'] = persistence
        if cleanup is not None: row['cleanup_state'] = cleanup
        row.update(error_code=error_code, browser_download_id=identifier, producer_state=state, filename=filename,
            bytes_received=data.get('bytes_received', -1), total_bytes=data.get('total_bytes', -1),
            file_size=data.get('file_size', -1), checked_at=time.time())
        normalize_cancel_evidence(row)
        if row.get('cancel_state') in ('pending', 'unknown') and state in ('interrupted', 'gone', 'complete') and row.get('download_persistence') != 'unknown' and row.get('cleanup_state') not in ('pending','unknown'):
            row['cancel_state'] = 'settled'
        if persist: self._save()

    @staticmethod
    def _accept_page(row, data):
        for key in ('route', 'page_binding', 'response_token', 'method', 'expires_at', 'source_root'):
            if data.get(key) != row.get(key): raise ProtocolError('download_page_binding')
        if 'admission_diagnostics' in data:
            row['admission_diagnostics'] = diagnostic_projection(data['admission_diagnostics'], 4)
        observation = data.get('observation_state', 'unknown')
        if not isinstance(observation, str) or not re.fullmatch('[a-z_]{1,80}', observation):
            raise ProtocolError('download_observation_state')
        retirement = data.get('observer_retirement')
        if row.get('observer_retirement') is not None and retirement != row['observer_retirement']:
            raise ProtocolError('download_observer_retirement_changed')
        retirement_worker = data.get('observer_retirement_worker_generation')
        if retirement == 'cancelled_before_worker_restart' and data.get('download_persistence') not in ('saved','unknown'):
            raise ProtocolError('download_observer_persistence')
        if (retirement_worker is not None and (retirement != 'cancelled_before_worker_restart'
                or not isinstance(retirement_worker, str) or not re.fullmatch('[0-9a-f]{32}', retirement_worker)
                or retirement_worker == row['page_binding']['worker_generation'])
                or retirement == 'cancelled_before_worker_restart' and retirement_worker is None
                or row.get('observer_retirement_worker_generation') is not None
                    and retirement_worker != row['observer_retirement_worker_generation']):
            raise ProtocolError('download_observer_reconciliation')
        if retirement is not None:
            # An authenticated scoped witness settles the observer, never HTTP
            # effects. It cannot erase a previously consumed response or ID.
            if (retirement not in ('cancelled_while_armed','cancelled_before_worker_restart') or data.get('cancel_requested') is not True
                    or data.get('producer_state') != 'gone' or observation != 'cancelled_before_response'
                    or any(data.get(k) is not None or row.get(k) is not None
                           for k in ('response','token_filename','browser_download_id'))
                    or SelectedDownloads.page_ambiguity(row) or data.get('ambiguity_reason') is not None):
                raise ProtocolError('download_observer_retirement')
        incoming_barrier = data.get('ambiguity_reason')
        if incoming_barrier is not None and incoming_barrier not in ('ambiguous_page_guid', 'ambiguous_download_id'):
            raise ProtocolError('download_ambiguity_reason')
        barrier = SelectedDownloads.page_ambiguity(row) or incoming_barrier or (
            observation if observation.startswith('ambiguous_') else None)
        if barrier:
            row['ambiguity_reason'] = barrier; row['cancel_requested'] = True
        row['observation_state'] = barrier or observation
        if retirement is not None:
            row['observer_retirement'] = retirement; row['cancel_requested'] = True
            if retirement_worker is not None: row['observer_retirement_worker_generation'] = retirement_worker
        response = data.get('response')
        if response is None:
            if data.get('browser_download_id') is not None: raise ProtocolError('download_page_provenance')
            return
        allowed = {'fetch_request_id', 'network_request_id', 'frame_id', 'session_id', 'status_code',
                   'resource_type', 'original_filename', 'page_guid', 'continuation_state', 'id_observed'}
        fetch_only = isinstance(response, dict) and response.get('request_binding') == 'fetch_response_only_v1'
        if fetch_only:
            allowed = allowed | {'request_binding'}
        if (not isinstance(response, dict) or set(response) != allowed
                or any(not isinstance(response[k], str) or not 0 < len(response[k]) <= 256
                       for k in ('fetch_request_id', 'frame_id', 'original_filename'))
                or (response['network_request_id'] is not None if fetch_only else
                    not isinstance(response['network_request_id'], str) or not 0 < len(response['network_request_id']) <= 256)
                or response['resource_type'] != 'Document'
                or response['frame_id'] != row['page_binding']['frame_id'] or response['session_id'] is not None
                or type(response['status_code']) is not int or not 200 <= response['status_code'] <= 299
                or response['continuation_state'] not in ('not_attempted', 'attempted', 'acknowledged', 'unknown', 'unmodified')
                or type(response['id_observed']) is not bool
                or response['page_guid'] is not None and (not isinstance(response['page_guid'], str)
                    or not re.fullmatch('[0-9a-fA-F-]{36}', response['page_guid']))
                or any(c in response['original_filename'] for c in '/\\<>:"|?*')
                or len(response['original_filename'].encode()) > 240
                or not re.search(r'\.[A-Za-z0-9]{1,16}$', response['original_filename'])
                or response['original_filename'].startswith('.') or response['original_filename'].strip() != response['original_filename']
                or response['original_filename'].endswith('.')
                or any(ord(c) < 32 or ord(c) == 127 for c in response['original_filename'])):
            raise ProtocolError('download_page_provenance')
        extension = re.search(r'\.[A-Za-z0-9]{1,16}$', response['original_filename']).group(0)
        if data.get('token_filename') != row['response_token'] + extension:
            raise ProtocolError('download_response_token')
        previous = row.get('response')
        if previous:
            if set(previous) != set(response):
                raise ProtocolError('download_response_changed')
            for key in allowed - {'page_guid', 'continuation_state', 'id_observed'}:
                if response[key] != previous[key]: raise ProtocolError('download_response_changed')
            if previous['page_guid'] and previous['page_guid'] != response['page_guid']:
                raise ProtocolError('download_guid_changed')
            if previous['id_observed'] and not response['id_observed']: raise ProtocolError('download_id_changed')
        if data.get('browser_download_id') is not None and (not response['id_observed']
                or response['continuation_state'] not in ('attempted', 'acknowledged', 'unknown')):
            raise ProtocolError('download_page_provenance')
        if previous and previous['continuation_state'] in ('acknowledged', 'unknown', 'unmodified') and response['continuation_state'] != previous['continuation_state']:
            raise ProtocolError('download_continuation_changed')
        row['token_filename'] = data['token_filename']
        row['response'] = copy.deepcopy(response)
        row['observation_state'] = barrier or observation

    def observe(self, peer, packet):
        """Save exact response identity before authorizing a single header continuation."""
        nonce = packet.get('ack_nonce')
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
            raise ProtocolError('download_observation_shape')
        try:
            self.message(peer, packet)
            row = self.records[packet['download']['download_id']]
            self._page_current(row)
            with self.lock:
                if row.get('cancel_requested') or row['owner_session'] in self.fences:
                    raise WorkbenchError('download_admission_stopped', 'Original admission ended.', effect_state='none')
            peer.send({'type': 'managed_download_observation_result', 'ack_nonce': nonce, 'ok': True})
        except (WorkbenchError, OSError, ProtocolError) as error:
            peer.send({'type': 'managed_download_observation_result', 'ack_nonce': nonce, 'ok': False,
                       'error': {'code': getattr(error, 'code', 'download_observation_unsaved')}})

    def message(self, peer, packet):
        if type(packet.get('managed_download_version')) is not int or packet['managed_download_version'] != 1 or not isinstance(packet.get('download'), dict):
            raise ProtocolError('download_message')
        data = packet['download']
        with self.broker.lock, self.lock:
            row = self.records.get(data.get('download_id'))
            if not row:
                raise ProtocolError('download_unknown_intent')
            if (peer.identity['profile_id'] != row['profile_id'] or peer.identity['context_id'] != row['context_id']
                    or peer.identity['private_context'] != (row['context_kind'] == 'private')):
                raise ProtocolError('download_message_peer')
            if (row.get('route') in ('page_response','profile_api_blob') and row.get('browser_download_id') is None
                    and data.get('browser_download_id') is not None
                    and peer.identity.get('worker_generation') != (row.get('page_binding') or row.get('source_binding'))['worker_generation']):
                raise ProtocolError('download_worker_changed')
            self._accept(row, {'download': data}, worker_generation=peer.identity.get('worker_generation'),
                terminal_claim=self._previous_claim_terminal(row))

    @staticmethod
    def _public(row):
        result = {k:copy.deepcopy(v) for k,v in row.items() if k not in ('url','nonce')}
        if 'producer_cancel_evidence' in result:
            result['producer_cancel_evidence']=cancel_projection(result['producer_cancel_evidence'],row['download_id'],row['context_kind'],row.get('browser_download_id'))
        result['producer_cancel_evidence_status']=result.get('producer_cancel_evidence',{}).get('coverage','not_recorded')
        if row.get('route') == 'profile_api_blob' and result.get('blob_source'):
            href = result['blob_source'].pop('href')
            result['blob_source']['href_sha256'] = hashlib.sha256(href.encode()).hexdigest()
        return result

    def inspect_saved(self, workspace, owner_session, download_id):
        """Read only an already retained, owner-bound record; never consult a producer.

        Intentionally uses a strict scalar allowlist. Nested producer payloads,
        paths, tokens, URLs, and content are never traversed or serialized.
        """
        if not isinstance(owner_session, str) or not 0 < len(owner_session) <= 128:
            raise WorkbenchError('download_owner_required', 'Supply the exact original owner.', effect_state='none')
        if not isinstance(download_id, str) or not re.fullmatch(r'[0-9a-f]{32}', download_id):
            raise WorkbenchError('download_id_required', 'Supply the exact original download ID.', effect_state='none')
        with self.lock:
            row = self.records.get(download_id)
            if not isinstance(row, dict) or row.get('owner_session') != owner_session or row.get('workspace') != workspace:
                raise WorkbenchError('download_owner_mismatch', 'No saved download matches this owner, workspace and ID.', effect_state='none')
            # No _public(), no producer command, no filesystem stat and no _save().
            def scalar(key, allowed):
                value = row.get(key)
                return value if type(value) is str and value in allowed else 'unknown'
            # A durable close obligation is not a producer heartbeat. In
            # particular, reboot/runtime/cache changes do not rule out a
            # browser resuming its original download. This projection conveys
            # no retirement authority and never updates original receipts.
            reasons = []
            if (row.get('route') == 'page_response' and
                    (type(row.get('ambiguity_reason')) is str and bool(row['ambiguity_reason'])
                     or type(row.get('observation_state')) is str
                        and row['observation_state'].startswith('ambiguous_'))):
                reasons.append('page_identity_ambiguous')
            if scalar('producer_state', {'complete','interrupted','gone'}) == 'unknown':
                reasons.append('producer_unsettled')
            for key, values, reason in (
                    ('download_persistence', ('unknown',), 'persistence_unknown'),
                    ('cleanup_state', ('pending','unknown'), 'cleanup_unsettled'),
                    ('capture_state', ('finalizing','unknown'), 'capture_unsettled'),
                    ('cancel_state', ('pending','unknown'), 'cancel_unsettled')):
                if type(row.get(key)) is str and row[key] in values:
                    reasons.append(reason)
            local_capture = download_id in getattr(self, 'finalizing', ())
            if local_capture:
                reasons.append('local_capture_in_progress')
            return {
                'ok': True, 'evidence_kind': 'saved_stale_not_live',
                'live_checked': False, 'filesystem_bytes_verified': False,
                'original_owner_session': owner_session, 'workspace': workspace,
                'download_id': download_id,
                'producer_state': scalar('producer_state',
                    {'intent','attempted','in_progress','complete','interrupted','gone','unknown'}),
                'capture_state': scalar('capture_state',
                    {'not_attempted','finalizing','verified','unknown'}),
                'cancel_state': scalar('cancel_state', {'not_requested','pending','unknown','settled'}),
                'native_download_id_known': type(row.get('browser_download_id')) is int
                    and 0 <= row['browser_download_id'] <= 2**31 - 1,
                'download_persistence': scalar('download_persistence', {'saved','unknown'}),
                'cleanup_state': scalar('cleanup_state', {'pending','unknown','settled'}),
                'route': scalar('route', {'profile_api_get','page_response','profile_api_blob'}),
                'metadata_scope': 'allowlisted_saved_scalars_only',
                'unknown_fields': 'not_inferred',
                'lifecycle': {
                    'authority': 'diagnostic_only',
                    'scope': 'saved_record_and_local_capture_only',
                    'blocks_owner_close': bool(reasons),
                    'blocking_reasons': reasons,
                    'local_capture_in_progress': local_capture,
                    'external_producer_liveness': 'not_checked',
                    'retirement_evidence': 'independent_receipt_not_recorded',
                    'retirement_allowed': False,
                    'required_evidence': ('original_bound_producer_reconciliation'
                        if any(reason != 'local_capture_in_progress' for reason in reasons)
                        else 'local_capture_completion' if local_capture else 'not_required'),
                },
            }

    def operation(self, workspace, action='state', *, request_id=None, download_id=None,
                  profile_id=None, context_id=None, context_kind='ordinary', url=None,
                  source_workspace=None, destination=None, expected_sha256=None, max_bytes=8192,
                  claim_id=None, claim_epoch=None, target_generation=None, expected_generation=None,
                  expected_origin=None, frame_id=None, method='GET', observation_id=None, target_id=None, filename=None):
        owner = work_context.get()
        if not owner:
            raise WorkbenchError('work_session_required', 'Use a durable work session for managed downloads.', effect_state='none')
        self.broker.config.workspace(workspace)
        if action not in ('start', 'arm', 'start_blob', 'state', 'cancel', 'stop', 'capture', 'publish'):
            raise WorkbenchError('invalid_download_action', 'Use start, state, cancel, stop, capture or publish.', effect_state='none')
        if action == 'start_blob':
            if url is not None or context_kind != 'ordinary':
                raise WorkbenchError('invalid_blob_source', 'Select an ordinary observed anchor; arbitrary URL initiation is unavailable.', effect_state='none')
            return self._start_blob(workspace, owner, request_id, claim_id=claim_id, claim_epoch=claim_epoch,
                target_generation=target_generation, expected_generation=expected_generation, expected_origin=expected_origin,
                frame_id=frame_id, observation_id=observation_id, target_id=target_id, intended_filename=filename, source_workspace=source_workspace)
        if action == 'arm':
            from .selected_tabs import origin, valid_id
            if (not valid_id(claim_id) or type(claim_epoch) is not int or type(expected_generation) is not int
                    or method not in ('GET', 'POST') or not isinstance(url, str) or len(url.encode()) > 8192):
                raise WorkbenchError('invalid_download_arm', 'Use an exact durable claim, document and HTTP GET/POST response.', effect_state='none')
            try: origin(url)
            except (ProtocolError, ValueError) as error:
                raise WorkbenchError('invalid_download_arm', 'Use a bounded HTTP(S) URL.', effect_state='none') from error
            self.broker.journal.validate_id(request_id)
            identifier = hashlib.sha256(('selected-download:' + owner + ':' + request_id).encode()).hexdigest()[:32]
            with self.lock:
                admitted = copy.deepcopy(self.records.get(identifier))
            if admitted is not None:
                b = admitted.get('page_binding', {})
                wanted = {'claim_id': claim_id, 'claim_epoch': claim_epoch, 'target_generation': target_generation,
                    'document_epoch': expected_generation, 'origin': expected_origin, 'frame_id': frame_id}
                if (admitted.get('route') != 'page_response' or admitted['owner_session'] != owner
                        or admitted['workspace'] != workspace or admitted['request_id'] != request_id
                        or any(b.get(k) != v for k, v in wanted.items()) or admitted['url'] != url
                        or admitted['method'] != method or admitted['source_root']['workspace'] != source_workspace):
                    raise WorkbenchError('request_conflict', 'This request_id was admitted with different arguments.', effect_state='none')
                original_payload = {'tool': 'selected_download', 'workspace': workspace, 'owner': owner, 'action': action,
                    'page_binding': b, 'url': url, 'method': method, 'source_workspace': source_workspace}
                def never_rearm():
                    raise WorkbenchError('download_admission_unknown', 'Recover the original intent; it cannot be rearmed.', effect_state='unknown')
                return self.broker.journal.run(request_id, original_payload, never_rearm, resource='managed-arm:' + claim_id)
            with self.broker.lock:
                claim = self.broker.claims.get(claim_id)
                if not claim or claim['owner_session'] != owner:
                    raise WorkbenchError('download_claim_changed', 'Use this task’s current durable claim.', effect_state='none')
                binding = copy.deepcopy(self.broker._binding(claim))
                peer = self.broker.peers.get(binding['peer_id'])
                trust = self.broker.trust_records.get(getattr(peer, 'trust_key', None), {})
                if (binding['claim_epoch'] != claim_epoch or binding['target_generation'] != target_generation
                        or binding['document_epoch'] != expected_generation or binding['origin'] != expected_origin
                        or binding['frame_id'] != frame_id or binding['context_kind'] not in ('ordinary','private')):
                    raise WorkbenchError('download_claim_changed', 'Use the current exact root frame and document.', effect_state='none')
                binding.update(worker_generation=peer.identity.get('worker_generation') if peer else None, trust_id=trust.get('trust_id'))
            self._page_current({'page_binding': binding})
            self.broker.journal.validate_id(request_id)
            payload = {'tool': 'selected_download', 'workspace': workspace, 'owner': owner, 'action': action,
                'page_binding': binding, 'url': url, 'method': method, 'source_workspace': source_workspace}
            identifier = hashlib.sha256(('selected-download:' + owner + ':' + request_id).encode()).hexdigest()[:32]
            def arm():
                if not source_workspace or not self.files:
                    raise WorkbenchError('download_folder_access_required', 'Select an already approved incoming workspace.', effect_state='none')
                descriptor = self.files._root_descriptor(source_workspace)
                try: root_stat = os.fstat(descriptor)
                finally: os.close(descriptor)
                self._page_current({'page_binding': binding})
                with self.lock:
                    if owner in self.fences: raise WorkbenchError('download_admission_stopped', 'Task downloads were stopped.', effect_state='none')
                    if identifier in self.records: raise WorkbenchError('download_admission_unknown', 'Recover the original intent.', effect_state='unknown')
                    if len(self.active_ids()) >= self.LIMIT or len(self.records) >= self.HISTORY_LIMIT:
                        raise WorkbenchError('download_resource_limit', 'Reconcile pending downloads first.', effect_state='none')
                    if any(r.get('route') == 'page_response' and r.get('page_binding', {}).get('claim_id') == claim_id
                           and self.unsettled(r) for r in self.records.values()):
                        raise WorkbenchError('download_arm_pending', 'Reconcile this claim’s original scoped observation.', effect_state='none')
                    row = {'download_id': identifier, 'owner_session': owner, 'workspace': workspace, 'request_id': request_id,
                        'installation_id': self.broker.install_id, 'runtime_generation': self.broker.instance_id,
                        'profile_id': binding['profile_id'], 'context_id': binding['context_id'], 'context_kind': binding['context_kind'],
                        'nonce': uuid.uuid4().hex, 'relative_filename': 'LocalWorkbench/' + identifier + '.download',
                        'route': 'page_response', 'page_binding': binding, 'url': url, 'method': method,
                        'response_token': 'workbench-owned-' + uuid.uuid4().hex,
                        'expires_at': time.time() + 30, 'created_at': time.time(), 'producer_state': 'intent',
                        'browser_download_id': None, 'capture_state': 'not_attempted', 'cancel_state': 'not_requested',
                        'source_root': {'workspace': source_workspace, 'dev': root_stat.st_dev, 'inode': root_stat.st_ino}}
                    self.records[identifier] = row; self._save()
                try:
                    result = self._command(row, 'arm', peer=peer, trust=trust)
                    with self.lock: self._accept(row, result)
                except BaseException:
                    with self.lock: row['producer_state'] = 'unknown'; self._save()
                    raise
                return {'ok': True, 'download': self._public(row), 'bytes_captured': False,
                    'scope': 'one_scoped_next_http_attachment_response', 'causal_action_attribution': False}
            return self.broker.journal.run(request_id, payload, arm, resource='managed-arm:' + claim_id,
                initial_checkpoint={'download_id': identifier, 'effect_state': 'unknown', 'phase': 'before_response_observation'})
        if action == 'start':
            from .selected_tabs import origin, valid_id
            if not all(valid_id(x) for x in (profile_id, context_id)) or context_kind not in ('ordinary', 'private'):
                raise WorkbenchError('download_profile_required', 'Select the exact paired profile/context.', effect_state='none')
            origin(url)
            if not isinstance(url, str) or len(url.encode()) > 8192:
                raise WorkbenchError('invalid_download_url', 'Use a bounded HTTP(S) URL.', effect_state='none')
            self.broker.journal.validate_id(request_id)
            payload = {'tool': 'selected_download', 'workspace': workspace, 'owner': owner, 'action': action,
                'profile_id': profile_id, 'context_id': context_id, 'context_kind': context_kind, 'url': url,
                'source_workspace': source_workspace}
            identifier = hashlib.sha256(('selected-download:' + owner + ':' + request_id).encode()).hexdigest()[:32]
            def start():
                with self.lock:
                    if owner in self.fences:
                        raise WorkbenchError('download_admission_stopped', 'This task has stopped new downloads.', effect_state='none')
                peer, trust = self._peer(profile_id, context_id, context_kind, starting=True)
                if context_kind == 'private':
                    raise WorkbenchError('private_download_unverified', 'Private download routing has not been qualified; no request started.', effect_state='none')
                if not source_workspace or not self.files:
                    raise WorkbenchError('download_folder_access_required', 'Select an already approved incoming workspace before initiation.', effect_state='none')
                descriptor = self.files._root_descriptor(source_workspace)
                try: root_stat = os.fstat(descriptor)
                finally: os.close(descriptor)
                with self.lock:
                    if identifier in self.records:
                        raise WorkbenchError('download_admission_unknown', 'Recover the original intent; do not start again.', effect_state='unknown', download_id=identifier)
                    if owner in self.fences:
                        raise WorkbenchError('download_admission_stopped', 'This task has stopped new downloads.', effect_state='none')
                    if len(self.active_ids()) >= self.LIMIT or len(self.records) >= self.HISTORY_LIMIT:
                        raise WorkbenchError('download_resource_limit', 'Reconcile pending downloads before admitting more.', effect_state='none')
                    row = {'download_id': identifier, 'owner_session': owner, 'workspace': workspace,
                        'request_id': request_id, 'installation_id': self.broker.install_id,
                        'profile_id': profile_id, 'context_id': context_id, 'context_kind': context_kind,
                        'runtime_generation': self.broker.instance_id, 'nonce': uuid.uuid4().hex,
                        # An extension in a filename suggestion can be rewritten
                        # by Chrome from the response MIME type. Keep the owned
                        # staging name extensionless and require that exact path.
                        'url': url, 'relative_filename': 'LocalWorkbench/' + identifier,
                        'producer_state': 'intent', 'browser_download_id': None, 'capture_state': 'not_attempted',
                        'cancel_state': 'not_requested', 'created_at': time.time(), 'route': 'profile_api_get'}
                    row['source_root'] = {'workspace': source_workspace,
                        'dev': root_stat.st_dev, 'inode': root_stat.st_ino}
                    self.records[identifier] = row
                    self._save()
                try:
                    result = self._command(row, 'start', peer=peer, trust=trust)
                    with self.lock: self._accept(row, result)
                except BaseException:
                    with self.lock:
                        if row['producer_state'] == 'intent': row['producer_state'] = 'unknown'
                        self._save()
                    raise
                return {'ok': True, 'download': self._public(row), 'bytes_captured': False}
            return self.broker.journal.run(request_id, payload, start, resource='managed-start:' + context_id,
                initial_checkpoint={'download_id': identifier, 'effect_state': 'unknown', 'phase': 'before_original_download'})
        if action == 'stop':
            self.broker.journal.validate_id(request_id)
            payload = {'tool': 'selected_download', 'workspace': workspace, 'owner': owner, 'action': 'stop'}
            def stop():
                with self.lock:
                    if owner not in self.fences and len(self.fences) >= self.HISTORY_LIMIT:
                        raise WorkbenchError('download_history_limit', 'Retained Stop fences require reconciliation.', effect_state='none')
                    self.fences.add(owner)
                    rows = [row for row in self.records.values() if row['owner_session'] == owner and self.unsettled(row)]
                    for row in rows: row['cancel_requested'] = True; row['cancel_state'] = 'pending'
                    self._save()
                outcomes = []
                deadline = time.monotonic() + 2
                for row in rows:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        with self.lock: row['cancel_state'] = 'unknown'; self._save()
                        outcomes.append({'download_id': row['download_id'], 'cleanup': 'unknown', 'reason': 'stop_control_budget'})
                        continue
                    try:
                        result = self._command(row, 'cancel', timeout=remaining)
                        with self.lock: self._accept(row, result)
                    except (WorkbenchError, OSError, ProtocolError) as error:
                        with self.lock: row['cancel_state'] = 'unknown'; self._save()
                        outcomes.append({'download_id': row['download_id'], 'cleanup': 'unknown', 'reason': getattr(error, 'code', type(error).__name__)})
                    else: outcomes.append({'download_id': row['download_id'], 'producer_state': row['producer_state']})
                return {'ok': True, 'admission_stopped': True, 'outcomes': outcomes, 'remaining': self.active_ids(owner)}
            return self.broker.journal.run(request_id, payload, stop, resource='managed-stop:' + owner)
        with self.lock:
            row = self._record(download_id, owner)
            if row['workspace'] != workspace:
                raise WorkbenchError('download_workspace_mismatch', 'Use the original task workspace.', effect_state='none')
            if action == 'capture' and not source_workspace:
                admitted = row.get('source_root') or {}
                hint = ({'admitted_source_workspace': admitted['workspace']}
                    if admitted.get('workspace') else {})
                raise WorkbenchError('download_source_workspace_required',
                    'For capture, keep workspace as the original task workspace and explicitly set '
                    'source_workspace to the original admitted incoming workspace, even when supplied to arm/start.',
                    effect_state='none', **hint)
        if action == 'state':
            with self.lock:
                before = copy.deepcopy(row)
            try:
                peer, trust = self._peer(row['profile_id'], row['context_id'], row['context_kind'])
                worker_generation = peer.identity.get('worker_generation')
                result = self._command(row, 'state', peer=peer, trust=trust)
                with self.broker.lock, self.lock:
                    data = result.get('download')
                    previous_response = before.get('response') or {}
                    current_response = row.get('response') or {}
                    incoming_response = data.get('response') if isinstance(data, dict) else None
                    current_guid = current_response.get('page_guid')
                    incoming_guid = incoming_response.get('page_guid') if isinstance(incoming_response, dict) else None
                    if current_guid is not None and incoming_guid is not None and incoming_guid != current_guid:
                        raise ProtocolError('download_guid_changed')
                    id_superseded = (before.get('browser_download_id') is None
                            and row.get('browser_download_id') is not None
                            and isinstance(data, dict) and data.get('browser_download_id') is None)
                    guid_superseded = (row.get('route') == 'page_response'
                            and isinstance(incoming_response, dict)
                            and previous_response.get('page_guid') is None
                            and current_guid is not None and incoming_guid is None
                            and before.get('browser_download_id') == row.get('browser_download_id')
                            and data.get('browser_download_id') == row.get('browser_download_id'))
                    retirement_superseded = (row.get('route') == 'page_response'
                            and before.get('observer_retirement') is None
                            and row.get('observer_retirement') in ('cancelled_while_armed','cancelled_before_worker_restart')
                            and isinstance(data, dict) and data.get('observer_retirement') is None
                            and not self.page_ambiguity(before)
                            and isinstance(data.get('observation_state', 'unknown'), str)
                            and not self.page_ambiguity(data)
                            and all(snapshot.get(key) is None for snapshot in (before, data)
                                    for key in ('response', 'browser_download_id', 'token_filename')))
                    completion_superseded = (before.get('producer_state') == 'in_progress'
                            and row.get('producer_state') == 'complete'
                            and isinstance(data, dict) and data.get('producer_state') == 'in_progress'
                            and row.get('browser_download_id') is not None
                            and before.get('browser_download_id') == row['browser_download_id'] == data.get('browser_download_id')
                            and isinstance(data.get('observation_state', 'unknown'), str)
                            and not any(self.page_ambiguity(snapshot) for snapshot in (before, row, data))
                            and data.get('download_persistence') != 'unknown'
                            and data.get('cleanup_state') not in ('pending', 'unknown')
                            and data.get('error_code') is None)
                    if id_superseded or guid_superseded or retirement_superseded or completion_superseded:
                        # A native event can bind identity or retire an unused
                        # observer, or complete the same original download,
                        # after an older reply was serialized. Validate that
                        # snapshot without replacing the newer durable row.
                        # Completion never suppresses new ambiguity or cleanup
                        # uncertainty, and interrupted downloads may resume.
                        self._accept(before, result, persist=False)
                        return {'ok': True, 'download': self._public(row), 'live_check': False,
                            'unavailable_reason': 'download_state_superseded',
                            'bytes_captured': row.get('artifact') is not None}
                    self._accept(row, result, worker_generation=worker_generation, terminal_claim=self._previous_claim_terminal(row))
            except WorkbenchError as error:
                return {'ok': True, 'download': self._public(row), 'live_check': False,
                    'unavailable_reason': error.code, 'bytes_captured': row.get('artifact') is not None}
            return {'ok': True, 'download': self._public(row), 'live_check': True,
                'bytes_captured': row.get('artifact') is not None}
        self.broker.journal.validate_id(request_id)
        payload = {'tool': 'selected_download', 'workspace': workspace, 'owner': owner, 'action': action,
            'download_id': download_id, 'source_workspace': source_workspace,
            'destination': destination, 'expected_sha256': expected_sha256}
        def perform():
            with self.lock:
                self._record(download_id, owner)
                if action == 'cancel':
                    row['cancel_requested'] = True
                    row['cancel_state'] = 'pending'; self._save()
            if action == 'cancel':
                try:
                    result = self._command(row, 'cancel')
                    with self.lock: self._accept(row, result)
                except BaseException:
                    with self.lock: row['cancel_state'] = 'unknown'; self._save()
                    raise
                return {'ok': True, 'download': self._public(row), 'bytes_captured': row.get('artifact') is not None}
            if action == 'capture':
                return self._capture(row, source_workspace, max_bytes)
            with self.lock:
                if row.get('route') == 'page_response' and self.page_ambiguity(row):
                    raise WorkbenchError('download_page_provenance', 'Ambiguous original response identity requires reconciliation.', effect_state='none')
            artifact = row.get('artifact')
            if row.get('capture_state') != 'verified' or not artifact:
                raise WorkbenchError('download_bytes_unverified', 'Capture the original completed file first.', effect_state='none')
            from .capability_profiles import CapabilityPolicy
            CapabilityPolicy(self.broker.config.capability_profile, self.broker.config.history_access).check('write_file')
            result = self.files.write_file(workspace, destination, request_id + ':publish',
                expected_sha256=expected_sha256, artifact_id=artifact['artifact_id'])
            return {'ok': True, 'download_id': download_id, 'artifact': artifact, 'publication': result}
        return self.broker.journal.run(request_id, payload, perform,
            resource=('managed-control:' if action == 'cancel' else 'managed:') + download_id,
            initial_checkpoint={'download_id': download_id, 'phase': action, 'effect_state': 'unknown'})

    def _capture(self, row, source_workspace, max_bytes):
        if type(max_bytes) is not int or not 0 <= max_bytes <= 16384:
            raise WorkbenchError('invalid_limit', 'Use an integer preview budget from 0 to 16384 bytes.', effect_state='none')
        result = self._command(row, 'state')
        with self.lock:
            self._accept(row, result)
            if row.get('route') == 'page_response' and self.page_ambiguity(row):
                raise WorkbenchError('download_page_provenance', 'Ambiguous original response identity requires reconciliation.', effect_state='none')
            if row['producer_state'] != 'complete' or not row.get('filename'):
                raise WorkbenchError('download_not_complete', 'The original browser download is not complete.', effect_state='none')
            if not self.files:
                raise WorkbenchError('download_folder_access_required', 'Configure the incoming folder in Workbench Folder access.', effect_state='none')
            root = self.broker.config.workspace(source_workspace).root
            admitted = row.get('source_root')
            if not admitted or admitted['workspace'] != source_workspace:
                raise WorkbenchError('download_folder_access_required', 'Use the original admitted incoming workspace.', effect_state='none')
            descriptor = self.files._root_descriptor(source_workspace)
            try: current_root = os.fstat(descriptor)
            finally: os.close(descriptor)
            if (current_root.st_dev, current_root.st_ino) != (admitted['dev'], admitted['inode']):
                raise WorkbenchError('workspace_changed', 'The admitted incoming directory was replaced.', effect_state='none')
            filename = Path(row['filename'])
            try: relative = filename.relative_to(root).as_posix()
            except ValueError:
                raise WorkbenchError('download_folder_access_required', 'The original file is outside this approved folder.', effect_state='none')
            if row.get('route') == 'page_response' and (not row.get('response', {}).get('page_guid')
                    or not row['response'].get('id_observed') or row.get('browser_download_id') is None):
                raise WorkbenchError('download_page_provenance', 'Exact Page GUID and DownloadItem ID are required before capture.', effect_state='none')
            if row.get('route') != 'page_response' and not filename.as_posix().endswith('/' + row['relative_filename']):
                raise WorkbenchError('download_filename_changed', 'The original managed filename changed; no bytes adopted.', effect_state='none')
            self.finalizing.add(row['download_id']); row['capture_state'] = 'finalizing'; self._save()
        try:
            captured = self.files.read_file(source_workspace, relative, max_bytes=min(max_bytes, 16384))
            artifact = self.broker.store.verify(captured['artifact_id'])
            if not artifact['verified'] or artifact['bytes'] != row['file_size']:
                raise WorkbenchError('download_file_changed', 'Observed file bytes differ from the completed download metadata.', effect_state='unknown')
            with self.lock:
                row['artifact'] = {k: captured[k] for k in ('artifact_id', 'sha256', 'total_bytes', 'capture_id')}
                row['capture_state'] = 'verified'; self._save()
            return {'ok': True, 'download_id': row['download_id'], 'artifact': row['artifact'],
                'bytes_captured': True, 'representation': 'stable_downloaded_file_snapshot', 'wire_bytes_claimed': False}
        except BaseException:
            with self.lock: row['capture_state'] = 'unknown'; self._save()
            raise
        finally:
            with self.lock: self.finalizing.discard(row['download_id'])
