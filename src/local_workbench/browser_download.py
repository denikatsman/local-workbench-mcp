"""Private candidate: original downloads in entire Playwright-owned contexts.

No URL fetches, user profiles, ordinary-browser routing or new file writer.
The sole SDK-private field is the original Artifact absolutePath, pinned in
INPUT-PINS.json. CDP progress measures producer bytes, not pending disk size.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path

from .browser import OwnedBrowser, ELEMENT_INFO, safe_url
from .context import work_context
from .errors import WorkbenchError
from .persistence import atomic_json

SDK_DOWNLOAD_PINS = {
    '_impl/_download.py': '064d6807d82b5dcd8094a2f1b910c1d336363bf135200ee194fef1ec3ba75e04',
    '_impl/_artifact.py': '3596db711366248a193c6a0f1be8547034987b7274c949d2ccbe3c6d3198ac71',
    'driver/package/lib/coreBundle.js': '549070af3acabb3efcc4f55bfe6210f9f7c2fcf633cf7eaa59bfe60719969171',
}



class OwnedDownloadBrowser(OwnedBrowser):
    MAX_CACHED_RECEIPTS = 128
    EVENT_SECONDS = 5
    DRAIN_SECONDS = 10

    def __init__(self, config, store, journal, instance_id, files):
        super().__init__(config, store, journal, instance_id)
        self.files = files
        self.download_root = config.state_dir / 'browser-downloads'
        self.download_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.download_spool = self.download_root / ('spool-' + uuid.uuid4().hex)
        self.download_spool.mkdir(mode=0o700)
        self._downloads, self._download_live, self._download_cdp = {}, {}, {}
        self._admissions = set()
        self._admission_ids = {}
        self._receipt_write_lock = None
        self._unarmed_tasks = set()
        self._unarmed_downloads = {}
        self._download_drain_task = None

    def open(self, workspace, url, request_id, width=1280, height=800, profile_id=None, allow_downloads=False):
        if allow_downloads is True:
            self._validate_download_sdk()
        return super().open(workspace, url, request_id, width, height, profile_id, allow_downloads)

    def _bind_page(self, record, page):
        identifier = self._page_id(record, page)
        already_bound = identifier in record['bound_pages']
        super()._bind_page(record, page)
        if already_bound:
            return
        # Bind before the first navigation, including popup pages. The known
        # Download object is the only authority for cancelling its original.
        def route(download):
            captures = [live for live in self._download_live.values()
                if live['record'] is record and live.get('capture_page') is page
                and live.get('download_handler') is not None and not live['task'].done()]
            if len(captures) == 1:
                captures[0]['download_handler'](download)
            else:
                self._track_unarmed_download(record, page, download, 'not_armed')
        page.on('download', route)

    def _track_unarmed_download(self, record, page, download, reason):
        key = id(download)
        if key in self._unarmed_downloads:
            return
        identifier = uuid.uuid4().hex
        receipt = {'download_id': identifier, 'session_id': record['id'],
            'owner_work_session_id': record.get('work_session_id'), 'runtime_instance_id': self.instance_id,
            'page_id': self._page_id(record, page), 'capture_state': 'refused', 'reason': reason,
            'artifact': None, 'bytes_adopted': False, 'cleanup_state': 'pending', 'created_at': time.time()}
        # Persist and track all unresolved resources. Only settled in-memory
        # history may be evicted; its durable receipt is kept.
        for old_key, old in list(self._unarmed_downloads.items()):
            if len(self._unarmed_downloads) < self.MAX_CACHED_RECEIPTS:
                break
            if old['task'].done() and old['receipt']['cleanup_state'] == 'verified':
                self._unarmed_downloads.pop(old_key)
        task = asyncio.create_task(self._cleanup_unarmed_download(download, receipt))
        self._unarmed_downloads[key] = {'download': download, 'receipt': receipt, 'task': task}
        if len(self._unarmed_downloads) >= self.MAX_CACHED_RECEIPTS:
            record['download_closing'] = True
        self._event(record, 'download_refused', download_id=identifier, reason=reason,
                    cleanup_state='pending', bytes_adopted=False)

    async def _cleanup_unarmed_download(self, download, receipt):
        await self._save_receipt(receipt)
        try:
            self._validate_download_sdk()
            await download.cancel()
            receipt['cancel_state'] = 'browser_acknowledged'
            # Delete only the artifact represented by this exact owned SDK
            # Download. Never infer a path from URL, name or directory listing.
            try:
                await download.delete()
                receipt['cleanup_state'] = 'verified'
            except Exception as error:
                # Cancellation can retire the SDK artifact before delete. Only
                # a terminal failure plus absence at this known owned GUID path
                # establishes that there is no retained original to clean.
                failure = await download.failure()
                raw = download._impl_obj._artifact._initializer.get('absolutePath')
                original = Path(raw) if isinstance(raw, str) else None
                if (failure is not None and original is not None
                        and original.parent.resolve() == self.download_spool.resolve()):
                    try:
                        original.lstat()
                    except FileNotFoundError:
                        receipt.update(cleanup_state='verified', original_absent_after_terminal_cancel=True)
                    else:
                        receipt.update(cleanup_state='unverified', cleanup_error_kind=type(error).__name__)
                else:
                    receipt.update(cleanup_state='unverified', cleanup_error_kind=type(error).__name__)
        except Exception as error:
            receipt.update(cleanup_state='unverified', cleanup_error_kind=type(error).__name__)
        await self._save_receipt(receipt)

    async def _drain_unarmed(self, session_id, bounded):
        deadline = asyncio.get_running_loop().time() + self.DRAIN_SECONDS
        while True:
            resources = [row for row in self._unarmed_downloads.values()
                if session_id is None or row['receipt']['session_id'] == session_id]
            tasks = [row['task'] for row in resources if not row['task'].done()]
            if not tasks:
                break
            pending = asyncio.gather(*tasks, return_exceptions=True)
            if not bounded:
                await asyncio.shield(pending)
            else:
                try:
                    await asyncio.wait_for(asyncio.shield(pending), max(0, deadline - asyncio.get_running_loop().time()))
                except asyncio.TimeoutError as error:
                    raise WorkbenchError('browser_download_cleanup_pending',
                        'Owned unarmed download cleanup is still running; retain its context.', effect_state='unknown') from error
            # Events can register a new exact handle while earlier cleanup is
            # awaiting the browser. Recollect instead of trusting that snapshot.
        unresolved = [row for row in resources if row['receipt']['cleanup_state'] != 'verified']
        if unresolved:
            raise WorkbenchError('browser_download_cleanup_unverified',
                'An owned download cleanup could not be verified. Its resource handle remains retained.',
                effect_state='unknown', download_ids=[row['receipt']['download_id'] for row in unresolved[:20]])

    async def _save_receipt(self, receipt):
        if self._receipt_write_lock is None:
            self._receipt_write_lock = asyncio.Lock()
        async with self._receipt_write_lock:
            receipt['updated_at'] = time.time()
            await asyncio.to_thread(atomic_json, self.download_root / (receipt['download_id'] + '.json'), dict(receipt))

    def _receipt(self, download_id):
        if not isinstance(download_id,str) or len(download_id)!=32 or any(c not in '0123456789abcdef' for c in download_id):
            raise WorkbenchError('unknown_download','Use the opaque download_id returned by start.')
        receipt = self._downloads.get(download_id)
        if receipt is None:
            try:
                receipt=json.loads((self.download_root/(download_id+'.json')).read_text())
            except FileNotFoundError:
                raise WorkbenchError('unknown_download', 'Use a retained download_id.') from None
            if receipt['runtime_instance_id']!=self.instance_id and receipt['capture_state'] not in {'complete','interrupted','unknown','refused'}:
                receipt.update(capture_state='unknown', recovered_after_runtime_end=True, error='Runtime ended before finalization; original click must not replay.')
        if work_context.get() != receipt['owner_work_session_id']:
            raise WorkbenchError('work_session_mismatch', 'This download belongs to a different work context.', effect_state='none')
        return receipt

    def _workspace_binding(self, workspace):
        self.files._check_root(workspace)
        info = os.fstat(self.files._roots[workspace])
        return {'workspace_root': str(self.config.workspace(workspace).root),
                'workspace_root_identity': [str(info.st_dev), str(info.st_ino)]}

    def _verify_publication_source(self, receipt):
        binding = self._workspace_binding(receipt['workspace'])
        if any(receipt.get(key) != value for key, value in binding.items()):
            raise WorkbenchError('download_workspace_changed',
                'This retained download belongs to a different original workspace directory.', effect_state='none')
        artifact = receipt.get('artifact')
        if (not isinstance(artifact, dict) or artifact.get('artifact_id') != 'sha256:' + str(artifact.get('sha256'))
                or type(artifact.get('bytes')) is not int or artifact['bytes'] < 0):
            raise WorkbenchError('download_artifact_unverified', 'The retained download descriptor is invalid.', effect_state='none')
        verified = self.store.verify(artifact['artifact_id'])
        if not verified['verified'] or verified['bytes'] != artifact['bytes']:
            raise WorkbenchError('download_artifact_unverified',
                'The retained bytes no longer match the original download snapshot.', effect_state='none')
        return binding

    @staticmethod
    def _validate_download_sdk():
        import playwright
        package = Path(playwright.__file__).resolve().parent
        for relative, expected in SDK_DOWNLOAD_PINS.items():
            path = package / relative
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as error:
                raise WorkbenchError('download_sdk_unavailable', 'The supported local download SDK is unavailable.', effect_state='none') from error
            if digest != expected:
                raise WorkbenchError('download_sdk_changed', 'The installed download SDK needs compatibility qualification.', effect_state='none')

    async def _install_progress(self, record):
        browser = record['context'].browser
        key = record['id']
        if key in self._download_cdp:
            return
        page_cdp=await record['context'].new_cdp_session(record['page'])
        try:
            target=(await page_cdp.send('Target.getTargetInfo'))['targetInfo']
        finally:
            await page_cdp.detach()
        context_id=target.get('browserContextId')
        if not context_id:
            raise WorkbenchError('download_context_unbound','Exact owned browserContextId is unavailable; no default routing substitution.',effect_state='none')
        cdp = await browser.new_browser_cdp_session()
        await cdp.send('Browser.setDownloadBehavior',{'behavior':'allowAndName','browserContextId':context_id,
            'downloadPath':str(self.download_spool),'eventsEnabled':True})
        record['download_progress_context_id']=context_id
        self._download_cdp[key] = cdp

        def progress(event):
            for identifier, live in tuple(self._download_live.items()):
                if live.get('guid') != event['guid'] or self._downloads[identifier]['session_id'] != key:
                    continue
                receipt = self._downloads[identifier]
                received = int(event.get('receivedBytes', 0))
                receipt['producer_received_bytes'] = max(receipt['producer_received_bytes'], received)
                receipt['producer_total_bytes'] = int(event.get('totalBytes', 0))
                receipt['producer_state'] = event.get('state')
                receipt['producer_progress_events'] += 1
                if received > receipt['producer_ceiling_bytes']:
                    receipt['producer_overshoot_bytes'] = max(receipt['producer_overshoot_bytes'],
                        received - receipt['producer_ceiling_bytes'])
                    if not live.get('cancel_requested'):
                        live['cancel_requested'] = True
                        receipt.update(cancel_reason='producer_limit', cancel_state='requested')
                        live['cancel_task'] = asyncio.create_task(self._cancel_known(identifier))
        cdp.on('Browser.downloadProgress', progress)

    async def _cancel_known(self, identifier):
        live, receipt = self._download_live[identifier], self._downloads[identifier]
        download = live.get('download')
        if download is not None:
            try:
                await download.cancel()
                receipt['cancel_state'] = 'browser_acknowledged'
            except Exception:
                receipt['cancel_state'] = 'unknown'
        await self._save_receipt(receipt)

    async def _validated_control(self, record, observation_id, element_id):
        observation = record['observation']
        if (not observation or observation['id'] != observation_id or not observation['valid']
                or observation['generation'] != record['generation']):
            raise WorkbenchError('stale_observation', 'Take a fresh snapshot before arming a download.', effect_state='none')
        handle = record['handles'].get(element_id)
        if handle is None:
            raise WorkbenchError('unknown_element', 'Choose an observed download control.', effect_state='none')
        current = self._control(await handle.evaluate(ELEMENT_INFO))
        expected = observation['controls'][element_id]
        fields = ('tag', 'role', 'type', 'label', 'disabled', 'value_sha256', 'checked', 'href_sha256', 'download')
        if (not current['connected'] or current['value_truncated'] or current['disabled']
                or any(current.get(key) != expected.get(key) for key in fields)):
            raise WorkbenchError('target_changed', 'The observed download control changed.', effect_state='none')
        if current['tag'] != 'a' or not current.get('href_sha256'):
            raise WorkbenchError('unsupported_download_control', 'This candidate requires a fresh observed anchor; buttons remain a named gap.', effect_state='none')
        return handle, current

    def _retained_call(self, function, *args, timeout=3):
        """A response deadline cannot cancel admission, click or capture."""
        self._start()
        owner = work_context.get()
        async def run():
            token = work_context.set(owner)
            try:
                return await function(*args)
            finally:
                work_context.reset(token)
        future = asyncio.run_coroutine_threadsafe(run(), self._loop)
        self._admissions.add(future)
        self._admission_ids[args[-1]]={'future':future,'owner':owner,'session_id':args[0],'cancel_requested':False}
        def completed(done):
            self._admissions.discard(done)
            self._admission_ids.pop(args[-1],None)
            receipt=self._downloads.get(args[-1])
            if receipt and receipt['capture_state']=='admission_pending':
                error=done.exception()
                if error is not None:
                    receipt.update(capture_state='unknown',error_kind=type(error).__name__,
                        error='Admission ended before capture; inspect original request and never replay click.')
                    atomic_json(self.download_root/(args[-1]+'.json'),dict(receipt))
        future.add_done_callback(completed)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError as error:
            # Deliberately keep this Future. Journal's same-ID failure is final;
            # the retained download receipt supplies the later capture result.
            raise WorkbenchError('download_response_timeout', 'Admission continues; inspect the original download_id. Do not repeat its click.',
                                 download_id=args[-1], effect_state='unknown') from error

    async def _start_download(self, session_id, observation_id, element_id, request_id, identifier):
        self._validate_download_sdk()
        record = self._record(session_id, mutate=True)
        if not record.get('allow_downloads') or record.get('work_session_id') is None:
            raise WorkbenchError('download_authority_denied', 'Open this owned context with explicit download authority.', effect_state='none')
        async with record['lock']:
            if record.get('download_closing'):
                raise WorkbenchError('browser_closing', 'Owned context is closing.', effect_state='none')
            if len(self._downloads)>=self.MAX_CACHED_RECEIPTS:
                for old_id in list(self._downloads):
                    old_live=self._download_live.get(old_id)
                    if not old_live or old_live['task'].done():
                        self._downloads.pop(old_id,None)
                        self._download_live.pop(old_id,None)
                    if len(self._downloads)<self.MAX_CACHED_RECEIPTS:break
                if len(self._downloads)>=self.MAX_CACHED_RECEIPTS:
                    raise WorkbenchError('download_active_limit','Active download resources are full.',effect_state='none')
            if any(self._downloads[i]['session_id'] == session_id and not live['task'].done()
                   for i, live in self._download_live.items()):
                raise WorkbenchError('download_in_progress', 'Finish or cancel the current owned-context download first.', effect_state='none')
            handle, current = await self._validated_control(record, observation_id, element_id)
            await self._install_progress(record)
            if record.get('download_closing') or self._admission_ids.get(identifier,{}).get('cancel_requested'):
                raise WorkbenchError('browser_closing','Owned context is closing or admission was canceled.',effect_state='none')
            ceiling = min(self.config.max_artifact_bytes,
                          max(0, (self.config.max_storage_bytes - self.store.storage_bytes()) // 2))
            if ceiling <= 0:
                raise WorkbenchError('storage_limit', 'No download staging headroom remains.', effect_state='none')
            receipt = {'download_id':identifier, 'request_id':request_id, 'runtime_instance_id':self.instance_id,
                'owner_work_session_id':record['work_session_id'], 'workspace':record['workspace'],
                'session_id':session_id, 'page_id':self._page_id(record, record['page']),
                'frame_id':self._frame_id(record, record.get('frame') or record['page'].main_frame),
                'generation':record['generation'], 'observation_id':observation_id, 'element_id':element_id,
                **self._workspace_binding(record['workspace']),
                'href_sha256':current['href_sha256'], 'capture_state':'armed', 'click_state':'none',
                'artifact':None, 'original_file':None, 'suggested_filename':None,
                'producer_ceiling_bytes':ceiling, 'producer_received_bytes':0, 'producer_total_bytes':0,
                'producer_progress_events':0, 'producer_overshoot_bytes':0, 'progress_browser_context_id':record['download_progress_context_id'], 'cancel_state':'not_requested',
                'budget_semantics':'producer cancellation threshold; no hard pre-write disk quota; retained artifacts use configured store limits',
                'created_at':time.time(), 'publication_state':'not_requested'}
            self._downloads[identifier] = receipt
            await self._save_receipt(receipt)
            task = asyncio.create_task(self._capture(record, handle, identifier))
            self._download_live[identifier] = {'task':task, 'record':record, 'download':None,
                'cancel_requested':False, 'browser':id(record['context'].browser)}
            return {'ok':True, 'download_id':identifier, 'capture_state':'armed', 'effect_state':'none',
                    **self._continuation('armed', True),
                    'next_step':'Call state for this download_id; armed is pending. Do not repeat start. Publication is a separate explicit action.'}

    async def _capture(self, record, handle, identifier):
        receipt, live = self._downloads[identifier], self._download_live[identifier]
        page = record['page']
        event = asyncio.get_running_loop().create_future()
        live['armed_event']=event
        live['event_downloads']=[]
        redirect_targets={receipt['href_sha256']}

        def requested(request):
            prior=request.redirected_from
            if prior is not None and hashlib.sha256(prior.url.encode()).hexdigest() in redirect_targets:
                if len(redirect_targets)<16:
                    redirect_targets.add(hashlib.sha256(request.url.encode()).hexdigest())


        def downloaded(download):
            live['event_downloads'].append(download)
            if len(live['event_downloads'])>1 or hashlib.sha256(download.url.encode()).hexdigest() not in redirect_targets:
                receipt['ambiguous_page_download']=True
                live['cancel_requested']=True
                for candidate in live['event_downloads']:
                    self._track_unarmed_download(record, page, candidate, 'ambiguous_capture')
                if not event.done():event.set_result(None)
                return
            if event.done():return
            live['download'] = download
            raw=download._impl_obj._artifact._initializer.get('absolutePath')
            if isinstance(raw,str) and Path(raw).parent.resolve()==self.download_spool.resolve():
                live['guid']=Path(raw).name
            event.set_result(download)
        page.on('request',requested)
        live['capture_page'] = page
        live['download_handler'] = downloaded
        try:
            async with record['lock']:
                if live['cancel_requested'] or record.get('download_closing'):
                    receipt.update(capture_state='interrupted', click_state='none', cancel_state='before_click')
                    return
                # Recheck freshness at the actual dispatch boundary.
                await self._validated_control(record, receipt['observation_id'], receipt['element_id'])
                receipt.update(capture_state='click_pending', click_state='unknown')
                await self._save_receipt(receipt)
                record['observation'] = None
                try:
                    await handle.click(timeout=5000)
                    receipt['click_state'] = 'dispatched'
                except Exception as error:
                    receipt['click_error_kind'] = type(error).__name__
            try:
                download = await asyncio.wait_for(asyncio.shield(event), self.EVENT_SECONDS)
            except asyncio.TimeoutError:
                receipt.update(capture_state='unknown', error='No correlated browser download event; original click must not replay.')
                return
            if download is None or receipt.get('ambiguous_page_download'):
                receipt.update(capture_state='unknown',error='Multiple or uncorrelated same-page downloads; no original bytes attributed.')
                return
            receipt['redirect_target_hashes']=sorted(redirect_targets)
            raw_path = download._impl_obj._artifact._initializer.get('absolutePath')
            if not isinstance(raw_path, str):
                raise WorkbenchError('download_path_unavailable', 'Pinned local SDK did not supply the original artifact path.')
            original = Path(raw_path)
            if original.parent.resolve() != self.download_spool.resolve() or original.name in {'', '.', '..'}:
                raise WorkbenchError('download_path_unowned', 'Original browser artifact is outside this exact owned spool.')
            live['guid'] = original.name
            receipt.update(capture_state='in_progress', suggested_filename=download.suggested_filename,
                           download_url=safe_url(download.url), original_path=str(original),
                           correlation='actual Page download event + armed href hash + pinned local artifact GUID')
            completion = asyncio.create_task(download.path())
            while not completion.done():
                if live['cancel_requested'] and receipt['cancel_state'] == 'not_requested':
                    receipt['cancel_state'] = 'requested'
                    await self._cancel_known(identifier)
                await self._save_receipt(receipt)
                await asyncio.wait({completion}, timeout=.1)
            path = await completion
            failure = await download.failure()
            if failure:
                receipt.update(capture_state='interrupted', browser_failure=failure)
                return
            if path != original:
                raise WorkbenchError('download_path_changed', 'Finished artifact does not match the observed original path.')
            if receipt.get('ambiguous_page_download'):
                receipt.update(capture_state='unknown',error='Multiple same-page downloads; no bytes attributed.')
                return
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise WorkbenchError('download_not_regular', 'Original browser artifact is not a regular file.')
                receipt['original_file'] = {'path':str(path), 'device':before.st_dev, 'inode':before.st_ino,
                    'bytes':before.st_size, 'mtime_ns':before.st_mtime_ns, 'ctime_ns':before.st_ctime_ns}
                if before.st_size > receipt['producer_ceiling_bytes'] or receipt['producer_overshoot_bytes']:
                    receipt.update(capture_state='refused', error='Original download exceeded the configured producer threshold.',
                                   producer_overshoot_bytes=max(receipt['producer_overshoot_bytes'], before.st_size-receipt['producer_ceiling_bytes']))
                    return
                receipt['capture_state'] = 'finalizing'
                await self._save_receipt(receipt)
                artifact = await asyncio.to_thread(self.store.put_stream, stream, 'owned-browser-download:' + identifier)
                after = os.fstat(stream.fileno())
                identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if identity(before) != identity(after):
                    receipt.update(capture_state='unknown', candidate_artifact=artifact,
                                   error='Original browser file changed during snapshot; do not publish automatically.')
                    return
            verified = await asyncio.to_thread(self.store.verify, artifact['artifact_id'])
            if not verified['verified'] or verified['bytes'] != before.st_size:
                raise WorkbenchError('download_artifact_unverified', 'Retained artifact verification failed.')
            receipt.update(capture_state='complete', artifact=artifact, artifact_verified=verified,
                           host_bytes_retained=True, website_task_complete='unknown')
        except WorkbenchError as error:
            receipt.update(capture_state='refused' if error.code in {'artifact_limit','storage_limit'} else 'unknown',
                           error=error.as_dict())
        except Exception as error:
            receipt.update(capture_state='interrupted' if live['cancel_requested'] else 'unknown',
                           error_kind=type(error).__name__)
        finally:
            live['armed_event']=None
            live['download_handler'] = None
            page.remove_listener('request',requested)
            if not event.done():
                event.cancel()
            await self._save_receipt(receipt)
            # Delete only this exact browser-owned original after successful
            # immutable capture; unknown/failed originals retain their receipt.
            if receipt['capture_state'] == 'complete':
                try:
                    await live['download'].delete()
                    receipt['original_cleanup'] = 'owned_browser_artifact_deleted'
                except Exception:
                    receipt['original_cleanup'] = 'unknown'
                await self._save_receipt(receipt)

    @staticmethod
    def _continuation(capture_state, finalization_pending):
        pending_states = {'admission_pending', 'armed', 'click_pending', 'in_progress', 'finalizing'}
        terminal_states = {'complete', 'interrupted', 'unknown', 'refused'}
        pending = bool(finalization_pending or capture_state in pending_states)
        terminal = bool(not pending and capture_state in terminal_states)
        return {'pending': pending, 'terminal': terminal,
                'finalization_pending': bool(finalization_pending),
                'next_action': 'state' if pending else 'publish' if capture_state == 'complete' else 'inspect_receipt',
                'retry_start': False}

    async def _state(self, identifier, wait_ms):
        admission=self._admission_ids.get(identifier)
        deadline=time.monotonic()+wait_ms/1000
        if admission and wait_ms and not admission['future'].done():
            try:
                await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(admission['future'])),wait_ms/1000)
            except (asyncio.TimeoutError,WorkbenchError):pass
        receipt = self._receipt(identifier)
        if receipt['capture_state']=='admission_pending' and admission and admission['future'].done():
            receipt.update(capture_state='unknown',error='Admission ended before capture; inspect original request and never replay click.')
        live = self._download_live.get(identifier)
        if live and wait_ms:
            try:
                await asyncio.wait_for(asyncio.shield(live['task']), max(0,deadline-time.monotonic()))
            except asyncio.TimeoutError:
                pass
        finalization_pending = bool((admission and not admission['future'].done()) or (live and not live['task'].done()))
        return {'ok':True, **dict(receipt), **self._continuation(receipt['capture_state'], finalization_pending)}

    async def _cancel(self, identifier):
        receipt = self._receipt(identifier)
        live = self._download_live.get(identifier)
        admission=self._admission_ids.get(identifier)
        if not live and admission and not admission['future'].done():
            admission['cancel_requested']=True
            return {'ok':True,'download_id':identifier,'cancel_state':'admission_cancel_requested','capture_state':'admission_pending'}
        if not live or live['task'].done():
            return {'ok':True, 'download_id':identifier, 'cancel_state':'already_terminal', 'capture_state':receipt['capture_state']}
        live['cancel_requested'] = True
        receipt['cancel_reason'] = 'explicit_cancel'
        await self._cancel_known(identifier)
        return {'ok':True, 'download_id':identifier, 'cancel_state':receipt['cancel_state'], 'capture_state':receipt['capture_state']}

    def browser_download(self, session_id, action, *, request_id=None, download_id=None,
                         observation_id=None, element_id=None, path=None, expected_sha256=None,
                         wait_ms=0, response_timeout=3):
        if action == 'start':
            if not request_id or not observation_id or not element_id:
                raise WorkbenchError('invalid_download_start', 'Start requires fresh observation, element and request IDs.')
            identifier = uuid.uuid4().hex
            payload = {'tool':'browser_download', 'action':action, 'session_id':session_id,
                'observation_id':observation_id, 'element_id':element_id, 'owner':work_context.get(), 'runtime':self.instance_id}
            def start():
                record=self._record(session_id,mutate=True)
                if not record.get('allow_downloads') or record.get('work_session_id') is None:
                    raise WorkbenchError('download_authority_denied','Open with explicit download authority.',effect_state='none')
                pending={'download_id':identifier,'session_id':session_id,'owner_work_session_id':record['work_session_id'],
                    'runtime_instance_id':self.instance_id,'workspace':record['workspace'],'capture_state':'admission_pending',
                    **self._workspace_binding(record['workspace']),
                    'click_state':'none','artifact':None,'created_at':time.time()}
                atomic_json(self.download_root/(identifier+'.json'),pending)
                self._downloads[identifier]=pending
                self.journal.checkpoint(request_id,{'download_id':identifier,'phase':'before_download_admission','effect_state':'unknown'})
                return self._retained_call(self._start_download,session_id,observation_id,element_id,request_id,identifier,timeout=response_timeout)
            return self.journal.run(request_id,payload,start,resource='browser:'+session_id)
        receipt = self._receipt(download_id)
        if receipt['session_id'] != session_id:
            raise WorkbenchError('download_binding_mismatch', 'Download belongs to a different owned context.', effect_state='none')
        if action == 'state':
            if type(wait_ms) is not int or not 0 <= wait_ms <= 10000:
                raise WorkbenchError('invalid_range', 'wait_ms must be 0..10000.')
            return self._call(self._state, download_id, wait_ms, timeout=12)
        if action == 'cancel':
            payload = {'tool':'browser_download', 'action':action, 'download_id':download_id, 'owner':work_context.get(), 'runtime':self.instance_id}
            return self.journal.run(request_id, payload, lambda:self._call(self._cancel, download_id))
        if action != 'publish':
            raise WorkbenchError('invalid_download_action', 'Use start, state, cancel or publish.')
        if receipt['capture_state'] != 'complete' or not receipt['artifact']:
            raise WorkbenchError('download_not_complete', 'Only a verified retained artifact can be published.', effect_state='none')
        payload = {'tool':'browser_download', 'action':action, 'download_id':download_id, 'owner':work_context.get(),
            'runtime':self.instance_id, 'workspace':receipt['workspace'], 'path':path, 'expected_sha256':expected_sha256,
            'workspace_root':receipt.get('workspace_root'), 'workspace_root_identity':receipt.get('workspace_root_identity'),
            'artifact_id':receipt['artifact']['artifact_id']}
        child = 'bdp:' + hashlib.sha256(json.dumps({**payload, 'parent_request_id':request_id},sort_keys=True).encode()).hexdigest()
        def publish():
            # Hash and original-root checks happen inside the journal before any
            # publication. Old receipts lacking identity cannot authorize writes.
            self._verify_publication_source(receipt)
            result = self.files.write_file(receipt['workspace'], path, child, expected_sha256=expected_sha256,
                                           artifact_id=receipt['artifact']['artifact_id'])
            async def save_publication():
                receipt.update(publication_state='published', publication_request_id=request_id, publication_child_request_id=child, publication=result)
                await self._save_receipt(receipt)
            self._call(save_publication)
            return {'ok':True, 'download_id':download_id, 'publication':result, 'child_request_id':child}
        return self.journal.run(request_id, payload, publish, resource='browser-download-publish:'+download_id)

    async def _drain_downloads(self, session_id=None, bounded=True):
        admissions=[asyncio.wrap_future(a['future']) for a in self._admission_ids.values()
            if not a['future'].done() and (session_id is None or a['session_id']==session_id)]
        if admissions:
            pending = asyncio.gather(*admissions, return_exceptions=True)
            if not bounded:
                await asyncio.shield(pending)
            else:
                try:
                    await asyncio.wait_for(asyncio.shield(pending), self.DRAIN_SECONDS)
                except asyncio.TimeoutError as error:
                    raise WorkbenchError('browser_download_cleanup_pending','Owned admission remains active; context handles retained.',effect_state='unknown') from error
        tasks = []
        for identifier, live in tuple(self._download_live.items()):
            if session_id is not None and self._downloads[identifier]['session_id'] != session_id:
                continue
            live['record']['download_closing'] = True
            if not live['task'].done():
                if self._downloads[identifier]['capture_state'] != 'finalizing':
                    live['cancel_requested'] = True
                    self._downloads[identifier]['cancel_reason'] = 'owned_context_close'
                    await self._cancel_known(identifier)
                tasks.append(live['task'])
        if tasks:
            pending = asyncio.gather(*tasks, return_exceptions=True)
            if not bounded:
                await asyncio.shield(pending)
            else:
                try:
                    await asyncio.wait_for(asyncio.shield(pending), self.DRAIN_SECONDS)
                except asyncio.TimeoutError as error:
                    raise WorkbenchError('browser_download_cleanup_pending', 'Owned capture still finalizes; context and task handles remain retained.', effect_state='unknown') from error

        await self._drain_unarmed(session_id, bounded)

    async def _close_session(self, session_id):
        record = self._sessions.get(session_id)
        if record:
            self._check_owner(record)
            record['download_closing'] = True
            await self._drain_downloads(session_id)
        cdp=self._download_cdp.pop(session_id,None)
        if cdp:
            try:await cdp.detach()
            except Exception:pass
        if record is None:
            return await super()._close_session(session_id)
        async with record['lock']:
            async with self._lifecycle_lock:
                # Close the event source before the final drain. Keep the session
                # resource addressable until every late exact handle settles.
                await record['context'].close()
                await self._drain_unarmed(session_id, True)
                await self._persist(record, 'closed')
                self._sessions.pop(session_id, None)
                if not self._sessions:
                    await self._browser.close()
                    await self._playwright.stop()
                    self._browser = self._playwright = None
        return {'ok': True, 'session_id': session_id, 'closed': True, 'ordinary_user_profile_accessed': False,
                'owned_browser_released': not self._sessions}

    async def _shutdown_download_barrier(self):
        failure = None
        try:
            await self._drain_downloads(bounded=False)
        except Exception as error:
            failure = error
        # Retire the sources of new download events, then settle all exact
        # handles created during closure before the base may stop the loop.
        for record in list(self._sessions.values()):
            try:
                await record['context'].close()
            except Exception as error:
                if failure is None:
                    failure = error
        try:
            await self._drain_unarmed(None, False)
        except Exception as error:
            if failure is None:
                failure = error
        if failure is not None:
            raise failure

    async def _shutdown(self):
        for record in self._sessions.values():
            record['download_closing'] = True
        if self._download_drain_task is None:
            self._download_drain_task = asyncio.create_task(self._shutdown_download_barrier())
        # Cancellation from the base close deadline cannot abandon this single
        # drain. Further close calls observe the original cleanup completion.
        drain_failure = None
        try:
            try:
                await asyncio.shield(self._download_drain_task)
            except asyncio.CancelledError:
                await asyncio.shield(self._download_drain_task)
        except Exception as error:
            drain_failure = error
            self.shutdown_report['download_cleanup_unverified'] = True
        finally:
            for cdp in list(self._download_cdp.values()):
                try:await cdp.detach()
                except Exception:pass
            self._download_cdp.clear()
            # Explicit server shutdown still releases its owned browser even
            # when an original's deletion cannot be certified. Keep that failed
            # receipt rather than abandoning the driver or claiming success.
            await super()._shutdown()
        if drain_failure is not None:
            raise drain_failure
