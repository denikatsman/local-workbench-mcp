"""Owned browser contexts with fresh observations and explicit effect receipts.

An isolated Playwright-managed Chromium instance uses one private event
loop. It never attaches to the user's ordinary browser profile.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import re
import stat
from importlib.metadata import version as package_version
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .errors import WorkbenchError
from .persistence import atomic_json
from .views import response_size
from .context import work_context
from .browser_profiles import BrowserProfiles


ELEMENT_INFO = """el => ({tag:el.tagName.toLowerCase(),role:el.getAttribute('role'),
    type:el.getAttribute('type'),label:(el.getAttribute('aria-label')||el.innerText||el.getAttribute('placeholder')||'').slice(0,180),
    disabled:!!el.disabled,connected:el.isConnected,password:el.type==='password',
    href:el.tagName==='A'?el.href:null,download:el.tagName==='A'?el.getAttribute('download'):null,
    value:el.type==='password'?null:('value' in el?String(el.value).slice(0,1048576):null),
    value_truncated:el.type!=='password'&&'value' in el&&String(el.value).length>1048576,
    checked:'checked' in el?!!el.checked:null})"""


def safe_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc.split('@')[-1], parsed.path, '', ''))


def owned_headless_executable(chromium_executable):
    """Resolve the pinned SDK shell from its already-started full-browser identity.

    Playwright's public executable_path describes Chromium, not its headless
    shell. Read only the qualified SDK's literal path tables and descriptors;
    never start another Node process or infer a platform/cache directory.
    Format drift fails closed and SDK upgrades require explicit qualification.
    """
    def read(path, limit):
        with path.open('rb') as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError('SDK metadata exceeds qualified size')
        return data.decode('utf-8')

    def paths(table, name):
        sections = re.findall(r'^      "' + re.escape(name) + r'": \{\n(.*?)^      \},?$', table, re.M | re.S)
        if len(sections) != 1:
            raise ValueError('Missing or ambiguous SDK executable table')
        result = {}
        for line in sections[0].splitlines():
            entry = re.fullmatch(r'        "([^"\n]+)": (void 0|\[[^\n]*\]),?', line)
            if entry is None or entry[1] in result:
                raise ValueError('Unqualified SDK executable entry')
            key, literal = entry.groups()
            if literal == 'void 0':
                if key != '<unknown>':
                    raise ValueError('Unexpected unsupported SDK platform')
                result[key] = None
                continue
            if re.fullmatch(r'(linux|mac|win)-(x64|arm64)', key) is None:
                raise ValueError('Unqualified SDK platform')
            tokens = json.loads(literal)
            if (not isinstance(tokens, list) or not 1 <= len(tokens) <= 8
                    or any(not isinstance(token, str) or not 1 <= len(token) <= 255
                           or token in ('.', '..') or re.search(r'[\x00-\x1f/\\:]', token) for token in tokens)):
                raise ValueError('Unsafe SDK executable path')
            result[key] = tokens
        if not result or result.get('<unknown>', False) is not None:
            raise ValueError('Unqualified SDK executable table shape')
        return result

    try:
        from playwright._impl._driver import compute_driver_executable
        if package_version('playwright') != '1.63.0':
            raise ValueError('Unqualified Playwright registry version')
        _, cli = compute_driver_executable()
        package = Path(cli).parent
        metadata = json.loads(read(package / 'package.json', 65536))
        if not isinstance(metadata, dict):
            raise ValueError('Invalid SDK package metadata')
        if metadata.get('name') != 'playwright-core' or metadata.get('version') != '1.63.0':
            raise ValueError('Unqualified driver package')
        manifest = json.loads(read(package / 'browsers.json', 131072))
        if not isinstance(manifest, dict) or not isinstance(manifest.get('browsers'), list):
            raise ValueError('Invalid SDK browser manifest')
        descriptors = {}
        for name in ('chromium', 'chromium-headless-shell'):
            matches = [entry for entry in manifest['browsers'] if entry['name'] == name]
            if len(matches) != 1:
                raise ValueError('Missing or ambiguous SDK descriptor')
            descriptor = matches[0]
            if (not isinstance(descriptor['revision'], str)
                    or re.fullmatch(r'[0-9]{1,10}', descriptor['revision']) is None
                    or descriptor.get('revisionOverrides', {}) != {}):
                raise ValueError('Unqualified SDK revision')
            descriptors[name] = descriptor
        source = read(package / 'lib/coreBundle.js', 4 * 1024 * 1024)
        marker = '    EXECUTABLE_PATHS = {\n'
        if source.count(marker) != 1:
            raise ValueError('Missing or ambiguous SDK path-table declaration')
        table, terminator, _ = source.split(marker, 1)[1].partition('\n    };')
        if not terminator or len(table) > 32768:
            raise ValueError('Unqualified SDK path-table boundary')
        full_paths, shell_paths = paths(table, 'chromium'), paths(table, 'chromium-headless-shell')
        if not isinstance(chromium_executable, str):
            raise ValueError('Invalid SDK full-browser identity')
        full = Path(chromium_executable)
        if not full.is_absolute() or any(part in ('.', '..') for part in full.parts):
            raise ValueError('Invalid SDK full-browser identity')
        matches = [(key, tokens) for key, tokens in full_paths.items() if tokens
                   and full.parts[-len(tokens):] == tuple(tokens)]
        if len(matches) != 1:
            raise ValueError('Unqualified or ambiguous SDK full-browser platform')
        platform, tokens = matches[0]
        cache = full.parents[len(tokens)]
        if full != cache / ('chromium-' + descriptors['chromium']['revision']) / Path(*tokens):
            raise ValueError('SDK full-browser revision anchor mismatch')
        shell_tokens = shell_paths[platform]
        if not shell_tokens:
            raise ValueError('Unsupported SDK headless-shell platform')
        executable = cache / ('chromium_headless_shell-' + descriptors['chromium-headless-shell']['revision']) / Path(*shell_tokens)
        try:
            present = stat.S_ISREG(executable.stat().st_mode)
        except FileNotFoundError:
            present = False
    except OSError as exc:
        raise WorkbenchError('browser_runtime_unavailable',
            'Could not read the matching Playwright runtime identity.',
            backend='playwright', runtime='chromium-headless-shell', effect_state='none',
            recovery='Check local runtime availability before retrying with a new request ID.') from exc
    except (ValueError, KeyError, TypeError, IndexError, ImportError) as exc:
        raise WorkbenchError('browser_runtime_incompatible',
            'Could not resolve the qualified Playwright headless-shell runtime.',
            backend='playwright', runtime='chromium-headless-shell', effect_state='none',
            recovery='Repair the pinned Playwright runtime before retrying with a new request ID.') from exc
    if not present:
        raise WorkbenchError('browser_runtime_missing',
            'The headless-shell build matching Playwright is not installed.',
            backend='playwright', runtime='chromium-headless-shell', executable=str(executable), effect_state='none',
            recovery="Run this environment's python -m playwright install --no-remove chromium locally, then retry with a new request ID.")
    return str(executable)


class OwnedBrowser:
    SHUTDOWN_GRACE_SECONDS = 10
    # Pinned Playwright's owned driver has a30s pipe-EOF exit watchdog.
    SHUTDOWN_RELEASE_SECONDS = 35
    def active_ids(self, work_session_id=None):
        if self._loop is None:
            return []
        async def inspect():
            return [identifier for identifier, record in self._sessions.items() if work_session_id is None
                    or record.get('work_session_id') == work_session_id]
        return self._call(inspect, timeout=3)

    def __init__(self, config, store, journal, instance_id):
        self.config, self.store, self.journal, self.instance_id = config, store, journal, instance_id
        self.root = config.state_dir / 'browser-sessions'
        self._start_lock = threading.Lock()
        self._loop = None
        self._thread = None
        self._closed = False
        self._browser = self._playwright = None
        self._engine = None
        self._headless_executable = None
        self._sessions = {}
        self._shutdown_future = None
        self._runtime_release_task = None
        self._shutdown_finished = threading.Event()
        self._shutdown_failure = None
        self.shutdown_report = {'state':'not_started','graceful_timed_out':False}
        self.profiles = BrowserProfiles(config, journal)

    def _start(self):
        with self._start_lock:
            if self._closed:
                raise WorkbenchError('browser_closed', 'Browser service is shutting down.')
            if self._loop is not None:
                return
            ready = threading.Event()
            def run():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                self._lifecycle_lock = asyncio.Lock()
                ready.set()
                try:
                    loop.run_forever()
                finally:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    loop.run_until_complete(asyncio.gather(*pending,return_exceptions=True))
                    loop.run_until_complete(loop.shutdown_asyncgens())
                    loop.run_until_complete(loop.shutdown_default_executor())
                    loop.close()
            self._thread = threading.Thread(target=run,name='workbench-browser',daemon=True)
            self._thread.start()
            if not ready.wait(3):
                raise WorkbenchError('browser_unavailable','Browser event loop did not start.')

    def _call(self, function, *args, timeout=30):
        self._start()
        context_id=work_context.get()
        async def run():
            token=work_context.set(context_id)
            try:return await function(*args)
            finally:work_context.reset(token)
        future = asyncio.run_coroutine_threadsafe(run(),self._loop)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise WorkbenchError('browser_timeout','Browser operation timed out; inspect the session before repeating an action.',
                                 effect_state='unknown') from exc

    @staticmethod
    def _url(url):
        if url == 'about:blank':
            return
        parsed = urlsplit(url)
        if (len(url)>8192 or parsed.scheme not in {'http','https'} or not parsed.hostname
                or parsed.username or parsed.password):
            raise WorkbenchError('invalid_url','Use an HTTP(S) URL without embedded credentials, or about:blank.')

    async def _ensure_browser(self):
        if self._browser is not None and self._browser.is_connected():
            return
        if any(record.get('profile_id') is None for record in self._sessions.values()):
            raise WorkbenchError('browser_disconnected','Owned browser disconnected; existing sessions are not silently rebound.')
        from playwright.async_api import async_playwright
        if self._playwright is None:
            self._playwright = await async_playwright().start()
        if self._headless_executable is None:
            self._headless_executable = await asyncio.to_thread(owned_headless_executable, self._playwright.chromium.executable_path)
        executable = self._headless_executable
        try:
            # Use the SDK-matched isolated headless shell for both profile routes.
            # The full Chromium build remains available to other browser consumers.
            self._browser = await self._playwright.chromium.launch(executable_path=executable,headless=True,
                downloads_path=getattr(self, 'download_spool', None),chromium_sandbox=True,handle_sigint=False,handle_sigterm=False,handle_sighup=False,timeout=15000)
            self._engine = {'backend':'playwright','channel':None,'runtime':'chromium-headless-shell',
                            'playwright_version':'1.63.0','version':self._browser.version,
                            'executable':executable,'chromium_sandbox':True,
                            'profile':'ephemeral automation context'}
        except Exception as exc:
            raise WorkbenchError('browser_launch_failed','Could not launch the isolated Playwright browser.',
                                 backend='playwright',executable=executable,effect_state='none') from exc

    def _record(self, session_id, mutate=False):
        record = self._sessions.get(session_id)
        if record is None:
            raise WorkbenchError('unknown_browser_session','No active owned session has that ID in this server instance.')
        if record['page'].is_closed():
            raise WorkbenchError('browser_target_closed','The owned page has closed; do not reuse its observations.')
        if record.get('frame') is not None and record['frame'].is_detached():
            raise WorkbenchError('browser_frame_detached', 'The selected frame detached; explicitly select a current target.')
        if mutate:self._check_owner(record)
        return record

    @staticmethod
    def _check_owner(record):
        owner=record.get('work_session_id')
        if owner is not None and work_context.get()!=owner:
            raise WorkbenchError('work_session_mismatch','This browser belongs to a different work context.',
                                 owner_work_session_id=owner,effect_state='none')

    def _event(self, record, kind, **data):
        if len(record['events']) >= 200:
            record['events_omitted'] += 1
            return
        record['events'].append({'sequence':len(record['events'])+1,'at':time.time(),'kind':kind,**data})

    @staticmethod
    def _page_id(record, page):
        for identifier, candidate in record['pages'].items():
            if candidate == page:
                return identifier
        identifier = uuid.uuid4().hex
        record['pages'][identifier] = page
        return identifier

    @staticmethod
    def _frame_id(record, frame):
        for identifier, candidate in record['frames'].items():
            if candidate == frame:
                return identifier
        identifier = uuid.uuid4().hex
        record['frames'][identifier] = frame
        return identifier

    def _bind_page(self, record, page):
        identifier = self._page_id(record, page)
        if identifier in record['bound_pages']:
            return
        record['bound_pages'].add(identifier)
        def navigated(frame):
            if record['page'] == page and (frame == page.main_frame or frame == record.get('frame')):
                record['generation'] += 1
            self._event(record, 'navigation', page_id=identifier, frame_id=self._frame_id(record, frame),
                        url=safe_url(frame.url), generation=record['generation'])
        page.on('framenavigated', navigated)
        page.on('pageerror', lambda error: self._event(record, 'page_error', page_id=identifier,
            message=str(error)[:4000], message_truncated=len(str(error)) > 4000))
        page.on('console', lambda message: self._event(record, 'console', page_id=identifier,
            level=message.type, text=message.text[:4000], text_truncated=len(message.text) > 4000))
        page.on('response', lambda response: self._event(record, 'response', page_id=identifier,
            url=safe_url(response.url), status=response.status, request_method=response.request.method, body_captured=False))
        page.on('requestfailed', lambda request: self._event(record, 'request_failed', page_id=identifier,
            url=safe_url(request.url), failure=request.failure))

    async def _target(self, session_id, action, expected_generation, request_id, page_id, frame_id, url):
        record = self._sessions.get(session_id)
        if record is None:
            raise WorkbenchError('unknown_browser_session', 'No owned context has this ID.')
        if action != 'list':
            self._check_owner(record)
        async with record['lock']:
            if action != 'list':
                if record['generation'] != expected_generation:
                    raise WorkbenchError('target_changed', 'Target generation changed; list/observe again.', effect_state='none')
                if action == 'select_page':
                    page = record['pages'].get(page_id)
                    if page is None or page.is_closed():
                        raise WorkbenchError('browser_target_closed', 'That page ID is unavailable; no other page was selected.')
                    record.update(page=page, frame=None)
                elif action == 'select_frame':
                    frame = record['frames'].get(frame_id)
                    if frame is None or frame.is_detached() or frame.page != record['page']:
                        raise WorkbenchError('browser_frame_detached', 'That frame is not a current child of the selected page.')
                    await frame.wait_for_load_state('domcontentloaded', timeout=10000)
                    record['frame'] = None if frame == record['page'].main_frame else frame
                elif action == 'new_page':
                    self.journal.checkpoint(request_id, {'session_id': session_id, 'phase': 'before_owned_page_creation', 'effect_state': 'none'})
                    page = await record['context'].new_page()
                    self._bind_page(record, page)
                    record.update(page=page, frame=None)
                    self.journal.checkpoint(request_id, {'session_id': session_id, 'page_id': self._page_id(record, page),
                        'phase': 'owned_page_created', 'effect_state': 'page_created'})
                    if url is not None:
                        await page.goto(url, wait_until='domcontentloaded', timeout=10000)
                elif action in ('back', 'forward'):
                    self._record(session_id, mutate=True)
                    if record.get('frame') is not None:
                        raise WorkbenchError('unsupported_history_scope', 'Back/forward operate on a page; explicitly select its main frame first.')
                    self.journal.checkpoint(request_id, {'session_id': session_id, 'phase': 'before_history_navigation', 'effect_state': 'unknown'})
                    await (record['page'].go_back if action == 'back' else record['page'].go_forward)(wait_until='domcontentloaded', timeout=10000)
                record['generation'] += 1
                record['observation'] = None
                await self._persist(record, 'open')
            targets = []
            for page in record['context'].pages:
                self._bind_page(record, page)
                identifier = self._page_id(record, page)
                frames = [{'frame_id': self._frame_id(record, frame), 'url': safe_url(frame.url),
                           'main_frame': frame == page.main_frame, 'selected': frame == (record.get('frame') or record['page'].main_frame)}
                          for frame in page.frames[:100]]
                targets.append({'page_id': identifier, 'url': safe_url(page.url), 'selected': page == record['page'],
                                'frames': frames, 'frame_listing_complete': len(page.frames) <= 100})
            result = {'ok': True, 'session_id': session_id, 'generation': record['generation'], 'targets': targets,
                      'scope': 'Pages and frames owned by this automation context; ordinary user tabs are separate.'}
            if response_size(result) > 8192:
                artifact = await asyncio.to_thread(self.store.put_bytes, json.dumps(result).encode(), 'owned-browser-targets:' + session_id)
                return {'ok': True, 'session_id': session_id, 'generation': record['generation'], 'target_artifact': artifact,
                        'view_complete': False}
            return result

    def target(self, session_id, action='list', expected_generation=None, request_id=None, page_id=None, frame_id=None, url=None):
        if action not in ('list', 'select_page', 'select_frame', 'new_page', 'back', 'forward'):
            raise WorkbenchError('invalid_browser_target', 'Choose a supported owned-target operation.')
        if url is not None:
            self._url(url)
            if action != 'new_page':
                raise WorkbenchError('invalid_browser_target', 'Only new_page accepts a URL here.')
        if action == 'list':
            return self._call(self._target, session_id, action, expected_generation, request_id, page_id, frame_id, url)
        if request_id is None or type(expected_generation) is not int:
            raise WorkbenchError('invalid_browser_target', 'Mutating target operations need request_id and expected_generation.')
        payload = {'tool': 'browser_target', 'session_id': session_id, 'action': action,
            'expected_generation': expected_generation, 'page_id': page_id, 'frame_id': frame_id,
            'url_sha256': hashlib.sha256(url.encode()).hexdigest() if url is not None else None}
        if work_context.get() is not None:
            payload['work_session_id'] = work_context.get()
        return self.journal.run(request_id, payload,
            lambda: self._call(self._target, session_id, action, expected_generation, request_id, page_id, frame_id, url), resource='browser:' + session_id)

    @staticmethod
    def _control(info):
        href=info.pop('href',None)
        info['href_sha256']=hashlib.sha256(href.encode()).hexdigest() if href is not None else None
        info['href_url']=safe_url(href) if href is not None else None
        value=info.pop('value')
        info['value_sha256']=hashlib.sha256(value.encode('utf-8','surrogatepass')).hexdigest() if value is not None else None
        info['value_hash_encoding']='utf8_surrogatepass'
        info['value_preview']=value[:256] if value is not None else None
        return info

    def _manifest(self, record, state):
        return {'session_id':record['id'],'server_instance_id':self.instance_id,'workspace':record['workspace'],
                'owner_work_session_id':record.get('work_session_id'),
                'created_at':record['created_at'],'state':state,'generation':record['generation'],
                'url':safe_url(record['page'].url),'ownership':'isolated_context_in_owned_browser',
                'engine':record.get('engine', self._engine), 'profile_id': record.get('profile_id'),
                'ordinary_user_profile_accessed':False,'allow_downloads':record.get('allow_downloads',False)}

    async def _persist(self, record, state):
        self.root.mkdir(mode=0o700,exist_ok=True)
        await asyncio.to_thread(atomic_json,self.root/(record['id']+'.json'),self._manifest(record,state))

    async def _open(self, workspace, url, width, height, request_id, session_id, profile_id=None, allow_downloads=False):
        async with self._lifecycle_lock:
            await self._ensure_browser()
            if len(self._sessions) >= 4:
                raise WorkbenchError('browser_session_limit','Close an owned browser session before opening another.',limit=4)
            if profile_id is None:
                context = await self._browser.new_context(viewport={'width':width,'height':height},device_scale_factor=1,
                                                          accept_downloads=allow_downloads)
                engine = dict(self._engine)
            else:
                if any(record.get('profile_id') == profile_id for record in self._sessions.values()):
                    raise WorkbenchError('browser_profile_in_use', 'This owned profile already has an open context; close it before reuse.')
                _, profile_path = self.profiles.load(workspace, profile_id)
                try:
                    context = await self._playwright.chromium.launch_persistent_context(str(profile_path), executable_path=self._headless_executable, headless=True,
                        chromium_sandbox=True, handle_sigint=False, handle_sigterm=False, handle_sighup=False,
                        viewport={'width':width,'height':height}, device_scale_factor=1, accept_downloads=allow_downloads, downloads_path=getattr(self, 'download_spool', None), timeout=15000)
                except Exception as error:
                    raise WorkbenchError('browser_profile_launch_failed', 'The owned profile could not launch; an external profile lock may be active.', effect_state='none') from error
                engine = {**self._engine, 'version': context.browser.version, 'profile': 'persistent owned automation profile'}
            try:
                page = await context.new_page()
            except BaseException:
                await context.close()
                raise
            record = {'id':session_id,'workspace':workspace,'context':context,'page':page,'lock':asyncio.Lock(),
                      'work_session_id':work_context.get(), 'profile_id': profile_id, 'engine': engine, 'allow_downloads':allow_downloads,
                      'generation':0,'created_at':time.time(),'events':[],'events_omitted':0,'observation':None,'handles':{}}
            record.update(pages={}, frames={}, frame=None, bound_pages=set())
            self._sessions[session_id] = record
        self._bind_page(record, page)
        context.on('page', lambda created: self._bind_page(record, created))
        try:
            await self._persist(record,'opening')
            self.journal.checkpoint(request_id,{'session_id':session_id,'phase':'browser_context_created','effect_state':'context_created'})
            await page.goto(url,wait_until='domcontentloaded',timeout=10000)
            await self._persist(record,'open')
            return {**self._manifest(record,'open'),'ok':True,'browser_version':self._browser.version,
                    'viewport':page.viewport_size,'effect_state':'context_created','verification_state':'navigation_observed'}
        except Exception as exc:
            # Keep the owned session addressable for diagnostics after a failed
            # navigation; only service shutdown or explicit close retires it.
            await self._persist(record,'navigation_failed')
            raise WorkbenchError('browser_navigation_failed','Owned session exists but initial navigation did not complete.',
                                 session_id=session_id,generation=record['generation'],effect_state='context_created') from exc

    def open(self, workspace, url, request_id, width=1280, height=800, profile_id=None, allow_downloads=False):
        if not self.config.workspace(workspace).executable:
            raise WorkbenchError('execution_denied','Owned browsers require an executable workspace.')
        if type(allow_downloads) is not bool:
            raise WorkbenchError('invalid_download_authority','allow_downloads must be boolean.')
        if allow_downloads and (work_context.get() is None or not self.config.workspace(workspace).writable):
            raise WorkbenchError('download_authority_denied','Downloads require an explicit work session and writable executable workspace.',effect_state='none')
        self._url(url)
        if any(type(value) is not int or not 320 <= value <= 2048 for value in (width,height)):
            raise WorkbenchError('invalid_viewport','Viewport dimensions must be 320..2048.')
        session_id = uuid.uuid4().hex
        payload={'tool':'browser_open','workspace':workspace,'url_sha256':hashlib.sha256(url.encode()).hexdigest(),'width':width,'height':height}
        if allow_downloads:payload['allow_downloads']=True
        if profile_id is not None:
            self.profiles.load(workspace, profile_id)
            payload['profile_id'] = profile_id
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        def launch():
            self.journal.checkpoint(request_id,{'session_id':session_id,'phase':'before_browser_open','effect_state':'unknown'})
            try:
                return self._call(self._open,workspace,url,width,height,request_id,session_id,profile_id,allow_downloads)
            except WorkbenchError as exc:
                raise WorkbenchError(exc.code,exc.message,**{**exc.details,'session_id':session_id}) from exc
        return self.journal.run(request_id,payload,launch,resource='browser-allocation')

    async def _snapshot_unlocked(self, record, include_screenshot, max_bytes, control_offset=0, control_limit=100):
        page, generation = record['page'], record['generation']
        target = record.get('frame') or page.main_frame
        for handle in record['handles'].values():
            await handle.dispose()
        record['handles'] = {}
        observation_id=uuid.uuid4().hex
        text = await target.evaluate("() => {const t=document.body?.innerText||'';return {text:t.slice(0,262144),total_code_units:t.length,capture_complete:t.length<=262144};}")
        try:
            text_bytes,text_encoding=text['text'].encode(),'utf-8'
        except UnicodeEncodeError:
            text_bytes,text_encoding=json.dumps(text['text'],ensure_ascii=True).encode(),'json_string'
        source = await asyncio.to_thread(self.store.put_bytes,text_bytes,'browser-text:'+record['id'])
        controls=[]
        handles = await target.query_selector_all('a,button,input,textarea,select,[role="button"],[role="checkbox"],[contenteditable="true"]')
        for index, handle in enumerate(handles):
            if not control_offset <= index < control_offset+control_limit:
                await handle.dispose()
                continue
            if not await handle.is_visible():
                await handle.dispose()
                continue
            info = self._control(await handle.evaluate(ELEMENT_INFO))
            element_id='e'+str(index+1)
            info['element_id']=element_id
            record['handles'][element_id]=handle
            controls.append(info)
        consistent = generation==record['generation']
        record['observation']={'id':observation_id,'generation':generation,'valid':consistent,
                               'controls':{item['element_id']:item for item in controls}}
        complete={'session_id':record['id'],'observation_id':observation_id,'generation':generation,'url':safe_url(page.url),
                  'title':await page.title(),'controls':controls,'control_offset':control_offset,'control_limit':control_limit,
                  'control_candidates':len(handles),'next_control_offset':control_offset+control_limit if control_offset+control_limit<len(handles) else None,
                  'controls_capture_complete':control_offset==0 and len(handles)<=control_limit,
                  'text_artifact':source,'text_capture_complete':text['capture_complete'],'text_artifact_encoding':text_encoding,
                  'source_text_code_units':text['total_code_units'],
                  'events':list(record['events']),'events_omitted':record['events_omitted'],
                  'network_scope':'metadata since session creation; query values and bodies not captured',
                  'consistent_generation':consistent,'frame_scope':'explicit selected frame' if record.get('frame') else 'main frame only',
                  'page_id': self._page_id(record, page), 'frame_id': self._frame_id(record, target),
                  'frame_url': safe_url(target.url), 'screenshot_scope': 'owned page viewport',
                  'additional_pages':max(0,len(record['context'].pages)-1)}
        artifact=await asyncio.to_thread(self.store.put_bytes,json.dumps(complete,ensure_ascii=True).encode(),'browser-observation:'+observation_id)
        result={**complete,'ok':True,'observation_artifact':artifact,'text_preview':text['text'][:2000],
                'view_complete':False,'events':record['events'][-5:]}
        if include_screenshot:
            raw=await page.screenshot(type='jpeg',quality=75,timeout=5000)
            if len(raw)>2*1024*1024:
                raise WorkbenchError('screenshot_limit','Screenshot exceeds 2 MiB; reduce the owned viewport.',session_id=record['id'])
            screenshot=await asyncio.to_thread(self.store.put_bytes,raw,'browser-screenshot:'+observation_id)
            result.update(screenshot_artifact=screenshot,mime_type='image/jpeg',viewport=page.viewport_size)
        result['consistent_generation']=record['observation']['valid']=generation==record['generation']
        while response_size(result)>max_bytes and result['controls']:
            result['controls']=result['controls'][:-1]
        while response_size(result)>max_bytes and result['text_preview']:
            result['text_preview']=result['text_preview'][:len(result['text_preview'])//2]
        while response_size(result)>max_bytes and result['events']:
            result['events']=result['events'][:-1]
        if response_size(result)>max_bytes:
            raise WorkbenchError('response_budget','Increase max_bytes for browser identity metadata.',observation_artifact=artifact['artifact_id'])
        result['view_complete']=(len(result['controls'])==len(controls) and len(result['text_preview'])==len(text['text'])
                                 and len(result['events'])==len(record['events']))
        return result

    async def _snapshot(self, session_id, include_screenshot, max_bytes, control_offset, control_limit):
        record=self._record(session_id)
        async with record['lock']:
            return await self._snapshot_unlocked(record,include_screenshot,max_bytes,control_offset,control_limit)

    def snapshot(self, session_id, include_screenshot=False, max_bytes=8192, control_offset=0, control_limit=100):
        if type(max_bytes) is not int or not 4096<=max_bytes<=262144:
            raise WorkbenchError('invalid_range','max_bytes must be 4096..262144.')
        if type(control_offset) is not int or control_offset<0 or type(control_limit) is not int or not 1<=control_limit<=200:
            raise WorkbenchError('invalid_range','Use nonnegative control_offset and control_limit 1..200.')
        from playwright.async_api import Error as PlaywrightError
        try:
            return self._call(self._snapshot,session_id,include_screenshot,max_bytes,control_offset,control_limit)
        except PlaywrightError as error:
            raise WorkbenchError('browser_observation_unavailable',
                                 'The page cannot be observed in its current state. Retry this read after navigation settles; no action was repeated.',
                                 session_id=session_id, effect_state='none', observation_state='unavailable') from error

    async def _navigate(self, session_id, url, expected_generation, request_id):
        record=self._record(session_id,mutate=True)
        async with record['lock']:
            if record['generation']!=expected_generation:
                raise WorkbenchError('target_changed','Page generation changed; observe again.',effect_state='none',generation=record['generation'])
            self.journal.checkpoint(request_id,{'session_id':session_id,'phase':'before_navigation','effect_state':'unknown'})
            try:
                await (record.get('frame') or record['page']).goto(url,wait_until='domcontentloaded',timeout=10000)
                await self._persist(record,'open')
                return {**self._manifest(record,'open'),'ok':True,'effect_state':'navigation_dispatched'}
            except Exception as exc:
                raise WorkbenchError('browser_navigation_failed','Navigation outcome requires a fresh observation.',
                                     session_id=session_id,generation=record['generation'],effect_state='unknown') from exc

    def navigate(self, session_id, url, expected_generation, request_id):
        self._url(url)
        payload={'tool':'browser_navigate','session_id':session_id,'url_sha256':hashlib.sha256(url.encode()).hexdigest(),
                 'expected_generation':expected_generation}
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        return self.journal.run(request_id,payload,lambda:self._call(self._navigate,session_id,url,expected_generation,request_id),
                                resource='browser:'+session_id)

    async def _action(self, session_id, observation_id, element_id, action, text, request_id):
        record=self._record(session_id,mutate=True)
        async with record['lock']:
            observation=record['observation']
            if not observation or observation['id']!=observation_id or not observation['valid'] or observation['generation']!=record['generation']:
                raise WorkbenchError('stale_observation','Take a new browser snapshot before acting.',effect_state='none')
            handle=record['handles'].get(element_id)
            if handle is None:
                raise WorkbenchError('unknown_element','Choose an element ID from this observation.',effect_state='none')
            current=self._control(await handle.evaluate(ELEMENT_INFO))
            expected=observation['controls'][element_id]
            if (not current['connected'] or current['value_truncated'] or any(current[key]!=expected[key]
                    for key in ('tag','role','type','label','disabled','value_sha256','checked'))):
                raise WorkbenchError('target_changed','The observed control changed; observe again.',effect_state='none')
            self.journal.checkpoint(request_id,{'session_id':session_id,'observation_id':observation_id,'element_id':element_id,
                                               'phase':'before_browser_action','effect_state':'unknown'})
            try:
                if action=='click':await handle.click(timeout=5000)
                elif action=='fill':await handle.fill(text,timeout=5000)
                elif action=='press':await handle.press(text,timeout=5000)
                elif action=='select':await handle.select_option(value=text,timeout=5000)
                elif action in ('check','uncheck'):await handle.set_checked(action=='check',timeout=5000)
                verification='not_requested'
                if action=='fill':verification='verified' if await handle.input_value()==text else 'failed'
                if action in ('check','uncheck'):verification='verified' if await handle.is_checked()==(action=='check') else 'failed'
                record['observation']=None
                result={'ok':True,'session_id':session_id,'generation':record['generation'],'action':action,
                        'action_dispatched':True,'effect_state':'action_dispatched','verification_state':verification,
                        'next_step':'take a fresh snapshot to inspect application outcome'}
                self.journal.checkpoint(request_id,result)
                return result
            except Exception as exc:
                record['observation']=None
                raise WorkbenchError('browser_action_uncertain','Action did not return a verified result; observe before retrying.',
                                     session_id=session_id,action=action,effect_state='unknown') from exc

    def action(self, session_id, observation_id, element_id, action, request_id, text=None):
        if action not in {'click','fill','press','select','check','uncheck'}:
            raise WorkbenchError('invalid_action','Unsupported browser action.')
        if action in {'fill','press','select'} and (not isinstance(text,str) or len(text.encode())>262144):
            raise WorkbenchError('invalid_text','This action requires text up to 256 KiB.')
        payload={'tool':'browser_action','session_id':session_id,'observation_id':observation_id,'element_id':element_id,
                 'action':action,'text_sha256':hashlib.sha256(text.encode()).hexdigest() if text is not None else None}
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        return self.journal.run(request_id,payload,lambda:self._call(self._action,session_id,observation_id,element_id,action,text,request_id),
                                resource='browser:'+session_id)

    async def _evaluate(self, session_id, source, arguments, expected_generation, request_id):
        record=self._record(session_id,mutate=True)
        async with record['lock']:
            if record['generation']!=expected_generation:
                raise WorkbenchError('target_changed','Observe the page before evaluating code.',effect_state='none')
            self.journal.checkpoint(request_id,{'session_id':session_id,'phase':'before_evaluation','effect_state':'unknown'})
            script="""async ({source,args}) => {
                const f=(0,eval)('('+source+String.fromCharCode(10)+')');const v=await (typeof f==='function'?f(args):f);
                if(v===undefined)return {kind:'undefined'};
                if(typeof v==='number'&&!Number.isFinite(v))return {kind:'nonfinite_number',value:String(v)};
                if(typeof v==='bigint'){const s=String(v);return s.length>10000?{kind:'output_limit',serialized_characters:s.length}:{kind:'bigint',value:s};}
                try{const s=JSON.stringify(v);if(s===undefined)return {kind:'unserializable',type:typeof v};
                    if(s.length>1048576)return {kind:'output_limit',serialized_characters:s.length};
                    return {kind:'json',serialized:s};}catch(e){return {kind:'unserializable',type:typeof v};}
            }"""
            try:
                value=await asyncio.wait_for((record.get('frame') or record['page']).evaluate(script,{'source':source,'args':arguments}),10)
                record['observation']=None
                artifact=await asyncio.to_thread(self.store.put_bytes,json.dumps(value).encode(),'browser-evaluation:'+session_id)
                result={'ok':True,'session_id':session_id,'generation':record['generation'],'result_artifact':artifact,
                        'value_kind':value['kind'],'effect_state':'evaluation_completed','verification_state':'not_requested',
                        'serialization':'JSON.stringify normalization; special root values are tagged'}
                if value['kind']=='json':
                    parsed=json.loads(value['serialized'])
                    if len(value['serialized'].encode())<2048:result['value']=parsed
                else:result['value_metadata']=value
                if response_size(result)>8192:
                    result.pop('value_metadata',None)
                    result['metadata_in_artifact']=True
                self.journal.checkpoint(request_id,result)
                return result
            except Exception as exc:
                record['observation']=None
                raise WorkbenchError('browser_evaluation_uncertain','Evaluation raised or timed out; effects may have occurred.',
                                     session_id=session_id,effect_state='unknown') from exc

    def evaluate(self, session_id, source, arguments, expected_generation, request_id):
        if not isinstance(source,str) or not 1<=len(source.encode())<=65536 or len(json.dumps(arguments).encode())>262144:
            raise WorkbenchError('invalid_evaluation','Use source up to 64 KiB and arguments up to 256 KiB.')
        payload={'tool':'browser_evaluate','session_id':session_id,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                 'arguments_sha256':hashlib.sha256(json.dumps(arguments,sort_keys=True).encode()).hexdigest(),'expected_generation':expected_generation}
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        return self.journal.run(request_id,payload,lambda:self._call(self._evaluate,session_id,source,arguments,expected_generation,request_id),
                                resource='browser:'+session_id)

    async def _close_session(self, session_id):
        record=self._sessions.get(session_id)
        if record is None:
            raise WorkbenchError('unknown_browser_session','No active owned context has this ID.')
        self._check_owner(record)
        async with record['lock']:
            async with self._lifecycle_lock:
                await record['context'].close()
                await self._persist(record,'closed')
                self._sessions.pop(session_id,None)
                if not self._sessions:
                    await self._browser.close()
                    await self._playwright.stop()
                    self._browser=self._playwright=None
            return {'ok':True,'session_id':session_id,'closed':True,'ordinary_user_profile_accessed':False,
                    'owned_browser_released':not self._sessions}

    def close_session(self, session_id, request_id):
        payload={'tool':'browser_close','session_id':session_id}
        if work_context.get() is not None:payload['work_session_id']=work_context.get()
        return self.journal.run(request_id,payload,
                                lambda:self._call(self._close_session,session_id),resource='browser:'+session_id)

    async def _release_owned_runtime(self):
        if self._playwright is None:
            if self._sessions or self._browser is not None:
                raise WorkbenchError('browser_cleanup_unverified','Owned contexts remain but their runtime handle is unavailable.',effect_state='unknown')
            self.shutdown_report.update(runtime_released=True, driver_exit_code=None)
            return
        # This subprocess object belongs to the pinned SDK transport we
        # created, not a PID found by name or read from old state.
        transport = self._playwright._impl_obj._connection._transport
        process = getattr(transport, '_proc', None)
        if process is None:
            raise WorkbenchError('browser_cleanup_unverified','The owned driver process handle is unavailable.',effect_state='unknown')
        self.shutdown_report.update(phase='runtime_release',owned_driver_pid=process.pid)
        await self._playwright.stop()
        await process.wait()
        if process.returncode != 0:
            self.shutdown_report['driver_exit_code']=process.returncode
            raise WorkbenchError('browser_cleanup_unverified','The owned driver did not exit normally; descendant cleanup remains unverified.',effect_state='unknown')
        self.shutdown_report.update(runtime_released=True,driver_exit_code=process.returncode)

    async def _shutdown(self):
        # A cancelled concurrent Future can stop retrieving the coroutine's
        # later exception; the structured shutdown failure remains authoritative.
        asyncio.current_task().add_done_callback(lambda task: None if task.cancelled() else task.exception())
        records = list(self._sessions.values())
        try:
            for record in records:
                self.shutdown_report.update(phase='context_close')
                await record['context'].close()
            if self._browser:
                self.shutdown_report.update(phase='browser_close')
                await self._browser.close()
        except Exception as error:
            self.shutdown_report['graceful_error_kind']=type(error).__name__
            raise
        finally:
            try:
                if self._runtime_release_task is None:
                    self._runtime_release_task = asyncio.create_task(self._release_owned_runtime())
                # Cancelling graceful shutdown must not cancel driver release.
                try:
                    await asyncio.shield(self._runtime_release_task)
                except asyncio.CancelledError:
                    # The deadline can arrive after graceful closure already
                    # entered finally. The same release task still owns cleanup.
                    await asyncio.shield(self._runtime_release_task)
                self.shutdown_report.update(phase='state_persistence')
                for record in records:
                    await self._persist(record,'closed_on_server_shutdown')
                self._sessions.clear()
                self._browser = self._playwright = None
                self.shutdown_report.update(state='completed',phase='completed')
            except BaseException as error:
                self._shutdown_failure = error
                if self.shutdown_report.get('runtime_released') is True:
                    self.shutdown_report.update(state='state_persistence_failed',phase='state_persistence')
                else:
                    self.shutdown_report.update(state='cleanup_unverified',phase='runtime_release')
                raise
            finally:
                self._shutdown_finished.set()

    def close(self):
        with self._start_lock:
            self._closed=True
            loop=self._loop
            if loop is None:return
            if self.shutdown_report.get('state') == 'completed' and not self._thread.is_alive():return
            if self._shutdown_future is None:
                self.shutdown_report.update(state='closing',phase='graceful')
                self._shutdown_future=asyncio.run_coroutine_threadsafe(self._shutdown(),loop)
            future=self._shutdown_future
        try:
            future.result(self.SHUTDOWN_GRACE_SECONDS)
        except concurrent.futures.TimeoutError:
            self.shutdown_report['graceful_timed_out']=True
            if not future.done():future.cancel()
            if not self._shutdown_finished.wait(self.SHUTDOWN_RELEASE_SECONDS):
                self.shutdown_report['state']='cleanup_pending'
                raise WorkbenchError('browser_cleanup_pending','Owned browser cleanup is still running. Its live handle is retained; do not start a replacement.',effect_state='unknown')
        except concurrent.futures.CancelledError:
            if not self._shutdown_finished.wait(self.SHUTDOWN_RELEASE_SECONDS):
                raise WorkbenchError('browser_cleanup_pending','Owned browser cleanup is still running.',effect_state='unknown')
        except Exception as error:
            # Graceful context/browser closure can fail after the finally path
            # successfully releases the owned driver. Preserve that distinction.
            self.shutdown_report['graceful_error_kind']=type(error).__name__
            if not self._shutdown_finished.is_set():
                raise WorkbenchError('browser_cleanup_pending','Owned browser cleanup has not finished.',effect_state='unknown') from error
        if self.shutdown_report.get('runtime_released') is not True:
            raise WorkbenchError('browser_cleanup_unverified','Owned browser runtime cleanup could not be verified.',effect_state='unknown') from self._shutdown_failure
        if not loop.is_closed():loop.call_soon_threadsafe(loop.stop)
        self._thread.join(3)
        if self._thread.is_alive():
            raise WorkbenchError('browser_cleanup_pending','The owned event loop has not exited yet.',effect_state='unknown')
        self.shutdown_report['loop_exited']=True
        if self._shutdown_failure is not None:
            raise WorkbenchError('browser_shutdown_state_failed','The owned runtime exited, but its shutdown state could not be persisted.',
                runtime_released=True,loop_exited=True,durability='unknown') from self._shutdown_failure
        if self.shutdown_report.get('graceful_timed_out'):
            raise WorkbenchError('browser_shutdown_timeout','Graceful shutdown exceeded its deadline; owned runtime release was verified.',
                runtime_released=True,loop_exited=True,cleanup_verified=True)
        if self.shutdown_report.get('graceful_error_kind'):
            raise WorkbenchError('browser_shutdown_graceful_failed','Graceful shutdown failed; owned runtime release was verified.',
                runtime_released=True,loop_exited=True,error_kind=self.shutdown_report['graceful_error_kind'])
