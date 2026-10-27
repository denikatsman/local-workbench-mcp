"""Private, bounded encrypted CIMD cache; never stores OAuth credentials."""
import asyncio
from collections import deque
import threading
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import uuid

from cryptography.fernet import InvalidToken

MAX_ENTRIES = 128
MAX_PAYLOAD = 24 * 1024
MAX_CIPHERTEXT = 36 * 1024
MAX_PENDING_IO = 32
MAX_SCHEDULERS = 128
# A failed invalidation must survive the lifetime of every store using this DB.
# Never evict a guard or create a second worker for an existing database path.
_SCHEDULERS = {}
_SCHEDULER_LOCK = threading.Lock()


class CacheIO:
    """One bounded serial worker per private DB, shared across store instances.

    Saturation discards optional queued cache work and substitutes one whole
    cache invalidation. Reads fall back to network until that barrier completes.
    No invalidation is dropped while an older write can still complete.
    """
    def __init__(self, purge, maximum=MAX_PENDING_IO):
        self.purge, self.maximum = purge, maximum
        self.queue = deque()
        self.lock = threading.Lock()
        self.running = False
        self.barrier = None
        self.generation = uuid.uuid4().hex
        self.enabled = False
        self.users = 0
        self.sealing = False

    @staticmethod
    def _future(loop):
        future = loop.create_future()
        future.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        return future

    def submit(self, function, args, fallback, invalidate=False, shutdown=False):
        loop = asyncio.get_running_loop()
        with self.lock:
            if not self.enabled or self.barrier is not None or self.sealing and not shutdown:
                # A queued whole-cache invalidation already covers this remove.
                # Do not await its shared future repeatedly: asyncio's waiter
                # tracking can retain callbacks after each caller times out.
                future = loop.create_future()
                future.set_result(fallback)
                return future
            if len(self.queue) >= self.maximum:
                while self.queue:
                    old_loop, old_future, _, _, old_fallback, _ = self.queue.popleft()
                    self._complete(old_loop, old_future, old_fallback)
                barrier = self._future(loop)
                self.barrier = barrier
                self.queue.append((loop, barrier, self.purge, (), None, True))
                future = barrier if invalidate else loop.create_future()
                if not invalidate: future.set_result(fallback)
            else:
                future = self._future(loop)
                self.queue.append((loop, future, function, args, fallback, invalidate))
            if not self.running:
                self.running = True
                threading.Thread(target=self._run, name='cimd-cache', daemon=True).start()
            return future

    @staticmethod
    def _complete(loop, future, result=None, error=None):
        def publish():
            if future.done(): return
            if error is None: future.set_result(result)
            else: future.set_exception(error)
        if not loop.is_closed():
            try: loop.call_soon_threadsafe(publish)
            except RuntimeError: pass

    def _run(self):
        while True:
            with self.lock:
                if not self.queue:
                    self.running = False
                    return
                loop, future, function, args, fallback, invalidate = self.queue.popleft()
                if self.barrier is not None and future is not self.barrier:
                    self._complete(loop, future, fallback)
                    continue
            result, error = None, None
            try: result = function(*args)
            except Exception as caught: error = caught
            with self.lock:
                if future is self.barrier:
                    # If purge fails, retain a completed fail-closed barrier:
                    # this process must not restore potentially obsolete bytes.
                    if error is None: self.barrier = None
                elif error is not None and invalidate:
                    # Ordinary removal is mandatory too. Queued/new optional
                    # reads and writes must not pass a failed invalidation.
                    if self.barrier is None: self.barrier = future
            self._complete(loop, future, result, error)

    def pending_count(self):
        with self.lock: return len(self.queue)


async def cache_io(scheduler, function, *args, fallback=None, invalidate=False, shutdown=False):
    future = scheduler.submit(function, args, fallback, invalidate, shutdown)
    return await asyncio.wait_for(asyncio.shield(future), .5)


def boot_session():
    """A stable same-boot clock domain. Unsupported hosts disable persistence."""
    try:
        if sys.platform == 'darwin':
            value = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'],
                capture_output=True, text=True, timeout=1, check=True).stdout.strip()
        elif sys.platform.startswith('linux'):
            value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        else:
            return None
        return value.lower() if re.fullmatch(r'[0-9a-fA-F-]{36}', value) else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


class MetadataCache:
    """Independent cache table in the existing private, issuer-specific OAuth DB."""
    def __init__(self, db_path, cipher, issuer, *, generation=None):
        self.path, self.cipher, self.issuer = Path(db_path), cipher, issuer
        self.state = 'unobserved'
        self.io = None
        with _SCHEDULER_LOCK:
            if generation is None:
                try:
                    with closing(self._open()) as db:
                        row = db.execute('SELECT generation FROM cimd_epoch WHERE id=1').fetchone()
                    generation = row[0] if row else None
                except (OSError, ValueError, sqlite3.Error):
                    self.state = 'unavailable'
                    return
            if not generation:
                self.state = 'unavailable'
                return
            key = os.path.abspath(self.path), generation
            self.generation = generation
            self.io = _SCHEDULERS.get(key)
            if self.io is None and len(_SCHEDULERS) < MAX_SCHEDULERS:
                self.io = CacheIO(self._purge)
                self.io.generation = generation
                _SCHEDULERS[key] = self.io
                self.io.enabled = True
            if self.io is None:
                self.state = 'disabled_capacity'

    def _open(self):
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('Unsafe metadata cache database')
        return sqlite3.connect(self.path.resolve().as_uri() + '?mode=rw', uri=True, timeout=.1)

    @staticmethod
    def begin_epoch(db):
        # Part of OwnerOAuth's mandatory startup transaction, before the
        # provider can accept work. No optional attach can leave a clean flag.
        generation = uuid.uuid4().hex
        db.execute('CREATE TABLE IF NOT EXISTS cimd_epoch '
                   '(id INTEGER PRIMARY KEY CHECK(id=1),generation TEXT NOT NULL,clean INTEGER NOT NULL)')
        previous = db.execute('SELECT clean FROM cimd_epoch WHERE id=1').fetchone()
        if previous != (1,) and db.execute("SELECT 1 FROM sqlite_master WHERE name='cimd_cache'").fetchone():
            db.execute('DELETE FROM cimd_cache')
        db.execute('INSERT OR REPLACE INTO cimd_epoch VALUES (1,?,0)', (generation,))
        return generation

    def _connection(self):
        db = self._open()
        try:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT generation FROM cimd_epoch WHERE id=1').fetchone()
            if row != (self.generation,):
                raise ValueError('Metadata cache belongs to another process generation')
            db.execute('UPDATE cimd_epoch SET clean=0 WHERE id=1')
            return db
        except BaseException:
            db.close()
            raise

    def attach(self):
        if self.io is None:
            return
        with self.io.lock:
            if self.io.sealing:
                raise RuntimeError('Metadata cache generation is closed; create a new OAuth provider')
            self.io.users += 1

    async def close(self):
        if self.io is None:
            return
        with self.io.lock:
            self.io.users -= 1
            last = self.io.users == 0
            if last:
                self.io.sealing = True
        if last:
            try:
                await cache_io(self.io, self._seal, shutdown=True)
            except (OSError, ValueError, sqlite3.Error, TimeoutError):
                self.state = 'unavailable'

    def _seal(self):
        # Serialized after earlier cache jobs and only after every resolver has
        # stopped. Failed invalidation prevents admission of this operation.
        with self.io.lock:
            if self.io.users or self.io.barrier is not None:
                return
        with closing(self._connection()) as db, db:
            db.execute('UPDATE cimd_epoch SET clean=1 WHERE id=1 AND generation=?',
                       (self.generation,))
        with self.io.lock:
            self.io.enabled = False

    async def load(self):
        if self.io is None:
            return []
        if not self.io.enabled:
            self.state = 'unavailable'
            return []
        try:
            records = await cache_io(self.io, self._load, fallback=[])
            self.state = 'invalidation_pending' if self.io.barrier is not None else 'available'
            return records
        except (OSError, ValueError, sqlite3.Error, TimeoutError):
            self.state = 'unavailable'
            return []

    def _load(self):
        with closing(self._connection()) as db, db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cimd_cache'").fetchone()
            if not exists:
                return []
            rows = db.execute('SELECT client_id,data FROM cimd_cache WHERE length(data)<=? '
                'ORDER BY updated DESC LIMIT ?', (MAX_CIPHERTEXT, MAX_ENTRIES)).fetchall()
        result = []
        for client_id, encrypted in rows:
            if not isinstance(client_id, str) or len(client_id) > 2048 or not isinstance(encrypted, bytes):
                continue
            try:
                raw = self.cipher.decrypt(encrypted)
                if len(raw) > MAX_PAYLOAD:
                    continue
                record = json.loads(raw)
                if (not isinstance(record, dict) or record.get('issuer') != self.issuer
                        or record.get('client_id') != client_id):
                    continue
                result.append(record)
            except (InvalidToken, ValueError, TypeError, RecursionError):
                continue
        return result

    async def put(self, client_id, record):
        if self.io is None:
            return False
        if not self.io.enabled:
            self.state = 'unavailable'
            return False
        try:
            raw = json.dumps({**record, 'issuer': self.issuer, 'client_id': client_id},
                allow_nan=False, separators=(',', ':')).encode()
            if len(raw) > MAX_PAYLOAD:
                return False
            encrypted = self.cipher.encrypt(raw)
            if len(encrypted) > MAX_CIPHERTEXT:
                return False
            stored = await cache_io(self.io, self._put, client_id, encrypted, record['fetched_wall'], fallback=False)
            if stored is False:
                self.state = 'saturated'
                return False
            self.state = 'available'
            return True
        except (OSError, ValueError, TypeError, sqlite3.Error, TimeoutError):
            self.state = 'unavailable'
            return False

    def _put(self, client_id, encrypted, updated):
        with closing(self._connection()) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS cimd_cache '
                       '(client_id TEXT PRIMARY KEY,data BLOB NOT NULL,updated REAL NOT NULL)')
            db.execute('INSERT OR REPLACE INTO cimd_cache VALUES (?,?,?)', (client_id, encrypted, updated))
            db.execute('DELETE FROM cimd_cache WHERE client_id NOT IN '
                       '(SELECT client_id FROM cimd_cache ORDER BY updated DESC LIMIT ?)', (MAX_ENTRIES,))
        return True

    async def remove(self, client_id):
        if self.io is None:
            return
        if not self.io.enabled:
            self.state = 'unavailable'
            return
        try:
            await cache_io(self.io, self._remove, client_id, invalidate=True)
            if self.io.barrier is not None:
                self.state = 'invalidation_pending'
        except (OSError, ValueError, sqlite3.Error, TimeoutError):
            self.state = 'unavailable'

    def _remove(self, client_id):
        with closing(self._connection()) as db, db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='cimd_cache'").fetchone():
                db.execute('DELETE FROM cimd_cache WHERE client_id=?', (client_id,))

    def _purge(self):
        # Only this disposable metadata table, never clients/grants/config.
        with closing(self._connection()) as db, db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='cimd_cache'").fetchone():
                db.execute('DELETE FROM cimd_cache')
