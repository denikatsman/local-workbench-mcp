"""Desktop supervisor. One owner, one authenticated service, one tunnel.

The native app owns stdin: closing it (including after an app crash) stops children.
stdout is a small JSON-lines status protocol; secrets never travel over that pipe.
"""
from __future__ import annotations

import argparse
import array
import asyncio
import concurrent.futures
import contextvars
import fcntl
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

from .config import Config, Workspace, OAUTH_DISCOVERY_MODES
from .errors import WorkbenchError

TUNNEL_URL = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com\b")


def emit(status: str, **fields):
    try:
        fd = sys.stdout.fileno()
        limit = os.fpathconf(fd, 'PC_PIPE_BUF')
        data = (json.dumps({"status": status, **fields}) + "\n").encode()
        if len(data) > limit:
            logging.getLogger('launcher.events').warning('Oversized launcher event: %s', data.decode().rstrip())
        while len(data) > limit and isinstance(fields.get('message'), str) and fields['message']:
            fields['message'] = fields['message'][:len(fields['message']) // 2]
            data = (json.dumps({"status": status, **fields}) + "\n").encode()
        if len(data) > limit or os.write(fd, data) != len(data):
            raise RuntimeError('Launcher event exceeded atomic publication limit')
    except BrokenPipeError:
        pass


def child_environment():
    # Do not forward TUNNEL_*, proxy credentials, API keys, or the owner secret
    # to cloudflared. The HTTP server receives the secret separately.
    env = {key: os.environ[key] for key in ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR")
           if key in os.environ}
    env["PATH"] = os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    for key in ('PYTHONDONTWRITEBYTECODE', 'PYTHONNOUSERSITE', 'PLAYWRIGHT_BROWSERS_PATH'):
        if key in os.environ: env[key] = os.environ[key]
    return env


def write_private(path: Path, text: str):
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    temporary.replace(path)


def prepare_profile(data_dir: Path, workspace: Path, writable: bool, executable: bool,
                    *, capability_profile='full_owner', history_access=True, incoming_folder: Path | None = None,
                    oauth_discovery_mode='client_metadata'):
    workspace = workspace.expanduser().resolve(strict=True)
    data_dir = data_dir.expanduser().resolve()
    if data_dir == workspace or data_dir.is_relative_to(workspace):
        raise ValueError("Choose a project folder, not your entire home folder. Private connection data must stay outside the shared folder.")
    identity = json.dumps([str(workspace), writable, executable]).encode()
    profile = data_dir / "profiles" / hashlib.sha256(identity).hexdigest()[:24]
    workspaces = {"project": Workspace("project", workspace, writable, executable)}
    if incoming_folder is not None:
        incoming = Workspace("incoming", incoming_folder)
        if data_dir == incoming.root or data_dir.is_relative_to(incoming.root) or incoming.root.is_relative_to(data_dir):
            raise ValueError("The incoming folder must not expose Workbench's private connection data.")
        # Filesystem identities also catch case/Unicode aliases on macOS volumes.
        if data_dir.exists():
            private_identity = os.stat(data_dir)
            incoming_identity = os.stat(incoming.root)
            if (any(os.path.samestat(os.stat(parent), private_identity) for parent in [incoming.root, *incoming.root.parents])
                    or any(os.path.samestat(os.stat(parent), incoming_identity) for parent in [data_dir, *data_dir.parents])):
                raise ValueError("The incoming folder must not expose Workbench's private connection data.")
        workspaces["incoming"] = incoming
    config = Config(workspaces, profile / "state",
                    capability_profile=capability_profile, history_access=history_access,
                    oauth_discovery_mode=oauth_discovery_mode)
    profile.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(profile, 0o700)
    path = profile / "workbench.json"
    document = {"state_dir": str(config.state_dir), "capability_profile": capability_profile,
        "history_access": history_access, "workspaces": {
        name: {"root": str(item.root), "writable": item.writable, "executable": item.executable}
        for name, item in workspaces.items()}}
    if oauth_discovery_mode != 'client_metadata':
        document['oauth_discovery_mode'] = oauth_discovery_mode
    write_private(path, json.dumps(document, indent=2))
    return path


def local_ready(port: int, origin: str) -> bool:
    # No system proxy: this is strictly the loopback listener we just started.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/.well-known/oauth-authorization-server", timeout=.4) as response:
            return json.load(response).get("issuer", "").rstrip("/") == origin
    except (OSError, ValueError, urllib.error.URLError):
        return False


def named_connection(data_dir: Path):
    path = data_dir / "named-tunnel.json"
    if not path.exists():
        return None
    settings = json.loads(path.read_text())
    if not isinstance(settings, dict):
        raise ValueError("Named tunnel settings must be a JSON object.")
    origin = settings.get("public_url", "")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Named tunnel public_url must be an HTTPS origin without a path or port.")
    port = settings.get("port")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Named tunnel port must be between 1024 and 65535.")
    token = data_dir / "tunnel-token"
    info = token.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or not 20 <= info.st_size <= 16384):
        raise ValueError("Named tunnel credentials must be a private, owner-only regular file.")
    return origin, port, token


def public_ready(port: int, origin: str) -> bool:
    # Use the installed HTTP stack's CA bundle on Macs whose Python has no
    # default certificates. Never disable verification or follow redirects.
    import certifi
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where())), NoRedirect())
    # Identify our API readiness probe; generic Python's user agent can be
    # rejected by Cloudflare's browser integrity checks before reaching OAuth.
    opener.addheaders = [("User-Agent", "LocalWorkbench/0.1")]
    try:
        with opener.open(origin + "/.well-known/oauth-authorization-server", timeout=4) as response:
            if response.geturl() != origin + "/.well-known/oauth-authorization-server":
                return False
            if json.load(response).get("issuer", "").rstrip("/") != origin:
                return False
        try:
            opener.open(origin + "/mcp", timeout=4).close()
        except urllib.error.HTTPError as response:
            return response.code == 401 and response.geturl() == origin + "/mcp"
    except (OSError, ValueError, urllib.error.URLError):
        pass
    return False


class Supervisor:
    def __init__(self, config: Path, cloudflared: Path, data_dir: Path, secret: str,
                 *, timeout: float = 90, tunnel_command=None, ready_probe=local_ready,
                 public_probe=public_ready, recovery_delays=(1, 2, 4, 8, 15, 30, 60),
                 lifecycle_nonce=None, health_interval=30, health_failure_threshold=3,
                 health_reset_after=60):
        self.config, self.cloudflared, self.data_dir, self.secret = config, cloudflared, data_dir, secret
        self.timeout, self.tunnel_command, self.ready_probe = timeout, tunnel_command, ready_probe
        self.public_probe = public_probe
        if not recovery_delays or any(delay <= 0 for delay in recovery_delays):
            raise ValueError("Tunnel recovery delays must be positive.")
        self.recovery_delays = tuple(recovery_delays)
        if (any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                for value in (health_interval, health_reset_after))
                or type(health_failure_threshold) is not int or health_failure_threshold < 2):
            raise ValueError("Route health requires positive finite intervals and at least two failures.")
        self.health_interval = health_interval
        self.health_failure_threshold = health_failure_threshold
        self.health_reset_after = health_reset_after
        self._probe_task = None
        self._probe_future = None
        self._probe_executor = None
        self.stop = asyncio.Event()
        self.lifecycle_nonce = lifecycle_nonce
        self.reservation_ack = asyncio.Event()
        self.guard_liveness = {}
        self.children = []
        self.readers = []
        self.process_readers = {}
        self.origin = None
        self.connected = False
        self.named = None
        self.tunnel = None
        self.service = None
        self.logger = logging.getLogger(f"launcher.{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    async def stop_owned_child(self, process, *, service, grace_seconds=45):
        if process in self.guard_liveness:
            # Only this supervisor held the writer. Guardian owns and waits the
            # actual payload; never kill the wrapper and orphan that ownership.
            fd = self.guard_liveness.pop(process)
            os.close(fd)
            await process.wait()
            return
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), grace_seconds if service else min(grace_seconds, 12))
        except TimeoutError:
            if service:
                # A slow durable finalizer is not permission to kill the host.
                # Keep the native app and readers alive; the waiting process
                # remains an owned handle with an observable stopping state.
                emit('stopping', message='Waiting for owned local operations to finish safely…')
            elif process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()

    async def pump(self, stream, label, process=None):
        # Read chunks, not readline: an oversized diagnostic line must not stall
        # the process. Only a small rolling suffix is needed to find the URL.
        tail = ""
        while data := await stream.read(8192):
            text = data.decode("utf-8", errors="replace")
            self.logger.info("%s %s", label, text.rstrip())
            if label == "tunnel" and process is self.tunnel:
                tail = (tail + text)[-16384:]
                if not self.named and (match := TUNNEL_URL.search(tail)):
                    self.origin = match.group(0)
                if "Registered tunnel connection" in tail:
                    self.connected = True

    async def spawn(self, args, env, label, *, pass_fds=()):
        life_read = life_write = event_fd = None
        if self.lifecycle_nonce:
            life_read, life_write = os.pipe()
            event_fd = os.dup(sys.stdout.fileno())
            ticket = uuid.uuid4().hex
            args = [sys.executable, str(Path(__file__).with_name('child_guardian.py')),
                    '--life-fd', str(life_read), '--event-fd', str(event_fd),
                    '--ticket', ticket, '--role', label, '--data-dir', str(self.data_dir),
                    *[part for fd in pass_fds for part in ('--payload-fd', str(fd))], '--', *args]
        try:
            process = await asyncio.create_subprocess_exec(*args, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                pass_fds=(*pass_fds, *([life_read, event_fd] if life_read is not None else [])))
        except BaseException:
            if life_write is not None:
                os.close(life_write)
            raise
        finally:
            for fd in (life_read, event_fd):
                if fd is not None:
                    os.close(fd)
        if life_write is not None:
            self.guard_liveness[process] = life_write
        self.children.append(process)
        if label == "tunnel":
            self.tunnel = process
        else:
            self.service = process
        reader = asyncio.create_task(self.pump(process.stdout, label, process))
        self.readers.append(reader)
        self.process_readers[process] = reader
        return process

    async def pause(self, duration=.1):
        try:
            await asyncio.wait_for(self.stop.wait(), duration)
        except TimeoutError:
            pass

    def check_children(self):
        for process in self.children:
            if process.returncode is not None:
                raise RuntimeError(f"A connection process stopped (exit {process.returncode}). Open diagnostics for details, then try Start again.")

    def check_service(self):
        if self.service is None or self.service.returncode is not None:
            raise RuntimeError("The local service stopped. Open diagnostics before starting again.")

    def start_probe(self, probe, port, origin):
        if self._probe_future is not None:
            raise RuntimeError("An owned readiness probe is still pending.")
        if self._probe_executor is None:
            self._probe_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="workbench-route-probe")
        self._probe_future = self._probe_executor.submit(contextvars.copy_context().run, probe, port, origin)
        self._probe_task = asyncio.wrap_future(self._probe_future)
        # The asyncio view can be cancelled independently. The retained
        # concurrent future, not this wrapper, owns actual worker completion.
        self._probe_task.add_done_callback(lambda task: None if task.cancelled() else task.exception())

    async def finish_probe(self, *, service_only=False):
        future = self._probe_future
        while not future.done():
            self.check_service() if service_only else self.check_children()
            if self.stop.is_set():
                return None  # The actual worker is joined after child drain.
            await self.pause(.05)
        self.check_service() if service_only else self.check_children()
        if self.stop.is_set():
            return None
        try:
            return None if future.cancelled() else future.result()
        finally:
            self._probe_task = self._probe_future = None

    async def supervised_probe(self, probe, port, origin, *, service_only=False):
        self.start_probe(probe, port, origin)
        return await self.finish_probe(service_only=service_only)

    async def join_probe(self):
        # Cancelling an asyncio wrapper cannot stop its thread. Retain and join
        # the actual completion before publishing final ownership proof.
        future = self._probe_future
        cancelled = False
        try:
            if future is not None:
                completion = asyncio.wrap_future(future)
                while not future.done():
                    try:
                        await asyncio.shield(completion)
                    except asyncio.CancelledError:
                        cancelled = True
                        self.stop.set()
                if not future.cancelled():
                    future.result()
        except Exception as exc:
            self.logger.warning("owned readiness probe ended with %s", type(exc).__name__)
        finally:
            self._probe_task = self._probe_future = None
            if self._probe_executor is not None:
                # All submitted work is now actually done; join the idle worker
                # before final ownership proof, without blocking on network I/O.
                self._probe_executor.shutdown(wait=True)
                self._probe_executor = None
        if cancelled:
            raise asyncio.CancelledError

    def route_health(self, port, origin):
        # Public success requires the existing strict issuer AND /mcp401
        # probes. Recheck loopback after public I/O before blaming the tunnel.
        try:
            if not self.ready_probe(port, origin):
                return "local_unhealthy"
            public = self.public_probe(port, origin)
            if not self.ready_probe(port, origin):
                return "local_unhealthy"
            return "healthy" if public else "public_unreachable"
        except Exception as exc:
            self.logger.warning("route health probe ended with %s", type(exc).__name__)
            return "indeterminate"

    async def retire_tunnel(self):
        process = self.tunnel
        if process is None:
            return
        # Fence buffered output before awaiting termination or reader cleanup.
        self.tunnel = None
        self.connected = False
        await self.stop_owned_child(process, service=False)
        reader = self.process_readers.pop(process)
        try:
            await asyncio.wait_for(asyncio.shield(reader), 1)
        except TimeoutError:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
            self.logger.info("tunnel retired reader drain timed out")
        self.readers.remove(reader)
        self.children.remove(process)

    async def recover_tunnel(self, command, env, port, origin, failures):
        # Only called for a permanent route after a fully verified Ready state.
        # Never restart/replay local jobs, grants, input or the backend service.
        emit("starting", message="Reconnecting your permanent address. Local work continues…")
        while not self.stop.is_set():
            delay = self.recovery_delays[min(failures, len(self.recovery_delays) - 1)]
            failures += 1
            retry_at = time.monotonic() + delay
            while not self.stop.is_set() and time.monotonic() < retry_at:
                self.check_service()
                await self.pause(min(.1, max(0, retry_at - time.monotonic())))
            self.check_service()
            if self.stop.is_set():
                return failures
            # Revalidate private credentials and route without changing identity.
            if named_connection(self.data_dir) != self.named:
                raise RuntimeError("The permanent connection configuration changed. Stop and Start to apply it safely.")
            await self.retire_tunnel()
            self.check_service()
            if self.stop.is_set():
                return failures
            try:
                await self.spawn(command, env, "tunnel")
            except OSError as exc:
                self.logger.warning("tunnel replacement could not start: %s", type(exc).__name__)
                continue
            deadline = time.monotonic() + self.timeout
            while not self.stop.is_set() and time.monotonic() < deadline:
                self.check_service()
                if self.tunnel.returncode is not None:
                    break
                if self.connected and await self.supervised_probe(self.ready_probe, port, origin, service_only=True):
                    if not self.stop.is_set() and await self.supervised_probe(self.public_probe, port, origin, service_only=True):
                        self.check_service()
                        if not self.stop.is_set() and self.tunnel.returncode is None:
                            return failures
                await self.pause()
        return failures

    async def run(self):
        handler = RotatingFileHandler(self.data_dir / "diagnostics.log", maxBytes=2 * 1024 * 1024,
                                     backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        self.logger.addHandler(handler)
        os.chmod(self.data_dir / "diagnostics.log", 0o600)
        listener = socket.socket()
        try:
            # Reserve the backend port until the authenticated service inherits
            # it: the tunnel must never forward to an unrelated local listener.
            self.named = named_connection(self.data_dir)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.named[1] if self.named else 0))
            port = listener.getsockname()[1]
            if self.lifecycle_nonce:
                # Native owner must retain this exact bound socket BEFORE any
                # possible backend/tunnel. Its copy fences missing guard proof.
                with socket.socket(fileno=os.dup(sys.stdin.fileno())) as control:
                    control.sendmsg([self.lifecycle_nonce.encode()],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))])
                deadline = time.monotonic() + self.timeout
                while not self.reservation_ack.is_set() and not self.stop.is_set():
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Native listener reservation was not acknowledged. No tools were started.')
                    await self.pause()
                if self.stop.is_set():
                    return
            env = child_environment()
            # Explicit empty config prevents an unrelated named-tunnel config
            # from being picked up from ~/.cloudflared/config.yml.
            tunnel_config = self.data_dir / "quick-tunnel.yml"
            write_private(tunnel_config, "{}\n")
            common = [str(self.cloudflared), "tunnel", "--config", str(tunnel_config),
                      "--no-autoupdate", "--metrics", "127.0.0.1:0", "--loglevel", "info", "--output", "json"]
            if self.named:
                self.origin = self.named[0]
                command = self.tunnel_command or [*common, "--grace-period", "2s", "run",
                                                   "--token-file", str(self.named[2])]
            else:
                command = self.tunnel_command or [*common, "--url", f"http://127.0.0.1:{port}",
                                                   "--grace-period", "2s"]
                emit("starting", message="Creating a temporary connection…")
                self.tunnel = await self.spawn(command, env, "tunnel")
            deadline = time.monotonic() + self.timeout
            while not self.origin and not self.stop.is_set():
                self.check_children()
                if time.monotonic() > deadline:
                    raise RuntimeError("Cloudflare did not return an address. Check your internet connection and open diagnostics.")
                await self.pause()
            if self.stop.is_set():
                return
            origin = self.origin
            emit("starting", message="Starting your local tools…")
            await self.spawn([sys.executable, "-m", "local_workbench", "--config", str(self.config), "serve",
                              "--transport", "http", "--port", str(port), "--public-url", origin,
                              "--listen-fd", str(listener.fileno())],
                             {**env, "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                              "LOCAL_WORKBENCH_OWNER_SECRET": self.secret,
                              **{key: os.environ[key] for key in (
                                  'LOCAL_WORKBENCH_NATIVE_SOCKET', 'LOCAL_WORKBENCH_NATIVE_TOKEN',
                                  'LOCAL_WORKBENCH_NATIVE_GENERATION', 'LOCAL_WORKBENCH_NATIVE_LAUNCH',
                                  'LOCAL_WORKBENCH_AUTOMATION_SOCKET', 'LOCAL_WORKBENCH_AUTOMATION_TOKEN',
                                  'LOCAL_WORKBENCH_AUTOMATION_GENERATION', 'LOCAL_WORKBENCH_AUTOMATION_LAUNCH',
                                  'LOCAL_WORKBENCH_AUTOMATION_CONTROL_SOCKET', 'LOCAL_WORKBENCH_AUTOMATION_CONTROL_TOKEN',
                                  'LOCAL_WORKBENCH_AUTOMATION_CONTROL_GENERATION', 'LOCAL_WORKBENCH_AUTOMATION_CONTROL_LAUNCH',
                                  'LOCAL_WORKBENCH_BROWSER_REGISTRY') if key in os.environ}},
                             "service", pass_fds=(listener.fileno(),))
            # Keep our duplicate through tunnel shutdown, even if the backend
            # dies: the permanent route must never reach an unrelated listener.
            if self.named:
                # Authenticate the backend before publishing the fixed route.
                while not await self.supervised_probe(self.ready_probe, port, origin):
                    self.check_children()
                    if self.stop.is_set():
                        return
                    if time.monotonic() > deadline:
                        raise RuntimeError("The local tools did not become ready. Open diagnostics.")
                    await self.pause()
                emit("starting", message="Connecting your permanent address…")
                if self.stop.is_set():
                    return
                self.tunnel = await self.spawn(command, env, "tunnel")
            while not self.stop.is_set():
                self.check_children()
                if self.connected and await self.supervised_probe(self.ready_probe, port, origin):
                    # Yield once and recheck children after the probe, including
                    # a competing process winning the ephemeral port race.
                    await self.pause(.05)
                    self.check_children()
                    if not self.named or await self.supervised_probe(self.public_probe, port, origin):
                        self.check_children()
                        break
                if time.monotonic() > deadline:
                    raise RuntimeError("The connection did not become ready. Open diagnostics for details, then try Start again.")
                await self.pause()
            if self.stop.is_set():
                return
            def publish_ready():
                emit("ready", url=origin + "/mcp", connection="stable" if self.named else "temporary",
                 message="Permanent address verified. Link ChatGPT below." if self.named else
                         "Local service ready; tunnel connected. Link ChatGPT below.")
            publish_ready()
            healthy_since = time.monotonic()
            next_health = healthy_since + self.health_interval
            unhealthy_samples = 0
            failures = 0
            while not self.stop.is_set():
                self.check_service()
                recover = self.named and self.tunnel.returncode is not None
                if self.named and not recover:
                    if self._probe_future is not None and self._probe_future.done():
                        health = await self.finish_probe(service_only=True)
                        if self.stop.is_set():
                            return
                        now = time.monotonic()
                        next_health = now + self.health_interval
                        if health == "healthy":
                            unhealthy_samples = 0
                            if healthy_since is None:
                                healthy_since = now
                            if now - healthy_since >= self.health_reset_after:
                                failures = 0
                        else:
                            healthy_since = None
                            unhealthy_samples = unhealthy_samples + 1 if health == "public_unreachable" else 0
                            self.logger.warning("permanent route health: %s; consecutive public failures %s/%s",
                                health, unhealthy_samples, self.health_failure_threshold)
                            recover = unhealthy_samples >= self.health_failure_threshold
                    elif self._probe_future is None and time.monotonic() >= next_health:
                        self.start_probe(self.route_health, port, origin)
                    recover = recover or self.tunnel.returncode is not None
                if recover:
                    # An in-flight old-route sample must not overlap replacement
                    # readiness or become authority for a different tunnel.
                    if self._probe_future is not None:
                        await self.finish_probe(service_only=True)
                        if self.stop.is_set():
                            return
                    failures = await self.recover_tunnel(command, env, port, origin, failures)
                    if self.stop.is_set():
                        return
                    self.check_service()
                    if self.tunnel.returncode is not None:
                        continue
                    publish_ready()
                    healthy_since = time.monotonic()
                    next_health = healthy_since + self.health_interval
                    unhealthy_samples = 0
                elif not self.named:
                    self.check_children()
                await self.pause(.3)
        finally:
            emit("stopping", message="Stopping the connection and local tools…")
            # Stop the tunnel first; then let the service shut down its own jobs.
            # Signal live subprocess handles only, never saved PIDs or pkill.
            drained = False
            try:
                ordered = ([self.tunnel] if self.tunnel else []) + [p for p in self.children if p is not self.tunnel]
                for process in ordered:
                    await self.stop_owned_child(process, service=process is not self.tunnel)
                for task in self.readers:
                    task.cancel()
                await asyncio.gather(*self.readers, return_exceptions=True)
                drained = True
            finally:
                try:
                    await self.join_probe()
                finally:
                    listener.close()
                    self.logger.removeHandler(handler)
                    handler.close()
                    # Never publish drain proof after incomplete child cleanup.
                    if drained and self._probe_task is None:
                        emit("children_stopped")


async def watch_parent(supervisor):
    reader = asyncio.StreamReader(limit=128)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport = None
    try:
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        # Sole reader demultiplexes reservation ACK, explicit Stop, and EOF.
        # The per-launch socketpair and nonce bind ACK to the exact handoff.
        if supervisor.lifecycle_nonce:
            packet = await reader.readline()
            if packet == ('reserved ' + supervisor.lifecycle_nonce + '\n').encode():
                supervisor.reservation_ack.set()
                await reader.read(1)
        else:
            await reader.read(1)
    finally:
        supervisor.stop.set()
        if transport:
            transport.close()


async def owned_run(supervisor):
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, supervisor.stop.set)
    parent = asyncio.create_task(watch_parent(supervisor))
    try:
        await supervisor.run()
    finally:
        parent.cancel()
        await asyncio.gather(parent, return_exceptions=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Workbench desktop process supervisor")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--incoming-folder", type=Path,
                        help="Locally selected read-only folder containing incoming browser downloads")
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--cloudflared", required=True, type=Path)
    parser.add_argument("--lifecycle-nonce", help="Native per-launch listener/guardian channel nonce")
    parser.add_argument("--allow-edits", action="store_true")
    parser.add_argument("--allow-commands", action="store_true")
    from .capability_profiles import PROFILES
    parser.add_argument("--capability-profile", choices=list(PROFILES), default='full_owner')
    parser.add_argument("--no-history-access", dest='history_access', action='store_false', default=True)
    parser.add_argument('--oauth-discovery-mode', choices=OAUTH_DISCOVERY_MODES, default='client_metadata')
    args = parser.parse_args(argv)
    lock = None
    try:
        os.umask(0o077)
        if args.lifecycle_nonce and not re.fullmatch(r'[0-9a-f]{32}', args.lifecycle_nonce):
            raise ValueError('Invalid native lifecycle nonce')
        secret = os.environ.pop("LOCAL_WORKBENCH_OWNER_SECRET", "")
        if len(secret) < 32:
            raise ValueError("The pairing code is missing. Quit and reopen Local Workbench.")
        if not args.cloudflared.is_file() or not os.access(args.cloudflared, os.X_OK):
            raise ValueError("cloudflared is missing. Re-run the Mac app installer after installing cloudflared.")
        args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(args.data_dir, 0o700)
        lock = os.open(args.data_dir / "launcher.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Local Workbench is already running. Use its existing window.") from None
        config = prepare_profile(args.data_dir, args.workspace, args.allow_edits, args.allow_commands,
                                 capability_profile=args.capability_profile, history_access=args.history_access,
                                 incoming_folder=args.incoming_folder, oauth_discovery_mode=args.oauth_discovery_mode)
        asyncio.run(owned_run(Supervisor(config, args.cloudflared, args.data_dir, secret,
                                        lifecycle_nonce=args.lifecycle_nonce)))
    except (ValueError, OSError, RuntimeError, WorkbenchError) as exc:
        emit("error", message=str(exc))
        return 1
    finally:
        if lock is not None:
            os.close(lock)
    emit("stopped", message="Stopped. Your files and saved tool history are retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
