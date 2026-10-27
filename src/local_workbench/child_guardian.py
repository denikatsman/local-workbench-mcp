"""Ephemeral owned-child lifetime guard. No PID files, discovery, or reattachment.

The supervisor alone owns the liveness writer. The native owner alone consumes
structured event records; payload output goes to a separate diagnostic pipe.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import sys


class PrivateRotatingLog(RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'a', encoding='utf-8')


def event(fd: int, status: str, ticket: str, role: str):
    data = (json.dumps(dict(status=status, ticket=ticket, role=role), separators=(',', ':')) + '\n').encode()
    # One successful atomic write BEFORE spawn is registration. A partial or
    # failed write is not registration and must never be followed by a payload.
    if len(data) > os.fpathconf(fd, 'PC_PIPE_BUF') or os.write(fd, data) != len(data):
        raise RuntimeError('Owned child event could not be published atomically')


async def stop_owned_payload(payload, wait, role, grace):
    if payload.returncode is None:
        try:
            payload.terminate()
        except ProcessLookupError:
            pass
    if role == 'tunnel':
        try:
            await asyncio.wait_for(asyncio.shield(wait), grace)
        except TimeoutError:
            if payload.returncode is None:
                try:
                    payload.kill()
                except ProcessLookupError:
                    pass
            await wait
    else:
        # Durable backend finalizers are never escalated by elapsed time.
        await wait


async def run(args):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    os.set_inheritable(args.life_fd, False)
    os.set_inheritable(args.event_fd, False)
    for fd in args.payload_fds:
        os.set_inheritable(fd, False)
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, os.fdopen(args.life_fd, 'rb', buffering=0))

    async def owner_gone():
        try:
            await reader.read(1)  # EOF or an explicit byte both revoke run intent.
        finally:
            stop.set()
    owner = asyncio.create_task(owner_gone())
    logger = logging.getLogger('guardian.' + args.ticket)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = PrivateRotatingLog(Path(args.data_dir) / ('child-' + args.role + '.log'),
        maxBytes=2 * 1024 * 1024, backupCount=3, encoding='utf-8')
    logger.addHandler(handler)
    payload = None
    output = None
    wait = None
    stopper = None
    try:
        event(args.event_fd, 'child_started', args.ticket, args.role)
        # Let an already closed liveness pipe revoke startup before spawning.
        await asyncio.sleep(0)
        if not stop.is_set():
            try:
                payload = await asyncio.create_subprocess_exec(*args.command,
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT, pass_fds=tuple(args.payload_fds))
            except OSError:
                # The exec API failed without producing a payload handle.
                logger.exception('Owned payload could not start')
                event(args.event_fd, 'child_stopped', args.ticket, args.role)
                return 1
            # Only the intended backend listener is inherited; no native event,
            # control, or liveness descriptor enters arbitrary payloads/jobs.
            for fd in args.payload_fds:
                os.close(fd)
            args.payload_fds = []
            os.set_blocking(sys.stdout.fileno(), False)

            async def drain():
                while data := await payload.stdout.read(8192):
                    logger.info('%s', data.decode('utf-8', errors='replace').rstrip())
                    try:
                        # Diagnostics remain complete in the private guard log
                        # even if its old supervisor died or stopped reading.
                        os.write(sys.stdout.fileno(), data)
                    except (BlockingIOError, BrokenPipeError):
                        pass
            output = asyncio.create_task(drain())
            wait = asyncio.create_task(payload.wait())
            stopper = asyncio.create_task(stop.wait())
            await asyncio.wait((wait, stopper), return_when=asyncio.FIRST_COMPLETED)
            await stop_owned_payload(payload, wait, args.role, args.tunnel_grace)
            await output
        # This receipt follows actual handle wait/output drain, not wrapper
        # exit, inventory absence, elapsed time, or a persisted process ID.
        event(args.event_fd, 'child_stopped', args.ticket, args.role)
        return payload.returncode if payload is not None else 0
    finally:
        # Exceptions after registration withhold completion. Native owner keeps
        # its reserved listener and refuses speculative replacement/normal Quit.
        if payload is not None and payload.returncode is None:
            await stop_owned_payload(payload, wait or asyncio.create_task(payload.wait()), args.role, args.tunnel_grace)
        if output is not None:
            await asyncio.gather(output, return_exceptions=True)
        owner.cancel()
        if stopper is not None:
            stopper.cancel()
        await asyncio.gather(owner, *([stopper] if stopper else []), return_exceptions=True)
        transport.close()
        for fd in args.payload_fds:
            os.close(fd)
        os.close(args.event_fd)
        logger.removeHandler(handler)
        handler.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--life-fd', type=int, required=True)
    parser.add_argument('--event-fd', type=int, required=True)
    parser.add_argument('--ticket', required=True)
    parser.add_argument('--role', choices=('service', 'tunnel'), required=True)
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--payload-fd', type=int, action='append', dest='payload_fds', default=[])
    parser.add_argument('--tunnel-grace', type=float, default=12)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ['--']:
        args.command = args.command[1:]
    if not args.command or len(args.ticket) != 32 or any(c not in '0123456789abcdef' for c in args.ticket):
        parser.error('Invalid owned child invocation')
    return asyncio.run(run(args))


if __name__ == '__main__':
    raise SystemExit(main())
