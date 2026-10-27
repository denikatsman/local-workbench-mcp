from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import sys

from .auth import OwnerOAuth
from .config import load_config
from .errors import WorkbenchError


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Workbench: explicit local files and process tools for MCP.")
    parser.add_argument("--config", required=True, help="Path to the workspace configuration JSON.")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect-state", help="Read-only job/spool diagnostics; no server startup or repair.")
    inspect.add_argument("--offset", type=int, default=0)
    inspect.add_argument("--limit", type=int, default=10)
    catalogue = commands.add_parser('inspect-catalogues', help='Read-only DB/WAL, blob and job diagnostics, independent of server construction.')
    catalogue.add_argument('--verify-blobs', action='store_true')
    catalogue.add_argument('--offset', type=int, default=0)
    catalogue.add_argument('--limit', type=int, default=20)
    recovery = commands.add_parser('recover-jobs', help='Build a separate byte-preserving recovery generation; never activates it or edits the source.')
    recovery.add_argument('--destination', required=True)
    recovery.add_argument('--max-bytes', type=int, default=1073741824)
    recovery.add_argument('--max-members', type=int, default=100000)
    recovery.add_argument('--timeout-ms', type=int, default=120000)
    evidence = commands.add_parser('read-job-evidence', help='Read an intact job spool without opening catalogue databases or signalling any PID.')
    evidence.add_argument('--job-id', required=True)
    evidence.add_argument('--stream', choices=['stdout', 'stderr'], default='stdout')
    evidence.add_argument('--offset', type=int, default=0)
    evidence.add_argument('--max-bytes', type=int, default=16384)
    browser_setup = commands.add_parser('browser-bridge-setup', help='Register the local native host; extension installation and per-tab grants remain local user actions.')
    browser_setup.add_argument('--browser-user-data', required=True)
    browser_setup.add_argument('--registry', required=True)
    serve = commands.add_parser("serve", help="Serve MCP; stdio by default, OAuth-protected loopback HTTP optionally.")
    serve.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    serve.add_argument("--port", type=int, default=8788)
    serve.add_argument("--listen-fd", type=int, help=argparse.SUPPRESS)
    serve.add_argument("--public-url", help="Externally visible HTTPS origin, or loopback HTTP for local tests.")
    serve.add_argument("--owner-secret-env", default="LOCAL_WORKBENCH_OWNER_SECRET",
                       help="Environment variable containing the random owner consent secret; never pass the secret as a flag.")
    args = parser.parse_args(argv)
    lock_fd = None
    try:
        config = load_config(args.config)
        if args.command == "inspect-state":
            from .diagnostics import inspect_state
            print(json.dumps(inspect_state(config.state_dir, args.offset, args.limit), ensure_ascii=True, indent=2))
            return 0
        if args.command == 'inspect-catalogues':
            from .catalogue_inspector import inspect_catalogues
            print(json.dumps(inspect_catalogues(config.state_dir, args.verify_blobs, args.offset, args.limit), ensure_ascii=True, indent=2))
            return 0
        if args.command == 'recover-jobs':
            from .catalogue_inspector import build_job_recovery_generation
            print(json.dumps(build_job_recovery_generation(config.state_dir, args.destination,
                             args.max_bytes, args.max_members, args.timeout_ms), ensure_ascii=True, indent=2))
            return 0
        if args.command == 'read-job-evidence':
            from .catalogue_inspector import read_job_evidence
            print(json.dumps(read_job_evidence(config.state_dir, args.job_id, args.stream, args.offset, args.max_bytes), ensure_ascii=True, indent=2))
            return 0
        if args.command == 'browser-bridge-setup':
            from .browser_setup import register_host
            print(json.dumps(register_host(config.state_dir, args.browser_user_data, args.registry), indent=2))
            return 0
        from .store import prepare_state
        prepare_state(config.state_dir)
        lock_fd = os.open(config.state_dir / "server.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another Local Workbench server already owns this state directory.") from None
        from .server import create_server, http_app
        if args.transport == "stdio":
            create_server(config).run()
        else:
            if not 1 <= args.port <= 65535:
                parser.error("port must be between 1 and 65535")
            if not args.public_url:
                parser.error("HTTP requires --public-url and an owner secret environment variable")
            oauth = OwnerOAuth(config.state_dir, args.public_url, os.environ.get(args.owner_secret_env, ""),
                               oauth_discovery_mode=config.oauth_discovery_mode)
            server = create_server(config, oauth=oauth)
            import uvicorn
            if args.listen_fd is not None:
                with socket.fromfd(args.listen_fd, socket.AF_INET, socket.SOCK_STREAM) as listener:
                    if listener.getsockname() != ("127.0.0.1", args.port) or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                        raise ValueError("Inherited listener must be a TCP socket bound to the configured loopback port.")
            uvicorn.run(http_app(server, oauth, args.port), host="127.0.0.1", port=args.port,
                        fd=args.listen_fd, access_log=False, proxy_headers=False, log_level="warning", limit_concurrency=32)
    except (WorkbenchError, ValueError, OSError) as exc:
        print(f"Local Workbench: {exc}", file=sys.stderr)
        return 2
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
    return 0
