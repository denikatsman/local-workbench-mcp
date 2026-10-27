"""Explicit native-host registration; no browser profile adoption or extension install."""
import json
import os
from pathlib import Path
import shlex
import sys

from .browser_wire import read_private_json
from .errors import WorkbenchError
from .persistence import atomic_json
from .selected_tabs import extension_identity


def register_host(state_dir, browser_user_data, registry, extension_dir=None, python=None):
    from .diagnostics import inspect_state
    state = Path(state_dir)
    if inspect_state(state)['state'] in ('unrecognized', 'unavailable'):
        raise WorkbenchError('unrecognized_state', 'Select a recognized Workbench state for browser setup.')
    browser = Path(browser_user_data)
    if browser.is_symlink() or not browser.is_dir():
        raise WorkbenchError('browser_setup_directory', 'Select an existing browser user-data directory; symlink adoption is refused.')
    extension = Path(extension_dir or Path(__file__).resolve().parents[2] / 'browser-extension')
    identity = extension_identity(extension)
    host_name = 'tools.localworkbench.selected_tabs'
    native_directory = browser / 'NativeMessagingHosts'
    if native_directory.is_symlink():
        raise WorkbenchError('browser_setup_directory', 'Native messaging storage may not be a symlink.')
    destination = native_directory / (host_name + '.json')
    owned = state / 'selected-browser'; owned.mkdir(mode=0o700, exist_ok=True)
    host = owned / 'native-host'
    manifest = {'name': host_name, 'description': 'Local Workbench explicitly selected browser tabs',
                'path': str(host.absolute()), 'type': 'stdio',
                'allowed_origins': ['chrome-extension://' + identity['extension_id'] + '/']}
    if destination.exists() or destination.is_symlink():
        if read_private_json(destination) != manifest:
            raise WorkbenchError('browser_registration_conflict', 'An existing browser-host registration differs; it was not replaced.')
    native_directory.mkdir(mode=0o700, exist_ok=True)
    executable = Path(python or sys.executable).absolute()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise WorkbenchError('browser_setup_runtime', 'The selected Python runtime is unavailable.')
    source = Path(__file__).resolve().parents[1]
    script = '#!/bin/sh\nexec /usr/bin/env -i ' + ' '.join([
        'HOME=' + shlex.quote(str(Path.home())), 'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
        'PYTHONPATH=' + shlex.quote(str(source)), shlex.quote(str(executable)),
        '-B -m local_workbench.browser_host --registry', shlex.quote(str(Path(registry).absolute())), '"$@"']) + '\n'
    temporary = owned / ('host-' + os.urandom(8).hex())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(script); output.flush(); os.fsync(output.fileno())
        temporary.replace(host)
    finally:
        temporary.unlink(missing_ok=True)
    atomic_json(destination, manifest)
    return {'ok': True, 'extension_id': identity['extension_id'], 'extension_directory': str(extension.absolute()),
            'host_manifest': str(destination), 'registry': str(Path(registry).absolute()),
            'extension_installed': False, 'browser_launched': False, 'tabs_granted': False,
            'scope': 'Native-host registration only; the user installs the extension and grants individual tabs locally.'}
