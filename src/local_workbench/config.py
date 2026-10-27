from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import WorkbenchError
from .capability_profiles import CapabilityPolicy

OAUTH_DISCOVERY_MODES = ('client_metadata', 'dynamic_registration')


@dataclass(frozen=True)
class Workspace:
    name: str
    root: Path
    writable: bool = False
    executable: bool = False

    def __post_init__(self):
        if type(self.writable) is not bool or type(self.executable) is not bool:
            raise WorkbenchError("invalid_config", "Permissions must be booleans.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.name):
            raise WorkbenchError("invalid_config", "Workspace names must be simple identifiers.")
        root = Path(self.root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise WorkbenchError("invalid_config", "Workspace root must be a directory.")
        object.__setattr__(self, "root", root)


@dataclass(frozen=True)
class Config:
    workspaces: dict[str, Workspace]
    state_dir: Path
    max_artifact_bytes: int = 512 * 1024 * 1024
    max_storage_bytes: int = 4 * 1024 * 1024 * 1024
    max_job_output_bytes: int = 256 * 1024 * 1024
    max_jobs: int = 4
    capability_profile: str = 'full_owner'
    history_access: bool = True
    oauth_discovery_mode: str = 'client_metadata'

    def __post_init__(self):
        CapabilityPolicy(self.capability_profile, self.history_access)
        if type(self.oauth_discovery_mode) is not str or self.oauth_discovery_mode not in OAUTH_DISCOVERY_MODES:
            raise WorkbenchError('invalid_config', 'Unknown OAuth discovery mode.')
        if not self.workspaces or any(k != v.name for k, v in self.workspaces.items()):
            raise WorkbenchError("invalid_config", "Configure at least one consistently named workspace.")
        for name in ("max_artifact_bytes", "max_storage_bytes", "max_job_output_bytes", "max_jobs"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise WorkbenchError("invalid_config", f"{name} must be a positive integer.")
        state = Path(self.state_dir).expanduser().resolve()
        for workspace in self.workspaces.values():
            if state == workspace.root or state.is_relative_to(workspace.root):
                raise WorkbenchError("invalid_config", "State must be outside exposed workspaces (it contains private journals and authentication data).")
        object.__setattr__(self, "state_dir", state)

    def workspace(self, name: str) -> Workspace:
        try:
            return self.workspaces[name]
        except KeyError:
            raise WorkbenchError("unknown_workspace", "Unknown workspace.", available=list(self.workspaces)) from None


def load_config(path: str | Path) -> Config:
    path = Path(path).expanduser().resolve(strict=True)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("workspaces"), dict) or not isinstance(raw.get("state_dir"), str):
        raise WorkbenchError("invalid_config", "Configuration requires a workspaces object and a state_dir string.")
    allowed = {"workspaces", "state_dir", "max_artifact_bytes", "max_storage_bytes", "max_job_output_bytes", "max_jobs", "capability_profile", "history_access", "oauth_discovery_mode"}
    unknown = set(raw) - allowed
    if unknown:
        raise WorkbenchError("invalid_config", "Unknown configuration keys.", keys=sorted(unknown))

    def absolute(value: str) -> Path:
        result = Path(value).expanduser()
        return result if result.is_absolute() else path.parent / result

    workspaces = {}
    for name, item in raw.get("workspaces", {}).items():
        if not isinstance(item, dict) or not isinstance(item.get("root"), str):
            raise WorkbenchError("invalid_config", "Each workspace requires a root path string.")
        if set(item) - {"root", "writable", "executable"}:
            raise WorkbenchError("invalid_config", f"Unknown workspace setting in {name}.")
        for permission in ("writable", "executable"):
            if type(item.get(permission, False)) is not bool:
                raise WorkbenchError("invalid_config", "Permissions must be JSON booleans.")
        workspaces[name] = Workspace(name, absolute(item["root"]), item.get("writable", False), item.get("executable", False))
    values = {key: value for key, value in raw.items() if key not in ("workspaces", "state_dir")}
    return Config(workspaces, absolute(raw["state_dir"]), **values)
