"""Single-owner MCP tool policy; not an OS sandbox or a principal partition."""
from .errors import WorkbenchError


COMMON = frozenset('''workspace_info runtime_info permissions_status
work_session_open work_session_list work_session_inspect work_session_note work_session_close
work_session_verify work_session_export storage_status storage_pin
catalogue_inspect state_inspect saved_download_inspect artifact_read artifact_view artifact_search
artifact_query artifact_batch_read artifact_preview artifact_verify artifact_provenance
artifact_upload artifact_upload_status operation_status operation_reconcile invocation_status
job_status job_observe job_list job_read job_cancel browser_close'''.split())
SOURCES = frozenset('''file_stat plist_query sqlite_query list_files workspace_inventory
archive_manifest archive_member read_file search_text'''.split())
DEVELOPMENT = frozenset('''work_session_lease work_session_scratch storage_cleanup
environment_resolve environment_profile change_set_prepare change_set_validate
change_set_inspect change_set_publish change_set_reconcile script_run filesystem_operation
service terminal workflow git_acquire diagnostic_run browser_open browser_download browser_profile browser_snapshot
browser_target browser_navigate browser_action browser_evaluate write_file edit_file
make_directory job_start job_input'''.split())
SELECTED_APPS = frozenset(('selected_browser', 'selected_download', 'browser_diagnostics', 'native_app'))
HISTORY = frozenset('''work_session_list work_session_inspect work_session_verify work_session_export
storage_status storage_pin storage_cleanup catalogue_inspect state_inspect saved_download_inspect
artifact_read artifact_view artifact_search artifact_query artifact_batch_read
artifact_preview artifact_verify artifact_provenance artifact_upload_status
operation_status operation_reconcile invocation_status job_status job_observe job_list job_read'''.split())
PROFILES = {
    'source_research': ('Selected-source research', COMMON | SOURCES),
    'project_development': ('Project development', COMMON | SOURCES | DEVELOPMENT),
    'selected_app': ('Selected-app operation', COMMON | SELECTED_APPS),
    'full_owner': ('Broad host execution', COMMON | SOURCES | DEVELOPMENT | SELECTED_APPS),
}
CONTROL_ACTIONS = {'browser_diagnostics': frozenset(('stop',)), 'browser_download': frozenset(('cancel',)),
                   'selected_download': frozenset(('cancel', 'stop')),
                   'terminal': frozenset(('stop', 'interrupt')),
                   'service': frozenset(('stop',)),
                   'selected_browser': frozenset(('detach',)),
                   'work_session_lease': frozenset(('inspect', 'restore', 'release')),
                   'work_session_scratch': frozenset(('inspect', 'retire', 'restore', 'reconcile'))}


class CapabilityPolicy:
    def __init__(self, profile='full_owner', history_access=True):
        if not isinstance(profile, str) or profile not in PROFILES:
            raise WorkbenchError('invalid_config', 'Choose a supported capability profile.', available=list(PROFILES))
        if type(history_access) is not bool:
            raise WorkbenchError('invalid_config', 'history_access must be a JSON boolean.')
        self.profile, self.history_access = profile, history_access

    def check(self, tool, arguments=None):
        if not self.history_access and (tool in HISTORY or tool == 'diagnostic_run' and isinstance(arguments, dict) and arguments.get('action') == 'inspect'):
            raise WorkbenchError('history_access_denied', 'Saved-evidence retrieval is disabled in this local configuration.',
                                 effect_state='none', profile=self.profile)
        action = arguments.get('action') if isinstance(arguments, dict) else None
        if not self.history_access and tool in ('browser_download', 'selected_download') and action == 'state':
            raise WorkbenchError('history_access_denied', 'Saved download evidence retrieval is disabled.', effect_state='none', profile=self.profile)
        if not self.history_access and tool == 'browser_diagnostics' and action in ('status','export'):
            raise WorkbenchError('history_access_denied','Saved diagnostic evidence retrieval is disabled.',effect_state='none')
        control = isinstance(action, str) and action in CONTROL_ACTIONS.get(tool, ())
        if tool not in PROFILES[self.profile][1] and not control:
            raise WorkbenchError('capability_profile_denied', 'This tool is not enabled by the local capability profile. Change the local configuration and restart Workbench.',
                                 effect_state='none', profile=self.profile)

    def describe(self):
        return {'active': self.profile, 'label': PROFILES[self.profile][0],
                'history_access': self.history_access,
                'artifact_access': 'same-owner saved evidence' if self.history_access else 'retrieval tools disabled',
                'profiles': [{'id': key, 'label': label, 'tool_count': len(tools)} for key, (label, tools) in PROFILES.items()],
                'authorization': 'Profile policy, OAuth consent, workspace access and selected-target grants all apply.',
                'containment': 'No OS sandbox or separate owner partition. Permitted commands execute as the host user; this policy does not prevent their indirect file or data access.',
                'changes': 'Local configuration is loaded by each server generation. There is no dedicated MCP profile-setting API.'}
