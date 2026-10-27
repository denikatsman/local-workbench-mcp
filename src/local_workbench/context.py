"""Caller-supplied task context. Attribution is not an authorization boundary."""
from contextvars import ContextVar

work_context=ContextVar('workbench_work_session',default=None)
work_admission=ContextVar('workbench_work_admission',default=None)
invocation_trace=ContextVar('workbench_invocation_trace',default=None)
capture_sensitive=ContextVar('workbench_capture_sensitive',default=False)
