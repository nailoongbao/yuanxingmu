"""Per-dispatch host identity for SDK APIs that do not supply a call ID."""
from contextlib import contextmanager
from contextvars import ContextVar


class HostInvocations:
    """Bind one persisted host nonce per dispatch, never per complete agent run.

    This context binding is not an isolation boundary or durable storage. The
    trusted host must save each nonce before dispatch and retain it on recovery.
    """

    def __init__(self):
        self._current = ContextVar("yuanxingmu_host_invocation", default=None)

    @contextmanager
    def bind(self, nonce: str):
        if type(nonce) is not str or not nonce or len(nonce) > 512:
            raise ValueError("host_invocation_nonce_required")
        token = self._current.set(nonce)
        try:
            yield
        finally:
            self._current.reset(token)

    def current(self) -> str | None:
        return self._current.get()
