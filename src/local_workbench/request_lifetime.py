"""Private per-HTTP-request transport observation, separate from peer Stop."""
import asyncio
import threading

SCOPE_KEY = 'local_workbench.request_lifetime'


class RequestLifetime:
    def __init__(self):
        self._lock = threading.Lock()
        self._listeners = set()
        self._disconnected = False
        self._closed = False
        self.disconnected = asyncio.Event()

    def subscribe(self, callback):
        with self._lock:
            notify = self._disconnected and not self._closed
            if not self._closed and not self._disconnected:
                self._listeners.add(callback)
        if notify:
            callback()
        def unsubscribe():
            with self._lock:
                self._listeners.discard(callback)
        return unsubscribe

    def disconnect(self):
        with self._lock:
            if self._closed or self._disconnected:
                return
            self._disconnected = True
            listeners = tuple(self._listeners)
            self._listeners.clear()
        self.disconnected.set()
        for callback in listeners:
            callback()

    def close(self):
        with self._lock:
            self._closed = True
            self._listeners.clear()

    async def watch(self, receive, observed):
        # The request body has already been consumed. This is the sole raw
        # receive owner; SDK consumers wait on the latched event via replay.
        while True:
            try:
                message = await receive()
            except Exception:
                return  # An exception alone does not prove http.disconnect.
            if message['type'] == 'http.disconnect':
                self.disconnect()
                try:
                    observed()
                except Exception:
                    pass  # Observation failures never control cleanup.
                return
