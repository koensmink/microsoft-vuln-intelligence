from __future__ import annotations

from dataclasses import dataclass
import logging
from threading import RLock
from time import monotonic


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CachedResponse:
    body: bytes
    status_code: int
    headers: tuple[tuple[str, str], ...]
    expires_at: float


class TTLResponseCache:
    """Small process-local cache guarded for concurrent FastAPI worker threads."""

    def __init__(self) -> None:
        self._entries: dict[str, CachedResponse] = {}
        self._lock = RLock()

    def get(self, key: str) -> CachedResponse | None:
        now = monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            return entry

    def set(
        self,
        key: str,
        *,
        body: bytes,
        status_code: int,
        headers: tuple[tuple[str, str], ...],
        ttl_seconds: int,
    ) -> None:
        with self._lock:
            self._entries[key] = CachedResponse(
                body=body,
                status_code=status_code,
                headers=headers,
                expires_at=monotonic() + ttl_seconds,
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


stats_cache = TTLResponseCache()
