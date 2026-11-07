"""In-memory TTL vault mock. Not encrypted and not suitable for production."""

from dataclasses import dataclass
import threading
import time


class VaultError(RuntimeError):
    """Vault operation failed; callers must not forward the original prompt."""


@dataclass
class _Entry:
    value: str
    expires_at: float


class InMemoryTokenVault:
    """Session-scoped mappings with lazy TTL expiry (mock implementation)."""

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._entries: dict[tuple[str, str, str], _Entry] = {}
        self._lock = threading.RLock()

    def put(self, session_id: str, token: str, value: str, *, tenant_id: str = "default") -> None:
        if not session_id or not tenant_id:
            raise VaultError("tenant_id and session_id are required")
        with self._lock:
            self._entries[(tenant_id, session_id, token)] = _Entry(value, time.monotonic() + self._ttl)

    def get(self, session_id: str, token: str, *, tenant_id: str = "default") -> str:
        with self._lock:
            key = (tenant_id, session_id, token)
            entry = self._entries.get(key)
            if entry is None:
                raise VaultError("unknown token or session")
            if time.monotonic() >= entry.expires_at:
                del self._entries[key]
                raise VaultError("token expired")
            return entry.value

    def delete_session(self, session_id: str, *, tenant_id: str = "default") -> None:
        with self._lock:
            for key in [key for key in self._entries if key[0] == tenant_id and key[1] == session_id]:
                del self._entries[key]
