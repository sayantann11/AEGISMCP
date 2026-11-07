"""Redis-backed encrypted token vault. Redis receives ciphertext only."""

import hashlib
import hmac
import re
from typing import Any

from .crypto import MappingCipher
from .vault import VaultError


_TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_\d{2,}\]")


class RedisTokenVault:
    """Redis vault adapter requiring an explicit tenant and session scope.

    Redis keys are HMAC-derived so tenant/session/token identifiers are not
    disclosed to Redis. Values are AES-GCM ciphertext with scope-bound AAD.
    The configured TTL is intentionally restricted to 5-15 minutes.
    """

    def __init__(self, redis_client: Any, cipher: MappingCipher, *, index_key: bytes,
                 ttl_seconds: int = 600) -> None:
        if len(index_key) < 32:
            raise ValueError("index_key must contain at least 32 bytes")
        if not 300 <= ttl_seconds <= 900:
            raise ValueError("ttl_seconds must be between 300 and 900")
        self._redis = redis_client
        self._cipher = cipher
        self._index_key = bytes(index_key)
        self._ttl = ttl_seconds

    @staticmethod
    def _scope(tenant_id: str, session_id: str, token: str) -> bytes:
        if (not tenant_id or not session_id or "\0" in tenant_id or "\0" in session_id
                or not _TOKEN_RE.fullmatch(token)):
            raise VaultError("tenant, session, or token scope is invalid")
        return b"aegismcp:v1\0" + tenant_id.encode() + b"\0" + session_id.encode() + b"\0" + token.encode()

    def _key(self, scope: bytes) -> str:
        digest = hmac.new(self._index_key, scope, hashlib.sha256).hexdigest()
        return "aegis:v1:" + digest

    def put(self, session_id: str, token: str, value: str, *, tenant_id: str) -> None:
        scope = self._scope(tenant_id, session_id, token)
        redis_key = self._key(scope)
        try:
            ciphertext = self._cipher.encrypt(value, associated_data=scope)
            # One atomic SET with EX: a mapping can never be written without TTL.
            result = self._redis.set(redis_key, ciphertext, ex=self._ttl)
            if result is not True and result != b"OK" and result != "OK":
                raise VaultError("Redis did not confirm mapping write")
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError("vault write failed; do not forward original prompt") from exc

    def get(self, session_id: str, token: str, *, tenant_id: str) -> str:
        scope = self._scope(tenant_id, session_id, token)
        try:
            payload = self._redis.get(self._key(scope))
            if payload is None:
                raise VaultError("unknown, expired, or unauthorized token")
            if isinstance(payload, memoryview):
                payload = payload.tobytes()
            if not isinstance(payload, bytes):
                raise VaultError("vault returned an invalid payload")
            return self._cipher.decrypt(payload, associated_data=scope)
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError("vault read/decryption failed; withhold response") from exc

    def delete(self, session_id: str, token: str, *, tenant_id: str) -> None:
        scope = self._scope(tenant_id, session_id, token)
        try:
            self._redis.delete(self._key(scope))
        except Exception as exc:
            raise VaultError("vault deletion failed") from exc


def create_tls_redis_client(*, host: str, port: int, username: str,
                            password: str, ca_certs: str,
                            client_cert: str, client_key: str) -> Any:
    """Create a TLS-verified redis-py client; no plaintext fallback is allowed."""
    if not all((host, username, password, ca_certs, client_cert, client_key)):
        raise ValueError("host, ACL credentials, CA certificate, and client certificate/key are required")
    try:
        import redis
    except ImportError as exc:
        raise RuntimeError("Install the 'redis' package to use RedisTokenVault") from exc
    return redis.Redis(host=host, port=port, username=username, password=password,
                       ssl=True, ssl_ca_certs=ca_certs, ssl_cert_reqs="required",
                       ssl_certfile=client_cert, ssl_keyfile=client_key,
                       decode_responses=False, socket_connect_timeout=2,
                       socket_timeout=2)
