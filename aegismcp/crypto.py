"""Application-layer authenticated encryption for token mappings."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(RuntimeError):
    pass


class MappingCipher:
    """AES-256-GCM cipher. Supply a 32-byte key from a secret manager/KMS."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires exactly 32 key bytes")
        self._key = bytes(key)

    @classmethod
    def from_base64(cls, encoded_key: str) -> "MappingCipher":
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except Exception as exc:
            raise ValueError("encryption key must be valid base64") from exc
        return cls(key)

    def encrypt(self, plaintext: str, *, associated_data: bytes) -> bytes:
        nonce = os.urandom(12)
        try:
            return nonce + AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        except Exception as exc:
            raise EncryptionError("mapping encryption failed") from exc

    def decrypt(self, payload: bytes, *, associated_data: bytes) -> str:
        if len(payload) < 12 + 16:
            raise EncryptionError("invalid encrypted mapping")
        try:
            value = AESGCM(self._key).decrypt(payload[:12], payload[12:], associated_data)
            return value.decode("utf-8")
        except Exception as exc:
            raise EncryptionError("mapping authentication/decryption failed") from exc
