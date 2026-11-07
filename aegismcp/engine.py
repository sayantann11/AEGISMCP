"""Reversible tokenization orchestration; all detection happens locally."""

from dataclasses import dataclass
import re

from .detectors import PatternDetector
from .vault import InMemoryTokenVault, VaultError


_TOKEN = re.compile(r"\[(?:[A-Z][A-Z0-9_]{0,47})_\d{2,}\]")


@dataclass(frozen=True)
class TokenizationResult:
    sanitized_text: str
    token_count: int


class TokenizationEngine:
    def __init__(self, detector: PatternDetector, vault: InMemoryTokenVault) -> None:
        self.detector = detector
        self.vault = vault

    def tokenize(self, text: str, session_id: str, *, tenant_id: str = "default") -> TokenizationResult:
        """Return sanitized content. Any vault error propagates (fail closed)."""
        if not session_id:
            raise VaultError("session_id is required")
        entities = self.detector.detect(text)
        # Preserve consistent tokens for repeated values in the same request.
        value_tokens: dict[tuple[str, str], str] = {}
        counters: dict[str, int] = {}
        replacements: list[tuple[int, int, str]] = []
        for entity in entities:
            key = (entity.kind, entity.value)
            token = value_tokens.get(key)
            if token is None:
                counters[entity.kind] = counters.get(entity.kind, 0) + 1
                token = f"[{entity.kind}_{counters[entity.kind]:02d}]"
                # Persist before exposing sanitized text to the outbound caller.
                self.vault.put(session_id, token, entity.value, tenant_id=tenant_id)
                value_tokens[key] = token
            replacements.append((entity.start, entity.end, token))
        sanitized = text
        for start, end, token in reversed(replacements):
            sanitized = sanitized[:start] + token + sanitized[end:]
        return TokenizationResult(sanitized, len(entities))

    def restore(self, response: str, session_id: str, *, tenant_id: str = "default") -> str:
        """Restore only tokens belonging to this session; unknown tokens fail closed."""
        mappings = self.resolve_tokens(response, session_id, tenant_id=tenant_id)
        restored = response
        for token, original in mappings.items():
            restored = restored.replace(token, original)
        return restored

    def resolve_tokens(self, text: str, session_id: str, *, tenant_id: str = "default") -> dict[str, str]:
        """Load and decrypt every recognized placeholder in text before output begins."""
        if not session_id:
            raise VaultError("session_id is required")
        tokens = list(dict.fromkeys(_TOKEN.findall(text)))
        return {token: self.vault.get(session_id, token, tenant_id=tenant_id) for token in tokens}
