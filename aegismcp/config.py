"""Configuration lookup with Sutraksh-first, AEGIS-compatible naming."""

from __future__ import annotations

import os


def get_setting(name: str, default: str | None = None, *aliases: str) -> str | None:
    """Return the first configured value, preferring the SUTRAKSH namespace.

    ``name`` may use either ``SUTRAKSH_`` or the legacy ``AEGIS_`` prefix.
    Unprefixed setting names are treated as ``SUTRAKSH_`` names. Aliases are
    checked after the canonical name, allowing existing generic environment
    variables (such as ``REDIS_HOST``) to remain supported.
    """
    if name.startswith("AEGIS_"):
        canonical = "SUTRAKSH_" + name.removeprefix("AEGIS_")
        candidates = (canonical, name, *aliases)
    elif name.startswith("SUTRAKSH_"):
        candidates = (name, *aliases)
    else:
        candidates = ("SUTRAKSH_" + name, *aliases)

    for candidate in candidates:
        value = os.getenv(candidate)
        if value is not None:
            return value
    return default
