"""Environment settings. The project was renamed from marlin-check to
oceansoftwarecheck on 2026-09-16: variables are read as OSC_<NAME>, with the
old MARLIN_<NAME> still honoured so a deployment can switch at its own pace."""

from __future__ import annotations

import logging
import os

log = logging.getLogger("oceansoftwarecheck")
_legacy_seen: set[str] = set()


def env(name: str, default: str = "") -> str:
    """OSC_<name>, falling back to the pre-rename MARLIN_<name>, then `default`."""
    new, old = f"OSC_{name}", f"MARLIN_{name}"
    if new in os.environ:
        return os.environ[new]
    if old in os.environ:
        if old not in _legacy_seen:
            _legacy_seen.add(old)
            log.warning("%s is deprecated, rename it to %s", old, new)
        return os.environ[old]
    return default
