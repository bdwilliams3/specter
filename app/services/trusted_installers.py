"""
Trusted installer allowlist.

Customers deploying Specter have known automation principals (GitOps controllers,
CI pipelines, OpenShift operators) that perform legitimate mutations — installing
charts, patching RBAC, creating ServiceAccounts. Treating those as threats
destroys signal-to-noise.

The allowlist is loaded from a ConfigMap-mounted YAML and matched against the
audit event's `user.username` with fnmatch glob semantics. Reloaded on a cadence
so customers can edit the ConfigMap without restarting the pod.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import threading
import time
from typing import Iterable

import yaml

from app.config import settings

logger = logging.getLogger(__name__)

# How often to re-read the ConfigMap file from disk
_RELOAD_INTERVAL_SECONDS = 60


class TrustedInstallers:
    def __init__(self, path: str):
        self._path = path
        self._patterns: list[str] = []
        self._mtime: float = 0.0
        self._last_check: float = 0.0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            mtime = os.path.getmtime(self._path)
        except OSError:
            if self._patterns:
                logger.warning("Trusted installers file vanished: %s", self._path)
                self._patterns = []
            return

        if mtime == self._mtime and self._patterns:
            return

        try:
            with open(self._path, "r") as f:
                doc = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error("Failed to parse %s: %s", self._path, e)
            return

        patterns = doc.get("trustedInstallers") or []
        if not isinstance(patterns, list):
            logger.error("trustedInstallers must be a list, got %s", type(patterns).__name__)
            return

        self._patterns = [str(p) for p in patterns if p]
        self._mtime = mtime
        logger.info("Loaded %d trusted-installer patterns from %s", len(self._patterns), self._path)

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._last_check < _RELOAD_INTERVAL_SECONDS:
            return
        with self._lock:
            self._last_check = now
            self._load()

    def is_trusted(self, username: str) -> bool:
        if not username:
            return False
        self._maybe_reload()
        return any(fnmatch.fnmatchcase(username, p) for p in self._patterns)

    @property
    def patterns(self) -> Iterable[str]:
        return tuple(self._patterns)


# Module-level singleton. Safe because the file is read lazily and the loader
# degrades to an empty list if the path is missing (dev environments).
trusted_installers = TrustedInstallers(settings.trusted_installers_path)
