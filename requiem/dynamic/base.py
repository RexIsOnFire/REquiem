"""Dynamic analysis backend interface.

A dynamic backend detonates (or pretends to detonate) a sample and returns
observed runtime behavior. ReQuiem ships a *simulated* backend so reports are
complete and demoable without dangerous live detonation; a real sandbox
(CAPE/Cuckoo, a Windows VM with an agent, a container jail) implements the same
interface and drops in unchanged.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import DynamicBehavior, FileIdentity


class DynamicBackend(ABC):
    name: str = "base"
    simulated: bool = True

    @abstractmethod
    def detonate(self, *, data: bytes, identity: FileIdentity,
                 static_hints: dict | None = None) -> DynamicBehavior:
        """Execute the sample and return observed behavior.

        ``static_hints`` lets the backend seed/steer its observations from what
        static analysis already found (e.g. imports, suspected classification).
        Real backends ignore hints or use them only to focus instrumentation.
        """
        raise NotImplementedError
