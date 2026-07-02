"""Sample-intelligence provider interface.

An intel provider answers one question: *what is publicly known about this
hash?* It returns metadata (family, prevalence, first-seen, tags) — never the
binary itself. ReQuiem deliberately does **not** auto-download malware samples;
acquisition is a manual, user-initiated action outside this interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import IntelResult


class IntelProvider(ABC):
    name: str = "base"

    @abstractmethod
    def lookup(self, *, sha256: str, md5: str | None = None, sha1: str | None = None) -> IntelResult:
        """Return what is known about the given hashes.

        Implementations must be resilient: on missing credentials, network
        failure, or an unknown sample, return ``IntelResult(known=False, ...)``
        with a human-readable ``detail`` rather than raising.
        """
        raise NotImplementedError


def gather_intel(
    providers: list[IntelProvider], *, sha256: str, md5: str | None, sha1: str | None
) -> list[IntelResult]:
    results: list[IntelResult] = []
    for p in providers:
        try:
            results.append(p.lookup(sha256=sha256, md5=md5, sha1=sha1))
        except Exception as exc:  # never let one provider break the run
            results.append(IntelResult(source=p.name, known=False, detail=f"error: {exc}"))
    return results
