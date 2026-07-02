"""Cloud behavior *by hash* — no local sandbox, no file upload.

For a public-facing deployment you don't want to host CAPE/Cuckoo VMs. Instead
you look up whether a hash has *already* been detonated on a hosted service
(Triage, VirusTotal, Hybrid Analysis) and pull that behavioral report. This
module defines the provider interface and a gatherer; each concrete provider
lives in its own module and maps its report through :mod:`normalize`.

A provider returns a :class:`DynamicBehavior` (marked ``simulated=False``) when
it has a report for the hash, or ``None`` when the hash is unknown to it. It
must never raise — network/credential problems yield ``None`` + a note.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..core.models import DynamicBehavior


@dataclass
class CloudLookup:
    """Result of a by-hash cloud behavior lookup."""

    source: str
    found: bool
    behavior: DynamicBehavior | None = None
    note: str = ""


class CloudBehaviorProvider(ABC):
    name: str = "cloud"

    @abstractmethod
    def lookup(self, *, sha256: str) -> CloudLookup:
        """Return a behavioral report for ``sha256`` if the service has one.

        Never raises: on missing credentials, network failure, or an unknown
        hash, return ``CloudLookup(found=False, note=...)``.
        """
        raise NotImplementedError


def gather_cloud_behavior(
    providers: list[CloudBehaviorProvider], *, sha256: str
) -> list[CloudLookup]:
    out: list[CloudLookup] = []
    for p in providers:
        try:
            out.append(p.lookup(sha256=sha256))
        except Exception as exc:  # never let one provider break the flow
            out.append(CloudLookup(source=p.name, found=False, note=f"error: {exc}"))
    return out


def first_behavior(lookups: list[CloudLookup]) -> DynamicBehavior | None:
    """Pick the richest available behavior (most signatures + processes)."""
    best: DynamicBehavior | None = None
    best_score = -1
    for lk in lookups:
        if lk.found and lk.behavior:
            b = lk.behavior
            score = len(b.memory) * 3 + len(b.process_tree) + len(b.network)
            if score > best_score:
                best, best_score = b, score
    return best


def default_cloud_providers(offline: bool = False) -> list[CloudBehaviorProvider]:
    """Assemble providers that are usable given current env/config."""
    import os

    if offline:
        return []
    providers: list[CloudBehaviorProvider] = []
    if os.environ.get("TRIAGE_TOKEN"):
        from .triage import TriageBackend
        providers.append(TriageBackend())
    if os.environ.get("VT_API_KEY"):
        from ..intel.vt_behavior import VTBehaviorProvider
        providers.append(VTBehaviorProvider())
    if os.environ.get("HYBRIDANALYSIS_API_KEY"):
        from .hybrid import HybridAnalysisProvider
        providers.append(HybridAnalysisProvider())
    return providers
