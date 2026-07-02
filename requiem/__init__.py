"""ReQuiem — an all-in-one malware analysis workbench.

Public entry point::

    from requiem import analyze
    report = analyze(open("sample.exe", "rb").read(), "sample.exe")
    print(report.summary)
"""
# Load a .env (VT/MalwareBazaar/CAPE keys) before anything reads os.environ.
from .core.config import ensure_loaded as _ensure_loaded

_ensure_loaded()

from .core.pipeline import PipelineOptions, analyze
from .core.models import AnalysisReport

__all__ = ["analyze", "AnalysisReport", "PipelineOptions"]
__version__ = "0.1.0"
