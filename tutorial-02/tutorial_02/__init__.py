"""Drive sqlmap against one or more WebGoat targets, ask Claude to summarise.

Public surface:

- :class:`SqliReport` — the multi-target Pydantic schema Claude is constrained to.
- :class:`TargetFinding` — one entry inside a :class:`SqliReport`.
- :func:`run_sqlmap` — subprocess wrapper around one ``sqlmap`` run.
- :func:`analyse_sqlmap_output` — single Claude call over the concatenated
  multi-target stdout, returning :class:`SqliReport`.
- :func:`parse_targets_file` — parse the multi-target file format.
"""
from __future__ import annotations

from .analyst import SqliReport, TargetFinding, analyse_sqlmap_output
from .sqlmap_runner import SqlmapResult, run_sqlmap
from .targets import Target, parse_targets_file

__all__ = [
    "SqliReport",
    "SqlmapResult",
    "Target",
    "TargetFinding",
    "analyse_sqlmap_output",
    "parse_targets_file",
    "run_sqlmap",
]
