"""Severity of an OSV record: the advisory's own rating, else a CVSS v3 score
computed from its vector."""

from __future__ import annotations

import math
from typing import Any

ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float:
    """Base score of a CVSS:3.0 / 3.1 vector string."""
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
    changed = parts["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[parts["PR"]]
    iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
    if impact <= 0:
        return 0.0
    total = impact + exploit
    return _roundup(min(1.08 * total if changed else total, 10.0))


def bucket(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def normalize(label: str) -> str:
    up = label.strip().upper()
    if up == "MEDIUM":
        return "MODERATE"
    return up if up in ORDER else "UNKNOWN"


def of_record(raw: dict[str, Any]) -> tuple[str, float | None]:
    """(severity label, CVSS score or None) for one OSV record."""
    for entry in raw.get("severity", []) or []:
        vec = str(entry.get("score", ""))
        if vec.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            try:
                score = cvss3_score(vec)
            except (KeyError, ValueError):
                continue
            return bucket(score), score
    label = (raw.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        return normalize(label), None
    return "UNKNOWN", None


def rank(label: str) -> int:
    """Lower is worse, for sorting."""
    return ORDER.index(label) if label in ORDER else len(ORDER)
