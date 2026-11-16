"""Risk aggregation: findings -> 0..100 blast radius score -> decision."""

from __future__ import annotations

from dataclasses import dataclass

from .rules import Finding, SEVERITY_WEIGHT

DECAY = 0.55
DISTINCT_BONUS = 6
MAX_SCORE = 100


@dataclass(slots=True)
class Assessment:
    score: int
    decision: str
    capabilities: list[str]
    severity: str
    findings: list[Finding]
    ask_at: int
    deny_at: int


def score_findings(findings: list[Finding]) -> int:
    if not findings:
        return 0
    weights = sorted((f.weight for f in findings), reverse=True)
    total = 0.0
    for i, w in enumerate(weights[:12]):
        total += w * (DECAY ** i)
    caps = {f.capability for f in findings}
    if len(caps) >= 3:
        total += DISTINCT_BONUS
    return max(0, min(MAX_SCORE, int(round(total))))


def worst_severity(findings: list[Finding]) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    if not findings:
        return "none"
    return max((f.severity for f in findings), key=lambda s: order.index(s))


def decide(score: int, findings: list[Finding], *, ask_at: int = 15, deny_at: int = 65) -> str:
    if any(f.severity == "critical" and f.capability in ("fs.device_write", "net.remote_exec") for f in findings):
        return "deny"
    if score >= deny_at:
        return "deny"
    if score >= ask_at:
        return "ask"
    return "allow"


def assess(findings: list[Finding], *, ask_at: int = 15, deny_at: int = 65) -> Assessment:
    s = score_findings(findings)
    caps = sorted({f.capability for f in findings})
    return Assessment(
        score=s,
        decision=decide(s, findings, ask_at=ask_at, deny_at=deny_at),
        capabilities=caps,
        severity=worst_severity(findings),
        findings=findings,
        ask_at=ask_at,
        deny_at=deny_at,
    )
