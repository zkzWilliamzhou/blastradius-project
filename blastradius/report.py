"""Rendering: human report, JSON, and SARIF-ish summary."""

from __future__ import annotations

import json
import os
import sys

from .policy import Decision, Policy
from .score import Assessment

VERSION = "1.0.0"

BADGE = {"allow": ("ALLOW", "32"), "ask": ("ASK", "33"), "deny": ("DENY", "31")}
SEV_COLOR = {"info": "36", "low": "34", "medium": "33", "high": "35", "critical": "31"}
SEV_MARK = {"info": "·", "low": "·", "medium": "▲", "high": "▲", "critical": "✖"}


def color_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def _c(text: str, code: str, on: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if on else text


def _fmt_path(p: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "~" and p.startswith(home + "/"):
        return "~" + p[len(home):]
    return p


def render_human(command: str, a: Assessment, d: Decision, policy: Policy, *, use_color: bool) -> str:
    label, code = BADGE[d.action]
    lines: list[str] = []
    lines.append(
        f"{_c('blastradius', '1', use_color)} {VERSION}   "
        f"{_c(label, code + ';1', use_color)}  {a.score}/100   "
        f"{_c('policy: ' + policy.name, '2', use_color)}"
    )
    shown = command.strip().replace("\n", " ⏎ ")
    if len(shown) > 160:
        shown = shown[:157] + "…"
    lines.append(f"  {_c('command', '2', use_color)}  {shown}")
    if a.capabilities:
        lines.append(f"  {_c('exposes', '2', use_color)}  {', '.join(a.capabilities)}")
    lines.append("")

    if not a.findings:
        lines.append(f"  {_c('no findings', '32', use_color)} — nothing in this command crosses a capability boundary.")
    for f in a.findings:
        mark = SEV_MARK.get(f.severity, "·")
        tone = SEV_COLOR.get(f.severity, "0")
        sev = f"{f.severity.upper():<9}"
        lines.append(f"  {_c(mark, tone, use_color)} {_c(sev, tone, use_color)} "
                     f"{_c(f.rule_id, '2', use_color):<14} {f.title}")
        ev = f.evidence.strip().replace("\n", " ⏎ ")
        if len(ev) > 150:
            ev = ev[:147] + "…"
        lines.append(f"      {_c('evidence', '2', use_color)}  {ev}")
        lines.append(f"      {_c('why', '2', use_color)}       {f.detail}")
        if f.mitigation:
            lines.append(f"      {_c('instead', '2', use_color)}   {f.mitigation}")
        lines.append("")

    if d.reasons:
        src = {"policy": "policy", "policy-default": "policy", "score": "score"}[d.source]
        lines.append(f"  {_c('decision', '2', use_color)}  {d.action} ({src}): {'; '.join(d.reasons)}")
    lines.append(
        f"  {_c('summary', '2', use_color)}  {len(a.findings)} finding(s) · "
        f"worst severity {a.severity} · {len(a.capabilities)} capability(ies)"
    )
    return "\n".join(lines)


def as_dict(command: str, a: Assessment, d: Decision, policy: Policy, *, notes: list[str] | None = None) -> dict:
    return {
        "tool": "blastradius",
        "version": VERSION,
        "command": command,
        "decision": d.action,
        "score": a.score,
        "severity": a.severity,
        "capabilities": a.capabilities,
        "reasons": d.reasons,
        "decision_source": d.source,
        "policy": policy.name,
        "findings": [
            {
                "rule": f.rule_id,
                "title": f.title,
                "capability": f.capability,
                "severity": f.severity,
                "detail": f.detail,
                "evidence": f.evidence,
                "mitigation": f.mitigation,
                "tags": list(f.tags),
            }
            for f in a.findings
        ],
        "notes": notes or [],
    }


def render_json(payload: dict, *, pretty: bool = False) -> str:
    return json.dumps(payload, indent=2 if pretty else None, ensure_ascii=False)


def hook_payload(d: Decision, a: Assessment, *, event: str = "PreToolUse") -> dict:
    reason = "; ".join(d.reasons) or "no findings"
    msg = f"blastradius: {d.action.upper()} (score {a.score}/100) — {reason}"
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": d.action,
            "permissionDecisionReason": msg,
        },
        "systemMessage": msg,
    }
