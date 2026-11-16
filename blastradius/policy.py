"""JSON policy engine.

A policy can only make things *stricter* by default: matching `deny` always wins
over `allow`. That is deliberate — a policy file that ships with a repo should
never be able to silently unblock a device wipe.
"""

from __future__ import annotations

import difflib
import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .rules import (Finding, PROTECTED_DEFAULT, SEVERITY_WEIGHT, match_glob,
                    observed_capabilities, protected_by)
from .shell import parse, unwrap

VERSION = 1
ACTIONS = ("allow", "ask", "deny")
RANK = {"allow": 0, "ask": 1, "deny": 2}


class PolicyError(ValueError):
    pass


TOP_KEYS = {"version", "name", "description", "default", "score_ask", "score_deny",
            "protected", "rules"}
RULE_KEYS = {"action", "capability", "program", "rule", "severity_min", "path_glob",
             "text", "protected_path", "reason"}


def _unknown(key: str, allowed: set[str], where: str) -> str:
    close = difflib.get_close_matches(key, sorted(allowed), n=1)
    hint = f" — did you mean `{close[0]}`?" if close else ""
    return f"{where}: unknown key `{key}`{hint}"


PRESET_DEFAULT = {
    "version": VERSION,
    "name": "balanced",
    "description": "Deny irreversible/system-level actions, ask for anything risky, allow normal work.",
    "default": "auto",
    "score_ask": 15,
    "score_deny": 65,
    "protected": list(PROTECTED_DEFAULT),
    "rules": [
        {"action": "deny", "capability": "fs.device_write", "reason": "raw device writes are unrecoverable"},
        {"action": "deny", "capability": "net.remote_exec", "reason": "executes code from outside this machine"},
        {"action": "deny", "capability": "sys.power", "reason": "takes the host down"},
        {"action": "deny", "severity_min": "critical", "reason": "critical finding"},
        {"action": "allow", "program": "rm", "path_glob": ["node_modules", "*/node_modules", "dist", "*/dist", "build", "*/build", ".next", "*/target"], "reason": "build artifacts are disposable"},
        {"action": "allow", "program": "cat", "path_glob": ["package.json", "README*"], "reason": "read-only, non-secret"},
    ],
}

PRESET_STRICT = {
    "version": VERSION,
    "name": "strict",
    "description": "For unattended agents: anything that deletes, publishes or leaves the machine needs approval.",
    "default": "ask",
    "score_ask": 8,
    "score_deny": 45,
    "protected": list(PROTECTED_DEFAULT),
    "rules": [
        {"action": "deny", "capability": "fs.device_write"},
        {"action": "deny", "capability": "net.remote_exec"},
        {"action": "deny", "capability": "cred.access"},
        {"action": "deny", "capability": "sys.power"},
        {"action": "deny", "severity_min": "high"},
        {"action": "ask", "capability": "fs.delete"},
        {"action": "ask", "capability": "net.egress"},
        {"action": "ask", "capability": "deploy.prod"},
        {"action": "ask", "capability": "code.publish"},
        {"action": "ask", "capability": "git.destructive"},
        {"action": "allow", "capability": "fs.read", "reason": "reads are safe in strict mode only for known trees"},
    ],
}

PRESET_PERMISSIVE = {
    "version": VERSION,
    "name": "permissive",
    "description": "Local dev box: only block the truly unrecoverable.",
    "default": "auto",
    "score_ask": 40,
    "score_deny": 80,
    "protected": ["~/.ssh/**", "/etc/shadow", "/etc/sudoers"],
    "rules": [
        {"action": "deny", "capability": "fs.device_write"},
        {"action": "deny", "rule": "BR001", "reason": "recursive delete of a system root"},
        {"action": "deny", "rule": "BR030", "reason": "piping the network into a shell"},
    ],
}

PRESETS = {"default": PRESET_DEFAULT, "strict": PRESET_STRICT, "permissive": PRESET_PERMISSIVE}


@dataclass(slots=True)
class Decision:
    action: str
    reasons: list[str] = field(default_factory=list)
    source: str = "score"
    matched: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class Policy:
    name: str = "balanced"
    default: str = "auto"
    score_ask: int = 15
    score_deny: int = 65
    protected: list[str] = field(default_factory=lambda: list(PROTECTED_DEFAULT))
    rules: list[dict] = field(default_factory=list)
    origin: str = "builtin"

    @classmethod
    def from_dict(cls, data: dict, origin: str = "file") -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError("policy must be a JSON object")
        if data.get("version") not in (None, VERSION):
            raise PolicyError(f"unsupported policy version: {data.get('version')!r}")
        default = data.get("default", "auto")
        if default not in (*ACTIONS, "auto"):
            raise PolicyError(f"`default` must be one of {ACTIONS + ('auto',)}")
        for key in data:
            if key not in TOP_KEYS:
                raise PolicyError(_unknown(key, TOP_KEYS, "policy"))
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise PolicyError("`rules` must be a list")
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                raise PolicyError(f"rule #{i} must be an object")
            for key in r:
                if key not in RULE_KEYS:
                    raise PolicyError(_unknown(key, RULE_KEYS, f"rule #{i}"))
            if r.get("action") not in ACTIONS:
                raise PolicyError(f"rule #{i}: `action` must be one of {ACTIONS}")
            if not (set(r) - {"action", "reason"}):
                raise PolicyError(f"rule #{i}: needs at least one condition "
                                  f"(capability/program/rule/severity_min/path_glob/text/protected_path)")
            if "severity_min" in r and r["severity_min"] not in SEVERITY_WEIGHT:
                raise PolicyError(f"rule #{i}: unknown severity `{r['severity_min']}`; "
                                  f"choose from {sorted(SEVERITY_WEIGHT)}")
            if "path_glob" in r and not isinstance(r["path_glob"], (str, list)):
                raise PolicyError(f"rule #{i}: `path_glob` must be a string or a list of strings")
            for k in ("capability", "program", "rule", "text", "protected_path"):
                if k in r and not isinstance(r[k], str):
                    raise PolicyError(f"rule #{i}: `{k}` must be a string")
        protected = data.get("protected", list(PROTECTED_DEFAULT))
        if not isinstance(protected, list) or not all(isinstance(p, str) for p in protected):
            raise PolicyError("`protected` must be a list of glob strings")
        try:
            ask = int(data.get("score_ask", 15))
            deny = int(data.get("score_deny", 65))
        except (TypeError, ValueError) as exc:
            raise PolicyError("score thresholds must be integers") from exc
        if not 0 <= ask < deny <= 100:
            raise PolicyError("require 0 <= score_ask < score_deny <= 100")
        return cls(
            name=str(data.get("name", "custom")),
            default=default,
            score_ask=ask,
            score_deny=deny,
            protected=protected,
            rules=rules,
            origin=origin,
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None) -> "Policy":
        if path is None:
            return cls.from_dict(json.loads(json.dumps(PRESET_DEFAULT)), origin="builtin:balanced")
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy {p}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy {p} is not valid JSON: {exc}") from exc
        return cls.from_dict(data, origin=str(p))

    def as_dict(self) -> dict:
        return {
            "version": VERSION,
            "name": self.name,
            "default": self.default,
            "score_ask": self.score_ask,
            "score_deny": self.score_deny,
            "protected": self.protected,
            "rules": self.rules,
        }


def _candidate_paths(text: str) -> list[str]:
    out: list[str] = []
    script = parse(text)
    stack = [script]
    while stack:
        node = stack.pop()
        for seg in node.segments():
            argv, _ = unwrap(seg.argv)
            for a in argv[1:]:
                if a and not a.startswith("-"):
                    out.append(a)
            for r in seg.redirects:
                if r.target:
                    out.append(r.target)
        stack.extend(node.subs)
    return out


def _programs_in(text: str) -> set[str]:
    script = parse(text)
    out: set[str] = set()
    stack = [script]
    while stack:
        node = stack.pop()
        out |= {s.program for s in node.segments() if s.program}
        stack.extend(node.subs)
    return out


def _rule_matches(rule: dict, finding: Finding | None, paths: list[str], text: str,
                  protected: list[str], programs: set[str], caps: set[str]) -> bool:
    """All conditions must hold (AND). A rule with no condition never matches."""
    checks = 0

    cap = rule.get("capability")
    if cap is not None:
        checks += 1
        if not any(fnmatch.fnmatchcase(c, str(cap)) for c in caps):
            return False

    prog = rule.get("program")
    if prog is not None:
        checks += 1
        if not any(fnmatch.fnmatchcase(p, str(prog)) for p in programs):
            return False

    rid = rule.get("rule")
    if rid is not None:
        checks += 1
        if finding is None or not fnmatch.fnmatchcase(finding.rule_id, str(rid)):
            return False

    sev = rule.get("severity_min")
    if sev is not None:
        checks += 1
        if sev not in SEVERITY_WEIGHT:
            raise PolicyError(f"unknown severity: {sev!r}")
        if finding is None or SEVERITY_WEIGHT[finding.severity] < SEVERITY_WEIGHT[sev]:
            return False

    globs = rule.get("path_glob")
    if globs is not None:
        checks += 1
        if isinstance(globs, str):
            globs = [globs]
        if not isinstance(globs, list):
            raise PolicyError("path_glob must be a string or a list of strings")
        if not any(match_glob(p, g) for p in paths for g in globs):
            return False

    needle = rule.get("text")
    if needle is not None:
        checks += 1
        if str(needle) not in text:
            return False

    if rule.get("protected_path") is not None:
        checks += 1
        pats = list(protected) + list(PROTECTED_DEFAULT)
        if not any(protected_by(p, pats) for p in paths):
            return False

    return checks > 0


def evaluate(text: str, findings: list[Finding], score: int, policy: Policy) -> Decision:
    paths = _candidate_paths(text)
    programs = _programs_in(text)
    caps = observed_capabilities(text, policy.protected) | {f.capability for f in findings}
    candidates: list[Finding | None] = list(findings) + [None]

    hits: list[tuple[str, str, dict]] = []
    for idx, rule in enumerate(policy.rules):
        try:
            ok = any(_rule_matches(rule, f, paths, text, policy.protected, programs, caps)
                     for f in candidates)
        except PolicyError:
            raise
        except Exception:
            ok = False
        if ok:
            hits.append((rule["action"], rule.get("reason") or f"policy rule #{idx}", rule))

    if hits:
        best = max(hits, key=lambda h: RANK[h[0]])
        reasons = list(dict.fromkeys(r for a, r, _ in hits if a == best[0]))[:4]
        return Decision(action=best[0], reasons=reasons, source="policy",
                        matched=[r for _, _, r in hits])

    if policy.default != "auto":
        return Decision(action=policy.default,
                        reasons=[f"policy default is `{policy.default}`"],
                        source="policy-default")
    if score >= policy.score_deny:
        return Decision(action="deny",
                        reasons=[f"score {score} ≥ deny threshold {policy.score_deny}"],
                        source="score")
    if score >= policy.score_ask:
        return Decision(action="ask",
                        reasons=[f"score {score} ≥ ask threshold {policy.score_ask}"],
                        source="score")
    return Decision(action="allow",
                    reasons=[f"score {score} below ask threshold {policy.score_ask}"],
                    source="score")


def write_preset(name: str, path: str | os.PathLike[str]) -> Path:
    if name not in PRESETS:
        raise PolicyError(f"unknown preset {name!r}; choose from {sorted(PRESETS)}")
    data = json.loads(json.dumps(PRESETS[name]))
    data["version"] = VERSION
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p
