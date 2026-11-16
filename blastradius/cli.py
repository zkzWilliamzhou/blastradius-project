"""Command line interface.

Exit codes (stable, documented):
    0  allow
    2  ask  (needs a human)
    3  deny
    4  usage / policy / IO error
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path

from . import __version__
from .policy import Policy, PolicyError, evaluate, write_preset, PRESETS
from .report import as_dict, hook_payload, render_human, render_json, color_enabled
from .rules import CROSS_RULES, RULES, SEVERITY_WEIGHT, analyze, parse_errors
from .score import assess

EXIT = {"allow": 0, "ask": 2, "deny": 3}
EXIT_ERROR = 4
MAX_STDIN = 256 * 1024


def _fail(msg: str, code: int = EXIT_ERROR) -> int:
    print(f"br: {msg}", file=sys.stderr)
    return code


def _read_input(args) -> str:
    if args.file:
        try:
            return Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SystemExit(_fail(f"cannot read {args.file}: {exc}"))
    if not args.command or args.command == ["-"]:
        data = sys.stdin.read(MAX_STDIN + 1)
        if len(data) > MAX_STDIN:
            raise SystemExit(_fail("stdin larger than 256 KiB, refusing to analyse"))
        return data
    return " ".join(args.command)


def _analyse(text: str, policy: Policy):
    findings = analyze(text, cwd=os.getcwd(), protected=policy.protected)
    score = assess(findings, ask_at=policy.score_ask, deny_at=policy.score_deny)
    decision = evaluate(text, findings, score.score, policy)
    # policy may upgrade a score-based allow/ask; keep the stricter verdict
    if decision.action == "allow" and score.decision == "deny":
        decision.action = "deny"
    return findings, score, decision


def cmd_check(args) -> int:
    text = _read_input(args)
    if not text.strip():
        return _fail("empty command")
    try:
        policy = Policy.load(args.policy)
    except PolicyError as exc:
        return _fail(str(exc))
    findings, a, d = _analyse(text, policy)
    if args.json:
        payload = as_dict(text, a, d, policy, notes=parse_errors(text))
        print(render_json(payload, pretty=args.pretty))
    else:
        print(render_human(text, a, d, policy, use_color=color_enabled() and not args.no_color))
    return EXIT[d.action]


def cmd_explain(args) -> int:
    from .shell import parse, unwrap

    text = _read_input(args)
    script = parse(text)

    def walk(node, depth=0):
        pad = "  " * depth
        for pid, pipe in enumerate(node.pipelines):
            print(f"{pad}pipeline {pid}")
            for seg in pipe.segments:
                argv, wrappers = unwrap(seg.argv)
                print(f"{pad}  segment {seg.index}: argv={seg.argv!r}"
                      f" program={seg.program!r} pipe_in={seg.stdin_from_pipe}")
                if wrappers:
                    print(f"{pad}    wrappers={wrappers!r} effective={argv!r}")
                for r in seg.redirects:
                    print(f"{pad}    redirect fd={r.fd or '-'} op={r.op} -> {r.target!r}"
                          + (f" (heredoc {len(r.body)}b)" if r.body else ""))
        if node.notes:
            print(f"{pad}notes: {node.notes}")
        for sub in node.subs:
            print(f"{pad}nested:")
            walk(sub, depth + 1)

    walk(script)
    return 0


def cmd_rules(args) -> int:
    items = []
    for r in RULES + CROSS_RULES:
        items.append({
            "id": r.id,
            "severity": r.severity,
            "capability": r.capability,
            "title": r.title,
            "tags": list(r.tags),
            "scope": "script" if r in CROSS_RULES else "segment",
        })
    items.sort(key=lambda x: x["id"])
    if args.json:
        print(render_json(items, pretty=True))
        return 0
    print(f"{'ID':<8}{'SEVERITY':<10}{'CAPABILITY':<18}TITLE")
    for it in items:
        print(f"{it['id']:<8}{it['severity']:<10}{it['capability']:<18}{it['title']}")
    print(f"\n{len(items)} rules")
    return 0


def cmd_policy(args) -> int:
    if args.policy_cmd != "init":
        return _fail("usage: br policy init [--preset NAME] [-o FILE]")
    target = args.output or "br-policy.json"
    try:
        p = write_preset(args.preset, target)
    except PolicyError as exc:
        return _fail(str(exc))
    print(f"wrote {p} (preset: {args.preset})")
    print("next: br check --policy %s 'rm -rf /'" % p)
    return 0


def _guard_fallback(reason: str, decision: str = "ask") -> int:
    """A hook must never crash the host agent: emit a decision and exit 0."""
    print(render_json({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"blastradius: {reason}",
    }, "systemMessage": f"blastradius: {reason}"}))
    return 0


def cmd_guard(args) -> int:
    """Agent hook mode: read a tool-call JSON envelope, emit a permission decision."""
    raw = sys.stdin.read(MAX_STDIN + 1)
    try:
        envelope = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return _guard_fallback("hook payload was not valid JSON; asking instead of guessing")
    if isinstance(envelope, str):
        command = envelope
        envelope = {}
    else:
        tool_input = envelope.get("tool_input") or envelope.get("input") or {}
        command = (
            tool_input.get("command")
            or envelope.get("command")
            or tool_input.get("cmd")
            or ""
        )
    if not isinstance(command, str) or not command.strip():
        # not a command we understand: stay out of the way
        return _guard_fallback("no shell command in payload", "allow")
    try:
        policy = Policy.load(args.policy)
    except PolicyError as exc:
        return _guard_fallback(f"policy error ({exc}); asking instead of guessing")
    findings, a, d = _analyse(command, policy)
    payload = hook_payload(d, a)
    if args.json:
        payload["blastradius"] = as_dict(command, a, d, policy, notes=parse_errors(command))
    print(render_json(payload))
    return 0


def cmd_selftest(args) -> int:
    from .corpus import CASES

    failures = []
    for case in CASES:
        cmd = case["cmd"]
        try:
            policy = Policy.load(None)
            findings, a, d = _analyse(cmd, policy)
        except Exception as exc:  # noqa: BLE001 - selftest must report, not crash
            failures.append((cmd, f"raised {type(exc).__name__}: {exc}"))
            continue
        got = {f.rule_id for f in findings}
        problems = []
        if case.get("decision") and d.action != case["decision"]:
            problems.append(f"decision {d.action} != {case['decision']} (score {a.score})")
        for r in case.get("rules", ()):
            if r not in got:
                problems.append(f"missing rule {r}")
        for r in case.get("not_rules", ()):
            if r in got:
                problems.append(f"unexpected rule {r}")
        if "max_score" in case and a.score > case["max_score"]:
            problems.append(f"score {a.score} > {case['max_score']}")
        if problems:
            failures.append((cmd, "; ".join(problems)))
            if args.verbose:
                print(f"FAIL {cmd}\n     {problems}")

    total = len(CASES)
    passed = total - len(failures)
    print(f"selftest: {passed}/{total} cases pass")
    if failures and not args.verbose:
        print("\nfailures:")
        for cmd, why in failures[:25]:
            print(f"  - {cmd!r}: {why}")
    return 0 if not failures else 1


def cmd_version(args) -> int:
    print(f"blastradius {__version__}")
    print(f"rules: {len(RULES) + len(CROSS_RULES)} · capabilities: "
          f"{len({r.capability for r in RULES + CROSS_RULES})}")
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # exit 2 is our "ask" code — never reuse it for usage errors
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="br",
        description="Score the blast radius of a shell command before running it. Never executes anything.",
        epilog="exit codes: 0 allow · 2 ask · 3 deny · 4 usage/policy error",
    )
    p.add_argument("--version", action="version", version=f"blastradius {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--policy", default=os.environ.get("BR_POLICY"),
                        help="path to a JSON policy (default: built-in balanced)")
        sp.add_argument("-f", "--file", help="read the command from a file instead of argv")
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.add_argument("--pretty", action="store_true", help="indent JSON output")
        sp.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    c = sub.add_parser("check", help="analyse a command (default)")
    common(c)
    c.add_argument("command", nargs="*", help="command text; '-' or empty reads stdin")
    c.set_defaults(func=cmd_check)

    e = sub.add_parser("explain", help="dump the parsed structure (no scoring)")
    common(e)
    e.add_argument("command", nargs="*")
    e.set_defaults(func=cmd_explain)

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rules)

    pol = sub.add_parser("policy", help="policy helpers")
    psub = pol.add_subparsers(dest="policy_cmd")
    psub.required = True
    pi = psub.add_parser("init", help="write a starter policy")
    pi.add_argument("--preset", default="default", choices=sorted(PRESETS))
    pi.add_argument("-o", "--output")
    pi.set_defaults(func=cmd_policy)

    g = sub.add_parser("guard", help="read a tool-call JSON on stdin, emit a hook decision")
    g.add_argument("--policy", default=os.environ.get("BR_POLICY"))
    g.add_argument("--json", action="store_true", help="include full report in the payload")
    g.set_defaults(func=cmd_guard)

    s = sub.add_parser("selftest", help="run the built-in regression corpus")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_selftest)

    v = sub.add_parser("version", help="version + rule count")
    v.set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    known = {"check", "explain", "rules", "policy", "guard", "selftest", "version"}
    check_flags = {"--json", "--pretty", "--policy", "-f", "--file", "--no-color"}
    if argv and argv[0] in check_flags:
        argv = ["check"] + argv  # `br --json 'rm -rf /'` just works
    elif argv and argv[0] not in known and not argv[0].startswith("-"):
        near = difflib.get_close_matches(argv[0], sorted(known), n=1, cutoff=0.75)
        if near and argv[0] not in ("rm", "ls", "mv", "cp", "sh", "pip", "git"):
            print(f"br: unknown command `{argv[0]}` — did you mean `{near[0]}`?", file=sys.stderr)
            return EXIT_ERROR
        argv = ["check"] + argv  # `br 'rm -rf /'` just works
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help (0) and usage errors (4)
        return int(exc.code or 0)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
