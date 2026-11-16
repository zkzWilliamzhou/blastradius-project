"""Structural tokenizer + parser for POSIX-ish shell command text.

This module never executes anything. It reads a command *string* and returns a
lightweight AST good enough to reason about intent:

    Script -> Pipeline -> Segment(argv, redirects)  (+ nested Scripts)

Deliberate limitations (documented, and surfaced as `notes`):
  * no variable expansion, no glob expansion, no alias resolution
  * no full grammar (no `case`/`for`/function bodies); grouping is flattened
  * unbalanced input is read best-effort and flagged, never crashes

Everything is bounded: input length, nesting depth, segment count.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_INPUT = 100_000
MAX_DEPTH = 4
MAX_SEGMENTS = 4096
MAX_HEREDOC = 20_000

WORD = "WORD"
RESERVED = {"!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done",
            "while", "until", "for", "in", "case", "esac", "select", "function",
            "time", "coproc", "[[", "]]"}
REDIR = "REDIR"
OP = "OP"


@dataclass(slots=True)
class Token:
    kind: str
    value: str
    raw: str
    start: int
    end: int
    fd: str = ""
    target: str = ""
    body: str = ""
    sub: str = ""


@dataclass(slots=True)
class Redirect:
    fd: str
    op: str
    target: str
    body: str = ""
    sub: str = ""

    @property
    def writes(self) -> bool:
        """True when this redirect creates/truncates a regular file."""
        if self.op in (">", ">>", ">|", "&>", "&>>"):
            return True
        if self.op == ">&" and not self.target.isdigit():
            return True
        return False

    @property
    def device_sink(self) -> bool:
        return self.target.startswith("/dev/") and not self.target.startswith(
            ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/")
        )


@dataclass(slots=True)
class Segment:
    argv: list[str]
    raws: list[str]
    redirects: list[Redirect]
    text: str
    pipeline: int = 0
    index: int = 0
    stdin_from_pipe: bool = False
    subs: list["Script"] = field(default_factory=list)

    @property
    def program(self) -> str:
        """Basename of argv[0] ('' for assignment-only segments)."""
        if not self.argv:
            return ""
        p = self.argv[0].rsplit("/", 1)[-1]
        return p

    @property
    def args(self) -> list[str]:
        return self.argv[1:]


@dataclass(slots=True)
class Pipeline:
    segments: list[Segment]


@dataclass(slots=True)
class Script:
    pipelines: list[Pipeline]
    subs: list["Script"] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    text: str = ""
    depth: int = 0

    def segments(self) -> list[Segment]:
        for pipe in self.pipelines:
            yield from pipe.segments


class _Lexer:
    CONTROL = "|&;()"

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        self.i = 0
        self.toks: list[Token] = []
        self.notes: list[str] = []
        self._pending: list[tuple[Token, str, bool]] = []

    def run(self) -> list[Token]:
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r\f\v":
                self.i += 1
                continue
            if c == "\\" and self.i + 1 < self.n and self.s[self.i + 1] == "\n":
                self.i += 2
                continue
            if c == "#":
                nl = self.s.find("\n", self.i)
                self.i = self.n if nl < 0 else nl
                continue
            if c == "\n":
                self.toks.append(Token(OP, "\n", "\n", self.i, self.i + 1))
                self.i += 1
                self._read_heredocs()
                continue
            if c in "<>" or (c == "&" and self.i + 1 < self.n and self.s[self.i + 1] == ">"):
                self._redir("")
                continue
            if c.isdigit():
                j = self.i
                while j < self.n and self.s[j].isdigit() and j - self.i < 3:
                    j += 1
                if j < self.n and self.s[j] in "<>":
                    self._redir(self.s[self.i:j])
                    continue
            for op in ("&&", "||", "|&", ";;", "|", "&", ";", "(", ")"):
                if self.s.startswith(op, self.i):
                    self.toks.append(Token(OP, op, op, self.i, self.i + len(op)))
                    self.i += len(op)
                    break
            else:
                self._word()
        return self.toks

    # -- helpers ---------------------------------------------------------
    def _redir(self, fd: str) -> None:
        s, n = self.s, self.n
        start = self.i
        i = self.i + len(fd)
        op = ""
        if fd == "" and s[i] == "&":
            op = "&>>" if s.startswith("&>>", i) else "&>"
        else:
            for cand in ("<<<", ">>", "<<-", "<<", "<>", "<&", ">&", ">|", ">", "<"):
                if s.startswith(cand, i):
                    op = cand
                    break
        if not op:  # stray '&' handled by caller; be defensive
            op = s[i]
        i += len(op)
        while i < n and s[i] in " \t":
            i += 1
        if i < n and s[i] == "(" and op in ("<", ">"):
            # process substitution: bash <(curl ...) -- the inner command is the input
            j = self._match_paren(i)
            tok = Token(REDIR, op, s[start:j], start, j, fd=fd, target="", sub=s[i + 1:j - 1])
            self.toks.append(tok)
            self.i = j
            return
        target, i = self._scan_word(i)
        tok = Token(REDIR, op, s[start:i], start, i, fd=fd, target=target)
        self.toks.append(tok)
        self.i = i
        if op in ("<<", "<<-"):
            self._pending.append((tok, target, op == "<<-"))

    def _scan_word(self, i: int) -> tuple[str, int]:
        s, n = self.s, self.n
        out: list[str] = []
        while i < n:
            c = s[i]
            if c in " \t\r\n\f\v" or c in self.CONTROL or c in "<>":
                break
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    self.notes.append("unterminated single quote")
                    j = n
                out.append(s[i + 1 : j])
                i = j + 1
                continue
            if c == '"':
                i += 1
                buf: list[str] = []
                while i < n and s[i] != '"':
                    if s[i] == "\\" and i + 1 < n and s[i + 1] in '"\\$`':
                        buf.append(s[i + 1])
                        i += 2
                        continue
                    if s[i] == "\\" and i + 1 < n and s[i + 1] == "\n":
                        i += 2
                        continue
                    buf.append(s[i])
                    i += 1
                if i >= n:
                    self.notes.append("unterminated double quote")
                i = min(i + 1, n)
                out.append("".join(buf))
                continue
            if c == "\\":
                if i + 1 < n:
                    out.append(s[i + 1])
                    i += 2
                else:
                    self.notes.append("trailing backslash")
                    i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                j = self._match_paren(i + 1)
                out.append(s[i:j])
                i = j
                continue
            if c == "`":
                j = s.find("`", i + 1)
                if j < 0:
                    self.notes.append("unterminated backtick")
                    j = n - 1 if n > i + 1 else n
                out.append(s[i : j + 1])
                i = j + 1
                continue
            out.append(c)
            i += 1
        return "".join(out), i

    def _match_paren(self, i: int) -> int:
        s, n = self.s, self.n
        depth = 0
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    self.notes.append("unbalanced $(")
                    return n
                i = j + 1
                continue
            if c == '"':
                j = i + 1
                while j < n and s[j] != '"':
                    j += 2 if s[j] == "\\" else 1
                i = j + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        self.notes.append("unbalanced $(")
        return n

    def _word(self) -> None:
        start = self.i
        val, i = self._scan_word(start)
        if i == start:  # unknown char: consume to guarantee progress
            i = start + 1
        tok = Token(WORD, val, self.s[start:i], start, i)
        self.toks.append(tok)
        self.i = i

    def _read_heredocs(self) -> None:
        s, n = self.s, self.n
        while self._pending:
            tok, delim, strip = self._pending.pop(0)
            lines: list[str] = []
            used = 0
            while self.i < n and used < MAX_HEREDOC:
                nl = s.find("\n", self.i)
                if nl < 0:
                    line = s[self.i :]
                    self.i = n
                else:
                    line = s[self.i : nl]
                    self.i = nl + 1
                cand = line.lstrip("\t") if strip else line
                if cand == delim:
                    break
                lines.append(cand)
                used += len(line) + 1
            tok.body = "\n".join(lines)


def _match_sub(raw: str, i: int) -> tuple[str, int]:
    """raw[i] == '$' and raw[i+1] == '(' -> (inner, index_after_close)."""
    n = len(raw)
    depth, j = 1, i + 2
    while j < n:
        c = raw[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = raw.find("'", j + 1)
            j = n if k < 0 else k + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return raw[i + 2:j], j + 1
        j += 1
    return raw[i + 2:], n


def _substitutions(raw: str) -> list[str]:
    """Inner text of $(...) and `...`, respecting single/double quote context.

    Inside double quotes a single quote is a literal character, so
    "don't $(cmd)" still has to yield `cmd`.
    """
    out: list[str] = []
    i, n = 0, len(raw)
    quote: str | None = None
    while i < n:
        c = raw[i]
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
                i += 1
                continue
        else:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                quote = "'"
                i += 1
                continue
            if c == '"':
                quote = '"'
                i += 1
                continue
        if c == "$" and i + 1 < n and raw[i + 1] == "(":
            inner, i = _match_sub(raw, i)
            if inner.strip():
                out.append(inner)
            continue
        if c == "`":
            j = raw.find("`", i + 1)
            if j < 0:
                break
            if raw[i + 1:j].strip():
                out.append(raw[i + 1:j])
            i = j + 1
            continue
        i += 1
    return out


_EMBEDDED_EXEC = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen)"
    r"|child_process\.exec|execSync|system|exec|eval)\s*\(\s*(['\"])(.+?)\1",
    re.S,
)


def _embedded_payloads(args: list[str]) -> list[str]:
    """Pull quoted command strings out of inline code: os.system("rm -rf /")."""
    out: list[str] = []
    for a in args:
        if len(a) < 12 or "(" not in a:
            continue
        for m in _EMBEDDED_EXEC.finditer(a):
            inner = m.group(2)
            if inner.strip():
                out.append(inner)
    return out


def _payloads(seg: Segment) -> list[str]:
    """Strings a segment hands to another interpreter (-c/-e style)."""
    out: list[str] = _embedded_payloads(seg.args)
    argv, _ = unwrap(seg.argv)
    if not argv:
        return out
    prog = argv[0].rsplit("/", 1)[-1]
    args = argv[1:]
    if not args:
        return out
    if prog in {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"}:
        for idx, a in enumerate(args):
            if a in ("-c", "--command") and idx + 1 < len(args):
                out.append(args[idx + 1])
            elif a.startswith("-") and not a.startswith("--") and "c" in a[1:] and idx + 1 < len(args):
                out.append(args[idx + 1])
    elif prog in {"eval", "exec"}:
        out.append(" ".join(args))
    elif prog in {"python", "python3", "python2", "pypy", "pypy3"}:
        for idx, a in enumerate(args):
            if a == "-c" and idx + 1 < len(args):
                out.append(args[idx + 1])
    elif prog in {"perl", "ruby", "node", "nodejs", "php", "lua", "deno", "bun"}:
        for idx, a in enumerate(args):
            if a in ("-e", "-c", "--eval", "-r") and idx + 1 < len(args):
                out.append(args[idx + 1])
    elif prog in {"kubectl", "oc"} and "exec" in args:
        if "--" in args:
            out.append(" ".join(args[args.index("--") + 1:]))
        else:
            rest = args[args.index("exec") + 1:]
            i = 0
            while i < len(rest) and rest[i].startswith("-"):
                i += 1
            if i + 1 < len(rest):
                out.append(" ".join(rest[i + 1:]))
    elif prog in {"docker", "podman", "nerdctl"} and "exec" in args:
        rest = args[args.index("exec") + 1:]
        i = 0
        while i < len(rest) and rest[i].startswith("-"):
            i += 2 if rest[i] in ("-e", "-u", "-w", "--env", "--user", "--workdir") else 1
        if i + 1 < len(rest):
            out.append(" ".join(rest[i + 1:]))
    elif prog in {"ssh", "rsh", "mosh", "sbatch", "qsub"}:
        tail = [a for a in args if not a.startswith("-")]
        if len(tail) >= 2:
            out.append(" ".join(tail[1:]))
    return out


def parse(text: str, depth: int = 0) -> Script:
    """Parse shell text into a Script. Bounded and non-throwing by design."""
    if not isinstance(text, str):
        text = str(text)
    notes: list[str] = []
    if len(text) > MAX_INPUT:
        notes.append("input truncated to %d bytes" % MAX_INPUT)
        text = text[:MAX_INPUT]

    lex = _Lexer(text)
    toks = lex.run()
    notes.extend(lex.notes)

    items: list[object] = []
    cur: dict | None = None
    for t in toks:
        if t.kind == OP:
            if cur is not None:
                items.append(cur)
                cur = None
            items.append(t)
            continue
        if cur is None:
            cur = {"words": [], "redirs": [], "start": t.start, "end": t.end}
        if t.kind == WORD:
            cur["words"].append((t.value, t.raw))
        else:
            cur["redirs"].append(Redirect(t.fd, t.value, t.target, t.body, t.sub))
        cur["end"] = t.end
    if cur is not None:
        items.append(cur)

    pipelines: list[Pipeline] = []
    segs: list[Segment] = []
    piped_next = False
    total = 0
    for it in items:
        if isinstance(it, Token):
            if it.value in ("|", "|&"):
                piped_next = True
                continue
            if segs:
                pipelines.append(Pipeline(segs))
                segs = []
            piped_next = False
            continue
        if total >= MAX_SEGMENTS:
            notes.append("segment cap reached; remainder ignored")
            break
        s0 = it["start"]
        e0 = it["end"]
        words = list(it["words"])
        while len(words) > 1 and words[0][0] in RESERVED:
            words.pop(0)  # `then rm -rf /`, `{ rm -rf /; }`, `! rm -rf /`
        seg = Segment(
            argv=[w[0] for w in words],
            raws=[w[1] for w in words],
            redirects=list(it["redirs"]),
            text=text[s0:e0].strip(),
            index=len(segs),
            stdin_from_pipe=piped_next,
        )
        segs.append(seg)
        piped_next = False
        total += 1
    if segs:
        pipelines.append(Pipeline(segs))

    for pid, pipe in enumerate(pipelines):
        for seg in pipe.segments:
            seg.pipeline = pid

    script = Script(pipelines=pipelines, notes=notes, text=text, depth=depth)
    if depth < MAX_DEPTH:
        for seg in script.segments():
            for raw in seg.raws:
                for inner in _substitutions(raw):
                    script.subs.append(parse(inner, depth + 1))
            for r in seg.redirects:
                # echo hi > "$(rm -rf /)" runs the substitution first
                for inner in _substitutions(r.target):
                    script.subs.append(parse(inner, depth + 1))
                if r.sub:
                    script.subs.append(parse(r.sub, depth + 1))
                if r.op in ("<<", "<<-") and r.body and seg.program in {
                        "sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}:
                    # `bash <<EOF ... EOF` -- the body IS the script
                    script.subs.append(parse(r.body, depth + 1))
            for payload in _payloads(seg):
                if payload.strip():
                    script.subs.append(parse(payload, depth + 1))
    return script


WRAPPERS = {"sudo", "doas", "env", "command", "builtin", "exec", "nohup", "nice",
            "time", "stdbuf", "timeout", "xargs", "setsid", "chroot", "unbuffer"}

ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
POSITIONAL_SKIP = {"chroot": 1, "timeout": 1}

_FLAG_WITH_VALUE = {
    "sudo": {"-u", "-g", "-p", "-C", "-h", "-r", "-t", "-U", "-T"},
    "doas": {"-u", "-C"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-s", "-a", "--delimiter", "-E"},
    "chroot": set(),
    "setsid": set(),
}


def unwrap(argv: list[str]) -> tuple[list[str], list[str]]:
    """Strip leading VAR=value assignments and privilege/exec wrappers."""
    used: list[str] = []
    gram = list(argv)
    while gram and ASSIGNMENT.match(gram[0]):
        gram.pop(0)  # FOO=1 rm -rf / is `rm`, not `FOO=1`
    for _ in range(6):
        if not gram:
            break
        prog = gram[0].rsplit("/", 1)[-1]
        if prog not in WRAPPERS:
            break
        used.append(prog)
        rest = gram[1:]
        takes_value = _FLAG_WITH_VALUE.get(prog, set())
        i = 0
        while i < len(rest):
            a = rest[i]
            if prog == "env" and ASSIGNMENT.match(a):
                i += 1
                continue
            if a == "--":
                i += 1
                break
            if a.startswith("-"):
                if a in takes_value and i + 1 < len(rest):
                    i += 2
                    continue
                i += 1
                continue
            break
        rest = rest[i:]
        rest = rest[POSITIONAL_SKIP.get(prog, 0):]  # chroot NEWROOT, timeout DURATION
        while rest and ASSIGNMENT.match(rest[0]):
            rest = rest[1:]
        gram = rest
    return gram, used
