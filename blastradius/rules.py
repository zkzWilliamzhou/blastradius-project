"""Rule engine: turns a parsed script into explainable findings.

Every finding answers four questions:
  1. what capability is being exercised      -> `capability`
  2. how bad is it                           -> `severity`
  3. where is the evidence                   -> `evidence`
  4. what should be done instead             -> `mitigation`

Rules never execute anything. They only inspect the AST built by `shell.py`.
Capabilities are a small closed vocabulary so policies stay stable.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from .shell import Redirect, Script, Segment, parse, unwrap

SEVERITY_WEIGHT = {"info": 2, "low": 6, "medium": 16, "high": 38, "critical": 65}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class Hit:
    detail: str
    mitigation: str = ""
    evidence: str = ""
    severity: str | None = None
    capability: str | None = None
    title: str | None = None


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    capability: str
    severity: str
    fn: Callable
    tags: tuple[str, ...] = ()
    description: str = ""


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    capability: str
    severity: str
    detail: str
    evidence: str
    mitigation: str
    weight: int
    segment: str = ""
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class Ctx:
    cwd: str = "."
    protected: list[str] = field(default_factory=list)


RULES: list[Rule] = []
CROSS_RULES: list[Rule] = []


def rule(rid: str, title: str, capability: str, severity: str,
         tags: tuple[str, ...] = (), desc: str = ""):
    def deco(fn):
        RULES.append(Rule(rid, title, capability, severity, fn, tags, desc))
        return fn
    return deco


def cross(rid: str, title: str, capability: str, severity: str,
          tags: tuple[str, ...] = (), desc: str = ""):
    def deco(fn):
        CROSS_RULES.append(Rule(rid, title, capability, severity, fn, tags, desc))
        return fn
    return deco


# --------------------------------------------------------------------------
# path vocabulary
# --------------------------------------------------------------------------
CATASTROPHIC = {
    "/", "/*", "~", "~/*", "/home", "/home/*", "/Users", "/Users/*", "/root",
    "/usr", "/usr/*", "/etc", "/etc/*", "/var", "/var/*", "/bin", "/bin/*",
    "/sbin", "/sbin/*", "/lib", "/lib/*", "/lib64", "/boot", "/boot/*",
    "/System", "/System/*", "/Library", "/Library/*", "/Applications", "/*/*",
}
BROAD = {
    "/tmp", "/tmp/*", "/opt", "/opt/*", "/srv", "/srv/*", "/data", "/data/*",
    "/mnt", "/mnt/*", "/media", "/media/*", "/workspace", "/workspace/*",
    ".", "./", "./*", "*", "..", "../", "../*", "~/.cache", "~/.config",
    "~/.local", "/var/log", "/var/log/*", "/etc/nginx", "/usr/local",
}
SAFE_HOME = {
    "node_modules", "dist", "build", ".next", "target", "tmp", ".cache",
    ".venv", "venv", "vendor", "__pycache__", ".pytest_cache", ".mypy_cache",
    "coverage", ".turbo", ".parcel-cache", "out",
}
DEVICE_RE = re.compile(r"^/dev/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|disk\d|mmcblk|mapper/|dm-)")

PROTECTED_DEFAULT = [
    "~/.ssh", "~/.ssh/**", "~/.aws/**", "~/.config/gh/**", "~/.docker/config.json",
    "~/.kube/config", "~/.gnupg/**", "~/.config/gcloud/**", "~/.netrc", "~/.npmrc",
    "~/.pypirc", "~/.git-credentials", "~/.bash_history", "~/.zsh_history",
    "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa", "**/id_ed25519",
    "**/id_ecdsa", "**/credentials.json", "**/secrets.yml", "**/secrets.yaml",
    "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/**", "~/Library/Keychains/**",
    "**/.pgpass", "**/.my.cnf", "/etc/passwd", "/etc/group", "/etc/fstab",
    "/etc/resolv.conf", "~/.ssh/authorized_keys",
]
# Files that *look* like secrets but are meant to be public.
SAFE_NAMES = {
    ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.test.example",
    "credentials.json.example", "secrets.example.yml", "secrets.example.yaml",
}
SAFE_SUFFIX = (".pub", ".example", ".sample", ".template", ".dist", ".md", ".mdx")


@lru_cache(maxsize=4096)
def norm_path(p: str) -> str:
    p = (p or "").strip().strip("\"'")
    p = p.replace("\\", "/")
    for pre in ("${HOME}", "$HOME"):
        if p == pre:
            p = "~"
            break
        if p.startswith(pre + "/"):
            p = "~" + p[len(pre):]
            break
    p = re.sub(r"(?<!:)/{2,}", "/", p)
    if not p:
        return p
    # lexical resolution: /tmp/../etc -> /etc, ~/ => ~, ./x -> x
    p = posixpath.normpath(p)
    return p


def is_safe_name(p: str) -> bool:
    base = norm_path(p).rsplit("/", 1)[-1]
    return base in SAFE_NAMES or base.endswith(SAFE_SUFFIX)


@lru_cache(maxsize=8192)
def match_glob(path: str, pattern: str) -> bool:
    p = norm_path(path)
    pat = norm_path(pattern)
    if p == pat:
        return True
    if fnmatch.fnmatchcase(p, pat):
        return True
    if pat.startswith("**/"):
        tail = pat[3:]
        if fnmatch.fnmatchcase(p, tail):
            return True
        if fnmatch.fnmatchcase(p.rsplit("/", 1)[-1], tail):
            return True
    if pat.startswith("~/"):
        rel = pat[2:]
        if p.startswith("~/"):
            return fnmatch.fnmatchcase(p[2:], rel)
        return fnmatch.fnmatchcase(p, rel) or fnmatch.fnmatchcase(p, "*/" + rel)
    if p.startswith("~/"):
        return fnmatch.fnmatchcase(p[2:], pat)
    return False


def protected_by(path: str, patterns: Iterable[str]) -> str | None:
    if is_safe_name(path):
        return None
    for pat in patterns:
        if match_glob(path, pat):
            return pat
    return None


HOME_ROOTS = ("/home/", "/Users/", "/root/")
SYSTEM_ROOTS = ("/usr/", "/etc/", "/var/", "/bin/", "/sbin/", "/lib/", "/lib64/",
                "/boot/", "/System/", "/Library/", "/opt/")


def classify_target(p: str) -> str:
    q = norm_path(p)
    if q in CATASTROPHIC:
        return "catastrophic"
    if q in BROAD:
        return "broad"
    if q.count("/") == 2:
        if q.startswith(HOME_ROOTS):
            return "catastrophic"  # /home/alice, /Users/bob
        if q.startswith(SYSTEM_ROOTS):
            return "broad"         # /etc/nginx, /var/www
    if q.startswith("~/") and q.count("/") == 1 and q[2:] not in SAFE_HOME:
        return "broad"  # a direct child of $HOME that is not a build dir
    if q.startswith("/") and q.count("/") == 1 and len(q) > 1:
        return "catastrophic"  # unnamed top-level directory
    return "normal"


BARELY_VAR = re.compile(r"^\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?[/*]?$")
HOME_VAR = re.compile(r"\$\{?HOME\}?")


def has_var(s: str) -> bool:
    return "$" in s or "`" in s


def flags_of(args: list[str]) -> list[str]:
    return [a for a in args if a.startswith("-") and a != "-"]


def short_flags(args: list[str]) -> str:
    out = []
    for a in flags_of(args):
        out.append(a if a.startswith("--") else a[1:])
    return " ".join(out)


def positional(args: list[str], skip_values: Iterable[str] = ()) -> list[str]:
    skip = set(skip_values)
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1:])
            break
        if a in skip and i + 1 < len(args):
            i += 2
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        out.append(a)
        i += 1
    return out


def eff(seg: Segment) -> tuple[str, list[str], list[str]]:
    """Effective (program, args, wrappers) with sudo/env/nice stripped."""
    argv, wrappers = unwrap(seg.argv)
    if not argv:
        return "", [], wrappers
    return argv[0].rsplit("/", 1)[-1], argv[1:], wrappers


SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs",
                "php", "lua", "deno", "bun", "Rscript", "osascript"}
EXEC_SINKS = SHELLS | INTERPRETERS
FETCHERS = {"curl", "wget", "fetch", "aria2c", "http", "https", "busybox"}
DECODERS = {"base64", "openssl", "xxd", "uudecode"}
NET_SEND = {"curl", "wget", "http", "https", "nc", "ncat", "netcat", "socat",
            "scp", "sftp", "rsync"}


DRY_FLAGS = {"-n", "--dry-run", "--dryrun", "--just-print", "--no-act",
             "--simulate", "--plan"}


def is_dry_run(args: list[str]) -> bool:
    for a in args:
        if a in DRY_FLAGS or a.startswith(("--dry-run=", "--dryrun=")):
            return True
    return False


GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                    "--exec-path", "--config-env"}
GIT_GLOBAL_PREFIX = ("--git-dir=", "--work-tree=", "--namespace=", "--exec-path=",
                     "--config-env=")


def git_subcommand(args: list[str]) -> tuple[str, list[str]]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith(GIT_GLOBAL_PREFIX) or (a.startswith("-C") and len(a) > 2):
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    if i >= len(args):
        return "", []
    return args[i], args[i + 1:]


def _is_recursive(args: list[str]) -> bool:
    f = short_flags(args)
    return "r" in f or "R" in f or "--recursive" in f


# --------------------------------------------------------------------------
# filesystem destruction
# --------------------------------------------------------------------------
@rule("BR001", "recursive delete", "fs.delete", "high", ("destructive", "irreversible"))
def r_rm(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("rm", "srm", "trash-put"):
        return
    if not _is_recursive(args):
        return
    paths = positional(args)
    if not paths:
        yield Hit(
            detail="`rm -r` with no path: the target depends on shell word splitting, easy to misfire",
            mitigation="pass an explicit path and `--` before it",
            evidence=seg.text, severity="low",
            title="recursive delete without an explicit path", capability="fs.delete",
        )
        return
    for p in dict.fromkeys(paths):
        if p in ("{}", "%", "$@", "$*"):
            yield Hit(
                detail=f"recursive delete of the placeholder `{p}`: the real path comes from a list at run time",
                mitigation="print the list first and delete concrete paths",
                evidence=seg.text, severity="medium",
                title="recursive delete of an unresolved path", capability="fs.delete",
            )
            continue
        if HOME_VAR.search(p):
            yield Hit(
                detail=f"`rm -r {p}` deletes the whole home directory; there is no undo",
                mitigation="delete a specific subdirectory; keep a snapshot before touching ~",
                evidence=seg.text, severity="critical",
                title="recursive delete of the home directory", capability="fs.delete",
            )
            continue
        if has_var(p):
            bare = bool(BARELY_VAR.match(p.strip("\"'")))
            yield Hit(
                detail=f"recursive delete of `{p}`: the real target is only known at run time"
                + (" — it is a bare variable, so it may be empty or `/`" if bare else ""),
                mitigation="print it first: `printf '%s\\n' \"$VAR\"`, then delete with `--` and an explicit path",
                evidence=seg.text,
                severity="high" if bare else "low",
                title="recursive delete of an unresolved path",
                capability="fs.delete",
            )
            continue
        tier = classify_target(p)
        if tier == "catastrophic":
            yield Hit(
                detail=f"`rm -r {p}` removes an entire system or home tree; there is no undo",
                mitigation="delete the specific subdirectory, or move it to trash / restore from a snapshot",
                evidence=seg.text, severity="critical",
                title="recursive delete of a system root", capability="fs.delete",
            )
        elif tier == "broad":
            yield Hit(
                detail=f"`rm -r {p}` wipes a whole directory rather than a build artifact",
                mitigation="narrow the path to the artifact (e.g. `node_modules`, `dist`) and list it first",
                evidence=seg.text, severity="high",
                title="recursive delete of a broad directory", capability="fs.delete",
            )


@rule("BR003", "find -delete over a tree", "fs.delete", "medium")
def r_find_delete(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog != "find":
        return
    joined = " ".join(args)
    if "-delete" not in args and not re.search(r"-exec\s+(rm|shred|unlink)\b", joined):
        return
    roots = [a for a in args if not a.startswith("-") and a not in ("(", ")", "!", "\\(")]
    target = roots[0] if roots else "."
    if "-exec" in args:
        body = args[args.index("-exec") + 1:]
        for a in body:
            if classify_target(a) == "catastrophic":
                yield Hit(
                    detail=f"the -exec body deletes `{a}`, a system path, once per match — the loop multiplies the damage",
                    mitigation="run the find without -exec, read the list, then delete explicitly",
                    evidence=seg.text, severity="critical",
                    title="find -exec deletes a system path", capability="fs.delete",
                )
                return
            if protected_by(a, ctx.protected):
                yield Hit(
                    detail=f"the -exec body touches a protected path (`{a}`)",
                    mitigation="exclude credential paths with `-path … -prune`",
                    evidence=seg.text, severity="high",
                    title="find -exec touches credentials", capability="cred.access",
                )
                return
    tier = classify_target(target)
    name_filter = "-name" in args or "-iname" in args or "-path" in args
    if tier == "catastrophic":
        if target in ("~", "~/") and name_filter:
            severity, title = "medium", "find -delete across the home tree"
        else:
            severity, title = "critical", "find -delete from a system root"
    elif target in (".", "./") or not target.startswith(("/", "~")):
        return  # relative cleanup (find . -name '*.pyc' -delete) is routine
    else:
        severity, title = "medium", "find -delete across a shared directory"
    yield Hit(
        detail=f"`find {target} … -delete` walks the tree and removes everything it matches, including files you never listed",
        mitigation="run the same find without `-delete` and read the list first",
        evidence=seg.text, severity=severity, title=title, capability="fs.delete",
    )


@rule("BR004", "raw write to a block device", "fs.device_write", "critical",
      ("destructive", "hardware"))
def r_dd(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog != "dd":
        return
    for a in args:
        if a.startswith("of="):
            target = a[3:]
            if target.startswith("/dev/") and not target.startswith("/dev/null"):
                yield Hit(
                    detail=f"`dd of={target}` overwrites a device node byte-for-byte; the filesystem and its data are gone",
                    mitigation="write to an image file (`of=disk.img`) and inspect it, or use `ddrescue`",
                    evidence=seg.text,
                )


@rule("BR005", "filesystem/partition tool on a device", "fs.device_write", "critical",
      ("destructive", "hardware"))
def r_mkfs(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    tools = {"mkfs", "mke2fs", "mkswap", "wipefs", "fdisk", "sfdisk", "parted",
             "gdisk", "sgdisk", "blkdiscard", "pvcreate", "cryptsetup"}
    if not (prog in tools or prog.startswith("mkfs.")):
        return
    if prog in ("fdisk", "parted", "gdisk", "sgdisk") and any(a in ("-l", "--list") for a in args):
        return
    if any(a in ("-h", "--help", "--version") for a in args):
        return
    yield Hit(
        detail=f"`{prog}` rewrites partition or filesystem metadata; every file on the target device is lost",
        mitigation="identify the device with `lsblk` and `blkid` first; prefer working on an image file",
        evidence=seg.text,
    )


@rule("BR006", "redirect into a device node", "fs.device_write", "critical")
def r_redirect_device(seg: Segment, ctx: Ctx):
    for r in seg.redirects:
        if r.device_sink:
            yield Hit(
                detail=f"`{r.op} {r.target}` streams data straight onto a raw device",
                mitigation="redirect to a regular file and verify it before writing to a device",
                evidence=seg.text,
            )


@rule("BR007", "mass or world-writable permission change", "priv.escalate", "high")
def r_chmod(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("chmod", "chown", "chgrp"):
        return
    pos = positional(args)
    if not pos:
        return
    recursive = _is_recursive(args)
    mode, targets = pos[0], pos[1:]
    world = prog == "chmod" and mode in ("777", "666", "a+rwx", "a+rw", "o+w", "o+wX")
    if recursive:
        for t in targets or ["."]:
            if norm_path(t) in (".", "*", "./"):
                continue  # `chmod -R 755 .` inside a project is routine
            tier = classify_target(t)
            if tier == "catastrophic":
                yield Hit(
                    detail=f"`{prog} -R {mode} {t}` changes ownership/permissions for an entire tree",
                    mitigation="apply it to the specific directory that needs it; `-R` on a root path breaks services",
                    evidence=seg.text,
                )
                return
    if world or mode in ("000", "0000"):
        yield Hit(
            detail=f"`{prog} {mode}` makes the target writable (or readable) by every user on the host",
            mitigation="use the narrowest mode (`644`/`755`) and a dedicated group",
            evidence=seg.text, severity="medium",
            title="world-writable permission", capability="priv.escalate",
        )


@rule("BR008", "privilege bit or admin group grant", "priv.escalate", "high")
def r_setuid(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "chmod":
        for a in args:
            if a in ("u+s", "g+s", "4755", "4777", "6755") or re.fullmatch(r"[46][0-7]{3}", a):
                yield Hit(
                    detail="setuid/setgid makes the binary run with the owner's privileges for every caller",
                    mitigation="prefer file capabilities (`setcap cap_net_bind_service=+ep`) over setuid",
                    evidence=seg.text,
                )
                break
    if prog == "setcap" and any(a.endswith(("+ep", "+eip", "+p")) for a in args):
        yield Hit(
            detail="grants a raw capability that survives across users",
            mitigation="grant the single capability the binary needs and revisit it on every upgrade",
            evidence=seg.text, severity="medium", capability="priv.escalate",
            title="capability granted to a binary",
        )
    if prog in ("usermod", "gpasswd", "adduser", "addgroup", "dscl") and any(
            a in ("sudo", "wheel", "admin", "docker", "root", "lxd") for a in args):
        yield Hit(
            detail="membership in this group is equivalent to root (docker/lxd are trivially escalatable)",
            mitigation="grant the specific command in sudoers instead of the whole group",
            evidence=seg.text,
        )


@rule("BR009", "in-place overwrite of a file", "fs.write", "medium")
def r_truncate(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("truncate", "shred"):
        return
    if prog == "truncate" and not any(a == "-s" or a.startswith("-s") or a.startswith("--size") for a in args):
        return
    yield Hit(
        detail=f"`{prog}` overwrites an existing file in place; the original bytes are unrecoverable",
        mitigation="copy to `.bak` first and confirm the path with `ls -l`",
        evidence=seg.text,
    )


@rule("BR013", "archive extracted into a system path", "fs.write", "high")
def r_extract(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    target = None
    if prog in ("tar", "bsdtar", "gtar"):
        creating = any(a.startswith("-") and "c" in a[1:] for a in args if not a.startswith("--")) or \
                   any(a in ("-c", "--create") for a in args)
        if creating:
            return
        for i, a in enumerate(args[:-1]):
            if a == "-C" or a.startswith("--directory="):
                target = args[i + 1] if a == "-C" else a.split("=", 1)[1]
    elif prog in ("unzip", "7z", "7za"):
        for i, a in enumerate(args[:-1]):
            if a in ("-d", "-o"):
                target = args[i + 1]
    if target and classify_target(target) in ("catastrophic", "broad"):
        yield Hit(
            detail=f"extracts an archive into `{target}`, scattering untracked files across a shared tree",
            mitigation="extract into a fresh directory and move only what you need",
            evidence=seg.text,
        )


@rule("BR010", "protected file mutated", "cred.protect", "high")
def r_protected_mutation(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    targets: list[str] = []
    if prog in ("rm", "truncate", "shred", "chmod", "chown", "tee", "ln", "install", "unlink"):
        targets = positional(args, skip_values=("-m", "-o", "-g", "-t", "--mode", "--owner", "-n"))
    elif prog in ("mv", "cp"):
        pos = positional(args, skip_values=("-m", "-o", "-g", "--mode"))
        targets = pos[-1:]  # only the destination is modified
    for t in dict.fromkeys(targets):
        pat = protected_by(t, ctx.protected)
        if pat:
            yield Hit(
                detail=f"`{prog}` modifies `{t}` (protected pattern `{pat}`)",
                mitigation="copy it with `cp -p`, edit the copy, swap atomically",
                evidence=seg.text,
            )
    for r in seg.redirects:
        if r.writes and protected_by(r.target, ctx.protected):
            yield Hit(
                detail=f"`{r.op} {r.target}` overwrites a protected file",
                mitigation="write to a temp file and `mv` it into place after review",
                evidence=seg.text,
            )


@rule("BR011", "rsync --delete mirror", "fs.delete", "high")
def r_rsync(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog != "rsync" or not any(a.startswith("--delete") for a in args):
        return
    if is_dry_run(args):
        return
    pos = positional(args)
    dest = pos[-1] if pos else "?"
    remote = ":" in dest and not dest.startswith("/") and "://" not in dest
    yield Hit(
        detail=f"`rsync --delete` makes `{dest}` an exact mirror: anything that exists only there is removed"
        + (" (remote destination)" if remote else " (local destination)"),
        mitigation="dry-run with `-n --itemize-changes`, then mirror into a versioned backup",
        evidence=seg.text,
    )


@rule("BR012", "irreversible git operation", "git.destructive", "high")
def r_git(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog != "git":
        return
    sub, rest = git_subcommand(args)
    if sub == "reset" and "--hard" in rest:
        yield Hit(
            detail="`git reset --hard` discards uncommitted work; those changes are not in any reflog entry",
            mitigation="`git stash push -u` first, or commit to a scratch branch",
            evidence=seg.text,
        )
    if sub == "clean" and any(re.fullmatch(r"-[a-zA-Z]*[fd][a-zA-Z]*", a) for a in rest) \
            and "n" not in short_flags(rest):
        yield Hit(
            detail="`git clean -f` deletes untracked files, which git never backed up",
            mitigation="run `git clean -nd` (dry run); keep `-x` off unless build output is disposable",
            evidence=seg.text,
        )
    if sub == "push" and not is_dry_run(rest):
        force = any(a in ("--force", "-f") or a.startswith("--force-with-lease") for a in rest)
        if force:
            branch = [a for a in rest if not a.startswith("-")][-1:]
            protected_branch = bool(branch) and any(b in ("main", "master", "release", "prod") for b in branch)
            lease = any(a.startswith("--force-with-lease") for a in rest)
            yield Hit(
                detail=f"force-push rewrites `{branch[0] if branch else 'the current branch'}`; "
                       "anyone who already pulled ends up with divergent history",
                mitigation="use `--force-with-lease`, or open a PR; never force-push a shared branch",
                evidence=seg.text,
                severity="high" if protected_branch else ("low" if lease else "medium"),
                title="force-push rewrites shared history", capability="git.destructive",
            )
    if sub in ("filter-branch", "filter-repo") and "--force" in rest:
        yield Hit(
            detail="history rewriting invalidates every existing clone of the repository",
            mitigation="announce a freeze window and coordinate before rewriting shared history",
            evidence=seg.text,
        )
    if sub in ("checkout", "restore") and "." in rest and any(a in ("--", ".") for a in rest) \
            and "--staged" not in rest:
        if is_dry_run(rest):
            return
        yield Hit(
            detail="throws away every uncommitted change in the working tree",
            mitigation="stash first, or discard one file at a time",
            evidence=seg.text, severity="medium", capability="git.destructive",
            title="discard local changes",
        )
    if sub == "stash" and rest[:1] and rest[0] in ("clear", "drop"):
        yield Hit(
            detail="dropped stashes are unreachable from any ref; there is no undo",
            mitigation="`git stash show -p stash@{0}` before dropping",
            evidence=seg.text, severity="low", capability="git.destructive",
            title="delete stashed work",
        )


# --------------------------------------------------------------------------
# privilege
# --------------------------------------------------------------------------
@rule("BR020", "privilege wrapper", "priv.escalate", "low")
def r_sudo(seg: Segment, ctx: Ctx):
    prog, args, wrappers = eff(seg)
    if "sudo" in wrappers or "doas" in wrappers:
        yield Hit(
            detail=f"runs `{prog}` as root: mistakes are no longer bounded by file permissions",
            mitigation="run unprivileged and grant only the needed capability; `sudo -l` shows the boundary",
            evidence=seg.text, severity="low",
        )
    if prog == "su":
        yield Hit(
            detail="opens a root (or other user's) shell: everything typed afterwards bypasses the audit trail",
            mitigation="use `sudo -u user -- command` for one command instead of an interactive shell",
            evidence=seg.text, severity="medium",
            title="interactive user switch", capability="priv.escalate",
        )


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------
@rule("BR032", "reverse shell primitive", "net.remote_exec", "critical",
      ("malicious", "exfiltration"))
def r_reverse_shell(seg: Segment, ctx: Ctx):
    text = seg.text
    if "/dev/tcp/" in text or "/dev/udp/" in text:
        yield Hit(
            detail="`/dev/tcp` opens a raw socket from the shell — the classic reverse-shell primitive",
            mitigation="never run this unless you wrote it yourself",
            evidence=seg.text,
        )
    prog, args, _ = eff(seg)
    if prog in ("nc", "ncat", "netcat", "socat") and (
            "-e" in args or "--exec" in args or any("EXEC:" in a for a in args)):
        yield Hit(
            detail="netcat with `-e` hands a shell to whoever connects",
            mitigation="remove `-e`; use `nc -l` only for one known peer on a trusted network",
            evidence=seg.text,
        )


@rule("BR033", "listening socket", "net.listen", "high")
def r_listen(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("nc", "ncat", "netcat", "socat"):
        return
    if not any(a.startswith("-") and "l" in a for a in args):
        return
    local_only = any(a in ("127.0.0.1", "localhost", "::1") for a in args) or "-s 127.0.0.1" in seg.text
    yield Hit(
        detail="opens a listening socket, so anything that can reach this port can talk to it",
        mitigation="bind to 127.0.0.1, pick a random port, and close it when done",
        evidence=seg.text, severity="low" if local_only else "high",
        title="listener bound to localhost" if local_only else "listener exposed on all interfaces",
        capability="net.listen",
    )


@rule("BR034", "data leaves the machine", "net.egress", "high")
def r_upload(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in NET_SEND or is_dry_run(args):
        return
    if prog in ("scp", "sftp", "rsync"):
        pos = positional(args)
        if len(pos) >= 2 and (":" in pos[-1]):
            yield Hit(
                detail="copies local files to a remote host; if the source is a secret or a dump, this is exfiltration",
                mitigation="copy to a path you control and confirm the host with `ssh -G`",
                evidence=seg.text, severity="high",
                title="files copied to a remote host", capability="net.egress",
            )
        return
    if prog == "nc" or prog == "socat":
        return
    for a in args:
        if a.startswith(("-T", "--upload-file")) or a.startswith(("-F", "--form")) and "=@" in a \
                or a.startswith(("-d", "--data")) and "@" in a:
            yield Hit(
                detail=f"`{a}` ships local file content to a remote endpoint",
                mitigation="upload to an authenticated endpoint you control; do not let a command string choose the destination",
                evidence=seg.text, severity="high",
                title="file uploaded to the network", capability="net.egress",
            )
            return
        if a.startswith(("@", "=@")) or "=@" in a:
            yield Hit(
                detail="the request body references a local file",
                mitigation="check what the file contains before it leaves the machine",
                evidence=seg.text, severity="high",
                title="local file sent as request body", capability="net.egress",
            )
            return
    if any(a.startswith(("-d", "--data")) for a in args):
        yield Hit(
            detail="sends a request body to a remote endpoint",
            mitigation="keep the endpoint constant in code rather than in the command string",
            evidence=seg.text, severity="low",
            title="request body posted to the network", capability="net.egress",
        )


@rule("BR035", "remote command over ssh", "net.remote", "low")
def r_ssh(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("ssh", "rsh", "mosh", "telnet"):
        return
    tail = [a for a in args if not a.startswith("-")]
    if len(tail) < 2:
        return
    yield Hit(
        detail=f"runs `{' '.join(tail[1:])[:80]}` on `{tail[0]}` — a different machine, a different blast radius",
        mitigation="run an idempotent, logged script remotely and confirm the host first",
        evidence=seg.text,
    )


BENIGN_PAYLOAD = re.compile(
    r"ssh-agent|direnv|pyenv init|rbenv init|asdf |nvm |conda shell|brew shellenv|"
    r"kubectl completion|starship init|zoxide init|mise activate|git rev-parse|"
    r"npm config get|go env",
    re.I,
)
DESTRUCTIVE_API = re.compile(
    r"rmtree|os\.remove|os\.unlink|shutil\.|os\.system|subprocess|exec\(|"
    r"\brm -rf\b|drop table|truncate table|formatted|mkfs",
    re.I,
)


@rule("BR036", "inline interpreter payload", "opaque.code", "low")
def r_opaque(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    payload = ""
    if prog in SHELLS:
        for i, a in enumerate(args):
            if a in ("-c", "--command") and i + 1 < len(args):
                payload = args[i + 1]
                break
            if a.startswith("-") and not a.startswith("--") and "c" in a and i + 1 < len(args):
                payload = args[i + 1]
                break
    elif prog in ("python", "python3", "perl", "ruby", "node", "php", "lua"):
        for i, a in enumerate(args):
            if a in ("-c", "-e", "-r", "--eval") and i + 1 < len(args):
                payload = args[i + 1]
                break
    elif prog == "eval":
        payload = " ".join(args)
    if not payload or BENIGN_PAYLOAD.search(payload):
        return
    if ("$(" in payload or "`" in payload) and re.search(r"https?://|curl|wget", payload):
        yield Hit(
            detail="a remote document is fetched and executed inside a string — nothing between download and exec is reviewed",
            mitigation="download to a file, read it, verify a checksum, then run it",
            evidence=seg.text, severity="critical",
            title="remote payload executed from a string", capability="net.remote_exec",
        )
        return
    if DESTRUCTIVE_API.search(payload):
        yield Hit(
            detail="the string performs filesystem/process operations that static analysis cannot follow",
            mitigation="move the code into a reviewed file and run that",
            evidence=seg.text, severity="medium",
            title="inline code with destructive calls", capability="opaque.code",
        )
        return
    yield Hit(
        detail="inline code as a string: only the string is visible, not what it does",
        mitigation="prefer a reviewed script file over `-c` one-liners for anything that writes",
        evidence=seg.text,
    )


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------
READERS = {"cat", "less", "more", "head", "tail", "strings", "xxd", "base64",
           "cp", "mv", "scp", "rsync", "tar", "zip", "grep", "awk", "sed", "sort",
           "python", "python3", "node", "jq", "bat", "open", "source", "."}


@rule("BR040", "reads a secret store", "cred.access", "high", ("secrets",))
def r_secret_read(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in READERS:
        return
    targets = positional(args, skip_values=("-n", "-c", "-A", "-B", "-C", "-e", "--lines", "-m"))
    for t in dict.fromkeys(targets):
        pat = protected_by(t, ctx.protected)
        if pat:
            yield Hit(
                detail=f"reads `{t}` (protected pattern `{pat}`): a secret that reaches the transcript is a leaked secret",
                mitigation="reference secrets by name (`$TOKEN`) instead of printing them; redact logs",
                evidence=seg.text,
            )
            return
    if prog in ("tar", "zip") and any(a.startswith(("~/.ssh", "~/.aws")) for a in args):
        yield Hit(
            detail="archives a credential directory",
            mitigation="archive only the files that actually need to move",
            evidence=seg.text,
        )


@rule("BR041", "dumps the process environment", "cred.access", "low")
def r_env_dump(seg: Segment, ctx: Ctx):
    if seg.program in ("env", "printenv", "set") and not seg.args:
        yield Hit(
            detail="prints every environment variable, including tokens and credentials",
            mitigation="print only what you need: `printenv TOKEN | cut -c1-4`",
            evidence=seg.text,
        )


@rule("BR042", "shell history tampering", "sys.antiforensics", "medium")
def r_history(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "history" and "-c" in args:
        yield Hit(
            detail="clearing shell history removes the only record of this session",
            mitigation="archive it instead (`history > /tmp/session.log`)",
            evidence=seg.text,
        )
    for r in seg.redirects:
        if r.writes and r.target.endswith(("_history", ".bash_history")):
            yield Hit(
                detail="overwrites shell history",
                mitigation="append with `>>` if you must, and keep a copy",
                evidence=seg.text,
            )
    if prog in ("cat", "less", "tail", "grep") and any("history" in a for a in args):
        yield Hit(
            detail="reads prior commands, which often contain inline secrets (`export TOKEN=…`)",
            mitigation="avoid typing secrets inline; use a keychain or a `0600` env file",
            evidence=seg.text, severity="low",
            title="reads shell history", capability="cred.access",
        )


@rule("BR044", "private key exported", "cred.access", "high", ("secrets",))
def r_gpg_export(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "gpg" and any(a in ("--export-secret-keys", "--export-secret-subkeys") for a in args):
        yield Hit(
            detail="exports the private key material, unencrypted unless `-a --export-secret-keys | gpg -c` is used",
            mitigation="export to an encrypted file and move it over a channel you control",
            evidence=seg.text,
        )
    if prog in ("ssh-keygen", "openssl") and any(a in ("-y", "-p") for a in args) and "~/.ssh" in seg.text:
        yield Hit(
            detail="reads or rewrites a private key file",
            mitigation="keep the key offline; use an agent for daily work",
            evidence=seg.text, severity="medium",
            title="private key touched", capability="cred.access",
        )


@rule("BR071", "loader injection", "opaque.code", "high", ("evasion",))
def r_ld_preload(seg: Segment, ctx: Ctx):
    if re.search(r"\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES)=", seg.text):
        yield Hit(
            detail="injects a shared library into every process the command starts; the injected code is invisible in the command line",
            mitigation="inspect the library first and run it in a sandbox",
            evidence=seg.text,
        )
    elif re.search(r"\b(LD_LIBRARY_PATH|DYLD_LIBRARY_PATH)=", seg.text):
        yield Hit(
            detail="changes where the dynamic loader looks for libraries",
            mitigation="point the loader at a directory you control and keep it out of shared scripts",
            evidence=seg.text, severity="low",
            title="dynamic loader path changed", capability="opaque.code",
        )


@rule("BR073", "package manager pointed at an untrusted index", "supply.install", "high",
      ("supply-chain",))
def r_registry(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    joined = " ".join(args)
    if prog in ("npm", "yarn", "pnpm") and "config" in args and "set" in args:
        if re.search(r"(registry|@[\w-]+:registry)\s+http://", joined):
            yield Hit(
                detail="downgrades the registry to plaintext HTTP: packages can be swapped in transit",
                mitigation="use the https endpoint, or a mirror you control with pinned certs",
                evidence=seg.text,
            )
    if prog in ("pip", "pip3") and "config" in args and "set" in args and "http://" in joined:
        yield Hit(
            detail="sets a plaintext package index; installs can be tampered with",
            mitigation="use https and `--require-hashes`",
            evidence=seg.text,
        )


@rule("BR043", "keychain query", "cred.access", "medium")
def r_keychain(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "security" and any(a in ("find-generic-password", "find-internet-password", "dump-keychain") for a in args):
        yield Hit(
            detail="reads a stored credential out of the system keychain",
            mitigation="let the application read the keychain itself; do not print the secret",
            evidence=seg.text,
        )


# --------------------------------------------------------------------------
# system
# --------------------------------------------------------------------------
@rule("BR050", "power state change", "sys.power", "high")
def r_power(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog in ("shutdown", "reboot", "halt", "poweroff"):
        if any(a in ("--help", "--version") for a in args):
            return
        if prog == "shutdown" and "-c" in args:
            return  # cancel a pending shutdown
        yield Hit(
            detail="takes the host down; unsaved work and running jobs are lost",
            mitigation="check `who` first; prefer `systemctl reboot` so the shutdown is logged",
            evidence=seg.text,
        )
    if prog == "init" and args[:1] in (["0"], ["6"]):
        yield Hit(
            detail="changes the runlevel to shutdown/reboot",
            mitigation="use `systemctl isolate` or ask the owner of the host",
            evidence=seg.text,
        )


@rule("BR051", "broad process kill", "proc.kill", "high")
def r_kill(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("kill", "killall", "pkill"):
        return
    if prog == "kill" and ("-1" in args or "-0" in args):
        yield Hit(
            detail="signals every process this user owns, including the shell's own parent",
            mitigation="find the PID first (`pgrep -af`) and signal one process group",
            evidence=seg.text,
        )
    elif prog in ("killall", "pkill") and any(a in ("-9", "-KILL", "--signal=KILL") for a in args):
        yield Hit(
            detail=f"`{prog}` with SIGKILL cannot be caught; services get no chance to flush state",
            mitigation="try SIGTERM first, then SIGKILL for a specific PID",
            evidence=seg.text, severity="medium",
        )


@rule("BR052", "system service disabled", "sys.service", "high")
def r_service(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("systemctl", "service", "launchctl", "sv", "update-rc.d", "chkconfig"):
        return
    action = next((a for a in args if a in ("stop", "disable", "mask", "kill", "unload", "bootout")), None)
    if not action:
        return
    units = [a for a in args if not a.startswith("-") and a != action]
    critical_units = {"sshd", "ssh", "network", "networking", "systemd-resolved",
                      "firewalld", "ufw", "docker", "nginx", "postgresql", "mysql",
                      "containerd", "kubelet"}
    hit = [u for u in units if u.split(".")[0].split("/")[-1] in critical_units]
    yield Hit(
        detail=(f"`{action} {hit[0]}` can cut off remote access or the network stack"
                if hit else f"`{action}` a service: it stops answering until someone notices"),
        mitigation="keep a second SSH session open; use `systemctl restart` for config changes",
        evidence=seg.text, severity="high" if hit else "medium",
        title="critical service disabled" if hit else "service stopped",
        capability="sys.service",
    )


@rule("BR053", "persistence hook installed", "sys.persist", "medium")
def r_persist(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "crontab":
        if "-r" in args:
            yield Hit(
                detail="`crontab -r` deletes every scheduled job for this user, without a backup",
                mitigation="`crontab -l > backup.cron` first",
                evidence=seg.text, severity="high",
                title="all cron jobs deleted", capability="sys.persist",
            )
        elif any(a in ("-e",) for a in args):
            yield Hit(
                detail="opens the crontab for editing: the result runs unattended forever",
                mitigation="commit the crontab to the provisioning repo and install it from there",
                evidence=seg.text, severity="medium",
                title="crontab edited", capability="sys.persist",
            )
        return
    if prog in ("systemctl", "launchctl") and any(a in ("enable", "bootstrap") for a in args):
        yield Hit(
            detail="enables a unit at boot: it survives reboots and is easy to forget",
            mitigation="record it in your provisioning repo instead of enabling by hand",
            evidence=seg.text,
        )
    if re.search(r"(>>?|tee\s+-a)\s*(~|\$HOME)?/?\.(bashrc|zshrc|profile|bash_profile)|"
                 r"/etc/(profile|rc\.local|cron\.)", seg.text):
        yield Hit(
            detail="appends to a shell startup file, which runs on every future login",
            mitigation="source a dedicated file from `.bashrc` and keep that file in version control",
            evidence=seg.text,
        )
    if prog in ("at", "batch") or (prog == "systemd-run" and any(a.startswith("--on-active") for a in args)):
        yield Hit(
            detail="schedules a job for later; nothing will be watching when it fires",
            mitigation="log the job output to a file and note it somewhere you will see",
            evidence=seg.text, severity="low",
        )


@rule("BR054", "host filtering disabled", "sys.firewall", "high")
def r_firewall(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "iptables" and any(a in ("-F", "--flush") for a in args):
        yield Hit(
            detail="`iptables -F` drops every rule; the host is unfiltered until rules are restored",
            mitigation="save first (`iptables-save > rules.v4`) and apply changes reversibly",
            evidence=seg.text,
        )
    if (prog == "ufw" and "disable" in args) or (prog == "setenforce" and args[:1] == ["0"]) \
            or (prog == "firewall-cmd" and "--panic-on" in args):
        yield Hit(
            detail="turns the host firewall or mandatory access control off",
            mitigation="open the one port you need instead of disabling the policy",
            evidence=seg.text,
        )


# --------------------------------------------------------------------------
# publish / deploy / cloud
# --------------------------------------------------------------------------
@rule("BR060", "irreversible publish", "code.publish", "high")
def r_publish(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog in ("npm", "yarn", "pnpm", "bun") and args[:1] == ["publish"] and not is_dry_run(args):
        yield Hit(
            detail="package versions are immutable once published; a wrong tarball needs a new version",
            mitigation="`npm pack` and inspect the tarball; publish from CI with provenance",
            evidence=seg.text,
        )
    if prog in ("twine", "poetry", "cargo", "gem", "dotnet", "mvn") and not is_dry_run(args) \
            and any(a in ("upload", "publish", "push", "deploy", "nuget") for a in args):
        yield Hit(
            detail="publishes an artifact to a public registry under your identity",
            mitigation="dry-run against a local index first",
            evidence=seg.text,
        )


@rule("BR061", "cloud or platform resource deletion", "deploy.prod", "high")
def r_cloud(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    joined = " ".join(args)
    if prog == "aws" and re.search(r"\bs3\s+(rm|rb)\b", joined) and (
            "--recursive" in args or "--force" in args or " rb " in f" {joined} ") and not is_dry_run(args):
        yield Hit(
            detail="recursive object delete/removal has no undo unless versioning is enabled",
            mitigation="check bucket versioning and MFA-delete; use `--dryrun` to list what would go",
            evidence=seg.text,
        )
    if prog == "aws" and re.search(r"\bs3\s+sync\b", joined) and "--delete" in args:
        yield Hit(
            detail="`s3 sync --delete` removes objects that exist only at the destination",
            mitigation="run with `--dryrun` first and confirm the bucket is the intended direction",
            evidence=seg.text,
        )
    if prog == "aws" and "ec2" in args and "terminate-instances" in args:
        yield Hit(
            detail="terminates instances; ephemeral volumes go with them",
            mitigation="snapshot first, or `stop-instances` if the state can wait",
            evidence=seg.text,
        )
    if prog == "aws" and not is_dry_run(args) and re.search(
            r"\b(delete|remove|terminate|deregister|purge)-[a-z-]+", joined):
        yield Hit(
            detail=f"`aws {joined.split()[0] if joined else ''}` destroys a cloud resource; several of these have no undo "
                   "(`--skip-final-snapshot` and `--force` remove the last safety net)",
            mitigation="check the resource's deletion protection and take a snapshot first; `--dry-run` where supported",
            evidence=seg.text, severity="high",
            title="cloud resource deleted", capability="deploy.prod",
        )
    if prog in ("helm",) and args[:1] in (["uninstall"], ["delete"]):
        yield Hit(
            detail="uninstalling a release removes its objects; PVCs may go with it",
            mitigation="`helm get manifest` first, and keep `--keep-history`",
            evidence=seg.text, severity="high",
            title="release uninstalled", capability="deploy.prod",
        )
    if prog == "terraform" and args[:1] in (["destroy"], ["apply"]):
        if args[:1] == ["destroy"] or "-auto-approve" in args:
            yield Hit(
                detail="applies infrastructure changes with no human reading the plan",
                mitigation="run `terraform plan` and review the diff; never `-auto-approve` against prod state",
                evidence=seg.text,
            )
    if prog == "kubectl" and "delete" in args and not is_dry_run(args) and any(
            a in ("--all", "--all-namespaces", "-A", "namespace", "namespaces", "ns",
                  "pvc", "pv", "-f") or a.startswith("ns/")
            for a in args):
        yield Hit(
            detail="deletes cluster objects; removing a PVC/PV destroys the underlying data",
            mitigation="`kubectl diff` first, and delete by name with `--dry-run=server`",
            evidence=seg.text,
        )
    if prog in ("docker", "podman") and args[:2] in (["system", "prune"], ["volume", "prune"]):
        flags = "".join(short_flags(args).split())
        if "a" in flags or "all" in flags or "f" in flags:
            yield Hit(
                detail="prunes images/volumes; anonymous volumes hold data no container references",
                mitigation="`docker system df` first, and prune by label",
                evidence=seg.text, severity="medium",
                title="prune container storage", capability="fs.delete",
            )


@rule("BR062", "destructive SQL in a shell payload", "deploy.prod", "high")
def r_sql(seg: Segment, ctx: Ctx):
    if not re.search(r"\b(drop\s+(database|table|schema)|truncate\s+table|flushall|flushdb)\b",
                     seg.text, re.I):
        return
    prog, args, _ = eff(seg)
    if prog not in ("psql", "mysql", "mariadb", "sqlite3", "redis-cli", "mongo",
                    "mongosh", "clickhouse-client", "cockroach"):
        return
    yield Hit(
        detail="DDL/DML that cannot be rolled back once committed",
        mitigation="`BEGIN; … ROLLBACK;` to verify first, or take a dump/snapshot before the statement",
        evidence=seg.text,
    )


@rule("BR063", "public-read object", "secret.expose", "medium")
def r_public_acl(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog == "aws" and any(a in ("public-read", "public-read-write") for a in args):
        yield Hit(
            detail="makes the object readable by anyone on the internet, forever",
            mitigation="share a presigned URL with an expiry instead",
            evidence=seg.text,
        )


@rule("BR064", "container escape surface", "priv.escalate", "high")
def r_container(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("docker", "podman", "nerdctl") or args[:1] not in (["run"], ["create"], ["exec"]):
        return
    if "--privileged" in args:
        yield Hit(
            detail="`--privileged` disables every container boundary; the container can own the host",
            mitigation="grant the specific capability (`--cap-add`) or device instead",
            evidence=seg.text,
        )
    for i, a in enumerate(args):
        if a in ("-v", "--volume") and i + 1 < len(args):
            spec = args[i + 1]
            src = spec.split(":")[0]
            if src in ("/", "/etc", "/var/run", "/var/run/docker.sock", "/proc", "/sys"):
                yield Hit(
                    detail=f"mounts `{src}` into the container; a root process inside can rewrite the host",
                    mitigation="mount the narrowest subdirectory, read-only (`:ro`) where possible",
                    evidence=seg.text,
                )
    if any(a in ("--pid=host", "--net=host", "--userns=host") for a in args):
        yield Hit(
            detail="shares a host namespace: isolation between container and host is gone",
            mitigation="use the default namespace and publish only the ports you need",
            evidence=seg.text, severity="medium",
            title="host namespace shared", capability="priv.escalate",
        )


# --------------------------------------------------------------------------
# supply chain
# --------------------------------------------------------------------------
@rule("BR065", "container data removed", "fs.delete", "high")
def r_volume(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog not in ("docker", "podman", "nerdctl"):
        return
    if args[:2] == ["compose", "down"] and any(a in ("-v", "--volumes") for a in args):
        yield Hit(
            detail="`compose down -v` deletes the named volumes, which is where the database actually lives",
            mitigation="back up the volume (`docker run --rm -v vol:/v -v $PWD:/b alpine tar czf /b/vol.tgz /v`) first",
            evidence=seg.text,
        )
    elif args[:2] == ["volume", "rm"]:
        yield Hit(
            detail="removing a named volume destroys its contents; nothing else references that data",
            mitigation="inspect it first (`docker volume inspect`) and copy the data out",
            evidence=seg.text,
        )


@rule("BR090", "code installed straight from a URL", "supply.install", "high",
      ("supply-chain",))
def r_supply(seg: Segment, ctx: Ctx):
    prog, args, _ = eff(seg)
    if prog in ("pip", "pip3", "uv", "poetry", "pipx") and args[:1] in (["install"], ["add"], ["run"]):
        bad = [a for a in args if re.match(r"^(git\+|https?://|file://)", a) or a in
               ("--index-url", "--extra-index-url", "--trusted-host")]
        if bad:
            yield Hit(
                detail=f"installs code from `{bad[0]}`, which runs its build hooks at install time",
                mitigation="pin a hash (`--require-hashes`) and install from the index your org trusts",
                evidence=seg.text,
            )
    if prog in ("npm", "yarn", "pnpm", "bun") and args[:1] in (["install"], ["i", "add"]):
        bad = [a for a in args if re.match(r"^(git\+|https?://|file:)", a)]
        if bad:
            yield Hit(
                detail=f"installs a package from `{bad[0]}`; its install scripts run on this machine",
                mitigation="prefer a registry version, and run `npm ci --ignore-scripts` when possible",
                evidence=seg.text,
            )
    if prog in ("gem", "cargo") and any(a.startswith(("git+", "http")) for a in args):
        yield Hit(
            detail="installs a package from a VCS/URL source rather than a signed registry",
            mitigation="pin a tagged release and verify the checksum",
            evidence=seg.text, severity="medium",
            title="package installed from a URL", capability="supply.install",
        )


# --------------------------------------------------------------------------
# obfuscation
# --------------------------------------------------------------------------
@rule("BR070", "obfuscated command", "opaque.code", "medium", ("evasion",))
def r_obfuscation(seg: Segment, ctx: Ctx):
    text = seg.text
    if "${IFS}" in text or "$IFS" in text:
        yield Hit(
            detail="`$IFS` hides word boundaries from naive pattern matching — a classic evasion trick",
            mitigation="treat an obfuscated command as untrusted; run it in a throwaway sandbox",
            evidence=seg.text,
        )
    if re.search(r"\beval\b", text) and "base64" in text and ("-d" in text or "--decode" in text):
        yield Hit(
            detail="decodes a hidden payload and evaluates it — what runs is not what you can read",
            mitigation="decode to a file, read it, then decide",
            evidence=seg.text, severity="critical",
            title="decoded payload executed", capability="opaque.code",
        )
        return
    if re.search(r"\beval\b", text) and ("$(" in text or "`" in text) and not BENIGN_PAYLOAD.search(text):
        yield Hit(
            detail="`eval` runs a string built at runtime; the visible command is not the executed one",
            mitigation="print the string first (`set -x`), then run the literal command",
            evidence=seg.text,
        )


@rule("BR099", "analysis incomplete", "opaque.code", "medium", ("meta",),
      "The command was too large or too malformed to analyse completely; the verdict is a lower bound.")
def _analysis_incomplete(seg: Segment, ctx: Ctx):
    return ()


# --------------------------------------------------------------------------
# cross-segment rules
# --------------------------------------------------------------------------
@cross("BR030", "remote content piped into a shell", "net.remote_exec", "critical",
       ("supply-chain", "irreversible"))
def c_fetch_exec(script: Script, ctx: Ctx):
    for pipe in script.pipelines:
        segs = pipe.segments
        for i, seg in enumerate(segs[:-1]):
            prog, _, _ = eff(seg)
            if prog not in FETCHERS:
                continue
            for nxt_seg in segs[i + 1:]:
                nxt, nargs, _ = eff(nxt_seg)
                if nxt in EXEC_SINKS:
                    yield Hit(
                        detail=f"`{prog} … | {nxt}` executes a remote document without review — the server can change it at any time",
                        mitigation="download to a file, read it, verify a published checksum, then run it",
                        evidence=f"{seg.text} | {nxt_seg.text}",
                    )
                    break
                if nxt in EXEC_SINKS or nxt in ("sudo", "doas", "tee", "cat", "dd", "sponge"):
                    continue  # shell reached via a pass-through filter
                break


@cross("BR038", "process substitution feeding a shell", "net.remote_exec", "critical")
def c_process_substitution(script: Script, ctx: Ctx):
    for seg in script.segments():
        prog, _, _ = eff(seg)
        if prog not in EXEC_SINKS:
            continue
        for r in seg.redirects:
            if not r.sub:
                continue
            inner = parse(r.sub, 1)
            for sub_seg in inner.segments():
                sprog, _, _ = eff(sub_seg)
                if sprog in FETCHERS or sprog in DECODERS:
                    yield Hit(
                        detail=f"`{seg.text.strip()[:40]}` reads its script from `<({r.sub.strip()[:60]})` — "
                               "the code is fetched and executed in one step",
                        mitigation="download to a file, read it, verify the checksum, then run it",
                        evidence=seg.text,
                    )
                    break


@cross("BR031", "decoded blob piped into a shell", "net.remote_exec", "critical")
def c_decode_exec(script: Script, ctx: Ctx):
    for pipe in script.pipelines:
        segs = pipe.segments
        for i, seg in enumerate(segs[:-1]):
            prog, args, _ = eff(seg)
            if prog not in DECODERS:
                continue
            if prog != "openssl" and not any(a in ("-d", "--decode", "-D", "-r") for a in args):
                continue
            if prog == "openssl" and "base64" not in args:
                continue
            for nxt_seg in segs[i + 1:]:
                nxt, _, _ = eff(nxt_seg)
                if nxt in EXEC_SINKS:
                    yield Hit(
                        detail="a base64/hex blob is decoded and executed: the real payload never appears in the clear",
                        mitigation="decode to a file, inspect it, then run it deliberately",
                        evidence=f"{seg.text} | {nxt_seg.text}",
                    )
                    break
                break


@cross("BR039", "local content piped into a shell", "opaque.code", "low")
def c_pipe_exec(script: Script, ctx: Ctx):
    for pipe in script.pipelines:
        segs = pipe.segments
        for i, seg in enumerate(segs[:-1]):
            prog, _, _ = eff(seg)
            if prog in FETCHERS or prog in DECODERS:
                continue  # covered by BR030 / BR031
            nxt, _, _ = eff(segs[i + 1])
            if nxt in EXEC_SINKS:
                yield Hit(
                    detail=f"`{seg.text.strip()[:50]} | {nxt}` runs generated text as a program",
                    mitigation="write the script to a file, read it, then execute the file",
                    evidence=f"{seg.text} | {segs[i + 1].text}",
                )


@cross("BR037", "downloaded file executed in a second step", "net.remote_exec", "high")
def c_fetch_then_run(script: Script, ctx: Ctx):
    fetched: dict[str, str] = {}
    for seg in script.segments():
        prog, args, _ = eff(seg)
        if prog in ("curl", "wget", "fetch"):
            for i, a in enumerate(args):
                if a in ("-o", "-O", "--output") and i + 1 < len(args):
                    fetched[args[i + 1]] = seg.text
                elif a.startswith("--output="):
                    fetched[a.split("=", 1)[1]] = seg.text
        elif prog in SHELLS:
            if any(a in fetched for a in args) or any(
                    a.endswith(".sh") and a in fetched for a in args):
                yield Hit(
                    detail="a file is downloaded and then executed in a separate step; the exec is easy to miss when auditing",
                    mitigation="pin the checksum of the downloaded file before executing it",
                    evidence=seg.text, severity="high",
                    title="downloaded script executed", capability="net.exec_download",
                )
    return


@cross("BR080", "credential read followed by network egress", "net.exfil", "critical",
       ("exfiltration", "irreversible"))
def c_exfil(script: Script, ctx: Ctx):
    for pipe in script.pipelines:
        seen_secret: str | None = None
        for seg in pipe.segments:
            prog, args, _ = eff(seg)
            if seen_secret is None:
                if prog in READERS and any(protected_by(t, ctx.protected)
                                           for t in positional(args)):
                    seen_secret = seg.text
                elif seg.program in ("env", "printenv", "set") and not seg.args:
                    seen_secret = seg.text
            if seen_secret and prog in NET_SEND:
                yield Hit(
                    detail=f"`{seen_secret.strip()}` is read and then sent to `{seg.text.strip()[:60]}` in the same pipeline",
                    mitigation="never pipe a credential into a network client; use the provider's own auth flow",
                    evidence=f"{seen_secret} | {seg.text}",
                )
                break
    # a network client that names a protected path is exfiltration on its own
    for seg in script.segments():
        prog, args, _ = eff(seg)
        if prog not in NET_SEND:
            continue
        for a in args:
            target = a.split("@", 1)[1] if a.startswith("@") or "=@" in a else a
            if protected_by(target, ctx.protected):
                yield Hit(
                    detail=f"`{seg.text.strip()[:80]}` uploads a protected file",
                    mitigation="remove the secret from the request; rotate it if this already ran",
                    evidence=seg.text,
                )
                break


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------
def _iter_scripts(script: Script, depth: int = 0) -> Iterator[Script]:
    yield script
    if depth >= 4:
        return
    for sub in script.subs:
        yield from _iter_scripts(sub, depth + 1)


PROGRAM_CAPS: dict[str, set[str]] = {
    "rm": {"fs.delete"}, "rmdir": {"fs.delete"}, "unlink": {"fs.delete"},
    "shred": {"fs.delete"}, "mv": {"fs.write"}, "cp": {"fs.read", "fs.write"},
    "tee": {"fs.write"}, "truncate": {"fs.write"}, "mkdir": {"fs.write"},
    "touch": {"fs.write"}, "install": {"fs.write"}, "ln": {"fs.write"},
    "cat": {"fs.read"}, "less": {"fs.read"}, "head": {"fs.read"},
    "tail": {"fs.read"}, "bat": {"fs.read"}, "strings": {"fs.read"},
    "chmod": {"priv.escalate"}, "chown": {"priv.escalate"}, "chgrp": {"priv.escalate"},
    "setcap": {"priv.escalate"}, "sudo": {"priv.escalate"}, "doas": {"priv.escalate"},
    "su": {"priv.escalate"}, "usermod": {"priv.escalate"},
    "curl": {"net.egress"}, "wget": {"net.egress"}, "scp": {"net.egress"},
    "rsync": {"net.egress"}, "sftp": {"net.egress"}, "nc": {"net.egress"},
    "ncat": {"net.egress"}, "socat": {"net.egress"}, "ssh": {"net.remote"},
    "docker": {"deploy.prod"}, "podman": {"deploy.prod"}, "kubectl": {"deploy.prod"},
    "helm": {"deploy.prod"}, "terraform": {"deploy.prod"}, "ansible": {"deploy.prod"},
    "npm": {"supply.install"}, "yarn": {"supply.install"}, "pip": {"supply.install"},
    "pip3": {"supply.install"}, "poetry": {"supply.install"}, "cargo": {"supply.install"},
    "systemctl": {"sys.service"}, "launchctl": {"sys.service"}, "service": {"sys.service"},
    "crontab": {"sys.persist"}, "at": {"sys.persist"},
    "kill": {"proc.kill"}, "pkill": {"proc.kill"}, "killall": {"proc.kill"},
    "shutdown": {"sys.power"}, "reboot": {"sys.power"}, "halt": {"sys.power"},
    "iptables": {"sys.firewall"}, "ufw": {"sys.firewall"}, "firewall-cmd": {"sys.firewall"},
    "git": {"git.destructive"}, "chattr": {"fs.write"}, "eval": {"opaque.code"},
}


def observed_capabilities(text: str, protected: list[str] | None = None) -> set[str]:
    """What the command *touches*, independent of whether it is dangerous.

    Policies need this: `deny capability fs.delete` must fire even for a command
    that raises no finding (`rm -rf node_modules`).
    """
    pats = protected or PROTECTED_DEFAULT
    caps: set[str] = set()
    script = parse(text)
    stack = [script]
    while stack:
        node = stack.pop()
        for seg in node.segments():
            prog, args, wrappers = eff(seg)
            caps |= PROGRAM_CAPS.get(prog, set())
            pos_args = [a for a in args if not a.startswith("-")]
            if prog == "dd":
                targets = [a[3:] for a in args if a.startswith("of=")]
                caps.add("fs.device_write" if any(
                    t.startswith("/dev/") and not t.startswith("/dev/null") for t in targets
                ) else "fs.write")
            elif prog in ("fdisk", "parted", "gdisk", "sgdisk", "wipefs", "mke2fs",
                          "blkdiscard", "cryptsetup") or prog.startswith("mkfs."):
                caps.add("fs.device_write" if any(a.startswith("/dev/") for a in pos_args)
                         else "fs.read")
            for w in wrappers:
                caps |= PROGRAM_CAPS.get(w, set())
            if prog in SHELLS and any(a in ("-c",) for a in args):
                caps.add("opaque.code")
            for r in seg.redirects:
                if r.writes:
                    caps.add("fs.write")
                if r.device_sink:
                    caps.add("fs.device_write")
                if protected_by(r.target, pats):
                    caps.add("cred.access")
            for a in args:
                if a.startswith("-"):
                    continue
                if protected_by(a, pats):
                    caps.add("cred.access")
                if a.startswith("/dev/") and DEVICE_RE.match(a):
                    caps.add("fs.device_write")
        stack.extend(node.subs)
    return caps


def all_capabilities(findings: Iterable[Finding]) -> list[str]:
    return sorted({f.capability for f in findings})


def analyze(text: str, *, cwd: str = ".", protected: list[str] | None = None) -> list[Finding]:
    script = parse(text)
    ctx = Ctx(cwd=cwd, protected=protected or PROTECTED_DEFAULT)
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def emit(rid: str, base: Rule, hit: Hit, seg_text: str) -> None:
        sev = hit.severity or base.severity
        cap = hit.capability or base.capability
        title = hit.title or base.title
        evidence = hit.evidence or seg_text
        key = (rid, evidence)
        if key in seen:
            return
        seen.add(key)
        out.append(Finding(
            rule_id=rid, title=title, capability=cap, severity=sev,
            detail=hit.detail, evidence=evidence, mitigation=hit.mitigation,
            weight=SEVERITY_WEIGHT.get(sev, 8), segment=seg_text, tags=base.tags,
        ))

    for node in _iter_scripts(script):
        for seg in node.segments():
            for r in RULES:
                try:
                    hits = r.fn(seg, ctx)
                except Exception:  # a broken rule must never break the run
                    continue
                for hit in hits or ():
                    emit(r.id, r, hit, seg.text)
        for r in CROSS_RULES:
            try:
                hits = r.fn(node, ctx)
            except Exception:
                continue
            for hit in hits or ():
                emit(r.id, r, hit, node.text)

    if any("truncated" in n for n in script.notes) and len(text) > 4096:
        # the tail of a truncated command is where the payload usually hides
        for extra in analyze(text[-4096:], cwd=cwd, protected=ctx.protected):
            if (extra.rule_id, extra.evidence) not in seen:
                seen.add((extra.rule_id, extra.evidence))
                out.append(extra)

    if script.notes:
        hard = any("truncated" in n or "cap reached" in n for n in script.notes)
        base = next((r for r in RULES if r.id == "BR099"), None)
        if base is not None:
            out.append(Finding(
                rule_id="BR099",
                title=base.title,
                capability="opaque.code",
                severity="high" if hard else "medium",
                detail="the analyser could not read the whole command (%s); treat this verdict as a lower bound"
                       % "; ".join(script.notes[:3]),
                evidence=text[:160],
                mitigation="split the command into smaller, reviewable pieces",
                weight=SEVERITY_WEIGHT["high" if hard else "medium"],
                segment=text[:160],
                tags=("meta",),
            ))
    # a truncated script must never look cleaner than it is
    out.sort(key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), f.rule_id))
    return out


def parse_errors(text: str) -> list[str]:
    return parse(text).notes


__all__ = ["Finding", "Hit", "Rule", "RULES", "CROSS_RULES", "analyze",
           "PROTECTED_DEFAULT", "SEVERITY_WEIGHT", "SEVERITY_ORDER",
           "match_glob", "protected_by", "classify_target"]
