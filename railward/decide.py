"""The gate: a pure decision function.

``decide(request, policy)`` returns a :class:`Decision`. It never touches the network or
filesystem and has no global state, so the same inputs always give the same output.

Design choices that matter for safety:

* Default-deny. If no rule matches, the policy default (deny or ask) applies.
* Fail-closed on bad input. A non-mapping request, a missing action, an oversized or
  unparseable command, or a non-string path is denied, not waved through.
* Evasion-resistant matching. Commands are tokenized and the argv[0] basename is used, so
  ``/bin/rm``, ``RM`` (case), extra whitespace, and ``a; rm -rf /`` style injection are all
  seen as the same ``rm``. Command regexes match case-insensitively. Paths are canonicalized
  (``.`` and ``..`` collapsed) before globbing, so ``work/../../etc`` cannot masquerade as an
  in-scope path.
* Compound-aware. A shell command is only as safe as its most dangerous part. The whole command,
  every top-level segment (split on ``| ; && || &``), every command- and process-substitution
  body (``$(...)``, ``<(...)``, ``>(...)`` and backticks, recursively), every output-redirection
  target (checked as a write) and every input-redirection target (checked as a read) are each
  evaluated, and the most restrictive verdict wins. An anchored allow (``^echo``) can no longer
  wave a payload through a pipe, and an allowed command cannot read a protected file through
  ``< secrets``. The whole command is always evaluated too, so a gap in decomposition can only
  miss an added deny, never open a hole.
"""
from __future__ import annotations

import fnmatch
import posixpath
import shlex
from dataclasses import dataclass
from types import MappingProxyType

from .policy import MAX_BRACE_EXPANSIONS, Policy, expand_braces  # noqa: F401

_MAX_COMMAND = 100_000  # bound the matching input
_SEVERITY = ("allow", "ask", "deny")  # index is severity; most restrictive (highest) wins

@dataclass(frozen=True)
class Decision:
    verdict: str    # allow | deny | ask
    reason: str
    rule_id: str    # "" when the policy default applied


def _normalized_command(command: str) -> str | None:
    """Return a normalized command string, or None if it cannot be parsed."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not argv:
        return ""
    head = posixpath.basename(argv[0]) or argv[0]
    return " ".join([head, *argv[1:]])


def _canonical_path(path: str) -> str:
    # Pure normalization, no filesystem access: collapses '.', '..', and duplicate slashes.
    return posixpath.normpath(path)


def _glob(pattern: str, value: str) -> bool:
    """fnmatch, plus one documented extension: a ``**/`` prefix means "at any depth, including none".

    Plain fnmatch has no notion of a path separator, so ``*`` already crosses ``/`` and ``*/X``
    matches ``a/X`` and ``/repo/X`` but NOT a bare ``X``. That gap matters: the dangerous file is
    usually named relative to the repo root (``CLAUDE.md``, ``.mcp.json``), and a rule written to
    catch it nested would sail straight past the top-level form. ``**/CLAUDE.md`` catches both.

    The extension only ever makes a pattern match MORE. On a deny rule that is strictly stronger.
    On an allow rule it would be strictly weaker, so ``railward lint`` reports an allow rule that
    uses it rather than leaving the widening silent.
    """
    for alt in expand_braces(pattern):
        if alt.startswith("**/"):
            tail = alt[3:]
            if fnmatch.fnmatchcase(value, tail) or fnmatch.fnmatchcase(value, "*/" + tail):
                return True
        elif fnmatch.fnmatchcase(value, alt):
            return True
    return False


def _segments(command: str) -> list[str]:
    """Split a command on top-level shell control operators (| || & && ; newline), respecting
    single and double quotes and backslash escapes, so an escaped or quoted operator is not a
    split point."""
    segs: list[str] = []
    buf: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if command[i:i + 2] in ("&&", "||"):
            segs.append("".join(buf))
            buf = []
            i += 2
            continue
        if c in (";", "|", "&", "\n"):
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def _substitutions(command: str) -> list[str]:
    """Return the bodies of command and process substitutions: ``$(...)``, ``<(...)``, ``>(...)``
    (all nested-aware) and backticks, each of which executes a command. Single-quoted regions are
    skipped (no expansion happens there); double-quoted regions are scanned, because substitutions
    do execute inside double quotes."""
    subs: list[str] = []
    i, n = 0, len(command)
    in_single = False
    while i < n:
        c = command[i]
        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "'":
            in_single = True
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if command[i:i + 2] in ("$(", "<(", ">("):  # command and process substitution
            depth, j = 1, i + 2
            start = j
            while j < n and depth:
                if command[j] == "(":
                    depth += 1
                elif command[j] == ")":
                    depth -= 1
                j += 1
            subs.append(command[start:j - 1])
            i = j
            continue
        if c == "`":
            j = command.find("`", i + 1)
            if j == -1:
                break
            subs.append(command[i + 1:j])
            i = j + 1
            continue
        i += 1
    return subs


def _redirect_targets(command: str) -> list[str]:
    """Return write targets introduced by output redirection (``>`` ``>>`` ``>|`` ``&>``),
    quote-aware. These are files the command writes, so they are checked against write rules."""
    targets: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == ">":
            j = i + 1
            while j < n and command[j] in (">", "|", "&"):
                j += 1
            while j < n and command[j] in (" ", "\t"):
                j += 1
            if j < n and command[j] == "(":  # >(cmd) is process substitution, handled elsewhere
                i = j + 1
                continue
            start = j
            while j < n and command[j] not in (" ", "\t", ";", "|", "&", "<", ">", "\n"):
                if command[j] in ("'", '"'):
                    qq = command[j]
                    j += 1
                    while j < n and command[j] != qq:
                        j += 1
                j += 1
            tgt = command[start:j].strip("'\"")
            if tgt:
                targets.append(tgt)
            i = j
            continue
        i += 1
    return targets


def _read_targets(command: str) -> list[str]:
    """Return files opened for reading via input redirection (``< file``), quote-aware. A heredoc
    (``<<``) delimiter and a process substitution (``<(...)``) are not files and are skipped; the
    latter is handled as a substitution. These targets are checked against read rules, so an
    allowed command cannot read a protected file through a redirection the path rules never saw."""
    targets: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "<":
            if command[i + 1:i + 2] in ("<", "("):  # heredoc or process substitution, not a file
                i += 2
                continue
            j = i + 1
            while j < n and command[j] in (" ", "\t"):
                j += 1
            start = j
            while j < n and command[j] not in (" ", "\t", ";", "|", "&", "<", ">", "\n"):
                if command[j] in ("'", '"'):
                    qq = command[j]
                    j += 1
                    while j < n and command[j] != qq:
                        j += 1
                j += 1
            tgt = command[start:j].strip("'\"")
            if tgt:
                targets.append(tgt)
            i = j
            continue
        i += 1
    return targets


# Commands whose job is to read a file and put its contents somewhere the agent can see them.
# Secret rules are path-based, but ``cat /etc/shadow`` carries no ``path`` field: it is a bash
# command whose ARGUMENT is the path, so without this extraction every path rule is bypassed by
# spelling the read as a shell command.
_READ_COMMANDS = frozenset({
    "cat", "head", "tail", "tac", "nl", "less", "more", "strings", "xxd", "od", "hexdump",
    "base64", "base32", "uuencode", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk",
    "cut", "column", "sort", "uniq", "wc", "file", "jq", "yq", "md5sum", "sha1sum", "sha256sum",
    "shasum", "openssl", "cp", "mv", "scp", "rsync", "tar", "zip", "gzip", "install",
    "sqlite3", "sqlite",
})

# Commands whose FIRST positional argument is a pattern or script, not a file. Treating it as a
# path would deny an innocent ``grep secret-handling-notes README`` on the search term alone, so
# the first positional is skipped for these.
_PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk"})


def _command_read_targets(fragment: str) -> list[str]:
    """File arguments of a known read-command, to be checked as reads.

    Deliberately over-inclusive on arguments and under-inclusive on commands. Every target here is
    an ADDITIONAL sub-decision and the final verdict is the most restrictive one, so a wrong guess
    can only add a deny that a path rule already justified, never remove one. A missed command is
    a missed protection, never a hole.
    """
    try:
        argv = shlex.split(fragment)
    except ValueError:
        return []
    if not argv:
        return []
    head = (posixpath.basename(argv[0]) or argv[0]).lower()
    if head not in _READ_COMMANDS:
        return []
    targets: list[str] = []
    skip_pattern = head in _PATTERN_FIRST
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        if skip_pattern:            # the search pattern or script, not a file
            skip_pattern = False
            continue
        targets.append(arg)
    return targets


# Interpreters that take a program as a command-line STRING. The string is code, so it is pushed
# back through the gate: `python -c "import os;os.system('rm -rf /')"` must not be safe merely
# because the dangerous token sits inside a quoted argument.
_INLINE_CODE_FLAGS = MappingProxyType({
    "python": ("-c",), "python2": ("-c",), "python3": ("-c",), "perl": ("-e", "-E"),
    "ruby": ("-e",), "node": ("-e", "--eval", "-p"), "deno": ("eval",), "bun": ("-e",),
    "php": ("-r",), "sh": ("-c",), "bash": ("-c",), "zsh": ("-c",), "dash": ("-c",),
    "ksh": ("-c",), "Rscript": ("-e",),
})

# Recursion bound. Inline code can nest (`sh -c "python -c '...'"`), and a crafted payload could
# nest arbitrarily; an unbounded walk is a hang, and a hang is a fail-open.
_MAX_FRAGMENT_DEPTH = 8


def _inline_code(fragment: str) -> list[str]:
    """Program strings passed to an interpreter via ``-c`` / ``-e`` / ``-r``."""
    try:
        argv = shlex.split(fragment)
    except ValueError:
        return []
    if not argv:
        return []
    head = posixpath.basename(argv[0]) or argv[0]
    flags = _INLINE_CODE_FLAGS.get(head) or _INLINE_CODE_FLAGS.get(head.lower())
    if not flags:
        return []
    out: list[str] = []
    for i, arg in enumerate(argv[1:], start=1):
        if arg in flags and i + 1 < len(argv):
            out.append(argv[i + 1])
    return out


def _fragments(command: str) -> list[str]:
    """Every independently-executable SHELL command string inside ``command``: top-level segments
    plus the bodies of every command substitution, recursively."""
    out: list[str] = []
    stack = [(command, 0)]
    seen: set[str] = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > _MAX_FRAGMENT_DEPTH:
            continue
        seen.add(cur)
        out.extend(_segments(cur))
        for nested in _substitutions(cur):
            stack.append((nested, depth + 1))
    return out


def _inline_fragments(command: str) -> list[str]:
    """Every interpreter inline-code string reachable from ``command``, recursively.

    Kept separate from ``_fragments`` because these are held to a DIFFERENT rule (see
    ``_evaluate``): an inline program is code, not a shell command, so the fail-closed default must
    not be applied to it. If it were, every ``python -c`` would deny on the default, since a Python
    expression matches no shell rule, and the gate would be unusable for ordinary work.
    """
    out: list[str] = []
    stack = [(command, 0)]
    seen: set[str] = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen or depth > _MAX_FRAGMENT_DEPTH:
            continue
        seen.add(cur)
        for code in _inline_code(cur):
            out.append(code)
            # Inline code can itself contain shell: `sh -c "curl x | sh"`. Walk into its segments,
            # substitutions and any further inline code so a nested payload is still reached.
            for nested in [code, *_segments(code), *_substitutions(code)]:
                stack.append((nested, depth + 1))
            out.extend(_segments(code))
        for nested in _segments(cur) + _substitutions(cur):
            if nested != cur:
                stack.append((nested, depth + 1))
    return out


def _match(action: str, normalized: str | None, command: str | None,
           canonical: str | None, policy: Policy) -> Decision:
    """The atomic rule loop: first match wins, else the fail-closed default."""
    for rule in policy.rules:
        if not _glob(rule.action, action):
            continue
        if rule.command is not None:
            if normalized is None or command is None:
                continue
            # Precompiled and validated at load, so it is never None here and never re-raises.
            rx = rule.command_re
            if not (rx.search(normalized) or rx.search(command)):
                continue
        if rule.path is not None:
            if canonical is None or not _glob(rule.path, canonical):
                continue
        return Decision(rule.effect, rule.reason or f"matched {rule.id}", rule.id)
    return Decision(policy.default, f"default-{policy.default}: no rule matched", "")


def _most_restrictive(decisions: list[Decision]) -> Decision:
    # max returns the first element on ties, and the whole-command decision is always first, so a
    # compound that resolves to the same severity keeps the whole command's rule attribution.
    return max(decisions, key=lambda d: _SEVERITY.index(d.verdict))


def _prepare(request: object) -> tuple[Decision | None, str, str | None, str | None]:
    """Shared front matter for decide/trace: validate the request. Returns an early fail-closed
    Decision (and empty rest) on malformed input, else (None, action, command, canonical)."""
    if not isinstance(request, dict):
        return Decision("deny", "malformed request: not a mapping", ""), "", None, None
    action = request.get("action")
    if not isinstance(action, str) or not action:
        return Decision("deny", "malformed request: missing action", ""), "", None, None
    command = request.get("command")
    if command is not None and (not isinstance(command, str) or len(command) > _MAX_COMMAND):
        return Decision("deny", "malformed command", ""), "", None, None
    path = request.get("path")
    if path is not None and not isinstance(path, str):
        return Decision("deny", "malformed path", ""), "", None, None
    canonical = _canonical_path(path) if path is not None else None
    return None, action, command, canonical


def _evaluate(action: str, command: str | None, canonical: str | None,
              policy: Policy) -> list[tuple[str, Decision]]:
    """Every labelled sub-decision that feeds the final verdict, in evaluation order. The whole
    command (with the request path), then each extra fragment as a command, then each output
    redirection as a write and each input redirection as a read."""
    if command is None:
        return [("action", _match(action, None, None, canonical, policy))]

    out: list[tuple[str, Decision]] = []
    seen: set[str] = set()
    read_args: list[str] = []
    for idx, frag in enumerate([command, *_fragments(command)]):
        if frag in seen:
            continue
        seen.add(frag)
        normalized = _normalized_command(frag)
        if normalized is None:
            return [("unparseable command", Decision("deny", "unparseable command", ""))]
        label = "command" if idx == 0 else "sub-command"
        frag_path = canonical if idx == 0 else None
        out.append((f"{label}: {frag}", _match(action, normalized, frag, frag_path, policy)))
        # Per fragment, so `pwd; cat /etc/shadow` is caught in the segment that reads.
        read_args.extend(_command_read_targets(frag))

    for tgt in _redirect_targets(command):
        out.append((f"writes: {tgt}", _match("write", None, None, _canonical_path(tgt), policy)))
    for tgt in _read_targets(command):
        out.append((f"reads: {tgt}", _match("read", None, None, _canonical_path(tgt), policy)))
    for tgt in dict.fromkeys(read_args):  # de-duplicated, order preserved for a stable trace
        out.append((f"reads: {tgt}", _match("read", None, None, _canonical_path(tgt), policy)))

    # Interpreter inline code, deny-only. A NAMED rule matching the program string counts, so
    # `python -c "import os;os.system('rm -rf /')"` is denied by the same rule that names `rm`.
    # No match contributes nothing, so an ordinary one-liner falls through to whatever the policy
    # says about running an interpreter at all (in strict.yaml: ask). This preserves the invariant
    # that decomposition can only ADD a deny, never open a hole, and it is why the semantic
    # ceiling is honest: `python -c "shutil.rmtree('/')"` names nothing, so it asks, not denies.
    for code in dict.fromkeys(_inline_fragments(command)):
        normalized = _normalized_command(code)
        if normalized is None:
            continue
        decision = _match(action, normalized, code, None, policy)
        if decision.rule_id and decision.verdict != "allow":
            out.append((f"inline code: {code}", decision))
    return out


def decide(request: object, policy: Policy) -> Decision:
    early, action, command, canonical = _prepare(request)
    if early is not None:
        return early
    return _most_restrictive([d for _, d in _evaluate(action, command, canonical, policy)])


def trace(request: object, policy: Policy) -> list[tuple[str, Decision]]:
    """The labelled sub-decisions behind ``decide``, for ``railward explain``. The final verdict is
    the most restrictive of these."""
    early, action, command, canonical = _prepare(request)
    if early is not None:
        return [("request", early)]
    return _evaluate(action, command, canonical, policy)
