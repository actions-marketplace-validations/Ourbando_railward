"""Declarative policy: an ordered list of rules, evaluated first-match-wins.

The default is fail-closed. A policy may only set ``default: deny`` or ``default: ask``;
``default: allow`` is rejected on load, so a policy can never silently permit everything.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

EFFECTS = ("allow", "deny", "ask")

# A single rule may not expand past this many concrete patterns. Brace alternation multiplies, so
# a policy typo like ten nested ten-way groups is 10^10 patterns and a hang, which is a fail-open.
# Rejected at LOAD, the same treatment the catastrophic-regex check gets in policy.py.
MAX_BRACE_EXPANSIONS = 512


@functools.lru_cache(maxsize=2048)
def expand_braces(pattern: str) -> tuple[str, ...]:
    """Expand ``{a,b}`` alternation into brace-free patterns, outermost group first, nesting-aware.

    fnmatch has no brace syntax, so without this a policy needs one rule per filename and the
    dangerous-path rules become dozens of near-duplicates nobody reads. Pure and total: an
    unbalanced brace is treated as a literal rather than raising, because a policy that fails to
    load is a gate that is not running.
    """
    start = pattern.find("{")
    if start == -1:
        return (pattern,)

    depth, end = 0, -1
    for i in range(start, len(pattern)):
        if pattern[i] == "{":
            depth += 1
        elif pattern[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return (pattern,)  # unbalanced: literal

    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in pattern[start + 1:end]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))

    prefix, suffix = pattern[:start], pattern[end + 1:]
    out: list[str] = []
    for part in parts:
        out.extend(expand_braces(prefix + part + suffix))
    return tuple(out)


# A group that contains an unbounded quantifier and is itself quantified, e.g. ``(a+)+`` or
# ``(.*)*``. This is the classic catastrophic-backtracking (ReDoS) shape: matching a crafted input
# can take exponential time, which would hang the gate. Such a regex is rejected at load, so a
# policy typo cannot turn the gate into a denial-of-service (a hang is a fail-open).
_CATASTROPHIC = re.compile(r"\([^()]*[+*}][^()]*\)[*+{]")


def _is_catastrophic_regex(pattern: str) -> bool:
    return _CATASTROPHIC.search(pattern) is not None


@dataclass(frozen=True)
class Rule:
    effect: str                 # allow | deny | ask
    action: str = "*"           # fnmatch glob on the request action (e.g. "bash", "write", "*")
    command: str | None = None  # regex (case-insensitive) matched against the command
    path: str | None = None     # fnmatch glob matched against the canonicalized path
    reason: str = ""
    id: str = ""
    # Precompiled at construction so an invalid regex is a loud load error, never a silent skip at
    # decision time (a skipped deny rule is a fail-open by typo).
    command_re: "re.Pattern[str] | None" = field(default=None, compare=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.effect not in EFFECTS:
            raise ValueError(f"bad effect {self.effect!r}, expected one of {EFFECTS}")
        if self.command is not None:
            try:
                compiled = re.compile(self.command, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"rule {self.id!r}: invalid command regex {self.command!r}: {exc}"
                ) from exc
            if _is_catastrophic_regex(self.command):
                raise ValueError(
                    f"rule {self.id!r}: command regex {self.command!r} can catastrophically "
                    f"backtrack (a quantified group over an unbounded quantifier); simplify it so "
                    f"the gate cannot be hung by a crafted command"
                )
            object.__setattr__(self, "command_re", compiled)
        if self.path is not None:
            # Brace alternation multiplies, so a nested typo can expand to millions of patterns and
            # hang the matcher. A hang is a fail-open, so the bound is checked at LOAD, the same
            # treatment the catastrophic-regex shape gets above.
            expansions = len(expand_braces(self.path))
            if expansions > MAX_BRACE_EXPANSIONS:
                raise ValueError(
                    f"rule {self.id!r}: path glob {self.path!r} expands to {expansions} patterns "
                    f"(limit {MAX_BRACE_EXPANSIONS}); split it into separate rules so matching "
                    f"stays bounded")


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default: str = "deny"       # fail-closed


def load_policy(source: str | Path, *, text: bool = False) -> Policy:
    """Load a policy from a YAML file (or, with ``text=True``, a YAML string)."""
    raw = str(source) if text else Path(source).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")

    default = data.get("default", "deny")
    if default not in ("deny", "ask"):
        raise ValueError("default must be 'deny' or 'ask' (allow-by-default is forbidden)")

    rules: list[Rule] = []
    for i, r in enumerate(data.get("rules") or []):
        if not isinstance(r, dict):
            raise ValueError("each rule must be a mapping")
        if "effect" not in r:
            raise ValueError(f"rule {i} is missing 'effect'")
        rules.append(
            Rule(
                effect=str(r["effect"]),
                action=str(r.get("action", "*")),
                command=None if r.get("command") is None else str(r["command"]),
                path=None if r.get("path") is None else str(r["path"]),
                reason=str(r.get("reason", "")),
                id=str(r.get("id", f"rule-{i}")),
            )
        )
    return Policy(rules=tuple(rules), default=default)
