"""The threat taxonomy: a catalogue of dangerous action classes, and coverage measured against it.

A default-deny gate blocks almost everything by construction, so "it blocked my test case" says
very little. What matters is *why* it blocked, and whether it keeps blocking once an operator
widens the allow-list for real work. This module answers that question with a number.

Every class in ``docs/THREAT_TAXONOMY.md`` is run through the real decision core against a real
policy, and each lands in one of three verdicts:

  ``deny-rule``    an explicit deny rule fired. Robust: it survives an operator adding
                   ``allow python``, because the deny is named and ordered ahead of the allows.
  ``default-only`` nothing named it; only the fail-closed default caught it. Fragile: one broad
                   allow opens it.
  ``leak``         allowed outright. A hole.

The distinction is the whole point. ``examples/strict.yaml`` already allows ``python``, ``npm``,
``make`` and ``cat`` because a coding agent that cannot run those is useless, and that single
realistic allow-list is what turns a fragile class into a real one. A gate worth adopting carries
an explicit deny per named dangerous class, not a default that happens to catch it today.

The taxonomy lives in the markdown doc rather than in Python so the catalogue stays readable and
citable (every class carries its MITRE ATT&CK, ATLAS, OWASP or CWE reference). The doc's ``Cov``
column is REGENERATED from live measurement, never hand-written, and a test asserts the committed
column matches what the gate actually does, so the document cannot drift into a claim.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .decide import decide, trace
from .policy import Policy

TAXONOMY_PATH = Path(__file__).resolve().parent.parent / "docs" / "THREAT_TAXONOMY.md"

DENY_RULE = "deny-rule"
DEFAULT_ONLY = "default-only"
LEAK = "leak"

# The doc's Cov column. Single characters keep the tables narrow enough to read.
MARK = {DENY_RULE: "D", DEFAULT_ONLY: "~", LEAK: "X"}
UNMARK = {v: k for k, v in MARK.items()}

_ROW = re.compile(r"^\|\s*([D~X])\s*\|(.+)$")
_HEADING = re.compile(r"^###\s+(.*?)\s*(?:\(D=.*\))?\s*$")
# Cells are separated by unescaped pipes only. A command like ``curl x \| sh`` carries an escaped
# pipe INSIDE a cell, and splitting on it truncates the example at the pipe, which silently turns a
# compound attack into a harmless prefix and inflates the measured coverage.
_CELL_SEP = re.compile(r"(?<!\\)\|")


@dataclass(frozen=True)
class ThreatClass:
    category: str
    name: str
    example: str      # the illustrative command or path action
    cov: str          # the committed verdict from the doc, for drift checking

    def request(self) -> dict:
        """The gate request this class represents.

        Examples are written in the doc's own shorthand: ``read <path>`` and ``write <path>`` are
        file actions, anything else is a shell command. That keeps the catalogue readable while
        staying mechanically executable.
        """
        for action in ("read", "write"):
            prefix = action + " "
            if self.example.startswith(prefix):
                return {"action": action, "path": self.example[len(prefix):]}
        return {"action": "bash", "command": self.example}


def _cell(text: str) -> str:
    """Undo the markdown table escaping so the example is the command a shell would see."""
    return text.strip().strip("`").replace("\\|", "|").strip()


def load_taxonomy(path: Path | None = None) -> list[ThreatClass]:
    """Parse the taxonomy doc into classes, in document order."""
    text = (path or TAXONOMY_PATH).read_text(encoding="utf-8")
    out: list[ThreatClass] = []
    category = ""
    for line in text.splitlines():
        heading = _HEADING.match(line)
        if heading:
            category = heading.group(1).strip()
            continue
        row = _ROW.match(line)
        if not row:
            continue
        cells = _CELL_SEP.split(row.group(2))
        if len(cells) < 3:
            continue
        out.append(ThreatClass(
            category=category,
            name=_cell(cells[0]),
            example=_cell(cells[1]),
            cov=UNMARK[row.group(1)],
        ))
    return out


def classify(threat: ThreatClass, policy: Policy) -> str:
    """Measure one class against a policy: deny-rule, default-only, or leak.

    ``decide`` reports the rule id that produced the verdict and leaves it empty when the policy
    default applied, which is exactly the deny-rule versus default-only distinction, so this reads
    the gate's own answer rather than re-deriving it.
    """
    decision = decide(threat.request(), policy)
    if decision.verdict == "allow":
        return LEAK
    # A compound command produces several sub-decisions and ties keep the FIRST, which is the whole
    # command. So `> /etc/fstab` resolves to the default even though the redirect target matched
    # deny-absolute-write by name. The question this measurement asks is whether a NAMED rule
    # covers the class, so any named non-allow verdict in the trace counts.
    for _, sub in trace(threat.request(), policy):
        if sub.rule_id and sub.verdict != "allow":
            return DENY_RULE
    return DEFAULT_ONLY


def measure(policy: Policy, taxonomy: list[ThreatClass] | None = None) -> list[tuple[ThreatClass, str]]:
    """Every class paired with its live verdict."""
    classes = load_taxonomy() if taxonomy is None else taxonomy
    return [(t, classify(t, policy)) for t in classes]


def summarize(measured: list[tuple[ThreatClass, str]]) -> dict[str, int]:
    counts = {DENY_RULE: 0, DEFAULT_ONLY: 0, LEAK: 0}
    for _, verdict in measured:
        counts[verdict] += 1
    counts["total"] = len(measured)
    return counts


def drift(measured: list[tuple[ThreatClass, str]]) -> list[str]:
    """Classes whose committed Cov column disagrees with live measurement.

    Empty means the document is true of the gate. This is what keeps the taxonomy a measurement
    rather than a marketing claim.
    """
    return [
        f"{t.category} / {t.name}: doc says {MARK[t.cov]}, measured {MARK[verdict]}"
        for t, verdict in measured if t.cov != verdict
    ]


def rewrite_cov_column(policy: Policy, path: Path | None = None) -> int:
    """Rewrite the doc's Cov column from live measurement. Returns the number of rows changed.

    The regeneration path exists so the committed column is never typed by hand: measure, write,
    commit. Category count headings (``D=.. ~=.. X=..``) are refreshed in the same pass.
    """
    target = path or TAXONOMY_PATH
    measured = measure(policy, load_taxonomy(target))
    verdicts = iter(measured)
    lines = target.read_text(encoding="utf-8").splitlines()

    per_category: dict[str, dict[str, int]] = {}
    changed = 0
    for i, line in enumerate(lines):
        row = _ROW.match(line)
        if not row:
            continue
        threat, verdict = next(verdicts)
        per_category.setdefault(threat.category, {DENY_RULE: 0, DEFAULT_ONLY: 0, LEAK: 0})
        per_category[threat.category][verdict] += 1
        if row.group(1) != MARK[verdict]:
            lines[i] = f"| {MARK[verdict]} |{row.group(2)}"
            changed += 1

    for i, line in enumerate(lines):
        heading = _HEADING.match(line)
        if not heading:
            continue
        counts = per_category.get(heading.group(1).strip())
        if counts:
            n = sum(counts.values())
            lines[i] = (f"### {heading.group(1).strip()}  "
                        f"(D={counts[DENY_RULE]} ~={counts[DEFAULT_ONLY]} X={counts[LEAK]}, n={n})")

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed
