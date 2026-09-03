#!/usr/bin/env python3
"""Bind the public README badges to measured reality; red on drift.

No import from any private system: the counts come from this repo's own suite and adversary, so
the public numbers can never overclaim. The tests badge may understate (adding tests is fine) but
never overstate; the proof badge must match the measured attacks-blocked exactly. Wired into CI.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def measured_tests() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return sum(1 for line in out.stdout.splitlines() if "::" in line)


def measured_attacks() -> tuple[int, int]:
    sys.path.insert(0, str(ROOT))
    from railward import adversary, load_policy

    results = adversary.run_attacks(load_policy(str(ROOT / "examples" / "strict.yaml")))
    blocked = sum(1 for r in results if not r["leaked"])
    return len(results), blocked


def main() -> int:
    readme = (ROOT / "README.md").read_text()
    tests = measured_tests()
    total, blocked = measured_attacks()
    problems: list[str] = []

    m = re.search(r"tests-(\d+)%20passing", readme)
    if not m:
        problems.append("tests badge not found in README")
    elif int(m.group(1)) > tests:
        problems.append(f"tests badge claims {m.group(1)} but only {tests} are measured (overclaim)")

    m = re.search(r"proof-(\d+)%2F(\d+)%20blocked", readme)
    if not m:
        problems.append("proof badge not found in README")
    elif (int(m.group(1)), int(m.group(2))) != (blocked, total):
        problems.append(
            f"proof badge claims {m.group(1)}/{m.group(2)} but measured {blocked}/{total} blocked"
        )

    if problems:
        print("CLAIMS DRIFT (README overclaims the code):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"claims bound: {tests} tests, {blocked}/{total} attacks blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
