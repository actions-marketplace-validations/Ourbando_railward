"""Command line: ``railward check | lint | attack | verify``."""
from __future__ import annotations

import argparse
import importlib.resources
import json
import os
import sys

from . import adversary
from . import art as _art
from . import lint as _lint
from . import log as plog
from .decide import decide, trace
from .policy import load_policy

# A deliberately holed policy for `railward ctf`, embedded so the game works from an installed
# package too (no repo files needed). It allows `rm`, so several attacks leak through it.
_CTF_POLICY = """
default: deny
rules:
  - {id: oops-allow-rm, effect: allow, action: bash, command: 'rm'}
  - {id: block-force-push, effect: deny, action: bash, command: 'git\\s+push\\b.*--force'}
  - {id: protect-secrets, effect: deny, action: '*', path: '*secret*'}
"""

_MARK = {"allow": "+", "ask": "?", "deny": "x"}


def _load_policy_arg(policy_arg: str | None):
    """No --policy means the strict policy shipped inside the package, so the command works
    from any directory, installed or checked out."""
    if policy_arg is None:
        text = importlib.resources.files("railward").joinpath(
            "policies/strict.yaml").read_text(encoding="utf-8")
        return load_policy(text, text=True)
    return load_policy(policy_arg)


def _request_from_args(args: argparse.Namespace) -> dict:
    if getattr(args, "command", None) is not None:
        return {"action": "bash", "command": args.command}
    return json.loads(args.action)


def cmd_explain(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    request = _request_from_args(args)
    final = decide(request, policy)
    print(f"verdict: {final.verdict}  ({final.reason})")
    print("because the most restrictive of:")
    for label, d in trace(request, policy):
        rule = f"[{d.rule_id}]" if d.rule_id else "[default]"
        print(f"  {_MARK.get(d.verdict, '?')} {d.verdict:5} {label}  {rule}")
    return 0 if final.verdict == "allow" else 1


def cmd_ctf(args: argparse.Namespace) -> int:
    policy = load_policy(_CTF_POLICY, text=True)
    results = adversary.run_attacks(policy)
    leaked = {r["attack"] for r in results if r["leaked"]}
    if args.list:
        for r in results:
            print(r["attack"])
        return 0
    if args.guess:
        if args.guess not in {r["attack"] for r in results}:
            print(f"no attack named {args.guess!r}. list them with: railward ctf --list")
            return 2
        if args.guess in leaked:
            print(f"HIT: {args.guess} leaks through the holed policy. You found a hole.")
            return 0
        print(f"MISS: {args.guess} is blocked. Keep looking.")
        return 1
    print(f"CTF: this holed policy lets {len(leaked)} of {len(results)} attacks through.")
    print("Find one:  railward ctf --guess <attack-name>")
    print("List them: railward ctf --list")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    request = json.loads(args.action)
    decision = decide(request, policy)
    print(f"{decision.verdict}: {decision.reason}", file=sys.stderr)
    return 0 if decision.verdict == "allow" else 1


def cmd_attack(args: argparse.Namespace) -> int:
    policy = _load_policy_arg(args.policy)
    if args.key and os.path.exists(args.key):
        key = plog.load_private(args.key)
    else:
        key = plog.new_key(args.key)
    proof = adversary.build_proof(policy, key)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True)
    blocked = proof["total"] - proof["leaked"]
    open_probes = proof["robustness_failed_open"]
    print(
        f"{proof['total']} attacks, {blocked} blocked, {proof['leaked']} leaked; "
        f"{proof['robustness_total']} fail-open probes, {open_probes} open -> {args.out}"
    )
    # The living portcullis: a picture of the proof, drawn only for a human at a terminal so the
    # one-line summary stays machine-parseable when piped.
    if _art.color_enabled(sys.stdout) and os.environ.get("RAILWARD_NO_ART") is None:
        print(_art.portcullis(proof["total"], proof["leaked"]), file=sys.stderr)
    return 1 if (proof["leaked"] or open_probes) else 0


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.proof, encoding="utf-8") as fh:
        proof = json.load(fh)
    public_key = plog.load_public(args.pubkey)
    ok, message = plog.verify_proof(proof, public_key)
    if not ok:
        print(f"FAIL: {message}")
        return 2
    leaked = sum(1 for r in proof["chain"] if r.get("leaked"))
    failed_open = sum(1 for r in proof["chain"] if r.get("failed_open"))
    if leaked or failed_open:
        print(f"FAIL: signed and chain intact, but {leaked} attack(s) leaked, "
              f"{failed_open} fail-open probe(s) open")
        return 1
    attacks = sum(1 for r in proof["chain"] if "attack" in r)
    probes = sum(1 for r in proof["chain"] if "probe" in r)
    print(f"OK: {attacks} attacks + {probes} fail-open probes, chain intact, "
          f"signature valid, 0 leaked, 0 fail-open")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except Exception as exc:  # noqa: BLE001 - any load failure is an invalid policy
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    problems = _lint.lint_policy(policy)
    if problems:
        print(f"LINT FAILED: {len(problems)} problem(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"lint clean: {len(policy.rules)} rules, default {policy.default}")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """Measure the policy against the threat taxonomy, per category.

    The headline number is not "how much did it block" (a default-deny gate blocks nearly
    everything) but how much it blocks BY NAME, which is what survives an operator widening the
    allow-list.
    """
    from . import taxonomy as tax

    try:
        policy = _load_policy_arg(args.policy)
    except Exception as exc:  # noqa: BLE001 - any load failure is an invalid policy
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2

    if args.update:
        changed = tax.rewrite_cov_column(policy)
        print(f"taxonomy Cov column regenerated: {changed} row(s) changed")
        return 0

    measured = tax.measure(policy)
    if args.leaks:
        for threat, verdict in measured:
            if verdict == tax.LEAK:
                print(f"{tax.MARK[verdict]}  {threat.category} / {threat.name}: {threat.example}")

    by_category: dict[str, dict[str, int]] = {}
    for threat, verdict in measured:
        row = by_category.setdefault(threat.category, {tax.DENY_RULE: 0, tax.DEFAULT_ONLY: 0, tax.LEAK: 0})
        row[verdict] += 1
    width = max(len(c) for c in by_category)
    for category, row in by_category.items():
        print(f"  {category.ljust(width)}  D={row[tax.DENY_RULE]:<4} "
              f"~={row[tax.DEFAULT_ONLY]:<4} X={row[tax.LEAK]}")

    counts = tax.summarize(measured)
    print(f"\n{counts['total']} classes: {counts[tax.DENY_RULE]} deny-rule, "
          f"{counts[tax.DEFAULT_ONLY]} default-only, {counts[tax.LEAK]} leak")
    problems = tax.drift(measured)
    if problems:
        # A doc that disagrees with the gate is an error in every context, so it always exits
        # nonzero. A leak is a finding, not an error: the taxonomy names two classes a
        # path-and-token gate cannot decide, so `--fail-on-leak` is opt-in for CI that wants zero.
        print(f"DOC DRIFT: {len(problems)} row(s) disagree with live measurement "
              f"(regenerate with --update)", file=sys.stderr)
        for p in problems[:10]:
            print(f"  - {p}", file=sys.stderr)
        return 2
    return 1 if (args.fail_on_leak and counts[tax.LEAK]) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="railward",
        description="a deterministic gate that ships with its own adversary and a re-runnable proof",
    )
    sub = parser.add_subparsers(dest="cmd")

    check = sub.add_parser("check", help="decide a single action (JSON) against a policy")
    check.add_argument("--policy", required=True)
    check.add_argument("--action", required=True, help='JSON, e.g. \'{"action":"bash","command":"ls"}\'')
    check.set_defaults(fn=cmd_check)

    lint = sub.add_parser("lint", help="statically check a policy loads and has no dead deny rule")
    lint.add_argument("--policy", required=True)
    lint.set_defaults(fn=cmd_lint)

    attack = sub.add_parser("attack", help="run the adversary and write a signed proof")
    attack.add_argument("--policy", default=None,
                        help="policy YAML (default: the strict policy shipped in the package)")
    attack.add_argument("--key", default="keys/demo.pem", help="signing key (generated if missing)")
    attack.add_argument("--out", default="proof.json")
    attack.set_defaults(fn=cmd_attack)

    verify = sub.add_parser("verify", help="verify a proof against a pinned public key")
    verify.add_argument("proof")
    verify.add_argument("--pubkey", default="examples/pubkey.pem")
    verify.set_defaults(fn=cmd_verify)

    explain = sub.add_parser("explain", help="show why a command is allowed, denied, or asked")
    explain.add_argument("--policy", required=True)
    explain.add_argument("--command", help="a shell command to explain")
    explain.add_argument("--action", help='or a full request JSON, e.g. \'{"action":"read","path":"x"}\'')
    explain.set_defaults(fn=cmd_explain)

    coverage = sub.add_parser(
        "coverage", help="measure a policy against the threat taxonomy (deny-rule / default-only / leak)")
    coverage.add_argument("--policy", default=None,
                          help="policy YAML (default: the strict policy shipped in the package)")
    coverage.add_argument("--leaks", action="store_true", help="list every leaking class")
    coverage.add_argument("--update", action="store_true",
                          help="regenerate the taxonomy doc's Cov column from live measurement")
    coverage.add_argument("--fail-on-leak", action="store_true",
                          help="exit 1 if any class leaks (doc drift always exits 2)")
    coverage.set_defaults(fn=cmd_coverage)

    ctf = sub.add_parser("ctf", help="a game: find an attack that slips through a holed policy")
    ctf.add_argument("--list", action="store_true", help="list the attack names")
    ctf.add_argument("--guess", help="name the attack you think leaks")
    ctf.set_defaults(fn=cmd_ctf)

    args = parser.parse_args(argv)
    if args.cmd is None:  # bare `railward`: show usage
        parser.print_help()
        return 0
    try:
        return args.fn(args)
    except FileNotFoundError as exc:
        # A missing input is an operator mistake, not a crash: name it and fail closed.
        print(f"error: no such file: {exc.filename or exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
