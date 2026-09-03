"""Static checks for a policy before you trust it.

Loading a policy already guarantees valid structure and compilable rule regexes (an invalid one
is rejected, never silently skipped). Linting adds one more sound check: a deny rule must not be
dead. A deny rule is dead when an earlier allow rule with no command or path constraint already
permits every input of that action, so the deny can never fire and the dangerous thing it was
meant to stop slips through. `railward lint` reports these so a policy is proven, not hoped.
"""
from __future__ import annotations

from .policy import Policy


def _action_covers(allow_action: str, deny_action: str) -> bool:
    # Sound, conservative: an allow for "*" covers any action; an exact action match covers itself.
    return allow_action == "*" or allow_action == deny_action


def lint_policy(policy: Policy) -> list[str]:
    """Return a list of problem strings; empty means the policy is clean."""
    problems: list[str] = []
    rules = policy.rules
    for rule in rules:
        # The ``**/`` prefix broadens a pattern (see decide._glob). Broadening a deny is the point;
        # broadening an allow silently permits more than it reads, so it is reported.
        if rule.effect == "allow" and (rule.path or "").startswith("**/"):
            problems.append(
                f"allow rule {rule.id!r} uses the widening '**/' path prefix: it would permit the "
                f"pattern at every depth, which is broader than it reads; write the exact path")
    for j, deny in enumerate(rules):
        if deny.effect != "deny":
            continue
        for allow in rules[:j]:
            if allow.effect != "allow":
                continue
            unconstrained = allow.command is None and allow.path is None
            if unconstrained and _action_covers(allow.action, deny.action):
                problems.append(
                    f"deny rule {deny.id!r} is dead: earlier allow rule {allow.id!r} "
                    f"(action {allow.action!r}, no command or path constraint) already permits "
                    f"every input it would block"
                )
                break
    return problems
