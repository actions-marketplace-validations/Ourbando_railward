"""The stable integration surface: decide before you run, from any agent runtime.

Everything else in this package is free to change shape. This module is the contract, and it is
deliberately tiny, because the whole adoption story is "wrap the place where your agent is about to
act, in about five lines, without learning how the gate works internally".

    from railward import Gate

    gate = Gate.from_policy("examples/strict.yaml")

    verdict = gate.check(action="bash", command=proposed_command)
    if verdict.blocked:
        return refuse(verdict.reason)
    if verdict.needs_human:
        return ask_the_operator(verdict.reason)
    run(proposed_command)

Three properties an adapter can rely on:

* **Veto only.** A Gate never runs, edits, or fetches anything. It answers, and the caller enforces.
  Nothing here can turn a refusal into an action.
* **Pure and deterministic.** The same request and policy always give the same verdict, with no
  clock, network, filesystem, or global state involved. That is what makes the signed proof
  re-runnable by someone who does not trust you.
* **Fail-closed.** A malformed request, an unparseable command, or an unrecognized action is
  refused. There is no input that produces "allow" by accident.

Writing an adapter for a new runtime is the same three steps every time: find the hook the runtime
calls before it acts, translate its payload into ``action`` / ``command`` / ``path``, and map the
verdict back onto whatever the runtime uses for "no". See ``ADAPTERS.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .decide import Decision, decide, trace
from .policy import Policy, load_policy


@dataclass(frozen=True)
class Verdict:
    """What the gate decided, in terms an adapter can branch on without knowing the internals."""

    verdict: str        # "allow" | "ask" | "deny"
    reason: str         # plain-English, safe to show a user or write to a log
    rule_id: str        # the rule that fired; "" when the fail-closed default applied

    @property
    def allowed(self) -> bool:
        """True only for an explicit allow. `ask` is NOT allowed."""
        return self.verdict == "allow"

    @property
    def blocked(self) -> bool:
        return self.verdict == "deny"

    @property
    def needs_human(self) -> bool:
        """The action is dangerous but plausibly legitimate: surface it, do not run it."""
        return self.verdict == "ask"

    @property
    def by_default(self) -> bool:
        """True when nothing named this action and only the fail-closed default caught it.

        Worth surfacing in a log: a default-only block is real but fragile, and it is the first
        thing to disappear when someone widens the allow-list.
        """
        return not self.rule_id

    def __bool__(self) -> bool:
        """So `if not gate.check(...)` reads correctly. Only an explicit allow is truthy."""
        return self.allowed


class Gate:
    """A loaded policy plus the decision function. Immutable and safe to share across threads."""

    __slots__ = ("_policy",)

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @classmethod
    def from_policy(cls, path: str | Path) -> "Gate":
        """Load from a YAML policy file."""
        return cls(load_policy(path))

    @classmethod
    def from_text(cls, yaml_text: str) -> "Gate":
        """Load from a YAML string, for adapters that ship their policy inline."""
        return cls(load_policy(yaml_text, text=True))

    @property
    def policy(self) -> Policy:
        return self._policy

    def check(self, action: str, *, command: str | None = None,
              path: str | None = None, **extra: object) -> Verdict:
        """Decide a single proposed action.

        ``action`` is the verb the runtime is about to perform ("bash", "read", "write", or any
        name your policy uses). Supply ``command`` for shell execution and ``path`` for file
        access; a runtime may pass both. Unknown keyword arguments are accepted and ignored, so a
        runtime can hand over its whole payload without the adapter having to filter it, and adding
        a field to that payload can never turn into a crash at the gate.
        """
        request: dict = {"action": action}
        if command is not None:
            request["command"] = command
        if path is not None:
            request["path"] = path
        return self._verdict(decide(request, self._policy))

    def check_request(self, request: object) -> Verdict:
        """Decide a raw request mapping, for adapters that already speak the request shape.

        Fail-closed on anything that is not a well-formed request, including ``None``, a list, or
        a mapping with no action.
        """
        return self._verdict(decide(request, self._policy))

    def explain(self, action: str, *, command: str | None = None,
                path: str | None = None) -> list[tuple[str, Verdict]]:
        """Every labelled sub-decision behind a verdict, for logs and incident review.

        A compound command is evaluated in pieces and the most restrictive piece wins, so this is
        what answers "which part of that one-liner was the problem".
        """
        request: dict = {"action": action}
        if command is not None:
            request["command"] = command
        if path is not None:
            request["path"] = path
        return [(label, self._verdict(d)) for label, d in trace(request, self._policy)]

    @staticmethod
    def _verdict(decision: Decision) -> Verdict:
        return Verdict(decision.verdict, decision.reason, decision.rule_id)
