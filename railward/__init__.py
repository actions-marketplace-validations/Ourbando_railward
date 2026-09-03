"""railward: a deterministic gate for untrusted agents.

The agent proposes actions; a pure, fail-closed function decides allow / deny / ask;
every decision can be signed into a hash-chained log. The repo also ships an adversary
that attacks the gate and a re-runnable, signed proof of the outcome.

Nothing here trusts the caller: unknown or malformed requests are denied.
"""
from .api import Gate, Verdict
from .decide import Decision, decide
from .policy import Policy, Rule, load_policy

__all__ = ["Gate", "Verdict", "decide", "Decision", "Policy", "Rule", "load_policy"]
__version__ = "0.3.0"
