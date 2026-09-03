# Adapters: putting railward in front of any agent runtime

railward does not know what an agent is. It answers one question, purely and deterministically:
given this proposed action and this policy, allow, ask, or deny? An adapter is the small piece of
glue that asks the question at the right moment and honours the answer.

Every adapter is the same three steps.

1. **Find the moment before the action.** Almost every runtime has one: a pre-tool hook, a
   permission callback, a middleware, or just the line in your own loop where you are about to
   call `subprocess.run`.
2. **Translate the payload into a request.** `action` is the verb; `command` and `path` carry the
   detail. You do not have to filter the payload, because unknown keyword arguments are ignored.
3. **Honour the verdict.** `deny` refuses, `ask` goes to a human, `allow` proceeds. Treating `ask`
   as permission is the one mistake that undoes the whole thing.

```python
from railward import Gate

gate = Gate.from_policy("examples/strict.yaml")

verdict = gate.check(action="bash", command=proposed)
if verdict.blocked:
    return refuse(verdict.reason)
if verdict.needs_human:
    return ask_operator(verdict.reason)
run(proposed)
```

## What the gate guarantees, so your adapter does not have to

| Property | What it means for the adapter |
|---|---|
| Veto only | The gate never runs, writes, or fetches anything. Enforcement is yours; it cannot be bypassed by the gate itself doing something. |
| Pure and deterministic | Same request plus same policy gives the same verdict, always. No clock, network, filesystem, or global state. This is what makes the signed proof re-runnable by a third party. |
| Fail-closed | Malformed requests, unparseable commands, and unknown actions are refused. No input yields `allow` by accident. |
| Compound-aware | `echo hi \| sh` is decomposed and the most restrictive part wins, so you pass the whole command string, not a pre-split one. |

## The verdict object

```python
verdict.allowed       # True ONLY for an explicit allow
verdict.blocked       # deny
verdict.needs_human   # ask: dangerous but plausibly legitimate
verdict.by_default    # nothing NAMED this action; only the fail-closed default caught it
verdict.reason        # plain English, safe to show a user or log
verdict.rule_id       # which rule fired ("" when the default applied)
bool(verdict)         # truthy only when allowed, so `if not verdict:` reads correctly
```

Log `by_default`. A default-only block is real, but it is the first protection to vanish when
somebody widens the allow-list for real work, and it is the difference the coverage report
measures. See [THREAT_TAXONOMY.md](THREAT_TAXONOMY.md).

## Worked example: a generic pre-execution hook

This is the whole adapter for a runtime that calls a function before every shell command and
expects `None` to proceed or a string to refuse.

```python
from railward import Gate

_GATE = Gate.from_policy("policy.yaml")

def before_shell(command: str) -> str | None:
    verdict = _GATE.check(action="bash", command=command)
    if verdict.allowed:
        return None
    if verdict.needs_human and operator_approves(command, verdict.reason):
        return None
    return f"refused by policy [{verdict.rule_id or 'default'}]: {verdict.reason}"
```

## Worked example: file access

```python
def before_read(path: str) -> str | None:
    verdict = _GATE.check(action="read", path=path)
    return None if verdict.allowed else verdict.reason

def before_write(path: str) -> str | None:
    verdict = _GATE.check(action="write", path=path)
    return None if verdict.allowed else verdict.reason
```

## Shipped adapter: Claude Code

`railward/hook.py` is a working `PreToolUse` adapter and the reference implementation to copy.
It maps `Bash` to `action: bash`, `Read`/`Edit`/`Write` to `read`/`write` with a path, and turns a
non-allow verdict into the runtime's block response. Install it with `hooks/hooks.json`.

## Explaining a refusal

When someone asks why a command was refused, hand them the decomposition rather than a guess:

```python
for label, verdict in gate.explain(action="bash", command="echo hi | sh"):
    print(f"{verdict.verdict:5} {label}  [{verdict.rule_id or 'default'}]")
```

The CLI does the same thing: `railward explain --policy policy.yaml --command "echo hi | sh"`.

## Notes for adapter authors

- **Load the policy once.** A `Gate` is immutable and safe to share across threads. Reloading per
  call just adds file I/O to a hot path.
- **Pass the raw command string.** Do not split it, strip it, or normalize it first. The gate's
  decomposition is the security-relevant part, and a helpful pre-clean is how a payload gets past it.
- **Do not add a bypass.** An environment variable that turns the gate off is the first thing an
  attacker sets. If you need an escape hatch, make it a policy change, which is reviewable.
- **Prove your adapter.** Add your runtime's dangerous shapes to `railward/adversary.py`: one line
  each, and they become rows in the signed proof.
