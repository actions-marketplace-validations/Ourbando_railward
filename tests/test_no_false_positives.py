"""A gate nobody can work under gets turned off, so over-blocking is a real failure mode.

Every deny rule that names a BARE command (`whoami`, `host`, `ping`, `id`) is anchored to the
start of a fragment rather than matched anywhere in the string. Unanchored, `\\bid\\b` denies
`git commit -m "fix id bug"` and `\\bhost\\b` denies `psql --host=localhost`. Both bit for real
while writing these rules, which is why they are pinned here.

The anchor tolerates one leading environment assignment, so `FOO=1 whoami` is still caught: the
fix must not open a hole while closing the noise.
"""
import pytest

from railward import Gate

STRICT = "examples/strict.yaml"


@pytest.fixture(scope="module")
def gate():
    return Gate.from_policy(STRICT)


# Ordinary developer work the policy explicitly allows. If any of these stops being allowed, the
# gate has become something a person would disable.
ALLOWED = [
    "git status",
    "git log --oneline -5",
    "git diff",
    "git add -A",
    "git commit -m 'fix id bug'",          # `id` as an English word, not the `id` command
    "python -m pytest -q",
    "python -m pytest -k 'host'",          # `host` inside a test selector
    "python3 manage.py runserver",
    "npm run build",
    "npm test",
    "make test",
    "cargo build",
    "go test ./...",
    "ls -la",
    "cat README.md",
    "cat docs/id_mapping.md",
    "grep -rn TODO src/",
    "grep -rn hostname src/",              # `hostname` as a search term
    "grep secret-handling-notes README",   # the SEARCH PATTERN must not be read as a path
    "rg 'def main' .",
    "find . -name '*.py'",
    "head -20 data.csv",
    "tail -f app.log",
    "diff a.txt b.txt",
    "echo 'ping the api'",                 # `ping` inside a quoted string
    "node server.js",
    "tsc --noEmit",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_ordinary_developer_work_is_allowed(gate, command):
    verdict = gate.check("bash", command=command)
    assert verdict.allowed, f"over-blocked ordinary work: {command!r} -> {verdict.reason}"


# The same tokens as real commands. Anchoring must not have opened a hole.
BLOCKED = [
    "whoami",
    "id",
    "hostname",
    "host evil.example",
    "dig x.evil.example",
    "ping -c1 10.0.0.1",
    "nmap -sS 10.0.0.0/24",
    "netstat -tulpn",
    "reboot",
    "shutdown -h now",
    "nsenter -t 1 -m -u -i -n -p sh",
    "unshare -r -m sh",
    "useradd -o -u 0 backdoor",
    "pkexec /bin/sh",
    "xmrig -o pool.evil.example:3333 -u wallet",
    "stress-ng --cpu 0 --vm 8",
]


@pytest.mark.parametrize("command", BLOCKED)
def test_the_real_command_is_still_denied(gate, command):
    assert gate.check("bash", command=command).blocked, f"anchoring opened a hole: {command!r}"


@pytest.mark.parametrize("command", [
    "FOO=1 whoami",
    "DEBUG=true nmap -sS 10.0.0.0/24",
])
def test_an_environment_prefix_does_not_evade_the_anchor(gate, command):
    """`^cmd` alone would be trivially bypassed by prefixing an assignment."""
    assert gate.check("bash", command=command).blocked, f"env prefix evaded the anchor: {command!r}"


@pytest.mark.parametrize("command", [
    "echo hi; whoami",
    "ls && ping 10.0.0.1",
    "echo $(whoami)",
])
def test_the_anchor_still_applies_per_fragment(gate, command):
    """Anchoring is per FRAGMENT, so hiding the command after a separator does not help."""
    assert gate.check("bash", command=command).blocked, f"fragment anchoring failed: {command!r}"
