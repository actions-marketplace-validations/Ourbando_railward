from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from railward import adversary, load_policy
from railward import log as plog

# The battery runs against the production-shaped policy, not the toy. A proof is only worth signing
# if it attests the policy people actually deploy: `examples/safe.yaml` is a teaching example with a
# deliberately tiny allow-list, so "safe.yaml blocked everything" would say more about the example
# than about the gate.
STRICT = "examples/strict.yaml"


def _results(policy_path):
    return adversary.run_attacks(load_policy(policy_path))


def test_strict_policy_blocks_every_attack():
    leaked = [r["attack"] for r in _results(STRICT) if r["leaked"]]
    assert leaked == [], f"unexpected leaks: {leaked}"


def test_every_attack_denies_rather_than_asks():
    """`ask` is not a block. An attack that only asked would ship a proof that overstates itself."""
    asked = [r["attack"] for r in _results(STRICT) if r["verdict"] != "deny"]
    assert asked == [], f"attacks that did not deny: {asked}"


# An UNKNOWN action type is the one thing only the default can catch: there is no rule to write
# for a category nobody has named yet, and refusing it is precisely the default's job.
DEFAULT_OWNED = {"unknown-action-network"}


def test_every_attack_is_blocked_by_a_named_rule():
    """Blocked by the fail-closed default is weaker than blocked by name: the default evaporates
    the moment an operator widens the allow-list, and the named rule does not."""
    unnamed = {r["attack"] for r in _results(STRICT) if not r["rule_id"]}
    assert unnamed == DEFAULT_OWNED, f"attacks caught only by the default: {unnamed - DEFAULT_OWNED}"


def test_attack_names_are_unique():
    """The proof is a hash chain of named rows; a duplicate would silently shadow one."""
    names = [a["name"] for a in adversary.ATTACKS]
    assert len(names) == len(set(names)), "duplicate attack names"


def test_safe_example_still_blocks_the_core_battery():
    """The toy policy is still held to the classes it was written to stop.

    It does not carry the newer named denies (agent poisoning, platform parity), which is exactly
    why a strict policy ships alongside it, so only the original core classes are asserted here.
    """
    core = {a["name"] for a in adversary.ATTACKS
            if a["name"].startswith(("bash-", "write-", "read-", "compound-"))}
    results = [r for r in _results("examples/safe.yaml") if r["attack"] in core]
    assert results, "core attack subset went missing"
    leaked = [r["attack"] for r in results if r["leaked"]]
    assert leaked == [], f"the toy policy leaked a core attack: {leaked}"


def test_holed_policy_leaks():
    results = adversary.run_attacks(load_policy("examples/holey.yaml"))
    assert any(r["leaked"] for r in results)


def test_proof_verifies_and_is_deterministic():
    key = Ed25519PrivateKey.generate()
    policy = load_policy(STRICT)
    p1 = adversary.build_proof(policy, key)
    p2 = adversary.build_proof(policy, key)
    assert p1["head"] == p2["head"]        # same attacks + probes -> same chain
    assert p1["leaked"] == 0
    assert p1["robustness_failed_open"] == 0
    ok, _ = plog.verify_proof(p1, key.public_key())
    assert ok


def test_holed_proof_reports_leaks():
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy("examples/holey.yaml"), key)
    assert proof["leaked"] > 0


def test_committed_reference_proof_is_current():
    """The shipped proof must attest the CURRENT battery, not a past one.

    This is a poka-yoke for a defect that already happened: the committed reference proof sat at
    an older battery while the live one had moved on, so the README told a reader to verify an
    attestation that no longer described the gate. Regenerate with:
        railward attack --policy examples/strict.yaml --key keys/demo.pem \
            --out examples/reference_proof.json
    """
    import json
    from pathlib import Path

    proof = json.loads(Path("examples/reference_proof.json").read_text(encoding="utf-8"))
    assert proof["total"] == len(adversary.ATTACKS), (
        f"reference proof attests {proof['total']} attacks but the battery has "
        f"{len(adversary.ATTACKS)}; regenerate it")
    assert proof["leaked"] == 0
    assert proof["kind"] == "railward-proof"

    names = {row["attack"] for row in proof["chain"] if "attack" in row}
    assert names == {a["name"] for a in adversary.ATTACKS}, "reference proof covers different attacks"


def test_committed_reference_proof_verifies_against_the_published_key():
    """A reader who does not trust us runs exactly this."""
    import json
    from pathlib import Path

    proof = json.loads(Path("examples/reference_proof.json").read_text(encoding="utf-8"))
    public_key = plog.load_public("examples/pubkey.pem")
    ok, message = plog.verify_proof(proof, public_key)
    assert ok, message
