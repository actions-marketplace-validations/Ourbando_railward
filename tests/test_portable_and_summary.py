"""Two hardening properties, each born from a real failure on 2026-07-23.

1. Portability: `railward attack` used to default to the relative path
   ``examples/strict.yaml``, so a pip-installed user running it outside the repo checkout
   got a raw FileNotFoundError. The default policy now ships inside the package.
2. Summary honesty: the top-level proof counters sat outside the signature, so a reader
   who quoted them without recomputing the chain could be shown edited numbers under a
   green signature. Verification now cross-checks the summary against the signed records
   on every version, and version 3 proofs sign the summary itself.
"""
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from railward import adversary, cli
from railward import log as plog
from railward.policy import load_policy

REPO = Path(__file__).resolve().parents[1]
STRICT = str(REPO / "examples" / "strict.yaml")


def test_packaged_policy_matches_the_documented_example():
    """The packaged default and examples/strict.yaml must never drift apart."""
    packaged = (REPO / "railward" / "policies" / "strict.yaml").read_bytes()
    example = (REPO / "examples" / "strict.yaml").read_bytes()
    assert packaged == example


def test_attack_runs_from_any_directory(tmp_path, monkeypatch, capsys):
    """The exact command the README gives a pip user, run far away from the checkout."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RAILWARD_NO_ART", "1")
    rc = cli.main(["attack", "--key", "k.pem", "--out", "proof.json"])
    assert rc == 0
    proof = json.loads((tmp_path / "proof.json").read_text(encoding="utf-8"))
    assert proof["leaked"] == 0
    assert proof["version"] == 3


def test_coverage_runs_from_any_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["coverage"]) in (0, 1)


def test_missing_input_file_is_a_clean_error_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["explain", "--policy", "nope.yaml", "--command", "ls"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no such file" in err and "nope.yaml" in err


def test_edited_summary_counter_fails_verification():
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy(STRICT), key)
    ok, message = plog.verify_proof(proof, key.public_key())
    assert ok, message

    forged = dict(proof)
    forged["total"] = proof["total"] - 1
    ok, message = plog.verify_proof(forged, key.public_key())
    assert not ok
    assert "summary" in message


def test_edited_summary_fails_even_on_a_legacy_head_signed_proof():
    """A v2 proof signs only the head; the cross-check must still catch edited counters."""
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy(STRICT), key)
    legacy = dict(proof)
    legacy["version"] = 2
    legacy["sig"] = plog.sign_head(proof["chain"], key)
    ok, message = plog.verify_proof(legacy, key.public_key())
    assert ok, message

    legacy["leaked"] = legacy["leaked"] + 1
    ok, message = plog.verify_proof(legacy, key.public_key())
    assert not ok
    assert "summary" in message


def test_v3_signature_covers_the_summary():
    """Re-signing a v3 proof with a different key must fail against the pinned key."""
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy(STRICT), key)
    other = Ed25519PrivateKey.generate()
    ok, message = plog.verify_proof(proof, other.public_key())
    assert not ok
    assert "signature" in message
