"""Hash-chained decision log and its Ed25519 anchor.

Each record carries the hash of the previous one, so any edit to an earlier record breaks
every hash after it. The head hash is signed. Verification recomputes the whole chain and
checks the signature against a *pinned* public key supplied by the caller, never a key
carried inside the log itself.
"""
from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _record_hash(record: dict, prev: str) -> str:
    body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
    return hashlib.sha256(canonical(body) + prev.encode()).hexdigest()


def build_chain(entries: list[dict]) -> list[dict]:
    """Turn a list of entries into a hash-chained list of records."""
    chain: list[dict] = []
    prev = ""
    for i, entry in enumerate(entries):
        record = {"seq": i, "prev": prev, **entry}
        record["hash"] = _record_hash(record, prev)
        chain.append(record)
        prev = record["hash"]
    return chain


def head_hash(chain: list[dict]) -> str:
    return chain[-1]["hash"] if chain else ""


def sign_head(chain: list[dict], private_key: Ed25519PrivateKey) -> str:
    return private_key.sign(head_hash(chain).encode()).hex()


def _chain_intact(chain: list[dict]) -> tuple[bool, str, str]:
    prev = ""
    for i, record in enumerate(chain):
        if record.get("seq") != i:
            return False, f"chain order broken at index {i}", ""
        if record.get("prev") != prev:
            return False, f"chain link broken at seq {i}", ""
        if record.get("hash") != _record_hash(record, prev):
            return False, f"hash mismatch at seq {i} (record was altered)", ""
        prev = record["hash"]
    return True, "ok", prev


def verify_chain(
    chain: list[dict], signature_hex: str, public_key: Ed25519PublicKey
) -> tuple[bool, str]:
    ok, message, head = _chain_intact(chain)
    if not ok:
        return False, message
    try:
        public_key.verify(bytes.fromhex(signature_hex), head.encode())
    except Exception:
        return False, "signature does not verify against the pinned key"
    return True, "ok"


# The top-level claims a reader might quote without recomputing the chain. From proof
# version 3 these are what the signature covers (the head pins every record, so the chain
# is still covered through it).
SUMMARY_KEYS = ("version", "kind", "total", "leaked", "robustness_total",
                "robustness_failed_open", "head")


def proof_summary(proof: dict) -> dict:
    return {k: proof[k] for k in SUMMARY_KEYS if k in proof}


def sign_proof(proof: dict, private_key: Ed25519PrivateKey) -> str:
    return private_key.sign(canonical(proof_summary(proof))).hex()


def verify_proof(proof: dict, public_key: Ed25519PublicKey) -> tuple[bool, str]:
    """Verify a whole proof document: chain integrity, summary honesty, signature.

    The summary cross-check runs on every version. A version 2 proof signs only the head,
    so its top-level counters sit outside the signature; a counter that disagrees with the
    signed records is a forgery either way, and fails here instead of reading as green.
    """
    chain = proof.get("chain") or []
    ok, message, head = _chain_intact(chain)
    if not ok:
        return False, message
    recomputed = {
        "total": sum(1 for r in chain if "attack" in r),
        "leaked": sum(1 for r in chain if r.get("leaked")),
        "robustness_total": sum(1 for r in chain if "probe" in r),
        "robustness_failed_open": sum(1 for r in chain if r.get("failed_open")),
        "head": head,
    }
    for key, value in recomputed.items():
        if key in proof and proof[key] != value:
            return False, (f"summary claims {key} = {proof[key]!r} but the signed records "
                           f"say {value!r} (summary was edited)")
    signed = canonical(proof_summary(proof)) if proof.get("version", 0) >= 3 else head.encode()
    try:
        public_key.verify(bytes.fromhex(proof["sig"]), signed)
    except Exception:
        return False, "signature does not verify against the pinned key"
    return True, "ok"


def new_key(private_path: str) -> Ed25519PrivateKey:
    """Generate a keypair, write the private PEM to ``private_path`` and the public PEM
    beside it (``.pub``). Returns the private key."""
    os.makedirs(os.path.dirname(private_path) or ".", exist_ok=True)
    key = Ed25519PrivateKey.generate()
    with open(private_path, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(os.path.splitext(private_path)[0] + ".pub", "wb") as fh:
        fh.write(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key


def load_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def load_public(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_public_key(fh.read())
