"""Signed-checkpoint audit anchoring (review P1: tamper-EVIDENT -> tamper-PROOF).

Closes the gap where a root attacker deletes or replaces the whole local log. Signed,
counted checkpoints + an independent remote reference detect deletion, truncation,
wholesale wipe, and forgery.
"""
import json, tempfile
from pathlib import Path
from sentinel.responder import AuditLog
from sentinel.audit_anchor import Signer, verify_checkpoints, RemoteAnchor

KEY = b"k" * 32

def _log(d, remote=None, every=10):
    a = AuditLog(Path(d)/"a.jsonl")
    a.enable_checkpoints(str(Path(d)/"cp.jsonl"), Signer(hmac_key=KEY), every=every, remote_sink=remote)
    return a

def test_valid_checkpoints_pass(tmp_path):
    a = _log(tmp_path)
    for i in range(55): a.write({"i": i})
    r = verify_checkpoints(str(tmp_path/"cp.jsonl"), hmac_key=KEY)
    assert r["ok"] and r["checkpoints"] == 5

def test_forged_signature_detected(tmp_path):
    a = _log(tmp_path)
    for i in range(20): a.write({"i": i})
    cp = tmp_path/"cp.jsonl"
    cp.write_text(cp.read_text() + json.dumps(
        {"cp_seq": 99, "count": 999, "chain_hash": "x", "sig": "deadbeef", "mode": "hmac", "ts": 0}) + "\n")
    assert not verify_checkpoints(str(cp), hmac_key=KEY)["ok"]

def test_wrong_key_fails(tmp_path):
    a = _log(tmp_path)
    for i in range(20): a.write({"i": i})
    assert not verify_checkpoints(str(tmp_path/"cp.jsonl"), hmac_key=b"wrong"*7)["ok"]

def test_partial_deletion_caught_by_remote(tmp_path):
    remote = RemoteAnchor(); a = _log(tmp_path, remote=remote)
    for i in range(55): a.write({"i": i})
    cp = tmp_path/"cp.jsonl"; cp.write_text("\n".join(cp.read_text().splitlines()[:-2]) + "\n")
    r = verify_checkpoints(str(cp), hmac_key=KEY, expected_last_seq=remote.last_seq,
                           expected_min_count=remote.last_count)
    assert not r["ok"] and "deletion" in r["reason"]

def test_full_wipe_caught_by_remote(tmp_path):
    remote = RemoteAnchor(); a = _log(tmp_path, remote=remote)
    for i in range(55): a.write({"i": i})
    (tmp_path/"cp.jsonl").write_text("")
    r = verify_checkpoints(str(tmp_path/"cp.jsonl"), hmac_key=KEY,
                           expected_last_seq=remote.last_seq, expected_min_count=remote.last_count)
    assert not r["ok"] and "wiped" in r["reason"]

def test_local_hash_chain_still_valid(tmp_path):
    a = _log(tmp_path)
    for i in range(30): a.write({"i": i})
    assert a.verify()          # base chain unaffected by checkpointing

def test_ed25519_if_available(tmp_path):
    import pytest
    ed = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    from sentinel.audit_anchor import CheckpointLog
    signer = Signer(ed_private_pem=pem)
    assert signer.mode == "ed25519"
    a = AuditLog(tmp_path/"a.jsonl")
    a._checkpoint = CheckpointLog(str(tmp_path/"cp.jsonl"), signer); a._checkpoint_every = 10
    for i in range(25): a.write({"i": i})
    assert verify_checkpoints(str(tmp_path/"cp.jsonl"), public_pem=pub_pem)["ok"]
