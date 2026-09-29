"""Tamper-EVIDENT is not tamper-PROOF. A root attacker can delete the whole audit log or
rewrite it with a fresh clean hash chain. Detection needs an anchor the attacker cannot forge.

This module adds signed checkpoints:
  • every N records, the log emits a checkpoint {seq, count, chain_hash} SIGNED with an
    HMAC key (or, if cryptography is present, an Ed25519 signature) the attacker doesn't have;
  • checkpoints carry a monotonically increasing `count`, so deleting records is detectable
    (the count would go backwards or a checkpoint would be missing);
  • checkpoints can be shipped OFF-HOST (append-only remote), so even wiping the local file
    leaves the remote record. This module provides the checkpoint + verification; the remote
    sink is a pluggable callback.

Threat model closed: silent deletion / wholesale replacement of the local log.
Still out of scope: an attacker who also steals the signing key (keep it off-host / in an HSM).
"""
from __future__ import annotations
import hashlib, hmac, json, time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    _HAVE_ED = True
except Exception:
    _HAVE_ED = False


class Signer:
    """HMAC by default (always available); Ed25519 if cryptography is installed and a key given."""
    def __init__(self, hmac_key: bytes | None = None, ed_private_pem: bytes | None = None):
        self.mode = "none"
        if ed_private_pem and _HAVE_ED:
            self._ed = serialization.load_pem_private_key(ed_private_pem, password=None)
            self.mode = "ed25519"
        elif hmac_key:
            self._hk = hmac_key
            self.mode = "hmac"

    def sign(self, data: bytes) -> str:
        if self.mode == "ed25519":
            return self._ed.sign(data).hex()
        if self.mode == "hmac":
            return hmac.new(self._hk, data, hashlib.sha256).hexdigest()
        return ""

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, sig: str) -> bool:
        return hmac.compare_digest(sig, hmac.new(key, data, hashlib.sha256).hexdigest())

    @staticmethod
    def verify_ed(public_pem: bytes, data: bytes, sig: str) -> bool:
        if not _HAVE_ED:
            raise RuntimeError("cryptography not available")
        pub = serialization.load_pem_public_key(public_pem)
        try:
            pub.verify(bytes.fromhex(sig), data); return True
        except Exception:
            return False


def checkpoint_payload(seq: int, count: int, chain_hash: str) -> bytes:
    """Canonical bytes that get signed. Includes count so deletion changes the signature target."""
    return json.dumps({"cp_seq": seq, "count": count, "chain_hash": chain_hash},
                      sort_keys=True).encode()


class CheckpointLog:
    """Wraps writing signed checkpoints to a sidecar file and (optionally) a remote sink."""
    def __init__(self, path: str, signer: Signer, remote_sink=None):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self.remote_sink = remote_sink or (lambda cp: None)
        self.seq = 0
        if self.path.exists() and self.path.read_text().strip():
            self.seq = json.loads(self.path.read_text().strip().splitlines()[-1])["cp_seq"]

    def emit(self, count: int, chain_hash: str) -> dict:
        self.seq += 1
        payload = checkpoint_payload(self.seq, count, chain_hash)
        cp = {"cp_seq": self.seq, "count": count, "chain_hash": chain_hash,
              "sig": self.signer.sign(payload), "mode": self.signer.mode, "ts": time.time()}
        with self.path.open("a") as f:
            f.write(json.dumps(cp) + "\n")
        self.remote_sink(cp)                 # ship off-host: survives local wipe
        return cp


def verify_checkpoints(path: str, *, hmac_key: bytes | None = None,
                       public_pem: bytes | None = None,
                       expected_last_seq: int | None = None,
                       expected_min_count: int | None = None) -> dict:
    """Verify every checkpoint's signature and that counts are strictly increasing.
    If expected_last_seq / expected_min_count are given (from an independent remote
    reference), also detect wholesale truncation: local data that ends before the remote
    knows it should. Returns {ok, checkpoints, last_seq, last_count, reason}."""
    p = Path(path)
    if not p.exists() or not p.read_text().strip():
        # An empty local log is only OK if the remote also knew of no checkpoints.
        if expected_last_seq:
            return {"ok": False, "checkpoints": 0, "last_seq": 0, "last_count": 0,
                    "reason": f"local log empty but remote saw {expected_last_seq} checkpoints (wiped)"}
        return {"ok": True, "checkpoints": 0, "last_seq": 0, "last_count": 0, "reason": "no checkpoints"}
    prev_count, prev_seq = -1, 0
    n = 0
    for line in p.read_text().strip().splitlines():
        cp = json.loads(line); n += 1
        payload = checkpoint_payload(cp["cp_seq"], cp["count"], cp["chain_hash"])
        if cp["mode"] == "hmac":
            if not hmac_key or not Signer.verify_hmac(hmac_key, payload, cp["sig"]):
                return {"ok": False, "checkpoints": n, "reason": f"bad HMAC at cp {cp['cp_seq']}"}
        elif cp["mode"] == "ed25519":
            if not public_pem or not Signer.verify_ed(public_pem, payload, cp["sig"]):
                return {"ok": False, "checkpoints": n, "reason": f"bad signature at cp {cp['cp_seq']}"}
        if cp["cp_seq"] != prev_seq + 1:
            return {"ok": False, "checkpoints": n, "reason": f"checkpoint gap: {prev_seq}->{cp['cp_seq']} (deletion?)"}
        if cp["count"] < prev_count:
            return {"ok": False, "checkpoints": n, "reason": f"count went backwards (truncation?)"}
        prev_count, prev_seq = cp["count"], cp["cp_seq"]
    # cross-check against the independent remote reference
    if expected_last_seq is not None and prev_seq < expected_last_seq:
        return {"ok": False, "checkpoints": n, "last_seq": prev_seq, "last_count": prev_count,
                "reason": f"local ends at cp {prev_seq} but remote saw {expected_last_seq} (deletion)"}
    if expected_min_count is not None and prev_count < expected_min_count:
        return {"ok": False, "checkpoints": n, "last_seq": prev_seq, "last_count": prev_count,
                "reason": f"local count {prev_count} < remote-known {expected_min_count} (truncation)"}
    return {"ok": True, "checkpoints": n, "last_seq": prev_seq, "last_count": prev_count,
            "reason": "all checkpoints valid"}



class RemoteAnchor:
    """A stand-in for an append-only remote store. Records the highest checkpoint it has seen.
    In production this is an external service the local host cannot roll back. Use as the
    `remote_sink` for CheckpointLog, and read `.last_seq` / `.last_count` at verification time.
    """
    def __init__(self):
        self.last_seq = 0
        self.last_count = 0
        self.log: list[dict] = []

    def __call__(self, cp: dict):
        # append-only: never decreases
        if cp["cp_seq"] > self.last_seq:
            self.last_seq = cp["cp_seq"]; self.last_count = cp["count"]
        self.log.append(cp)
