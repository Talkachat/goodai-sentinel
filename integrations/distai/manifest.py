"""Signed model manifest: the coordinator signs {filename: sha256}; nodes verify before loading.
Ed25519 via `cryptography`. Public key ships inside the node image; private key stays on the coordinator."""
from __future__ import annotations
import base64, hashlib, json, time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def sha256_file(p: Path, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def gen_keypair() -> tuple[bytes, bytes]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def _canon(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def sign_manifest(models: dict[str, str], priv: bytes, ttl_s: int = 7 * 86400, version: int = 1,
                  blocklist: list[str] | None = None) -> dict:
    """models = {filename: sha256}. Returns a signed manifest dict (also carries the fleet IP blocklist)."""
    body = {"version": version, "issued": int(time.time()), "expires": int(time.time()) + ttl_s,
            "models": models, "blocklist": sorted(blocklist or [])}
    sig = Ed25519PrivateKey.from_private_bytes(priv).sign(_canon(body))
    return {**body, "sig": base64.b64encode(sig).decode()}


def verify_manifest(doc: dict, pub: bytes, min_version: int = 0) -> dict:
    """Raises ValueError on any problem; returns the verified body."""
    body = {k: v for k, v in doc.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(doc.get("sig", "")), _canon(body))
    except (InvalidSignature, ValueError, KeyError) as e:
        raise ValueError("manifest signature invalid") from e
    if body.get("expires", 0) < time.time():
        raise ValueError("manifest expired")
    if body.get("version", 0) < min_version:
        raise ValueError("manifest rollback: version older than last seen")   # anti-downgrade
    return body


def verify_model(path: Path, manifest: dict) -> str:
    """Returns the hash if the model on disk matches the signed manifest; raises otherwise."""
    expected = manifest["models"].get(path.name)
    if expected is None:
        raise ValueError(f"{path.name} not in signed manifest")
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"{path.name} hash mismatch: model file was tampered with or corrupted")
    return actual
