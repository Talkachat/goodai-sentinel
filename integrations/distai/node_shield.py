"""Layer 1 — runs INSIDE every DistAI node container. No new permissions needed.

Drop-in for als_node_v2.py:

    from node_shield import NodeShield
    shield = NodeShield(coordinator, creds["node_id"], models_dir)
    shield.load_manifest(manifest_json)             # fetched from coordinator, signed
    shield.verify_model(model_path)                 # refuses tampered GGUFs
    pull_loop(..., shield=shield)                   # each job passes shield.check_job()

What it does:
  * every model file is verified against an Ed25519-signed manifest before loading
  * every job goes through Sentinel.request() under the distai-node-* policy
  * job bodies are validated against the protocol (no tool calls, no system-level fields,
    bounded max_tokens, only the fields llama-server needs)
  * results are checked for secret leakage before upload
  * the models directory is integrity-monitored between jobs
  * findings are reported to the coordinator (report:finding), never file contents
"""
from __future__ import annotations
import json, re, time
from pathlib import Path
from urllib.parse import urlparse
from sentinel.core import Sentinel
from sentinel.sensors import FileIntegritySensor
from sentinel.events import Event, Finding
from .manifest import verify_manifest, verify_model as _verify_model

HERE = Path(__file__).resolve().parent
POLICY = HERE / "policy_distai.yaml"

ALLOWED_JOB_FIELDS = {"messages", "max_tokens", "temperature", "top_p", "stream", "stop", "seed", "model"}
FORBIDDEN_JOB_FIELDS = {"tools", "tool_choice", "functions", "function_call", "logit_bias_file", "grammar_file",
                        "n_probs", "lora", "cache_prompt", "slot_save_path", "slot_restore_path"}
MAX_TOKENS_CAP = 4096
MAX_MESSAGES = 64
MAX_PROMPT_CHARS = 200_000
SECRET_RX = re.compile(r"(sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                       r"ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|\"api_key\"\s*:\s*\"[^\"]{8,}\")")


class ShieldError(Exception):
    pass


class NodeShield:
    def __init__(self, coordinator_url: str, node_id: str, models_dir: str | Path,
                 pubkey: bytes | None = None, audit_path: str | Path = "/tmp/sentinel_node_audit.jsonl",
                 notify=None):
        self.coordinator = urlparse(coordinator_url).netloc
        self.agent_id = f"distai-node-{node_id}"
        self.models_dir = Path(models_dir)
        self._verified_model = None
        self.pubkey = pubkey or (HERE / "coordinator_pub.key").read_bytes() if (HERE / "coordinator_pub.key").exists() else pubkey
        self.manifest: dict | None = None
        self.min_version = 0
        self.sentinel = Sentinel(watch_paths=[str(self.models_dir)], policy=POLICY, audit_path=audit_path,
                                 dry_run=True, warmup_s=0, notify=notify or (lambda m: None))
        self.blocked_ips: set[str] = set()
        self.findings: list[dict] = []
        self.stats = {"jobs": 0, "denied": 0, "leaks_blocked": 0}
        models_norm = str(self.models_dir)
        def _model_dir_rule(ev: Event):
            if ev.kind.startswith("file_") and str(ev.data.get("path", "")).startswith(models_norm):
                return Finding(ev, "model_tamper", "critical", f"{ev.kind} inside models dir: {ev.data.get('path')}", 0.95, "alert")
            return None
        self.sentinel.detector.rules.insert(0, _model_dir_rule)
        self.sentinel.tick()      # prime file-integrity baseline

    # ---- manifest & models ----
    def load_manifest(self, doc: dict):
        if self.pubkey is None:
            raise ShieldError("no coordinator public key: refusing to run unverified models")
        body = verify_manifest(doc, self.pubkey, self.min_version)
        self.manifest = body
        self.min_version = body["version"]
        self.blocked_ips = set(body.get("blocklist", []))
        self._req("verify:model", "model/manifest")

    def verify_model(self, path: str | Path) -> str:
        if self.manifest is None:
            raise ShieldError("manifest not loaded")
        try:
            digest = _verify_model(Path(path), self.manifest)
            self._verified_model = str(Path(path))
            return digest
        except ValueError as e:
            self._finding("model_tamper", "critical", str(e))
            raise ShieldError(str(e)) from e

    # ---- jobs ----
    def check_job(self, job: dict) -> dict:
        """Validate a job pulled from the coordinator. Returns a sanitized body or raises ShieldError."""
        self.stats["jobs"] += 1
        d = self._req("infer:chat", f"coordinator/{self.coordinator}", cost=0)
        if d.verdict != "allow":
            self.stats["denied"] += 1
            raise ShieldError(f"guardrail denied job: {d.reason}")
        body = job.get("body") or {}
        if not isinstance(body, dict):
            raise self._reject("job body is not an object")
        bad = FORBIDDEN_JOB_FIELDS & set(body)
        if bad:
            raise self._reject(f"job carries forbidden fields {sorted(bad)}")
        msgs = body.get("messages")
        if not isinstance(msgs, list) or not msgs or len(msgs) > MAX_MESSAGES:
            raise self._reject("messages missing or too many")
        total = 0
        for m in msgs:
            if not isinstance(m, dict) or m.get("role") not in ("system", "user", "assistant"):
                raise self._reject("malformed message")
            c = m.get("content")
            if isinstance(c, list):        # multimodal parts: text only on volunteer nodes
                raise self._reject("non-text content not allowed on volunteer nodes")
            total += len(str(c or ""))
        if total > MAX_PROMPT_CHARS:
            raise self._reject("prompt too large")
        clean = {k: v for k, v in body.items() if k in ALLOWED_JOB_FIELDS}
        try:
            mt = int(clean.get("max_tokens", 512))
        except (TypeError, ValueError):
            raise self._reject("max_tokens is not an integer")
        if mt <= 0:
            raise self._reject("max_tokens must be positive")
        clean["max_tokens"] = min(mt, MAX_TOKENS_CAP)
        for fld, lo, hi in (("temperature", 0.0, 2.0), ("top_p", 0.0, 1.0)):
            if fld in clean:
                try: v = float(clean[fld])
                except (TypeError, ValueError): raise self._reject(f"{fld} not a number")
                if not (lo <= v <= hi): raise self._reject(f"{fld} out of range")
                clean[fld] = v
        clean["stream"] = False
        self._integrity_tick()
        return clean

    def check_result(self, response: dict) -> dict:
        """Refuse to upload a result that contains secrets (the model has no business emitting them)."""
        text = json.dumps(response) if not isinstance(response, str) else response
        if SECRET_RX.search(text):
            self.stats["leaks_blocked"] += 1
            self._finding("secret_in_output", "high", "model output contained a credential-shaped string")
            raise ShieldError("result withheld: credential-shaped content")
        d = self._req("upload:result", f"coordinator/{self.coordinator}")
        if getattr(d, "verdict", "deny") != "allow":
            self.stats["denied"] += 1
            self._finding("upload_denied", "high", f"upload refused: {getattr(d,'reason','denied')}")
            raise ShieldError(f"upload refused: {getattr(d,'reason','denied')}")
        return response

    @staticmethod
    def _host(value: str) -> str:
        """Extract a bare hostname from a URL, netloc, or host:port string."""
        v = value if "//" in value else "//" + value
        return (urlparse(v).hostname or "").lower()

    def check_endpoint(self, url: str) -> None:
        """Every outbound call must go to the coordinator (or localhost inference)."""
        host = self._host(url)
        coord = self._host(self.coordinator)
        if host in ("127.0.0.1", "localhost", "::1"):
            return
        if not host or host != coord or host in {self._host(b) for b in self.blocked_ips}:
            self._finding("unexpected_endpoint", "critical", f"attempted call to {host or url}")
            raise ShieldError(f"outbound to {host or url} is not the coordinator")

    # ---- reporting ----
    def drain_findings(self) -> list[dict]:
        f, self.findings = self.findings, []
        if f:
            self._req("report:finding", f"coordinator/{self.coordinator}")
        return f

    # ---- internals ----
    def _req(self, action, target, **extra):
        return self.sentinel.request(self.agent_id, action, target, **extra)

    def _reject(self, why):
        self.stats["denied"] += 1
        self._finding("bad_job", "medium", why)
        return ShieldError(why)

    def _finding(self, rule, sev, reason):
        rec = {"ts": time.time(), "node": self.agent_id, "rule": rule, "severity": sev, "reason": reason[:200]}
        self.findings.append(rec)
        self.sentinel.audit.write({"finding": rec})

    def _integrity_tick(self):
        changed = False
        for f in self.sentinel.tick():
            if f.event.source == "file":
                self._finding(f.rule, f.severity, f.reason)
                changed = True
        # A change inside the models dir means a previously-verified GGUF may be tampered.
        # Re-verify against the manifest and refuse to proceed if it no longer matches.
        if changed and self._verified_model is not None:
            try:
                _verify_model(Path(self._verified_model), self.manifest)
            except Exception as e:
                self._finding("model_tamper_runtime", "critical", str(e))
                raise ShieldError(f"model changed at runtime and failed re-verification: {e}") from e
