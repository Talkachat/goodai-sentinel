"""Layer 2 — runs inside the DistAI coordinator. Sees every node; the nodes can't.

    from coordinator_guard import CoordinatorGuard
    guard = CoordinatorGuard(priv_key)
    # on poll:   if not guard.may_dispatch(node_id): return 204
    # on result: guard.observe_result(node_id, job, payload, latency_s)
    # on report: guard.ingest_findings(node_id, findings)
    # manifest:  guard.signed_manifest(models)   -> what nodes fetch

Per-node behavioural scoring (failure ratio, duplicate/empty output, timing, protocol violations,
self-reported findings) -> throttle -> quarantine. Fleet immune system: findings from many nodes
against the same destination become a signed blocklist pushed to all nodes via the manifest.
"""
from __future__ import annotations
import hashlib, json, time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from sentinel.core import Sentinel
from .manifest import sign_manifest

HERE = Path(__file__).resolve().parent


@dataclass
class NodeState:
    results: deque = field(default_factory=lambda: deque(maxlen=200))     # (ok, latency, out_hash, tokens)
    violations: int = 0
    findings: int = 0
    score: float = 0.0          # 0 = healthy, 1 = quarantined
    status: str = "ok"          # ok | throttled | quarantined
    since: float = field(default_factory=time.time)


class CoordinatorGuard:
    THROTTLE_AT, QUARANTINE_AT = 0.4, 0.8

    def __init__(self, priv_key: bytes, audit_path="./coordinator_audit.jsonl", approver=None, notify=None,
                 blocklist_votes: int = 3):
        self.priv = priv_key
        self.nodes: dict[str, NodeState] = defaultdict(NodeState)
        self.threat_votes: dict[str, set] = defaultdict(set)     # dst -> {node_ids}
        self.blocklist: set[str] = set()
        self.blocklist_votes = blocklist_votes
        self.manifest_version = 0
        self.sentinel = Sentinel(watch_paths=[], policy=HERE / "policy_distai.yaml", audit_path=audit_path,
                                 dry_run=True, warmup_s=0, approver=approver, notify=notify or (lambda m: None))

    # ---- dispatch gate ----
    def may_dispatch(self, node_id: str) -> bool:
        st = self.nodes[node_id]
        if st.status == "quarantined":
            return False
        if st.status == "throttled":
            return int(time.time() * 10) % 4 == 0      # ~25% of polls get work
        return True

    # ---- observations ----
    def observe_result(self, node_id: str, job: dict, payload: dict, latency_s: float):
        st = self.nodes[node_id]
        ok = payload.get("status") == "completed" and bool(payload.get("response"))
        resp = payload.get("response") or {}
        text = ""
        try:
            text = resp["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            ok = False
        tokens = (resp.get("usage") or {}).get("completion_tokens", 0)
        out_hash = hashlib.sha256(text.strip().lower().encode()).hexdigest()[:16] if text else ""
        st.results.append((ok, latency_s, out_hash, tokens))
        self._rescore(node_id)

    def observe_violation(self, node_id: str, what: str):
        """Protocol misuse: unknown job id, result for a job not assigned, malformed upload, bad api key…"""
        st = self.nodes[node_id]; st.violations += 1
        self.sentinel.audit.write({"node": node_id, "violation": what})
        self._rescore(node_id)

    def ingest_findings(self, node_id: str, findings: list[dict]):
        st = self.nodes[node_id]
        for f in findings:
            st.findings += 1
            self.sentinel.audit.write({"node": node_id, "finding": f})
            if f.get("rule") in ("unexpected_endpoint", "blocked_destination", "c2_port"):
                dst = (f.get("reason") or "").rsplit(" ", 1)[-1]
                if dst:
                    self.threat_votes[dst].add(node_id)
                    if len(self.threat_votes[dst]) >= self.blocklist_votes and dst not in self.blocklist:
                        self._push_blocklist(dst)
        self._rescore(node_id)

    # ---- scoring ----
    def _rescore(self, node_id: str):
        st = self.nodes[node_id]
        r = list(st.results)
        score = 0.0
        if len(r) >= 10:
            fail = sum(1 for ok, *_ in r if not ok) / len(r)
            hashes = [h for _, _, h, _ in r if h]
            dup = 1 - len(set(hashes)) / len(hashes) if hashes else 0
            lat = [l for _, l, _, _ in r]
            too_fast = sum(1 for l in lat if l < 0.05) / len(lat)          # answers faster than any model could
            score += 0.5 * fail + 0.5 * dup + 0.5 * too_fast
        score += min(0.6, 0.15 * st.violations) + min(0.3, 0.1 * st.findings)
        st.score = min(1.0, score)
        new = ("quarantined" if st.score >= self.QUARANTINE_AT else
               "throttled" if st.score >= self.THROTTLE_AT else "ok")
        if new != st.status:
            action = "quarantine:node" if new == "quarantined" else "release:node" if new == "ok" else "throttle:node"
            d = self.sentinel.request("distai-coordinator", action if action != "throttle:node" else "quarantine:node",
                                      f"node/{node_id}")
            self.sentinel.audit.write({"node": node_id, "transition": f"{st.status}->{new}", "score": round(st.score, 3),
                                       "verdict": d.verdict})
            if d.verdict == "allow":                 # only change operational state if authorized
                st.status, st.since = new, time.time()

    # ---- fleet immune system ----
    def _push_blocklist(self, dst: str):
        d = self.sentinel.request("distai-coordinator", "push:blocklist", f"dst/{dst}")
        if d.verdict == "allow":
            self.blocklist.add(dst)
            self.manifest_version += 1
            self.sentinel.audit.write({"blocklist_add": dst, "voters": sorted(self.threat_votes[dst]),
                                       "manifest_version": self.manifest_version})

    def signed_manifest(self, models: dict[str, str], ttl_s: int = 7 * 86400) -> dict:
        self.manifest_version += 1
        return sign_manifest(models, self.priv, ttl_s, self.manifest_version, sorted(self.blocklist))

    def snapshot(self) -> dict:
        return {n: {"status": s.status, "score": round(s.score, 2), "violations": s.violations, "findings": s.findings}
                for n, s in self.nodes.items()}
