"""FastAPI wiring for the DistAI coordinator v3 (layer 2). Add to main.py."""
from fastapi import FastAPI, Header, HTTPException, Request
from coordinator_guard import CoordinatorGuard
import os, time

guard = CoordinatorGuard(priv_key=bytes.fromhex(os.environ["DISTAI_MANIFEST_KEY"]))   # 32-byte Ed25519 seed, hex
MODELS = {"qwen2.5-7b-instruct-q4_k_m.gguf": "<sha256>", "qwen2.5-3b-instruct-q4_k_m.gguf": "<sha256>"}

def install(app: FastAPI, auth_node):
    """auth_node(node_id, api_key) -> raises 401 if invalid (your existing helper)."""

    @app.get("/als/manifest")
    def manifest():
        return guard.signed_manifest(MODELS)

    @app.post("/als/{node_id}/findings")
    def findings(node_id: str, body: list[dict], x_api_key: str = Header(...)):
        auth_node(node_id, x_api_key)
        guard.ingest_findings(node_id, body[:100])
        return {"ok": True, "status": guard.nodes[node_id].status}

    @app.get("/als/guard/snapshot")
    def snapshot(x_admin_key: str = Header(...)):
        if x_admin_key != os.environ["DISTAI_ADMIN_KEY"]: raise HTTPException(403)
        return guard.snapshot()

    # In your existing poll handler, first line:
    #     if not guard.may_dispatch(node_id): return Response(status_code=204)
    # In your existing result handler, after validating the job belongs to this node:
    #     guard.observe_result(node_id, job, payload, time.time() - job["dispatched_at"])
    # and on any protocol error (unknown job, wrong node, bad key):
    #     guard.observe_violation(node_id, "<what>")
