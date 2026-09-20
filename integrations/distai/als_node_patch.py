"""Minimal patch for als_node_v2.py — replaces pull_loop and wraps ensure_model.
Copy node_shield.py, manifest.py, policy_distai.yaml, coordinator_pub.key and the `sentinel/`
package into the image next to als_node_v2.py, then apply these three changes."""
import json, time, httpx
from pathlib import Path
from node_shield import NodeShield, ShieldError

# 1) after registration / resume, before start_engine:
def make_shield(coordinator: str, creds: dict, models_dir: Path) -> NodeShield:
    shield = NodeShield(coordinator, creds["node_id"], models_dir)
    r = httpx.get(f"{coordinator}/als/manifest", timeout=30); r.raise_for_status()
    shield.load_manifest(r.json())                        # signed; refuses expired/rolled-back/forged
    return shield

# 2) wrap the model: refuse to start llama-server on anything not in the signed manifest
def ensure_model_verified(shield: NodeShield, ensure_model, fname: str, url: str) -> Path:
    path = ensure_model(fname, url)
    shield.verify_model(path)                              # raises ShieldError on tamper
    return path

# 3) the guarded pull loop (drop-in replacement)
def pull_loop(coordinator: str, creds: dict, inference_url: str, shield: NodeShield):
    headers = {"x-api-key": creds["api_key"]}
    poll_url = f"{coordinator}/als/{creds['node_id']}/jobs/poll"
    shield.check_endpoint(poll_url); shield.check_endpoint(inference_url)
    last_report = time.time()
    while True:
        try:
            r = httpx.get(poll_url, headers=headers, timeout=40)
            if r.status_code == 204:
                continue
            r.raise_for_status(); job = r.json()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[distai] poll error ({e}); retrying in 5s"); time.sleep(5); continue

        job_id = job["job_id"]
        try:
            body = shield.check_job(job)                     # policy + protocol validation
            resp = httpx.post(f"{inference_url}/v1/chat/completions", json=body, timeout=600)
            resp.raise_for_status()
            payload = {"status": "completed", "response": shield.check_result(resp.json())}
        except ShieldError as e:
            print(f"[distai] job {job_id} refused by shield: {e}")
            payload = {"status": "refused", "response": None, "reason": str(e)[:200]}
        except Exception as e:
            print(f"[distai] job {job_id} failed: {e}")
            payload = {"status": "failed", "response": None}
        try:
            httpx.post(f"{coordinator}/als/{creds['node_id']}/jobs/{job_id}/result",
                       json=payload, headers=headers, timeout=30)
        except Exception as e:
            print(f"[distai] result upload failed ({e})")

        if time.time() - last_report > 60:                 # findings only — never file contents
            f = shield.drain_findings()
            if f:
                try: httpx.post(f"{coordinator}/als/{creds['node_id']}/findings", json=f, headers=headers, timeout=15)
                except Exception: pass
            last_report = time.time()
