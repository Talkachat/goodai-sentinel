# Policy Decision Point (PDP) — central policy service

Turns the local guardrail into a network service so a fleet shares one policy, one
rate/budget ledger, and one kill switch. Same `Guardrail` engine → decisions are identical
in-process or over HTTP.

## Run
```bash
pip install fastapi "uvicorn[standard]" httpx
uvicorn pdp.server:app --host 0.0.0.0 --port 8080
export PDP_KEY="$(openssl rand -hex 32)"   # production: node auth + TLS
```

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| POST | /decide | allow / deny / require_approval |
| POST | /grant | hot-path capability token |
| POST | /kill | global kill switch (fleet-wide) |
| POST | /reload | zero-downtime policy reload |
| GET | /health | status, stats, audit validity |

## Client
```python
from pdp.client import PDPClient
pdp = PDPClient(url="https://pdp.internal:8080", node_id="web-3")
if pdp.request("agent-1", "write:file", "/workspace/app.py")["verdict"] == "allow":
    do_it()
```
Fails closed for irreversible actions if the PDP is unreachable.
