# Incident Dashboard

A read-only web view of the audit log — severity cards, filters, and a live-updating table —
so you can see what the monitor is finding without reading raw JSON. **Zero dependencies**
(Python standard library only), so it runs anywhere the monitor runs.

## Run
```bash
python -m dashboard --audit ~/.goodai-sentinel/audit.jsonl --port 8787
# open http://127.0.0.1:8787
```

## Safety
- **Read-only:** it never writes to the audit log (proven by `test_dashboard_is_read_only`).
- **Localhost by default:** binds to 127.0.0.1; expose beyond localhost only behind auth/TLS.
- Auto-refreshes every 3s; shows newest first; filter by severity.

## What it shows
- Summary cards per severity (critical / high / deny / medium / low / info).
- A table of recent events with time, severity, rule/event, and detail (findings show their
  reason; agent decisions show action+target+verdict).
- Secrets are already redacted in the log by the masking layer, so nothing sensitive is shown.

## Limits
Simple single-file tool for one host's log. Fleet-wide dashboards, alerting, and historical
analytics belong in a real SIEM (ship the audit JSONL there); this is the local at-a-glance view.
