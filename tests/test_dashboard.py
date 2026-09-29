"""Read-only incident dashboard (review P2)."""
import json, tempfile, threading, time, urllib.request, hashlib
from pathlib import Path
from http.server import ThreadingHTTPServer
import dashboard.server as ds
from sentinel.responder import AuditLog

def _serve(audit_path, port):
    ds.AUDIT_PATH = str(audit_path)
    srv = ThreadingHTTPServer(("127.0.0.1", port), ds.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2); return srv

def _mklog(d):
    a = AuditLog(Path(d)/"a.jsonl")
    a.write({"event": "service_started"})
    a.write({"finding": {"rule": "dangerous_command", "severity": "critical", "reason": "rm -rf /"}, "action": "terminate"})
    a.write({"agent": "coder-1", "action": "shell:run", "target": "x", "verdict": "deny"})
    return Path(d)/"a.jsonl"

def test_api_returns_parsed_records(tmp_path):
    _mklog(tmp_path); srv = _serve(tmp_path/"a.jsonl", 8801)
    try:
        d = json.loads(urllib.request.urlopen("http://127.0.0.1:8801/api/records").read())
        assert len(d["records"]) == 3
        assert d["summary"].get("critical") == 1 and d["summary"].get("deny") == 1
    finally: srv.shutdown()

def test_severity_filter(tmp_path):
    _mklog(tmp_path); srv = _serve(tmp_path/"a.jsonl", 8802)
    try:
        d = json.loads(urllib.request.urlopen("http://127.0.0.1:8802/api/records?severity=critical").read())
        assert len(d["records"]) == 1 and d["records"][0]["_sev"] == "critical"
    finally: srv.shutdown()

def test_html_served(tmp_path):
    _mklog(tmp_path); srv = _serve(tmp_path/"a.jsonl", 8803)
    try:
        page = urllib.request.urlopen("http://127.0.0.1:8803/").read().decode()
        assert "GoodAI Sentinel" in page and "<table" in page
    finally: srv.shutdown()

def test_dashboard_is_read_only(tmp_path):
    log = _mklog(tmp_path)
    before = hashlib.sha256(log.read_bytes()).hexdigest()
    srv = _serve(log, 8804)
    try:
        urllib.request.urlopen("http://127.0.0.1:8804/api/records").read()
        urllib.request.urlopen("http://127.0.0.1:8804/api/health").read()
    finally: srv.shutdown()
    after = hashlib.sha256(log.read_bytes()).hexdigest()
    assert before == after          # dashboard never modifies the audit log

def test_missing_log_is_safe(tmp_path):
    srv = _serve(tmp_path/"nope.jsonl", 8805)
    try:
        d = json.loads(urllib.request.urlopen("http://127.0.0.1:8805/api/records").read())
        assert d["records"] == []
    finally: srv.shutdown()
