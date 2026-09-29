"""PII / secret redaction in audit records (review point: Data Masking & Privacy)."""
import json, tempfile
from pathlib import Path
from sentinel.masking import redact, redact_text
from sentinel.responder import AuditLog

def test_tokens_and_keys_redacted():
    assert "ghp_" not in redact_text("git push https://ghp_" + "A"*36 + "@github.com")
    assert "AKIA" not in redact_text("AKIAIOSFODNN7EXAMPLE key")
    assert "sk-" not in redact_text("openai sk-" + "a"*40)
    assert "«jwt»" in redact_text("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf")

def test_key_value_secrets_redacted():
    assert "hunter2" not in redact_text("mysql --password=hunter2")
    assert "hunter2" not in redact_text('{"api_key": "hunter2xyz"}')
    assert "s3cr3t" not in redact_text("TOKEN=s3cr3tvalue")

def test_pii_redacted():
    assert "«email»" in redact_text("taher@example.com")
    out = redact_text("card 4111 1111 1111 1111 end")
    assert "4111 1111 1111 1111" not in out

def test_sensitive_keys_replace_whole_value():
    r = redact({"password": "letmein", "note": "ok", "nested": {"secret": "abc", "fine": "keep"}})
    assert r["password"] == "«redacted»" and r["note"] == "ok"
    assert r["nested"]["secret"] == "«redacted»" and r["nested"]["fine"] == "keep"

def test_private_key_block_redacted():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----"
    assert "MIIabc123" not in redact_text(pem)

def test_audit_log_scrubs_and_chain_still_valid():
    with tempfile.TemporaryDirectory() as d:
        a = AuditLog(Path(d)/"a.jsonl")
        a.write({"event": "new_process", "cmdline": "curl -H 'Authorization: Bearer sk-" + "x"*40 + "' host"})
        a.write({"finding": {"target": "deploy --token=supersecret123"}})
        txt = (Path(d)/"a.jsonl").read_text()
        assert "supersecret123" not in txt and "sk-" + "x"*40 not in txt
        assert a.verify()          # redaction happens BEFORE hashing -> chain stays valid

def test_benign_content_untouched():
    assert redact_text("rm -rf /workspace/app.py") == "rm -rf /workspace/app.py"
    assert redact({"action": "write:file", "target": "/workspace/main.py"})["target"] == "/workspace/main.py"
