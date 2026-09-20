"""Hot-reload watcher (enhancement #3)."""
import time, tempfile
from pathlib import Path
from sentinel.guardrail import Guardrail
from sentinel.policy_watch import PolicyWatcher
from sentinel.events import Event

def dec(g, **d): return g.decide(Event("agent","agent_action",d)).verdict
BASE = Path("policy/agent_guardrails.yaml").read_text()

def test_watcher_reloads_on_change(tmp_path):
    f = tmp_path/"p.yaml"; f.write_text(BASE)
    g = Guardrail(str(f))
    w = PolicyWatcher(g, debounce=0.0)
    assert dec(g, agent_id="coder-1", action="read:x", target="/workspace/a") == "allow"
    f.write_text(BASE.replace("kill_switch: false", "kill_switch: true"))
    assert w.poll_once() is True
    assert dec(g, agent_id="coder-1", action="read:x", target="/workspace/a") == "deny"
    assert w.reloads == 1

def test_kill_switch_via_reload_kills_grants(tmp_path):
    from sentinel.tokens import TokenIssuer
    f = tmp_path/"p.yaml"; f.write_text(BASE)
    g = Guardrail(str(f)); t = TokenIssuer(g)
    w = PolicyWatcher(g, debounce=0.0)          # watcher captures baseline BEFORE the edit
    _, grant = t.grant("coder-1", "write:file", "/workspace/*")
    assert grant.validate("write:file", "/workspace/app.py")
    f.write_text(BASE.replace("kill_switch: false", "kill_switch: true"))
    assert w.poll_once() is True
    assert not grant.validate("write:file", "/workspace/app.py")   # reload -> engage -> revoke_all

def test_broken_yaml_does_not_wipe_policy_or_crash(tmp_path):
    f = tmp_path/"p.yaml"; f.write_text(BASE)
    g = Guardrail(str(f)); w = PolicyWatcher(g, debounce=0.0)
    f.write_text("this: : : not valid yaml: [")
    assert w.poll_once() is False and w.errors == 1
    # old policy still enforced
    assert dec(g, agent_id="coder-1", action="write:file", target="/workspace/app.py") == "allow"
    assert dec(g, agent_id="coder-1", action="shell:run", target="rm -rf /") == "deny"

def test_no_reload_when_unchanged(tmp_path):
    f = tmp_path/"p.yaml"; f.write_text(BASE)
    g = Guardrail(str(f)); w = PolicyWatcher(g, debounce=0.0)
    assert w.poll_once() is False and w.reloads == 0

def test_background_thread_start_stop(tmp_path):
    f = tmp_path/"p.yaml"; f.write_text(BASE)
    g = Guardrail(str(f)); w = PolicyWatcher(g, interval=0.05, debounce=0.0).start()
    time.sleep(0.12)
    f.write_text(BASE.replace("kill_switch: false", "kill_switch: true"))
    time.sleep(0.25)
    w.stop()
    assert g.policy.get("kill_switch") is True and w.reloads >= 1
