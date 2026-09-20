import copy, tempfile, yaml
from dataclasses import replace
from pathlib import Path
from redteam.run import evaluate
from redteam.attacks import corpus

POLICY = "policy/agent_guardrails.yaml"

def test_no_breaches_and_no_overblocks_on_shipping_policy():
    breaches, over, fam, caught = evaluate(POLICY)
    assert not breaches, f"guardrail allowed dangerous actions: {[b.family for b,_ in breaches][:5]}"
    assert not over, f"guardrail wrongly denied benign actions: {[b.action for b,_ in over][:5]}"
    assert sum(fam.values()) > 500   # corpus didn't silently shrink

def test_every_danger_family_has_coverage():
    _, _, fam, caught = evaluate(POLICY)
    for f in fam:
        assert caught[f] == fam[f], f"family {f} not fully stopped"

def _weakened(drop_pattern):
    pol = yaml.safe_load(Path(POLICY).read_text())
    pol["forbidden_patterns"].pop(drop_pattern, None)
    pol["agents"]["powerful-*"] = {"capabilities": ["*"], "allow_targets": ["*"],
        "require_approval": [], "rate_limit": {"max": 10**9, "window_s": 60}, "budget": 10**9}
    d = tempfile.mkdtemp(); p = Path(d) / "weak.yaml"; p.write_text(yaml.safe_dump(pol)); return str(p)

def _danger_at_powerful():
    return [replace(a, agent="powerful-1") if a.dangerous else a for a in corpus()]

def test_mutation_gate_actually_bites():
    # Removing a forbidden pattern AND giving an agent full scope must produce breaches,
    # proving the red team can detect a real regression (not just pass vacuously).
    for pat in ("reverse_shell", "download_exec", "destroy_data", "exfiltrate"):
        breaches, _, _, _ = evaluate(_weakened(pat), cases=_danger_at_powerful())
        assert breaches, f"removing {pat} did not create a detectable breach"
