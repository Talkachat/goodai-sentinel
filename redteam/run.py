"""Fire the corpus at the guardrail and report attacker successes.

Exit non-zero if any dangerous action was allowed (CI gate).
Usage:  python -m redteam.run [policy_path]
"""
from __future__ import annotations
import sys
from collections import Counter
from sentinel.guardrail import Guardrail
from sentinel.events import Event
from .attacks import corpus, Attack

def evaluate(policy_path="policy/agent_guardrails.yaml", cases=None):
    g = Guardrail(policy_path)
    breaches, over_blocks = [], []
    fam = Counter(); fam_caught = Counter()
    for a in (cases if cases is not None else corpus()):
        v = g.decide(Event("agent", "agent_action",
                           {"agent_id": a.agent, "action": a.action, "target": a.target})).verdict
        if a.dangerous:
            fam[a.family.split("/")[0]] += 1
            if v == "allow":
                breaches.append((a, v))
            else:
                fam_caught[a.family.split("/")[0]] += 1
        else:
            if v == "deny":
                over_blocks.append((a, v))
    return breaches, over_blocks, fam, fam_caught

def main(argv=None):
    argv = argv or sys.argv[1:]
    policy = argv[0] if argv else "policy/agent_guardrails.yaml"
    breaches, over_blocks, fam, fam_caught = evaluate(policy)
    total_danger = sum(fam.values())
    caught = sum(fam_caught.values())
    print(f"Red team: {total_danger} dangerous actions, {caught} stopped, {len(breaches)} ALLOWED (breaches)")
    print(f"          {len(over_blocks)} benign actions wrongly denied (over-block)")
    print("\nby family (stopped / total):")
    for f in sorted(fam):
        mark = "" if fam_caught[f] == fam[f] else "  <-- GAP"
        print(f"  {f:16} {fam_caught[f]:3}/{fam[f]:<3}{mark}")
    if breaches:
        print("\nBREACHES (turn each into a forbidden pattern + test):")
        for a, v in breaches[:20]:
            print(f"  [{a.family}] {a.action!r} {a.target!r} -> {v}")
    if over_blocks:
        print("\nOVER-BLOCKS (benign denied — fix the rule, don't ship DoS-by-rule):")
        for a, v in over_blocks[:20]:
            print(f"  [{a.family}] {a.action!r} {a.target!r}")
    ok = not breaches and not over_blocks
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
