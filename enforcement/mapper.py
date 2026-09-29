"""Map a real OS observation into the guardrail's (agent_id, action, target) vocabulary,
so the exact same policy that governs cooperating agents also governs raw OS activity."""
from __future__ import annotations
import re

# A process's command line -> the guardrail action it corresponds to.
# We are deliberately conservative: unknown maps to a generic "exec" so the guardrail's
# forbidden_patterns (rm -rf, curl|sh, etc.) still get a chance to fire on the target.
def process_to_action(cmdline: str, exe: str = "") -> tuple[str, str]:
    c = (cmdline or exe or "").strip()
    return "exec", c            # target = full command; guardrail patterns scan it

def connection_to_action(rip: str, rport: int) -> tuple[str, str]:
    return "net:connect", f"{rip}:{rport}"

# Which agent identity does un-attributed OS activity run as? A dedicated low-trust id,
# so its policy can be tuned separately from real named agents.
OS_AGENT_ID = "os-activity"
