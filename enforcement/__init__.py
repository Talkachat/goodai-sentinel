"""Independent enforcement layer (review #5, P0).

The guardrail only sees an agent's action if the agent *chooses* to call request().
A malicious or buggy agent that skips it is invisible. This layer closes that gap by
observing actions from OUTSIDE the agent — at the OS level — and applying the SAME
policy, so a forbidden action is caught even when no one asked permission.

Design: the guardrail is the single source of truth for allow/deny. The enforcer maps a
real OS event (a new process, an outbound connection) into the guardrail's action
vocabulary, asks the guardrail, and — if denied — acts (log / kill), independently of the
agent. This is detective+reactive enforcement; it does not replace kernel-level prevention
(eBPF LSM / Seccomp), which is the next step and is documented as such.
"""
__version__ = "0.1.0"
