"""Adversarial test harness for the Sentinel guardrail.

An attacker agent generates hostile actions across several evasion families and fires
them at Guardrail.decide(). A SUCCESS for the attacker = a genuinely dangerous action
that was NOT denied. Any success fails CI. Successes are printed so they can be turned
into new forbidden patterns + regression tests.
"""
