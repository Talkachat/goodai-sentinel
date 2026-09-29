"""GoodAI Sentinel — an open, embeddable defensive AI module.

Pipeline:  Sensors -> Detector (rules + baseline anomaly) -> Guardrail (policy)
           -> Responder (graded, human-in-the-loop actions) -> Audit log
"""
__version__ = "0.4.6"
