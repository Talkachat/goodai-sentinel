"""Queryable spill store + backpressure strategies (enhancement #2)."""
import tempfile
from pathlib import Path
from sentinel.audit_store import AuditStore
from sentinel.audit_async import AsyncAuditLog

def test_spill_all_keeps_everything_and_is_queryable(tmp_path):
    st = AuditStore(str(tmp_path/"s.db"), strategy="spill_all")
    for i in range(100):
        st.write({"finding": {"severity": "high" if i % 10 == 0 else "low"}, "i": i})
    assert st.count() == 100
    assert st.count("high") == 10
    assert len(st.query(severity="high")) == 10
    assert st.verify()

def test_sample_low_never_drops_high_severity(tmp_path):
    st = AuditStore(str(tmp_path/"s.db"), strategy="sample_low", sample_rate=0.0)  # drop ALL low
    for i in range(500):
        st.write({"severity": "low", "i": i})
    for i in range(50):
        st.write({"severity": "critical", "i": i})
    assert st.count("low") == 0            # all low sampled out
    assert st.count("critical") == 50      # every critical kept
    assert st.sampled_out == 500
    assert st.verify()

def test_sample_low_keeps_some_low(tmp_path):
    st = AuditStore(str(tmp_path/"s.db"), strategy="sample_low", sample_rate=1.0)  # keep all
    for i in range(200): st.write({"severity": "low", "i": i})
    assert st.count("low") == 200

def test_async_audit_spills_high_severity_under_saturation(tmp_path):
    import threading
    a = AsyncAuditLog(tmp_path/"a.jsonl", flush_ms=50, max_queue=5,
                      spill_strategy="sample_low", sample_rate=0.0, backpressure_s=0.0)
    gate = threading.Event()
    orig_flush = a._flush
    a._flush = lambda batch: gate.wait()          # pause writer inside flush (not closed)
    try:
        for i in range(300):
            a.write({"finding": {"severity": "critical"}, "i": i})
        for i in range(300):
            a.write({"severity": "low", "i": i})
        assert a.spill_high_severity_kept() >= 1
        assert a.dropped == 0
        hi = a.spill_query(severity="critical", limit=10)
        assert all(r["severity"] == "critical" for r in hi)
    finally:
        gate.set(); a._flush = orig_flush; a.close()

def test_store_survives_reopen(tmp_path):
    p = str(tmp_path/"s.db")
    st = AuditStore(p); st.write({"severity": "high", "x": 1}); st.close()
    st2 = AuditStore(p); st2.write({"severity": "high", "x": 2})
    assert st2.count() == 2 and st2.verify()   # chain continues across reopen
