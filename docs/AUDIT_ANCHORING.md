# Signed Audit Anchoring

**The gap (reviews #4/#5, P1):** the hash chain makes the log *tamper-evident* — you can tell
if a line was edited. But a root attacker can **delete the whole log** or **replace it with a
fresh clean chain**, and a purely local chain can't prove "there used to be 1000 records, not 5".

**The fix (`sentinel/audit_anchor.py`):** signed, counted checkpoints.
- Every N records the log emits a checkpoint `{seq, count, chain_hash}` **signed** with a key the
  attacker doesn't have (HMAC by default; Ed25519 if `cryptography` is installed).
- Checkpoints carry a strictly increasing `count` and `seq`, so deletion leaves a gap and
  truncation makes the count go backwards.
- Checkpoints are shipped to a **remote append-only sink** (a `remote_sink` callback). At
  verification time the local file is cross-checked against the remote's highest `seq/count`,
  so even wiping the local file entirely is detected.

## Threats now detected
| Attack | Detected by |
|---|---|
| Edit a record | base hash chain (existing) |
| Forge/replace a checkpoint | signature check |
| Delete recent checkpoints | remote `expected_last_seq` cross-check |
| Truncate the log | count-goes-backwards + remote `expected_min_count` |
| Wipe the local log entirely | remote knew of checkpoints, local has none |

## Use
```python
from sentinel.responder import AuditLog
from sentinel.audit_anchor import Signer, RemoteAnchor
remote = RemoteAnchor()                      # replace with a real append-only remote store
audit = AuditLog("audit.jsonl").enable_checkpoints(
    "checkpoints.jsonl", Signer(hmac_key=KEY), every=50, remote_sink=remote)
# ... later, independently:
from sentinel.audit_anchor import verify_checkpoints
verify_checkpoints("checkpoints.jsonl", hmac_key=KEY,
                   expected_last_seq=remote.last_seq, expected_min_count=remote.last_count)
```

## Limits (honest)
- The signing key must live **off-host** (HSM / remote signer). If the attacker steals the key,
  they can forge checkpoints — this closes deletion/replacement, not key theft.
- `RemoteAnchor` here is an in-process stand-in; production needs a real append-only service
  the host cannot roll back (e.g. an external log store or a transparency log).
- Checkpoints bound *how much* was deleted to a window of N records; per-record remote shipping
  would be stronger but heavier.
