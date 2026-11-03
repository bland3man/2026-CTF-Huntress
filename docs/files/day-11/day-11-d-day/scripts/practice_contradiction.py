#!/usr/bin/env python3
"""ONE call with the EXACT documented minimal body for op=practice, to settle whether the GM honours its own
documented untimed fallback.

Why this matters. The GM's own guidance text, returned verbatim in every response for this challenge, says:

  "For timed modes, start reconnects to the same attempt; only retry spends one of the
   unique_attempts_remaining. After all fresh variants are used, practice continues on the last artifact
   WITHOUT A TIMER or Hall of Fame time AND CAN STILL COMPLETE THE MODE."

That is a precise description of our state - all fresh variants used (unique_attempts_remaining = 0) - and the
attempt's own `next_op` field says `practice`. The saved openapi agrees that practice is the "legacy
continuation operation" and that its body is just {op, challenge}. If the documentation is right, practice is
the untimed path that completes Time Trial today with no window at all.

Measured repeatedly instead: `409 retry_variants_unavailable`. This script removes every possible excuse for
that - no client helper, no extra properties, the exact two documented fields, one call per target - so the
discrepancy can be reported to the organisers as a GM-side contradiction rather than as our mistake.

Zero variants at risk: a 409 spends nothing, and practice cannot spend what the pool does not have.
"""
import json
import sys
import time

sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM  # noqa: E402

BASE = "binary-reverse-engineering-day-11-d-collection-planner"
TARGETS = [BASE + "/time_trial", BASE + "/mastery", BASE]


def raw(gm, body):
    """One POST with EXACTLY this body. No helper, no added properties, 429-aware only."""
    blob = json.dumps(body, separators=(",", ":")).encode()
    hdr = {"Content-Type": "application/json"}
    if gm._tok:
        hdr["Authorization"] = "Bearer " + gm._tok
    for i in range(6):
        gm._reconnect()
        gm._c.request("POST", gm.path, body=blob, headers=hdr)
        r = gm._c.getresponse()
        d = r.read()
        if r.status == 429:
            time.sleep(1.2 + 0.8 * i)
            continue
        try:
            return r.status, json.loads(d)
        except ValueError:
            return r.status, {"_raw": d[:200].decode("utf-8", "replace")}
    return r.status, {"_raw": "rate_limited_persisted"}


gm = GM()
print("The GM's documented promise, from its own guidance field:")
print("  'After all fresh variants are used, practice continues on the last artifact without a timer")
print("   or Hall of Fame time and can still complete the mode.'")
print()

rows = []
for t in TARGETS:
    body = {"op": "practice", "challenge": t}          # EXACTLY the documented minimal body
    code, j = raw(gm, body)
    scal = {k: v for k, v in j.items() if not isinstance(v, (list, dict))}
    keep = {k: scal.get(k) for k in ("error", "result", "next_op", "unique_attempts_remaining",
                                     "deadline", "attempt_id") if k in scal}
    ids = len(j.get("answer_ids") or [])
    rows.append((t, code, keep, ids))
    print("POST %s" % json.dumps(body, separators=(",", ":")))
    print("  -> HTTP %s  %s  answer_ids=%d" % (code, json.dumps(keep, sort_keys=True), ids))
    print()
    time.sleep(1.5)

print("=== VERDICT ===")
honoured = [t for t, c, k, i in rows if c == 200 and str(k.get("result", "")).lower() != "expired"]
if honoured:
    print("practice IS honoured on: %s - the untimed path is open, solve it now." % honoured)
else:
    print("practice is REFUSED on every target, with the exact documented body and no extra properties.")
    print("So the live GM CONTRADICTS its own guidance text and its own next_op hint for this challenge:")
    print("  guidance says practice continues untimed after the fresh variants are used and can still")
    print("  complete the mode; next_op says 'practice'; the call answers 409 retry_variants_unavailable,")
    print("  an error about RETRY variants, for an operation documented as needing none.")
    print("This is a GM-SIDE defect to report to the organisers, not a client error on our side.")
json.dump([{"target": t, "http": c, "fields": k, "answer_ids": i} for t, c, k, i in rows],
          open("challenges/Day 11/D-Day/scripts/practice_contradiction.result.json", "w"), indent=1)
print("saved -> challenges/Day 11/D-Day/scripts/practice_contradiction.result.json")
