#!/usr/bin/env python3
"""Lane test: which op the ONE authorised timed write goes to, and when a dead Time Trial must not block Mastery.

Both behaviours were added on Day 12 (Pascal's Wager) and both are easy to regress silently, because each failure
costs a real attempt and only shows up live:

  autosolve_binary._first_op(pre, cid)
      When a FREE op=status read already says the current attempt is finished and the GM itself names
      next_op=practice, the single authorised timed write must BE that continuation: op=start would only RESUME the
      dead attempt, which still answers, so the client counts the gate pass's one write as spent and the op that
      would actually help is then refused. The verdict MUST be keyed by cid - one autosolve process walks several
      entries, op=status RAISES on an unstarted mode (409 start_required) and sets nothing, so an unkeyed global
      hands one entry's verdict to another (measured live: Mastery sent op=practice where op=start was correct).

  autosolve._gm_side_dead(err)
      "our solver was not ready" and "the GM has no variant left" are opposite situations. A Time Trial that lost
      its window to a 429 storm reads expired / unique_attempts_remaining=0, and BOTH documented heal ops answer
      409 retry_variants_unavailable: it can never become CORRECT by any call. Blocking Mastery on "the Time Trial
      is not CORRECT" then forfeits a mode we are measurably ready for, so only a readiness problem may block it.

ASCII only. Run: python3 challenges/_lib/_test_binary_first_op.py  -> must print RESULT: PASS
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import autosolve as A
import autosolve_binary as ab

TT = "chal/time_trial"
MA = "chal/mastery"
fails = []


def check(label, got, want):
    if got == want:
        print("PASS %s" % label)
    else:
        print("FAIL %s -> %r, expected %r" % (label, got, want))
        fails.append(label)


# ---- _first_op: the GM's own free reading decides the one write ----
check("expired + next_op=practice for THIS entry -> practice",
      ab._first_op((TT, {"result": "expired", "next_op": "practice"}), TT), "practice")
check("rotation_exhausted + next_op=practice -> practice",
      ab._first_op((TT, {"result": "rotation_exhausted", "next_op": "practice"}), TT), "practice")
check("a reading of ANOTHER entry never governs this one (the Day 12 leak)",
      ab._first_op((TT, {"result": "expired", "next_op": "practice"}), MA), "start")
check("no reading at all (status 409 start_required) -> start",
      ab._first_op(None, MA), "start")
check("a LIVE attempt is resumed with start, not practice",
      ab._first_op((TT, {"result": "in_progress", "next_op": "practice"}), TT), "start")
check("expired but the GM names no practice continuation -> start",
      ab._first_op((TT, {"result": "expired", "next_op": "retry"}), TT), "start")
check("a malformed reading degrades to start",
      ab._first_op("garbage", TT), "start")
check("2026-10-12: expired + unique_attempts_remaining 2 (the pool REFILLED) -> retry (start would only resume the corpse)",
      ab._first_op((TT, {"result": "expired", "next_op": "retry", "unique_attempts_remaining": 2}), TT), "retry")
check("a refilled pool wins over a stale next_op=practice",
      ab._first_op((TT, {"result": "expired", "next_op": "practice", "unique_attempts_remaining": 1}), TT), "retry")
check("expired + 0 left + next_op=practice stays practice (today's state)",
      ab._first_op((TT, {"result": "expired", "next_op": "practice", "unique_attempts_remaining": 0}), TT), "practice")
check("a LIVE attempt with attempts left is still resumed with start",
      ab._first_op((TT, {"result": "in_progress", "unique_attempts_remaining": 3}), TT), "start")
check("a bool or string count is never trusted",
      ab._first_op((TT, {"result": "expired", "next_op": "retry", "unique_attempts_remaining": True}), TT), "start")
# ---- _run_once really spends its ONE write on the retry when the pool refilled
calls = []


class _G:
    def retry(self, cid):
        calls.append("retry"); return {"answer_ids": ["a"], "deadline": None, "unique_attempts_remaining": 1}

    def start(self, cid, for_time=False):
        calls.append("start"); return {"answer_ids": ["a"], "deadline": None}

    def practice(self, cid):
        calls.append("practice"); return {"answer_ids": ["a"], "deadline": None}

    def artifacts(self, st):
        return [{"download": "x"}]

    def download(self, cid, e, i=0):
        return b"B"


_keep = (ab._prewarm, ab.analyse, ab._submit_all, ab.PRE[0])
ab._prewarm = lambda g, c, l, t=False: True        # real signature: _prewarm(gm, cid, log, for_time=False)
ab.analyse = lambda st, blobs: ({"a": "x"}, {}, {})
ab._submit_all = lambda *a, **k: {"result": "CORRECT"}
ab.PRE[0] = (TT, {"result": "expired", "next_op": "retry", "unique_attempts_remaining": 2})
try:
    ab._run_once(_G(), TT, lambda s: None)
finally:
    ab._prewarm, ab.analyse, ab._submit_all, ab.PRE[0] = _keep
check("_run_once sends exactly ONE write and it is the RETRY when the pool refilled", calls, ["retry"])

# ---- _gm_side_dead: only a readiness problem may block Mastery ----
check("retry_variants_unavailable is GM-side death",
      A._gm_side_dead('GM HTTP 409: {"error":"retry_variants_unavailable"}'), True)
check("rotation_exhausted is GM-side death",
      A._gm_side_dead("rotation_exhausted"), True)
check("prerequisite_required is NOT (it is a real ordering gate)",
      A._gm_side_dead('GM HTTP 409: {"error":"prerequisite_required"}'), False)
check("a lost window is NOT (the pool may still hold a variant)",
      A._gm_side_dead("timed window: 4.4s left, a 4.0s backoff would not leave 3s"), False)
check("an unready solver is NOT",
      A._gm_side_dead("HELD - 3 field(s) NOT solved locally"), False)
check("the repeat guard still carries the original error through",
      A._gm_side_dead('identical call refused 12s ago (GM HTTP 409: {"error":"retry_variants_unavailable"});'
                      ' NOT sent again for 48s'), True)

print("\nCOVERAGE: %d checks, %d failed" % (13, len(fails)))
print("RESULT: %s" % ("PASS" if not fails else "FAIL " + ", ".join(fails)))
sys.exit(1 if fails else 0)
