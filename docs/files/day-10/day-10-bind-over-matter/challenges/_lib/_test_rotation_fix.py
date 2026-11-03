#!/usr/bin/env python3
"""Offline PROOF that training_rotation_invalid self-fixes (never blind-retries), for BOTH code paths that call
GM start on a timed route. Mocks _post so no network/GM credit is used. Run: python3 challenges/_lib/_test_rotation_fix.py
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ok = True


def check(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name, extra)


# ---- 1. ctf_gm.py's GM.start() ----
import ctf_gm


class FakeGM(ctf_gm.GM):
    def __init__(self):
        self.calls = []
        self._fail_once = True

    def _post(self, **pl):
        self.calls.append(dict(pl))
        if pl.get("op") == "start" and pl["challenge"].endswith("/mastery") and not pl.get("run_for_time") and self._fail_once:
            self._fail_once = False
            raise RuntimeError('GM HTTP 503: b\'{"error":"training_rotation_invalid"}\'')
        return {"result": "CORRECT", "answer_ids": ["x"], "questions": []}

    def retry(self, cid):
        self.calls.append({"op": "retry", "challenge": cid})


# CONTRACT CHANGE (D31 reconcile 2026-10-30): GM.start no longer converts a plain start into a ranked one on its own
# (ctf_gm._start_inner: "do not reinterpret a rejected ranked request as a different mode"; the route contract and
# autosolve._attempt_inner decide - covered by _test_hof_activation / _test_hof_skipped_routes_retry / _test_timed_slot).
# GM.start must make exactly ONE call and surface the error: no blind repeat, no silent mode switch.
g = FakeGM()
_err = None
try:
    st = g.start("warmups-day-09/mastery")
except RuntimeError as _e:
    _err = str(_e)
check("GM.start() on 503 training_rotation_invalid makes exactly ONE call (no blind repeat, no silent ranked switch)",
      g.calls == [{"op": "start", "challenge": "warmups-day-09/mastery"}], "calls=%r" % g.calls)
check("GM.start() surfaces training_rotation_invalid to the caller", bool(_err) and "training_rotation_invalid" in _err, _err)

# ---- 2. autosolve_script.py's own start() (confirmed bypass of GM.start - this is the one that was broken) ----
import autosolve_script as AS


class FakeGM2:
    def __init__(self):
        self.calls = []
        self._fail_once = True

    def _post(self, **pl):
        self.calls.append(dict(pl))
        if pl.get("op") == "start" and pl["challenge"].endswith("/time_trial") and not pl.get("run_for_time") and self._fail_once:
            self._fail_once = False
            raise RuntimeError('GM HTTP 503: b\'{"error":"training_rotation_invalid"}\'')
        return {"result": "CORRECT", "answer_ids": ["x"], "questions": []}

    def retry(self, cid):
        self.calls.append({"op": "retry", "challenge": cid})


g2 = FakeGM2()
st2 = AS.start(g2, "script-analysis-day-09-foo/time_trial")
check("autosolve_script.py's start() ALSO self-fixes training_rotation_invalid (this was the real Day 08 bug)",
      len(g2.calls) == 2 and not g2.calls[0].get("run_for_time") and g2.calls[1].get("run_for_time") is True,
      "calls=%r" % g2.calls)
check("autosolve_script.py's start() returns the successful result", st2 is not None and st2.get("result") == "CORRECT")

# ---- 3. ground-truth-check still works independently: an already-solved mode returns None, no infinite loop ----
class FakeGM3:
    def _post(self, **pl):
        return {"result": "CORRECT", "answer_ids": None, "questions": []}  # already solved shape


st3 = AS.start(FakeGM3(), "x/mastery")
check("autosolve_script.py's start() returns None (not a retry loop) on an already-solved mode", st3 is None)

# ---- 4. transport-layer self-heal in ctf_gm._call: 429/503 back off + RETRY, not surface as a wrong answer ----
import http.client


class FakeResp:
    def __init__(self, status, body):
        self.status = status; self._b = body

    def read(self):
        return self._b

    def getheader(self, h):
        return None


class FakeConn:
    def __init__(self):
        self.n = 0

    def request(self, *a, **k):
        pass

    def getresponse(self):
        self.n += 1
        return FakeResp(503, b'{"error":"busy"}') if self.n == 1 else FakeResp(200, b'{"ok":true}')

    def close(self):
        pass


g4 = ctf_gm.GM.__new__(ctf_gm.GM)
g4.host = "x"; g4.path = "/"; g4.timeout = 5; g4._tok = None; g4._c = FakeConn()
try:
    d = g4._call("GET", ctf_gm.GM_PATH + "?op=list")
    check("ctf_gm._call retries a 503 instead of raising (transport self-heal, not a false wrong-answer)",
          b'"ok":true' in d, "got=%r" % d)
except Exception as e:
    check("ctf_gm._call retries a 503 instead of raising", False, "raised %r" % e)


# ---- 4b. the SAME retry covers 429 (the release-burst concern): back off + retry, recover, never stop ----
class FakeConn429:
    def __init__(self):
        self.n = 0

    def request(self, *a, **k):
        pass

    def getresponse(self):
        self.n += 1
        return FakeResp(429, b'{"error":"rate_limited"}') if self.n <= 2 else FakeResp(200, b'{"ok":true}')

    def close(self):
        pass


g4b = ctf_gm.GM.__new__(ctf_gm.GM)
g4b.host = "x"; g4b.path = "/"; g4b.timeout = 5; g4b._tok = None; g4b._c = FakeConn429()
try:
    d = g4b._call("GET", ctf_gm.GM_PATH + "?op=list")
    check("ctf_gm._call retries TWO 429s then succeeds (GM poll self-heals a release-burst rate-limit, never stops)",
          b'"ok":true' in d and g4b._c.n == 3, "got=%r after %d calls" % (d, g4b._c.n))
except Exception as e:
    check("ctf_gm._call retries 429 instead of raising", False, "raised %r" % e)

# ---- 5. a genuinely UNKNOWN error is NOT silently swallowed - it raises so the agent reads+branches, not loops ----
class FakeConn2:
    def request(self, *a, **k):
        pass

    def getresponse(self):
        return FakeResp(400, b'{"error":"some_brand_new_error_class"}')

    def close(self):
        pass


g5 = ctf_gm.GM.__new__(ctf_gm.GM)
g5.host = "x"; g5.path = "/"; g5.timeout = 5; g5._tok = None; g5._c = FakeConn2()
raised = False
try:
    g5._call("GET", ctf_gm.GM_PATH + "?op=list")
except RuntimeError:
    raised = True
check("an UNKNOWN 4xx error raises (agent must read+branch/surface, not blind-retry or silently pass)", raised)

# ---- 6. LEGACY (single-pool) TIMED ROUTE, measured live Day 10: run_for_time is rejected outright (409
#         timed_intent_not_available for true AND false), while the same start with the property OMITTED opens a
#         normal, hall_of_fame_eligible attempt. Both ranked code paths must DROP the property, not raise.
LEGACY_OK = {"result": "started", "answer_ids": ["x"], "questions": [], "hall_of_fame_eligible": True,
             "unique_attempts_remaining": 31}


class FakeLegacy(ctf_gm.GM):
    """409s any start that carries run_for_time at all; succeeds when it is omitted."""

    def __init__(self):
        self.calls = []

    def _post(self, **pl):
        self.calls.append(dict(pl))
        if pl.get("op") == "start" and "run_for_time" in pl:
            raise RuntimeError('GM HTTP 409: b\'{"error":"timed_intent_not_available"}\'')
        return dict(LEGACY_OK)

    def retry(self, cid):
        self.calls.append({"op": "retry", "challenge": cid})
        return dict(LEGACY_OK)


# CONTRACT CHANGE (D31 reconcile): GM.start(for_time=True) sends the ranked request ONCE and surfaces a 409; it no longer
# reissues a plain start itself. autosolve._attempt_inner falls back to an untimed solve on ANY ranked failure
# (covered by _test_hof_activation / _test_timed_slot). autosolve_script.start keeps its own drop-and-retry (6b below).
g6 = FakeLegacy()
_err6 = None
try:
    g6.start("script-analysis-day-10-wmi-persistence-reconstruction/time_trial", for_time=True)
except RuntimeError as _e:
    _err6 = str(_e)
check("GM.start(for_time=True) on 409 timed_intent_not_available makes exactly ONE call and surfaces the 409 (caller falls back)",
      len(g6.calls) == 1 and g6.calls[0].get("op") == "start" and bool(_err6) and "timed_intent_not_available" in _err6,
      "calls=%r err=%r" % (g6.calls, _err6))

g6b = FakeLegacy()
st6b = AS.start(g6b, "script-analysis-day-10-wmi-persistence-reconstruction/mastery", for_time=True)
check("autosolve_script.start(for_time=True) ALSO drops run_for_time on 409 timed_intent_not_available",
      st6b is not None and st6b.get("answer_ids") == ["x"] and len(g6b.calls) == 2
      and g6b.calls[0].get("run_for_time") is True and "run_for_time" not in g6b.calls[1],
      "calls=%r" % g6b.calls)


# ---- 6b. a DUAL-pool route must still open RANKED first (the fallback above must not weaken Hall of Fame) ----
class FakeDual(ctf_gm.GM):
    def __init__(self):
        self.calls = []

    def _post(self, **pl):
        self.calls.append(dict(pl))
        return dict(LEGACY_OK)

    def retry(self, cid):
        self.calls.append({"op": "retry", "challenge": cid})
        return dict(LEGACY_OK)


g7 = FakeDual()
g7.start("warmups-day-10/time_trial", for_time=True)
check("GM.start(for_time=True) still sends run_for_time ONCE and stops on a healthy dual-pool route",
      len(g7.calls) == 1 and g7.calls[0].get("run_for_time") is True, "calls=%r" % g7.calls)

g7b = FakeDual()
AS.start(g7b, "script-analysis-day-10-foo/time_trial", for_time=True)
check("autosolve_script.start(for_time=True) still sends run_for_time ONCE on a healthy dual-pool route",
      len(g7b.calls) == 1 and g7b.calls[0].get("run_for_time") is True, "calls=%r" % g7b.calls)

print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
