#!/usr/bin/env python3
"""The timed window is a HARD budget: autosolve_binary's 429 backoff must never sleep past an attempt's
deadline (Day 11 D-Day, the failure this guards). Offline, zero GM credit, ASCII only."""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import autosolve_binary as ab  # noqa: E402

passes, bad = 0, []


def check(name, cond, extra=""):
    global passes
    if cond:
        passes += 1
        print("PASS", name)
    else:
        bad.append(name)
        print("FAIL", name, extra)


def iso(secs_from_now):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + secs_from_now))


# --- _window parses the deadline, and an untimed start clears it
ab._window({"deadline": iso(30)})
left = ab._left()
check("a 30s window is parsed to ~30s remaining", left is not None and 25 <= left <= 32, "left=%r" % left)
ab._window({})
check("a start with no deadline means no window (untimed keeps the old behaviour)", ab._left() is None)
ab._window({"deadline": "not-a-date"})
check("an unparseable deadline degrades to no window, it never crashes the solve", ab._left() is None)


class Storm(object):
    """Answers 429 forever, like the 09:00 release storm."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *a):
        self.calls += 1
        raise RuntimeError("GM HTTP 429: b'{\"error\":\"rate_limited\"}'")


# --- inside a nearly-closed window, _gm must abandon instead of sleeping past the deadline
ab._window({"deadline": iso(2)})
s = Storm()
t0 = time.time()
try:
    ab._gm(s)
    outcome = "returned"
except ab.Expired:
    outcome = "Expired"
except RuntimeError:
    outcome = "RuntimeError"
el = time.time() - t0
check("a 429 inside a closing window raises Expired (not 40 sleeps)", outcome == "Expired", "outcome=%s" % outcome)
check("and it gives up immediately rather than burning the window", el < 1.0 and s.calls == 1,
      "elapsed=%.2fs calls=%d" % (el, s.calls))

# --- the D-Day regression itself: a window must not be slept away. 6s (not the real 30s) keeps the test
# fast while proving the same property: the backoff abandons the attempt before the deadline passes.
ab._window({"deadline": iso(6)})
s2 = Storm()
t0 = time.time()
try:
    ab._gm(s2)
    outcome2 = "returned"
except ab.Expired:
    outcome2 = "Expired"
except RuntimeError:
    outcome2 = "RuntimeError"
el2 = time.time() - t0
check("D-Day regression: a timed window is abandoned before the deadline, never slept through",
      outcome2 == "Expired" and el2 < 5.5, "outcome=%s elapsed=%.1fs" % (outcome2, el2))
check("the guard leaves time for download + analyse + submit (analyse needs ~2.2s)",
      el2 <= 6.0 - ab._GUARD_SECS + 0.5, "elapsed=%.1fs guard=%.1f" % (el2, ab._GUARD_SECS))

# --- untimed: the original 429 tolerance is preserved
ab._window(None)


class TwoThenOk(object):
    def __init__(self):
        self.calls = 0

    def __call__(self, *a):
        self.calls += 1
        if self.calls <= 2:
            raise RuntimeError("GM HTTP 429: rate_limited")
        return {"result": "CORRECT"}


t = TwoThenOk()
r = ab._gm(t)
check("untimed: 429s are still retried to success (no window = no budget)",
      r == {"result": "CORRECT"} and t.calls == 3, "calls=%d r=%r" % (t.calls, r))


class Other(object):
    def __call__(self, *a):
        raise RuntimeError("GM HTTP 409: timed_intent_not_available")


ab._window({"deadline": iso(30)})
try:
    ab._gm(Other())
    outcome3 = "returned"
except ab.Expired:
    outcome3 = "Expired"
except RuntimeError as e:
    outcome3 = "RuntimeError"
check("a non-429 error still propagates unchanged (the guard only governs 429 backoff)",
      outcome3 == "RuntimeError", "outcome=%s" % outcome3)
ab._window(None)

# --- _prewarm: prove the GM is responsive BEFORE a timed window opens
class GMStatus(object):
    """A GM stand-in whose op=status behaviour is scripted."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = 0

    def status(self, cid):
        self.calls += 1
        if self.behaviour == "ok":
            return {"result": "expired", "unique_attempts_remaining": 247}
        if self.behaviour == "empty":
            return {"result": "expired", "unique_attempts_remaining": 0}
        if self.behaviour == "409":
            raise RuntimeError("GM HTTP 409: start_required")
        raise RuntimeError("GM HTTP 429: rate_limited")


g = GMStatus("ok")
check("prewarm probes op=status before a TIMED start",
      ab._prewarm(g, "binary-x-day-11/time_trial", lambda m: None) is True and g.calls == 1,
      "calls=%d" % g.calls)

g = GMStatus("ok")
check("prewarm does NOT spend a call on an untimed route",
      ab._prewarm(g, "binary-x-day-11", lambda m: None) is True and g.calls == 0, "calls=%d" % g.calls)

g = GMStatus("409")
check("a 409 (start_required) counts as responsive: mastery is not blocked by its own gate",
      ab._prewarm(g, "binary-x-day-11/mastery", lambda m: None) is True, "")

g = GMStatus("429")
msgs = []
ab._window(None)
_real_sleep = ab.time.sleep
ab.time.sleep = lambda s: None          # the property under test is the call count, not the wall clock
check("a GM still in the 429 storm is reported, so a timed window is never opened blind",
      ab._prewarm(g, "binary-x-day-11/time_trial", msgs.append) is False and g.calls == 40,
      "calls=%d msgs=%r" % (g.calls, msgs[:1]))
ab.time.sleep = _real_sleep
ab._window(None)

# --- the pool-depth read: is a lost window recoverable, or is this a one-shot?
g = GMStatus("ok")
ab.POOL[0] = None
ab._prewarm(g, "binary-x-day-11/time_trial", lambda m: None)
check("prewarm records the untimed pool depth from op=status", ab.POOL[0] == 247, "POOL=%r" % ab.POOL[0])

g = GMStatus("empty")
msgs = []
ab.POOL[0] = None
ab._prewarm(g, "binary-x-day-11/time_trial", msgs.append)
check("an EMPTY untimed pool (0) is detected and warned about BEFORE the window opens",
      ab.POOL[0] == 0 and any("ONE-SHOT" in m for m in msgs), "POOL=%r msgs=%r" % (ab.POOL[0], msgs))
check("the warning names the real deadlock, so the 409 is never a mystery again",
      any("unique_attempts_remaining=0" in m for m in msgs), "msgs=%r" % msgs)
ab.POOL[0] = None

try:
    import adapter_coverage as AC
    AC.record("binary_timed_budget", passes, passes + len(bad), not bad)
except Exception:
    pass
print("RESULT:", "PASS" if not bad else "FAIL")
sys.exit(1 if bad else 0)
