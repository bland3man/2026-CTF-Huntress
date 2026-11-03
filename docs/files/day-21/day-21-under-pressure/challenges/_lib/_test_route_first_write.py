#!/usr/bin/env python3
"""ONE first-write rule for every lane (2026-10-12): the GM's own free status names the first write. autosolve.first_op_from_status is a table; route_first_write makes the very next gm.start() of THIS
attempt be that op (one-shot), for lanes whose adapters know nothing about practice. Fake GM, no network, nothing written anywhere."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import autosolve as A

bad = 0


def ck(label, ok, detail=""):
    global bad
    print(("PASS " if ok else "FAIL ") + label + ((" (%s)" % (detail,)) if detail != "" else ""))
    bad += (not ok)


F = A.first_op_from_status
ck("a fresh route (no status dict, the 409 start_required case) -> start", F(None) == "start" and F("GM HTTP 409: start_required") == "start")
ck("a LIVE attempt (not expired) -> start (it only reconnects)", F({"result": "in_progress", "deadline": "2999-01-01T00:00:00Z", "unique_attempts_remaining": 3}) == "start")
ck("expired with fresh variants left (uar >= 1) -> retry, even if next_op names something else", F({"result": "expired", "unique_attempts_remaining": 2, "next_op": "practice"}) == "retry")
ck("expired, none left, next_op practice (Day 11 D-Day / Day 12 Pascal's Wager at 16:04) -> practice", F({"result": "expired", "unique_attempts_remaining": 0, "next_op": "practice"}) == "practice")
ck("rotation_exhausted, none left, next_op practice -> practice", F({"result": "rotation_exhausted", "unique_attempts_remaining": 0, "next_op": "practice"}) == "practice")
ck("expired, none left, NO next_op -> start (never guess; the GM answers what it means)", F({"result": "expired", "unique_attempts_remaining": 0}) == "start")
ck("a bool or string pool count is never trusted as 'fresh variants left'", F({"result": "expired", "unique_attempts_remaining": True, "next_op": "practice"}) == "practice" and F({"result": "expired", "unique_attempts_remaining": "3"}) == "start")
ck("a CORRECT result -> start (nothing to continue)", F({"result": "CORRECT", "unique_attempts_remaining": 0, "next_op": None}) == "start")
ck("Day 21 warmups mastery: expired, 255 variants left, NO next_op -> retry (fallback uses this same rule)", F({"result": "expired", "unique_attempts_remaining": 255, "deadline": "2026-10-21T13:04:38.066Z"}) == "retry")


class GM:
    def __init__(self):
        self.calls = []

    def start(self, challenge, for_time=False):
        self.calls.append(("start", challenge))
        return {"answer_ids": ["a"], "deadline": None}

    def retry(self, challenge):
        self.calls.append(("retry", challenge))
        return {"answer_ids": ["a"], "deadline": None, "from": "retry"}

    def practice(self, challenge):
        self.calls.append(("practice", challenge))
        return {"answer_ids": ["a"], "deadline": None, "practice": True}


said = []
g = GM()
op = A.route_first_write(g, "warmups-day-13/time_trial", {"result": "expired", "unique_attempts_remaining": 0, "next_op": "practice"}, said.append)
r1 = g.start("warmups-day-13/time_trial")
r2 = g.start("warmups-day-13/time_trial")
ck("status expired + next_op practice: the FIRST start() becomes practice(), the second is the real start() again (one-shot)", op == "practice" and g.calls == [("practice", "warmups-day-13/time_trial"), ("start", "warmups-day-13/time_trial")] and r1.get("practice") is True, str(g.calls))
ck("it says out loud why (agents and the Commander can read the line)", said and "op=practice" in said[0] and "not start" in said[0], said[:1])
g = GM()
op = A.route_first_write(g, "x-day-13/mastery", {"result": "expired", "unique_attempts_remaining": 1, "next_op": "retry"}, said.append)
g.start("x-day-13/mastery")
ck("expired with a fresh variant left: the first start() becomes retry()", op == "retry" and g.calls == [("retry", "x-day-13/mastery")], str(g.calls))
g = GM()
op = A.route_first_write(g, "x-day-13/time_trial", None, said.append)
g.start("x-day-13/time_trial")
ck("no status / fresh route: nothing is overridden, the first write is the real start()", op == "start" and g.calls == [("start", "x-day-13/time_trial")] and "start" not in g.__dict__)
g = GM()
g.start = lambda challenge, for_time=False: g.calls.append(("own-start", challenge)) or {"answer_ids": []}      # a test double with its own instance start()
A.route_first_write(g, "y-day-13/time_trial", {"result": "expired", "unique_attempts_remaining": 0, "next_op": "practice"}, said.append)
g.start("y-day-13/time_trial")
g.start("y-day-13/time_trial")
ck("an instance-level start() is restored too after the one-shot", [c[0] for c in g.calls] == ["practice", "own-start"], str(g.calls))
src = open(os.path.join(HERE, "autosolve.py"), "rb").read().decode("utf-8")
ck("attempt() routes every non-binary lane's first timed write through the rule, after the pre-start status read", src.index("prewarm_ranked(gm, entry, say)\n                route_first_write(") > 0 and "not hasattr(mod, \"_prewarm\")" in src)
ck("the binary adapter keeps its own tested rule (its run() reads the status itself) and is NOT double-routed", "def _first_op" in open(os.path.join(HERE, "autosolve_binary.py"), "rb").read().decode("utf-8"))
print("RESULT:", "PASS" if not bad else "FAIL")
sys.exit(1 if bad else 0)
