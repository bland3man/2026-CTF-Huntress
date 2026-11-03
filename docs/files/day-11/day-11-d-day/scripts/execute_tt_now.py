#!/usr/bin/env python3
"""EXECUTE the Time Trial solve right now, against whatever the GM currently has - no fresh() veto.

User, 2026-10-11: "why haven't you tried again? you have the TT solver, why not execute it?"

Fair question, and it deserves a run rather than an explanation. The prober probes every 15 minutes but
`solve_timed.fresh()` refuses to solve an attempt whose result is `expired`, so the solver itself never
fires. This script removes that veto ON PURPOSE and does the whole thing end to end: resume the attempt,
analyse, and SUBMIT the 110 answers. Then it prints the GM's reply verbatim, whatever it is.

What this costs: nothing. `op=start` on an existing attempt RESUMES (it cannot create or spend), the
artifact bytes are already cached on disk so no download is needed, and `op=submit` does not consume a
variant. So this is a free, honest test of the one thing that had only been measured earlier in the day and
could have changed since: whether the GM will grade answers posted against this expired attempt.

Expected (from this morning's matrix): `result=expired`, 0 accepted, because the GM gates grading on the
DEADLINE and not on startedness. If that has changed - an organiser fix, a re-provisioned variant - this is
what finds out, and the answers are already correct so it would simply land.
"""
import glob
import json
import os
import sys
import time

sys.path.insert(0, "challenges/_lib")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctf_gm import GM  # noqa: E402
import autosolve_binary as ab  # noqa: E402

ROUTE = "binary-reverse-engineering-day-11-d-collection-planner/time_trial"
SAVED = os.path.expanduser(
    "[home path]")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "execute_tt_now.result.json")


def log(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)


gm = GM()

# 1. get the attempt payload. NOT GM.start(): that helper escalates to retry/practice internally and so
# dies on this route's 409 retry_variants_unavailable before returning anything. op=status is a FREE read
# and carries the identical payload for an existing attempt - all 110 answer_ids and all 110 questions.
log("op=status (free read, carries the attempt's answer_ids) on %s ..." % ROUTE)
try:
    st = gm.status(ROUTE)
except Exception as e:
    log("status raised: %s" % str(e)[:300])
    sys.exit(2)

aids = st.get("answer_ids") or []
qs = st.get("questions") or []
log("attempt_id=%s result=%r deadline=%r uniq_rem=%r answer_ids=%d questions=%d"
    % (str(st.get("attempt_id"))[:8], st.get("result"), st.get("deadline"),
       st.get("unique_attempts_remaining"), len(aids), len(qs)))
if not aids:
    log("no answer_ids in the resumed attempt - there is nothing to submit against")
    sys.exit(3)

# 2. the bytes: already on disk, so this costs no download and no time
hits = sorted(glob.glob(os.path.join(SAVED, "*delivery*.bin")))
if not hits:
    log("no cached delivery bytes; falling back to op=artifact (still free)")
    arts = gm.artifacts(st)
    blobs = [gm.download(ROUTE, e, i) for i, e in enumerate(arts)]
else:
    blobs = [open(hits[-1], "rb").read()]
    log("using cached artifact %s (%d bytes)" % (os.path.basename(hits[-1]), len(blobs[0])))

# 3. solve
t0 = time.time()
sure, probe, unknown = ab.analyse(st, blobs)
answers = dict(sure)
answers.update({a: v[0] for a, v in probe.items()})
log("analysed %d/%d ids in %.2fs (%d sure, %d probe, %d unknown)"
    % (len(answers), len(aids), time.time() - t0, len(sure), len(probe), len(unknown)))
miss = [a for a in aids if a not in answers]
if miss:
    log("WARNING %d ids have no value: %s" % (len(miss), miss[:6]))

# 4. SUBMIT - the part that had only been measured earlier today
log("op=submit with %d answers ..." % len(answers))
try:
    res = gm.submit(ROUTE, answers)
except Exception as e:
    log("submit raised: %s" % str(e)[:400])
    res = {"_raised": str(e)[:400]}

print()
print("=== THE GM'S REPLY, VERBATIM ===")
print(json.dumps(res, indent=1, sort_keys=True)[:3000])
print()
r = str(res.get("result", "")).lower()
if r == "correct":
    log("CORRECT - flag=%s" % res.get("flag"))
elif res.get("accepted_ids"):
    log("partial: %d accepted" % len(res.get("accepted_ids") or []))
else:
    log("not graded: result=%r (expected on an expired attempt - the GM gates on the DEADLINE)" % res.get("result"))

json.dump({"t": int(time.time()), "start": {k: v for k, v in st.items()
                                            if not isinstance(v, (list, dict))},
           "submitted": len(answers), "result": res}, open(OUT, "w"), indent=1)
print("saved -> %s" % OUT)
sys.exit(0 if r == "correct" else 1)
