#!/usr/bin/env python3
"""Offline coverage + timing check for Pascal's Wager (Day 12, binary-reverse-engineering).

Runs autosolve_binary.compute() against the STAGED single-solve bytes with a synthetic
start dict, and reports: any answer_id the adapter cannot answer, plus wall time.
No GM calls. ASCII only.
"""
import json, os, sys, time

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges", "_lib"))
import autosolve_binary as ab

STAGE = os.path.join(ROOT, "challenges", "Day 12", "_stage", "Pascals_Wager")
task = json.load(open(os.path.join(STAGE, "task.json")))
ids = task["answer_ids"]
blob = open(os.path.join(STAGE, "artifact_0.bin"), "rb").read()

start = dict(task)
start["answer_ids"] = ids

t0 = time.time()
try:
    ans = ab.compute(start, [blob])
except Exception as e:
    print("COMPUTE RAISED:", type(e).__name__, e)
    raise
dt = time.time() - t0

missing = [i for i in ids if i not in ans or ans[i] in (None, "")]
print("fields asked   :", len(ids))
print("fields answered:", len(ans))
print("MISSING        :", missing if missing else "none")
print("compute secs   : %.2f" % dt)
print()
for i in ids:
    if i.startswith("d12") or i.startswith("d11"):
        v = ans.get(i, "<MISSING>")
        print("%-34s %s" % (i, v if len(str(v)) < 110 else str(v)[:107] + "..."))
