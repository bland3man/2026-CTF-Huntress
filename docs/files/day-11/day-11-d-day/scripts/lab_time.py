#!/usr/bin/env python3
"""Offline lab: time autosolve_binary.analyse on the EXPIRED time_trial attempt's own saved bytes,
using the expired attempt's real answer_ids/questions (op=start returns them even when expired)."""
import glob, json, os, sys, time
sys.path.insert(0, "challenges/_lib")
import autosolve_binary as ab

qs = json.load(open("challenges/Day 11/D-Day/scripts/questions_start.json"))
aids = [q.get("answer_id") or q.get("id") for q in qs] if isinstance(qs[0], dict) else list(qs)
start = {"answer_ids": aids, "questions": qs}
d = os.path.expanduser("[home path]")
paths = sorted(glob.glob(os.path.join(d, "*_delivery*.bin")))
print("blobs:", [(os.path.basename(p), os.path.getsize(p)) for p in paths], flush=True)
blobs = [open(p, "rb").read() for p in paths]
t0 = time.time()
sure, probe, unknown = ab.analyse(start, blobs)
el = time.time() - t0
print("ANALYSE %.2fs -> %d sure, %d probe, %d unknown (of %d ids)" % (el, len(sure), len(probe), len(unknown), len(aids)), flush=True)
if unknown:
    print("UNKNOWN:", sorted(unknown))
if probe:
    print("PROBE:", {a: c[:3] for a, c in probe.items()})
miss = [a for a in aids if a not in sure and a not in probe and a not in unknown]
if miss:
    print("NOT PRODUCED AT ALL (%d):" % len(miss), miss)
json.dump({"sure": sure, "probe": {k: v for k, v in probe.items()}, "unknown": list(unknown)},
          open("challenges/Day 11/D-Day/scripts/lab_answers.json", "w"), indent=1, default=str)
print("saved lab_answers.json", flush=True)
