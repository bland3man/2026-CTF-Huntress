#!/usr/bin/env python3
"""Offline diagnostic for Day 09 Nimble: show what autosolve_binary cannot answer and the file inventory."""
import json, os, sys

sys.path.insert(0, "challenges/_lib")
import autosolve_binary as A
from ctf_gm import unzip

TASK = "challenges/Day 09/_stage/Nimble/task.json"
ART = "challenges/Day 09/_stage/Nimble/artifact_0.bin"

task = json.load(open(TASK))
aids = task.get("answer_ids") or [q["id"] for q in task["questions"]]
blob = open(ART, "rb").read()
files = unzip(blob)
print("members:")
for n, c in files:
    print("  %-34s %9d %s" % (os.path.basename(n), len(c), A.kind(c)))

start = {"answer_ids": aids}
sure, probe, unknown = A.analyse(start, [blob])
print("\nsure=%d probe=%d unknown=%d" % (len(sure), len(probe), len(unknown)))
for a, r in sorted(unknown.items()):
    print("UNKNOWN %s : %s" % (a, r))
for a, c in sorted(probe.items()):
    print("PROBE   %s : %s" % (a, c))
json.dump(sure, open("challenges/Day 09/Nimble/scripts/sure.json", "w"), indent=1)
