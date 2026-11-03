#!/usr/bin/env python3
"""Offline re-run of the script-analysis adapter, compared with answers the GM already graded.
Nothing is sent anywhere.

usage: offline_check.py single            # local Single bytes vs the GM-CORRECT single submit
       offline_check.py tt                # saved Time Trial bytes vs the proven Time Trial labels
"""
import json
import os
import sys

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges", "_lib"))
import autosolve_script as A  # noqa: E402

STAGE = os.path.join(ROOT, "challenges", "Day 15", "_stage", "Crumb_Trail")
REC = os.path.join(ROOT, "challenges", "Day 15", "_gm_record",
                   "script-analysis-day-15-credential-store-clues.homestation.jsonl")
TT_BLOB = ("[local path]"
           "/[id]/blob_0.bin")
# the 9 batch expansion labels the GM accepted in one submit on the Time Trial bytes (-> mode CORRECT)
TT_PROVEN = {"batch-benign-expansion": "percent", "batch-chain-expansion": "percent",
             "batch-downloader-expansion": "percent", "batch-dropper-expansion": "call_double",
             "batch-impact-expansion": "call_double", "batch-launcher-expansion": "percent",
             "batch-relay-expansion": "delayed", "batch-stager-expansion": "call_double",
             "batch-uploader-expansion": "call_double"}

which = sys.argv[1] if len(sys.argv) > 1 else "single"
task = json.load(open(os.path.join(STAGE, "task.json"), encoding="utf-8"))
blob = open(os.path.join(STAGE, "artifact_0.bin") if which == "single" else TT_BLOB, "rb").read()
start = {"answer_ids": task["answer_ids"], "questions": task["questions"]}

ans, un, bad, cand = A.solve_fields_ext(start, [blob])
print("%s: ids=%d answered=%d unresolved=%d cand=%d" % (which, len(start["answer_ids"]), len(ans), len(un), len(cand)))

lines = open(REC, encoding="utf-8").read().splitlines()
truth = dict(TT_PROVEN)
if which == "single":
    truth = json.loads(lines[4])["answers"]
else:
    truth.update({k: v for k, v in json.loads(lines[8])["answers"].items() if k not in TT_PROVEN})

bad_ids = [k for k in truth if ans.get(k) != truth[k]]
print("mismatch vs graded answers: %d" % len(bad_ids))
for k in sorted(bad_ids):
    print("  %-32s offline=%-14r graded=%r" % (k, ans.get(k), truth[k]))
