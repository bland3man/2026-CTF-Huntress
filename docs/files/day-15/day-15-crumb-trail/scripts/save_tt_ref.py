#!/usr/bin/env python3
"""Freeze the GM-ACCEPTED answer set of the Day 15 time_trial attempt as a regression reference:
the full batch we sent, with the 9 batch expansion labels replaced by the ones the GM accepted
in the submit that completed the mode.

usage: save_tt_ref.py
"""
import json
import os

ROOT = "[local path]"
REC = os.path.join(ROOT, "challenges/Day 15/_gm_record",
                   "script-analysis-day-15-credential-store-clues.homestation.jsonl")
OUT = os.path.join(ROOT, "challenges/Day 15/Crumb Trail/scripts/tt_accepted_answers.json")

PROVEN = {"batch-benign-expansion": "percent", "batch-chain-expansion": "percent",
          "batch-downloader-expansion": "percent", "batch-dropper-expansion": "call_double",
          "batch-impact-expansion": "call_double", "batch-launcher-expansion": "percent",
          "batch-relay-expansion": "delayed", "batch-stager-expansion": "call_double",
          "batch-uploader-expansion": "call_double"}

ans = None
for line in open(REC, encoding="utf-8"):
    if not line.strip():
        continue
    d = json.loads(line)
    if d.get("op") == "submit" and d.get("ch", "").endswith("/time_trial") and len(d.get("answers") or {}) > 1000:
        ans = d["answers"]
ans.update(PROVEN)
json.dump(ans, open(OUT, "w"), indent=1, sort_keys=True)
print("wrote", OUT, len(ans), "answers")
