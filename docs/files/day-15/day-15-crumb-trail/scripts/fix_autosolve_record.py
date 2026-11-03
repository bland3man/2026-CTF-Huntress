#!/usr/bin/env python3
"""Put the GM's OWN time_trial result into the board's autosolve record.

The diagnostic probe path that completed the mode returned its own result label ('probed'), so the record
kept result=probed / flag=null for a mode the GM answered CORRECT. The values written here are read back
out of the GM transcript, not typed in.

usage: fix_autosolve_record.py
"""
import json
import os

ROOT = "[local path]"
CID = "script-analysis-day-15-credential-store-clues"
REC = os.path.join(ROOT, "challenges/Day 15/_gm_record", CID + ".homestation.jsonl")
BOARD = os.path.join(ROOT, "challenges/Day 15/_board", CID + ".autosolve.json")

win = None
for line in open(REC, encoding="utf-8"):
    if not line.strip():
        continue
    d = json.loads(line)
    if d.get("op") == "submit" and d.get("ch") == CID + "/time_trial" \
            and str((d.get("resp") or {}).get("result", "")).upper() == "CORRECT":
        win = d["resp"]

doc = json.load(open(BOARD, encoding="utf-8"))
doc["time_trial"] = {"result": "CORRECT", "flag": win["flag"],
                     "solved_by": (win.get("solved_by") or {}).get("name"), "ranked": False}
json.dump(doc, open(BOARD, "w", encoding="utf-8"), indent=1)
print(json.dumps(doc["time_trial"]))
