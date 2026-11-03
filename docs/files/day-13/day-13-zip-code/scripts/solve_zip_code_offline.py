"""Offline reproduction of the Day 13 'Zip Code' Single Solve answer set.

No Game Master call: it feeds the on-disk task.json (the Single start payload) and
artifact_0.bin straight into the banked lane adapter, so the writeup can quote real
recovered values and prove 100 percent field coverage.

Run from the framework root:
  wsl --cd <root> python3 -I "challenges/Day 13/Zip Code/scripts/solve_zip_code_offline.py"
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.abspath("challenges/_lib"))
import autosolve_script as A  # noqa: E402

ROOT = "challenges/Day 13/_stage/Zip_Code"
start = json.load(open(os.path.join(ROOT, "task.json"), encoding="utf-8"))
blobs = [open(os.path.join(ROOT, "artifact_0.bin"), "rb").read()]

answers, unresolved, undecodable = A.solve_fields(start, blobs)

ids = start.get("answer_ids") or []
print("answer_ids in task : %d" % len(ids))
print("answered by adapter: %d" % len(answers))
print("unresolved         : %d %s" % (len(unresolved), unresolved[:20]))
print("undecodable files  : %s" % (undecodable or "none"))

if len(sys.argv) > 1 and sys.argv[1] == "--show":
    want = sys.argv[2] if len(sys.argv) > 2 else "host-"
    for k in sorted(answers):
        if k.startswith(want):
            print("  %-46s %s" % (k, str(answers[k])[:120]))

suffix = collections.Counter(k.rsplit("-", 1)[-1] for k in answers)
print("\nanswered by question suffix:",
      dict(sorted(suffix.items(), key=lambda kv: -kv[1])))
