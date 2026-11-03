#!/usr/bin/env python3
"""Offline replay of the Day 17 Single Solve answers (NO GM call) so the writeup can quote real values."""
import json
import os
import sys

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges/_lib"))
STAGE = os.path.join(ROOT, "challenges/Day 17/_stage/Fetch_Quest")

import autosolve_script as AS  # noqa: E402

task = json.load(open(os.path.join(STAGE, "task.json"), encoding="utf-8"))
blob = open(os.path.join(STAGE, "artifact_0.bin"), "rb").read()
A, un, bad, cand = AS.solve_fields_ext(task, [blob])
print("resolved=%d unresolved=%d undecodable=%d" % (len(A), len(un), len(bad)))
if un:
    print("UNRESOLVED:", un[:20])
if bad:
    print("UNDECODABLE:", bad[:20])
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "single_answers.json")
json.dump(A, open(out, "w", encoding="utf-8"), indent=1, sort_keys=True)
print("wrote", out)
print()
show = [k for k in sorted(A) if k.split("-")[0] in ("resource", "collection", "impact")]
show += [k for k in sorted(A) if k.startswith("polyglot-auto_hotkey-")]
show += [k for k in sorted(A) if k.startswith("host-")][:12]
for k in show:
    v = str(A[k])
    print("%-52s %s" % (k, v[:120]))
