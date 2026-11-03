#!/usr/bin/env python3
"""Offline mastery rehearsal for Pascal's Wager (Day 12).

Mastery asks the SAME 26 field suffixes as the Time Trial but over three delivered archives,
with ids 'setN.dNN_<suffix>'. This feeds the real staged mastery contract (360 ids) to
autosolve_binary.compute() with the single-solve bytes repeated as the three sets, and reports
any id the adapter cannot answer, plus the wall time (the mastery window budget is seconds).

No GM calls. ASCII only.
"""
import json, os, sys, time

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges", "_lib"))
import autosolve_binary as ab

STAGE = os.path.join(ROOT, "challenges", "Day 12", "_stage", "Pascals_Wager")
c = json.load(open(os.path.join(STAGE, "contract_mastery.json")))
ids = c.get("answer_ids") or [q.get("id") for q in (c.get("questions") or [])]
blob = open(os.path.join(STAGE, "artifact_0.bin"), "rb").read()

nsets = len({str(i).split(".")[0] for i in ids if "." in str(i)}) or 1
start = dict(c)
start["answer_ids"] = ids

t0 = time.time()
ans = ab.compute(start, [blob] * nsets)
dt = time.time() - t0

missing = [i for i in ids if i not in ans or ans[i] in (None, "")]
print("sets           :", nsets)
print("fields asked   :", len(ids))
print("fields answered:", len(ans))
print("MISSING        :", (missing[:12] if missing else "none"), ("(%d total)" % len(missing)) if missing else "")
print("compute secs   : %.2f" % dt)
print()
for i in ids:
    if i.endswith("d12_analysis_config_campaign") or i.endswith("d12_analysis_hcfg_offset"):
        print("%-38s %s" % (i, ans.get(i, "<MISSING>")))
