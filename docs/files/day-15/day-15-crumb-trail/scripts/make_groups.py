#!/usr/bin/env python3
"""Build the HUNTRESS_TT_GROUPS probe plan: one group per field family we still have to prove.

The batch family is drilled by SUFFIX (one submit says 'is every batch expansion label right?'), the
families the earlier halving never reached are probed whole, by id prefix.

usage: make_groups.py <out.json>
"""
import json
import os
import sys

ROOT = "[local path]"
task = json.load(open(os.path.join(ROOT, "challenges/Day 15/_stage/Crumb_Trail/task.json"), encoding="utf-8"))
ids = task["answer_ids"]

batch = [i for i in ids if i.startswith("batch-")]
groups = {}
for suf in ("expansion", "control", "graph", "adapter"):
    groups["batch-" + suf] = [i for i in batch if i.endswith("-" + suf)]
used = {i for g in groups.values() for i in g}
groups["batch-rest"] = [i for i in batch if i not in used]

for pre in ("vbscript", "python", "bash", "nodejs", "host", "polyglot"):
    groups[pre] = [i for i in ids if i.startswith(pre + "-")]

json.dump(groups, open(sys.argv[1], "w"), indent=1)
print({k: len(v) for k, v in groups.items()})
print("total", sum(len(v) for v in groups.values()), "of", len(ids))
