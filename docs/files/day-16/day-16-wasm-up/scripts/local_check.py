"""Offline check of the Day 16 (Wasm Up) adapter: run autosolve_binary.analyse() on the saved task
contract + the Single's artifact bytes and print what is sure / probe / unknown. No GM call at all."""
import json
import os
import sys

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges/_lib"))
import autosolve_binary as ab  # noqa: E402

stage = os.path.join(ROOT, "challenges/Day 16/_stage/Wasm_Up")
task = json.load(open(os.path.join(stage, "task.json")))
start = task.get("start") or task
if "answer_ids" not in start:
    for key in ("contract", "spec", "gm", "response"):
        if isinstance(task.get(key), dict) and "answer_ids" in task[key]:
            start = task[key]
            break
print("start keys:", sorted(start)[:20])
blob = open(os.path.join(stage, "artifact_0.bin"), "rb").read()

sure, probe, unknown = ab.analyse(start, [blob])
print("sure=%d probe=%d unknown=%d" % (len(sure), len(probe), len(unknown)))
for aid in sorted(probe):
    print("PROBE", aid, probe[aid])
for aid in sorted(unknown):
    print("UNKNOWN", aid, unknown[aid])
for aid in sorted(sure):
    if aid.startswith(("d15_", "d16_")):
        print("SURE", aid, "=", sure[aid])
