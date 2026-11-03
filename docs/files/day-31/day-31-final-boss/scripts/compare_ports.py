#!/usr/bin/env python3
"""Offline: run the current D31 clone and the D30-port on single_0.bin with the TT question set; diff results."""
import importlib.util, json, sys, os
ROOT = "[local path]"
sys.path.insert(0, ROOT + "/challenges/_lib")
D = ROOT + "/challenges/Day 31/⚙️ Final Boss"
mode = sys.argv[1] if len(sys.argv) > 1 else "time_trial"
paths = sys.argv[2:] or [D + "/scripts/binary_wip.py", D + "/scripts/binary_wip.py.d30-port"]

a = json.load(open(ROOT + "/challenges/Day 31/_board/binary-reverse-engineering-day-31-reversing-gauntlet.assignment.json"))
e = next(x for x in a["mode_entries"] if x["mode"] == mode)
start = {"questions": e["questions"], "answer_ids": e["answer_ids"]}
blob = open(D + "/artifacts/single_0.bin", "rb").read()


def load(p, name):
    from importlib.machinery import SourceFileLoader
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, p))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


res = []
for i, p in enumerate(paths):
    m = load(p, "adapter%d" % i)
    s, pr, u = m.analyse(start, [blob])
    res.append((s, pr, u))
    print("%s: sure=%d probe=%d unknown=%d" % (os.path.basename(p), len(s), len(pr), len(u)))
if len(res) == 2:
    (s0, p0, u0), (s1, p1, u1) = res
    diff = [k for k in s0 if k in s1 and s0[k] != s1[k]]
    lost = [k for k in s0 if k not in s1]
    print("DISAGREE on sure:", len(diff))
    for k in diff:
        print("  ", k, repr(s0[k])[:60], "->", repr(s1[k])[:60])
    print("LOST (sure in old, not in new):", lost)
    print("NEW UNKNOWN:", json.dumps(u1, indent=0)[:3000])
    print("NEW PROBE:", {k: v[:3] for k, v in p1.items()})
    miss = json.load(open(ROOT + "/challenges/Day 31/_board/binary-reverse-engineering-day-31-reversing-gauntlet.repair_capsule.json"))["missing_ids"]
    for k in miss:
        print("  %-55s %s" % (k, s1.get(k)))
else:
    s, pr, u = res[0]
    print("UNKNOWN:", json.dumps(u, indent=0)[:3000])
    print("PROBE:", {k: v[:3] for k, v in pr.items()})
