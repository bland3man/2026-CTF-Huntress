#!/usr/bin/env python3
"""OFFLINE Mastery-shape proof, zero GM calls.

Mastery carries about twice the fields over TWO deliveries, addressed with the adapter's
'setN.<field>' prefix (autosolve_binary._split). Build that exact shape locally from the saved
Time Trial bytes and confirm analyse() resolves every id, so the single real Mastery attempt is
never an experiment."""
import glob, json, os, sys, time
sys.path.insert(0, "challenges/_lib")
import autosolve_binary as ab

qs = json.load(open("challenges/Day 11/D-Day/scripts/questions_start.json"))
aids = [q.get("answer_id") or q.get("id") for q in qs] if isinstance(qs[0], dict) else list(qs)
d = os.path.expanduser("[home path]")
blob = open(sorted(glob.glob(os.path.join(d, "*_delivery*.bin")))[0], "rb").read()

# two deliveries, ids prefixed set1./set2. exactly as _split expects
m_aids, m_qs = [], []
for s in (1, 2):
    for q in qs:
        aid = q.get("answer_id") or q.get("id")
        q2 = dict(q)
        new = "set%d.%s" % (s, aid)
        if "answer_id" in q2:
            q2["answer_id"] = new
        q2["id"] = new
        m_aids.append(new)
        m_qs.append(q2)
start = {"answer_ids": m_aids, "questions": m_qs}
print("synthetic mastery: %d answer_ids over 2 deliveries" % len(m_aids), flush=True)
t0 = time.time()
sure, probe, unknown = ab.analyse(start, [blob, blob])
el = time.time() - t0
print("ANALYSE %.2fs -> %d sure, %d probe, %d unknown (of %d)" % (el, len(sure), len(probe), len(unknown), len(m_aids)))
if unknown:
    print("UNKNOWN:", sorted(unknown)[:30])
if probe:
    print("PROBE:", {k: v[:3] for k, v in list(probe.items())[:10]})
# both sets must resolve, and identically (same bytes in both deliveries)
bad = [a for a in m_aids if a not in sure and a not in probe]
print("unresolved:", bad[:20] if bad else "none")
mismatch = [a for a in aids if sure.get("set1." + a) != sure.get("set2." + a)]
print("set1 vs set2 consistency: %s" % ("OK (identical bytes -> identical answers)" if not mismatch
                                        else "MISMATCH %s" % mismatch[:10]))
print("RESULT:", "PASS" if not bad and not unknown and not mismatch else "FAIL")
