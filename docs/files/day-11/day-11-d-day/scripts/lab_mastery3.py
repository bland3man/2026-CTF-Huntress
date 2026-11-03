#!/usr/bin/env python3
"""OFFLINE Mastery proof against the REAL mastery questions contract, captured from the VM-side GM
(which returns the full public contract even on its 409 start_required). Zero GM calls here.

CORRECTION to the earlier synthetic run: today's mastery is 330 ids over THREE deliveries
(set1/set2/set3), not 220 over two. The KB's "about twice the fields" was wrong for today, and the
earlier offline proof had quietly assumed it."""
import collections
import glob
import json
import os
import re
import sys
import time

sys.path.insert(0, "challenges/_lib")
import autosolve_binary as ab  # noqa: E402

c = json.load(open("challenges/Day 11/D-Day/scripts/d11_mastery_contract.json"))
qs = c.get("questions") or []
aids = [q["id"] for q in qs]
print("real mastery contract: %d questions" % len(aids))
sets = collections.Counter(m.group(1) for a in aids for m in [re.match(r"^(set\d+)\.", a)] if m)
print("set prefixes:", dict(sets))
cores = sorted({re.sub(r"^set\d+\.", "", a) for a in aids})
print("distinct core fields: %d" % len(cores))

d = os.path.expanduser(
    "[home path]")
blob = open(sorted(glob.glob(os.path.join(d, "*_delivery*.bin")))[0], "rb").read()
n = len(sets) or 1
start = {"answer_ids": aids, "questions": qs}
print("replaying with %d deliveries (same bytes in each: proves COVERAGE + TIMING, never values)" % n)
t0 = time.time()
sure, probe, unknown = ab.analyse(start, [blob] * n)
el = time.time() - t0
print("ANALYSE %.2fs -> %d sure, %d probe, %d unknown (of %d)"
      % (el, len(sure), len(probe), len(unknown), len(aids)))
if unknown:
    print("UNKNOWN:", sorted(unknown)[:30])
if probe:
    print("PROBE:", {k: v[:3] for k, v in list(probe.items())[:10]})
bad = [a for a in aids if a not in sure and a not in probe]
print("unresolved:", bad[:20] if bad else "none")
ok = not bad and not unknown
print("fits a 30s window:", ("YES (%.2fs)" % el) if el < 20 else ("NO (%.2fs)" % el))
print("RESULT:", "PASS" if ok else "FAIL")
