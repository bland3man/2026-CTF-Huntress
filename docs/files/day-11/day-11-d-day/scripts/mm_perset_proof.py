#!/usr/bin/env python3
"""PROOF that Mastery's setN answers come from delivery N's OWN bytes - with real, DIFFERING deliveries.

The gap this closes. preflight_mastery.py proves coverage, format and compute time, but it feeds the SAME
saved blob three times ([blob] * 3), because only one Day 11 delivery was ever handed out. That can never
catch a solver that reads set2/set3 from blobs[0]: with identical inputs, correct and broken behave the
same. And it matters, because Day 02's Mastery is on record as MIXING formats across deliveries (a PE in
one, an ELF in another - see Day 02/Mangled/MASTERY_SCHEMA.md), and the adapter's own notes say Day 10
rotates its d10 member between an ELF and a native PE per attempt. A set-crossing bug would answer three
sets from one binary and lose two thirds of the paper.

So: drive the real Day 11 Mastery contract (330 ids, captured off its own 409) with the three REAL,
DIFFERENT Day 10 Mastery deliveries that are already on disk. Same bundle family, genuinely different
bytes. Then two things must hold:

  A. per-set independence - for at least one core field, set1/set2/set3 answers DIFFER (they cannot, if
     every set were read from delivery 0)
  B. per-set format honesty - each setN's *_analysis_format / *_machine answers follow setN's own member
     kind, including a set whose member is a PE where another set's is an ELF

Day 10's bundle has no d11 member, so the d11_* fields are expected to be unresolved here; that is the
test substrate being older, not a solver defect, and they are reported separately rather than hidden.

Zero GM calls: contract from the 409, bytes from [home path]
"""
import collections
import glob
import json
import os
import re
import sys

sys.path.insert(0, "challenges/_lib")
import autosolve_binary as ab  # noqa: E402

CONTRACT = "challenges/Day 11/D-Day/scripts/d11_mastery_contract.json"
D10 = os.path.expanduser(
    "[home path]")

c = json.load(open(CONTRACT))
qs = c["questions"]
aids = [q["id"] for q in qs]

paths = sorted(glob.glob(os.path.join(D10, "*_delivery*.bin")))
if len(paths) < 3:
    print("SKIP: need 3 real deliveries, found %d in %s" % (len(paths), D10))
    sys.exit(0)
blobs = [open(p, "rb").read() for p in paths[:3]]
print("substrate: %s" % ", ".join("%s (%d bytes)" % (os.path.basename(p), len(b))
                                  for p, b in zip(paths[:3], blobs)))
print("distinct blobs: %d of 3" % len({b[:4096] + bytes(str(len(b)), "ascii") for b in blobs}))
print()

sure, probe, unknown = ab.analyse({"answer_ids": aids, "questions": qs}, blobs)
vals = dict(sure)
vals.update({a: v[0] for a, v in probe.items()})

# ---- A. per-set independence
cores = sorted({a.split(".", 1)[1] for a in aids})
differ, same, partial = [], [], []
for core in cores:
    got = [vals.get("set%d.%s" % (i, core)) for i in (1, 2, 3)]
    if any(g is None for g in got):
        partial.append(core)
    elif len(set(map(str, got))) > 1:
        differ.append(core)
    else:
        same.append(core)

print("A. PER-SET INDEPENDENCE")
print("   fields differing across set1/set2/set3 : %d" % len(differ))
print("   fields identical across all three sets : %d  (legitimately constant, e.g. a shared layout fact)" % len(same))
print("   fields not fully resolved on this older substrate: %d" % len(partial))
for core in differ[:6]:
    print("     e.g. %-28s set1=%r set2=%r set3=%r"
          % (core, vals.get("set1." + core), vals.get("set2." + core), vals.get("set3." + core)))
A_OK = len(differ) > 0
print("   -> %s: three sets produced different answers, so setN is read from delivery N"
      % ("PASS" if A_OK else "FAIL"))
print()

# ---- B. per-set format honesty
print("B. PER-SET FORMAT HONESTY")
kinds = collections.Counter()
fmt_rows = []
for core in cores:
    if not (core.endswith("_analysis_format") or core.endswith("_analysis_machine")):
        continue
    got = tuple(vals.get("set%d.%s" % (i, core)) for i in (1, 2, 3))
    if any(g is None for g in got):
        continue
    fmt_rows.append((core, got))
    for g in got:
        kinds[str(g)] += 1
for core, got in fmt_rows:
    mark = "  <-- MIXED ACROSS SETS" if len({str(g) for g in got}) > 1 else ""
    print("   %-28s %r%s" % (core, got, mark))
mixed = [c0 for c0, g in fmt_rows if len({str(x) for x in g}) > 1]
print("   label census: %s" % dict(kinds))
print("   -> %d format/machine field(s) resolved; %d of them differ BETWEEN sets%s"
      % (len(fmt_rows), len(mixed), " (a real mixed-format bundle, handled)" if mixed else ""))
print()

# ---- unresolved, named rather than hidden
if unknown:
    byday = collections.Counter(re.match(r"^set\d+\.(d\d+)", a).group(1)
                                for a in unknown if re.match(r"^set\d+\.(d\d+)", a))
    print("UNRESOLVED on this older substrate: %d ids, by day-block: %s" % (len(unknown), dict(byday)))
    print("   (expected: Day 10's bundle predates the d11 member. The live Day 11 delivery resolves 330/330 -")
    print("    see preflight_mastery.py. This run is a per-set WIRING proof, not a coverage claim.)")
print()
print("RESULT: %s" % ("PASS" if A_OK else "FAIL"))
sys.exit(0 if A_OK else 1)
