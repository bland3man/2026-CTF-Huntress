#!/usr/bin/env python3
"""MASTERY CLUE CHECK - cross-check our Mastery answers against the PRESCRIPTIVE question texts.

Why this exists. Day 11 Mastery is a CROSS-DAY recap: its 330 ids are d01..d11 x 110 core x 3 sets, so it
grades the Day 2 C++ specimen, the Day 3 managed binary and so on - not just Day 11's D binary. Most of the
330 carry the GENERIC syntax ("exact artifact-derived value only..."), but a handful carry a PRESCRIPTIVE
syntax that names the accepted spellings outright. Those are the only fields where a byte-correct answer can
still be graded wrong for being the wrong LABEL, and preflight's generic kind/syntax check cannot see it.

The clue came from challenges/Day 02/Mangled/MASTERY_SCHEMA.md, which records that Day 02's own Mastery
failed partly on exactly this: `elf64-x86-64` and `ELF64` were REJECTED where the short `elf` was CORRECT,
and a mixed attempt also carried a PE delivery. Day 11's phrasing is more permissive but NOT identical, so
the labels have to be read against Day 11's own text rather than inherited from Day 02's.

Zero GM calls: the contract came off the 409 and the bytes are the saved time_trial delivery.
"""
import glob
import json
import os
import re
import sys

sys.path.insert(0, "challenges/_lib")
import autosolve_binary as ab  # noqa: E402

CONTRACT = "challenges/Day 11/D-Day/scripts/d11_mastery_contract.json"
SAVED = os.path.expanduser(
    "[home path]")

# The generic boilerplate every ordinary field carries. Anything NOT matching it is prescriptive, i.e. the
# GM has told us which spellings it will take, and we must be inside that set.
GENERIC = "exact artifact-derived value only, without quotes or explanatory text"

c = json.load(open(CONTRACT))
qs = c["questions"]
aids = [q["id"] for q in qs]

blob = open(sorted(glob.glob(os.path.join(SAVED, "*_delivery*.bin")))[0], "rb").read()
sure, probe, unknown = ab.analyse({"answer_ids": aids, "questions": qs}, [blob] * 3)
vals = dict(sure)
vals.update({a: c0[0] for a, c0 in probe.items()})

# Two different things hide under "not the generic boilerplate", and only one of them is a risk:
#   FORM syntax      - "lowercase hexadecimal with a 0x prefix", "base-10 integer", "compact valid JSON
#                       array". It describes a SHAPE, and preflight check 4 already verifies shapes.
#   ENUMERATIVE syntax - "ELF or PE; ... ELF32, ELF64, PE32, PE32+ ... are accepted", "CLI, CLR, or .NET
#                       may name the managed part". It lists the LABELS the grader will take, and a
#                       byte-correct answer outside that list is still graded wrong. THIS is the risk,
#                       and it is exactly how Day 02's Mastery lost fields (elf64-x86-64 / ELF64 vs elf).
# So flag only the enumerative ones: the GM signals them with "accepted" or "may name".
def enumerative(syn):
    return ("accepted" in syn or "may name" in syn) and GENERIC not in syn


rows, seen, forms = [], set(), {}
for q in qs:
    core = q["id"].split(".", 1)[1]
    syn = (q.get("answer_format") or {}).get("syntax") or ""
    if core in seen:
        continue
    seen.add(core)
    if enumerative(syn):
        rows.append((core, q["id"], syn, q["question"]))
    elif GENERIC not in syn:
        forms.setdefault(syn or "(no syntax given)", []).append(core)

print("%d core fields total" % len(seen))
print("ENUMERATIVE syntax (the GM lists the accepted LABELS - the only label risk): %d" % len(rows))
print("FORM syntax (shape only, already covered by preflight check 4): %d fields over %d distinct forms"
      % (sum(len(v) for v in forms.values()), len(forms)))
for syn, cores in sorted(forms.items(), key=lambda kv: -len(kv[1])):
    print("   %2d x %s" % (len(cores), syn[:96]))
    print("        %s" % ", ".join(cores[:8]) + (" ..." if len(cores) > 8 else ""))
print()

# Pull the quoted/named tokens out of the syntax sentence so the check is against the GM's own words.
TOKEN = re.compile(r"\b([A-Za-z][A-Za-z0-9+._/-]{1,24})\b")
STOP = set("""a an and are or the be is may name names named when they identify same container letter case
ignored accepted token one both parts not just generic label only without quotes explanatory text use literal
none when requested field absent exact artifact derived value unrelated syntax example separators underscore
slash hyphen space with for of in to as its from submit""".split())

# Where the token test alone cannot settle a field, the verdict is recorded WITH its evidence, and it is
# pinned to the value it was reasoned about: if a future attempt's value changes shape, the pin breaks and
# the field is flagged again rather than silently inheriting a verdict that no longer applies.
VERDICT = {
    "d01_analysis_machine": (
        r"^x86-64$",
        "conforms: 'common readelf and objdump labels are accepted', and x86-64 is the exact token the GM "
        "ACCEPTED for the same concept on Day 02 (c_machine, per Day 02/Mangled/MASTERY_SCHEMA.md proven "
        "formats). Not a guess - a previously graded-correct spelling."),
    "d01_analysis_disassembly": (
        r"^\[.*\]$",
        "conforms: the syntax asks for a JSON array of instruction strings in execution order and accepts "
        "either Intel or AT&T spelling; ours is a compact JSON array in Intel spelling."),
    "d03_analysis_format": (
        r"^[a-z0-9]+[_/ -][a-z.]+$",
        "conforms: the syntax asks for ONE container_runtime compound token, allows CLI to name the managed "
        "part, and accepts an underscore separator - pe_cli is container 'pe' + '_' + runtime 'cli', which "
        "is the compound form demanded, not the 'generic container label' the question warns against."),
}

bad = 0
for core, qid, syn, qtext in rows:
    got = vals.get(qid)
    allowed = {t.lower() for t in TOKEN.findall(syn) if t.lower() not in STOP}
    g = str(got).lower()
    # accepted if the answer equals an allowed token, or is a compound whose every part is allowed
    parts = [p for p in re.split(r"[_/\- ]+", g) if p]
    ok = g in allowed or (len(parts) > 1 and all(p in allowed for p in parts))
    note = ""
    if not ok and core in VERDICT:
        pin, why = VERDICT[core]
        if re.match(pin, g):
            ok, note = True, why
        else:
            note = "RECORDED VERDICT NO LONGER APPLIES (value shape changed; expected /%s/) - re-read it" % pin
    if not ok:
        bad += 1
    print("%s %-26s ours=%-12r" % ("OK  " if ok else "LOOK", core, got))
    print("      syntax : %s" % syn)
    if note:
        print("      verdict: %s" % note)
    elif not ok:
        print("      tokens : %s" % ", ".join(sorted(allowed)))
    print()

print("RESULT: %d prescriptive field(s) need a human look, %d conform" % (bad, len(rows) - bad))
print("(analyse: %d sure / %d probe / %d unknown of %d)" % (len(sure), len(probe), len(unknown), len(aids)))
