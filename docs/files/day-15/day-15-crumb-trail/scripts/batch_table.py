#!/usr/bin/env python3
"""Ground-truth table for the batch expansion/control labels.

Maps each .cmd/.bat fixture to its batch-* answer-id prefix through its OWN campaign_id (never by
assumption about file names), then prints the descriptor reconstruction statement next to the label the
GM graded. Run it on the Single bytes (labels = GM-CORRECT) and on the Time Trial bytes (labels = what we
sent, which the GM rejected for the expansion family).

usage: batch_table.py <fixture dir> <answers.json or 'single'|'tt'>
"""
import json
import os
import re
import sys

ROOT = "[local path]"
REC = os.path.join(ROOT, "challenges/Day 15/_gm_record",
                   "script-analysis-day-15-credential-store-clues.homestation.jsonl")

d = sys.argv[1]
which = sys.argv[2] if len(sys.argv) > 2 else "single"
lines = open(REC, encoding="utf-8").read().splitlines()
ans = json.loads(lines[4 if which == "single" else 8])["answers"]

by_campaign = {}
for k, v in ans.items():
    if k.startswith("batch-") and k.endswith("-campaign"):
        by_campaign[v] = k[len("batch-"):-len("-campaign")]

for f in sorted(os.listdir(d)):
    if not f.endswith((".cmd", ".bat")):
        continue
    t = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
    body = t[t.find(":HUNTRESS_INSPECT"):]
    camp = re.search(r"campaign_id=\^?\|?(campaign-[0-9a-f]+)", body.replace("^|", "|"))
    camp = camp.group(1) if camp else "?"
    pre = by_campaign.get(camp, "?")
    emit = re.search(r"echo\(\s*[%!](\w+)[%!]", body)
    var = emit.group(1) if emit else "?"
    recon = [l.strip() for l in body.splitlines()
             if re.search(r'(?i)(^|\s)(call\s+)?set\s+"?%s\s*=' % re.escape(var), l)
             or re.search(r'(?i)do\s+call\s+set\s+"?%s\s*=' % re.escape(var), l)]
    print("%-24s %-12s emit=%-24s exp=%-12s ctl=%s" % (
        f, pre, var, ans.get("batch-%s-expansion" % pre), ans.get("batch-%s-control" % pre)))
    for l in recon:
        print("      recon: %s" % l)
