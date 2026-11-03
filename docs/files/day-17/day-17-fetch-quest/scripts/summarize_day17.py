#!/usr/bin/env python3
"""Compact, read-only summary of the Day 17 Fetch Quest task/contracts for the writeup."""
import json
import os
import re
import sys
from collections import Counter

ROOT = "[local path]"
STAGE = os.path.join(ROOT, "challenges/Day 17/_stage/Fetch_Quest")


def load(name):
    with open(os.path.join(STAGE, name), "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def fields_of(doc):
    for key in ("fields", "questions", "answer_fields"):
        if isinstance(doc.get(key), list):
            return doc[key]
    # nested
    for key in ("challenge", "task", "spec", "detail"):
        sub = doc.get(key)
        if isinstance(sub, dict):
            got = fields_of(sub)
            if got:
                return got
    return []


def prefix(fid):
    # group by the leading family token(s)
    parts = fid.split("-")
    if parts[0] == "polyglot" and len(parts) > 1:
        return "polyglot-" + parts[1]
    return parts[0]


def report(label, doc):
    flds = fields_of(doc)
    print("== %s : %d fields" % (label, len(flds)))
    fam = Counter(prefix(f.get("id", "?")) for f in flds)
    print("   families: " + ", ".join("%s=%d" % kv for kv in fam.most_common()))
    suffix = Counter((f.get("id", "?").rsplit("-", 1) + [""])[1] for f in flds)
    print("   answer kinds: " + ", ".join("%s=%d" % kv for kv in suffix.most_common(14)))
    return flds


def main():
    task = load("task.json")
    pr = json.dumps(task)
    m = re.search(r'"prompt"\s*:\s*"([^"]{40,600})"', pr)
    if m:
        print("PROMPT: " + m.group(1))
    print()
    single = report("single_solve (task.json)", task)
    for name, label in (("contract_time_trial.json", "time_trial"),
                        ("contract_mastery.json", "mastery")):
        try:
            report(label, load(name))
        except Exception as exc:  # pragma: no cover
            print("== %s : unreadable (%s)" % (label, exc))
    print()
    print("-- single_solve headline fields (id | ask | answer-shape) --")
    want = ("scenario", "attack", "url", "wallet", "mutex", "campaign", "indicator",
            "graph", "lineage", "steps", "stage-count")
    shown = 0
    for f in single:
        fid = f.get("id", "")
        if any(w in fid for w in want) and shown < 40:
            ask = (f.get("prompt") or f.get("question") or f.get("ask") or "")[:140]
            print("%-46s %s" % (fid, ask.replace("\n", " ")))
            shown += 1
    print()
    print("-- ids mentioning the new/today layer --")
    for f in single:
        fid = f.get("id", "")
        if "auto_hotkey" in fid or "lineage" in fid or "download" in fid or "network" in fid:
            print("  " + fid)


if __name__ == "__main__":
    sys.exit(main())
