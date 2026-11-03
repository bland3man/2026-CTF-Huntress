#!/usr/bin/env python3
"""Probe the two Day 09 Nimble fields autosolve could not bank: d09_analysis_machine and d09_analysis_hcfg_offset."""
import json, sys

sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM

CID = "binary-reverse-engineering-day-09-nim-generated-runtime"
g = GM()


def sub(aid, val):
    r = g.submit(CID, {aid: val})
    res = str(r.get("result", "")).lower()
    print("%-30s %-12s -> %s remaining=%s" % (aid, val, res, r.get("remaining")))
    return res


if __name__ == "__main__":
    for aid, vals in json.load(open(sys.argv[1])).items():
        for v in vals:
            if sub(aid, v) in ("accepted", "correct"):
                break
