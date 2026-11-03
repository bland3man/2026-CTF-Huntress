#!/usr/bin/env python3
"""Candidate order for the 9 batch expansion labels of the Time Trial draw.

Top candidate = the plain reading of the descriptor reconstruction statement in that attempt's own bytes
(`call set "x=%%a%%%%b%%"` -> call_double, `for %%G ... call set` -> for_indirect, `!a!!b!` -> delayed,
`%a%%b%` -> percent); the rest of the enum follows as fallbacks.

usage: make_probe.py <out.json> <fixture dir>
"""
import json
import os
import re
import sys

ENUM = ["percent", "delayed", "call_double", "for_indirect"]
# fixture file -> batch-* answer-id prefix (each verified against that fixture's own campaign_id)
PREFIX = {"host-context.cmd": "benign", "memory-stage.bat": "stager", "embedded-write.cmd": "dropper",
          "remote-write.bat": "downloader", "outbound-transfer.cmd": "uploader",
          "local-dispatch.bat": "launcher", "impact-plan.cmd": "impact",
          "staged-handoff.bat": "chain", "relay-handoff.cmd": "relay"}


def natural(body, var):
    for l in body.splitlines():
        if not re.search(r'(?i)set\s+"?%s\s*=' % re.escape(var), l):
            continue
        if re.match(r'(?i)\s*for\s+%%', l):
            return "for_indirect"
        if re.search(r'(?i)(^|\s)call\s+set\s', l):
            return "call_double"
        val = l.split("=", 1)[1] if "=" in l else ""
        if re.search(r"![\w]+!", val):
            return "delayed"
        if re.search(r"%[\w]+%", val):
            return "percent"
    return "delayed"


out = {}
d = sys.argv[2]
for f, pre in sorted(PREFIX.items()):
    t = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
    body = t[t.find(":HUNTRESS_SEPARATOR_DONE"):]
    var = re.search(r"echo\(\s*[%!](\w+)[%!]", body).group(1)
    top = natural(body, var)
    out["batch-%s-expansion" % pre] = [top] + [v for v in ENUM if v != top]
    print("%-24s %-11s emit=%-24s top=%s" % (f, pre, var, top))

json.dump(out, open(sys.argv[1], "w"), indent=1)
