#!/usr/bin/env python3
"""Print the :HUNTRESS_INSPECT body of every batch fixture in a directory, so the descriptor
reconstruction statement and the wrapper around it can be read directly (GM question text is the spec).

usage: dump_batch.py <dir>
"""
import os
import re
import sys

d = sys.argv[1]
for f in sorted(os.listdir(d)):
    if not f.endswith((".cmd", ".bat")):
        continue
    t = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
    body = t[t.find(":HUNTRESS_INSPECT"):]
    body = re.sub(r'(?m)^\s*set "(?:FrAg|h|p|frag|part|seg)\w*=.*$', "    <frag>", body)
    print("=" * 20, f)
    print(body.rstrip())
    print()
