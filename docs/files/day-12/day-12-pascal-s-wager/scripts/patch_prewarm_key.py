#!/usr/bin/env python3
"""Assert-then-mutate patch: key the prewarm's free op=status reading by cid.

Why: one autosolve process walks several entries of the same challenge. _prewarm's op=status RAISES on an
unstarted mode (409 start_required), so it sets nothing - and an unkeyed module global then handed the Time
Trial's "expired, next_op=practice" verdict to Mastery, which sent op=practice where op=start was correct.
Fails loudly if the expected source text is not found. ASCII only.
"""
import sys

P = "[local path]"
s = open(P).read()

EDITS = [
    ('    try:\n'
     '        st = _gm(gm.status, cid)\n'
     '        POOL[0] = st.get("unique_attempts_remaining")\n'
     '        PRE[0] = st\n',
     '    POOL[0], PRE[0] = None, None     # never let the PREVIOUS entry\'s reading govern this one (a 409 status read sets nothing)\n'
     '    try:\n'
     '        st = _gm(gm.status, cid)\n'
     '        POOL[0] = st.get("unique_attempts_remaining")\n'
     '        PRE[0] = (cid, st)\n'),
    ('        if _first_op(st) == "practice":',
     '        if _first_op(PRE[0], cid) == "practice":'),
    ('    if _first_op(PRE[0]) == "practice":',
     '    if _first_op(PRE[0], cid) == "practice":'),
]

for old, new in EDITS:
    n = s.count(old)
    if n != 1:
        sys.exit("ABORT: expected exactly 1 occurrence, found %d for:\n%s" % (n, old[:90]))
    s = s.replace(old, new)

open(P, "w").write(s)
print("patched ok:", len(EDITS), "edits")
