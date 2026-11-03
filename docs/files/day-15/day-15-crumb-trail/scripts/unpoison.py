#!/usr/bin/env python3
"""Drop ONE stale key from the shared wrong-submit store: the single-field canary probe the GM ANSWERED
'accepted' (it banked the field), which the old recording rule filed as "wrong" and which then refused
every later probe. Only that key is removed - every other agent's protection for today stays.

usage: unpoison.py <challenge/mode> <answer id> <value>
"""
import json
import os
import sys

sys.path.insert(0, "[local path]")
import ctf_gm  # noqa: E402

challenge, qid, val = sys.argv[1], sys.argv[2], sys.argv[3]
key = ctf_gm._wrong_key(challenge, {qid: val})
path = os.path.expanduser(ctf_gm.WRONG_STORE)
d = json.load(open(path, encoding="utf-8"))
before = len(d.get("keys") or [])
d["keys"] = [k for k in d.get("keys") or [] if k != key]
json.dump(d, open(path, "w", encoding="utf-8"))
print("day", d.get("day"), "keys", before, "->", len(d["keys"]), "removed" if before != len(d["keys"]) else "NOT PRESENT")
