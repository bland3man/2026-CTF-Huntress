#!/usr/bin/env python3
"""Raw GM probe: one call per op, full body captured (not truncated to 200 chars)."""
import json, sys, urllib.parse, http.client
sys.path.insert(0, "challenges/_lib")
import ctf_gm
from ctf_gm import GM

gm = GM()
cid = sys.argv[1]


def raw(method, payload=None, q=None):
    path = gm.path if gm.path != "/" else "/"
    p = ctf_gm.GM_PATH
    full = p + ("?" + urllib.parse.urlencode(q) if q else "")
    full = full.replace(ctf_gm.GM_PATH, gm.path, 1) if full.startswith(ctf_gm.GM_PATH) else full
    body = None if payload is None else json.dumps(payload, separators=(",", ":"))
    hdr = {"Content-Type": "application/json"} if body is not None else {}
    if gm._tok:
        hdr["Authorization"] = "Bearer " + gm._tok
    gm._reconnect()
    gm._c.request(method, full, body=body, headers=hdr)
    r = gm._c.getresponse()
    d = r.read()
    return r.status, d


ops = sys.argv[2:] or ["start"]
for op in ops:
    pl = {"op": op, "challenge": cid}
    status, d = raw("POST", pl)
    try:
        j = json.loads(d)
    except Exception:
        print(op, status, d[:300]); continue
    keys = sorted(j.keys())
    print("=== op=%s HTTP %s keys=%s" % (op, status, keys), flush=True)
    for k in ("error", "result", "mode", "deadline", "started_at", "unique_attempts_remaining",
              "hall_of_fame_eligible", "next_op", "attempt_id", "retry_available", "variants_remaining"):
        if k in j:
            print("   %s = %r" % (k, j[k]))
    aid = j.get("answer_ids")
    if aid:
        print("   answer_ids = %d, first 6 %s" % (len(aid), aid[:6]))
    qs = j.get("questions")
    if qs:
        print("   questions = %d" % len(qs))
        out = "challenges/Day 11/D-Day/scripts/questions_%s.json" % op
        json.dump(qs, open(out, "w"), indent=1)
        print("   saved ->", out)
    if "download" in j or "downloads" in j or "artifacts" in j:
        print("   artifacts present")
