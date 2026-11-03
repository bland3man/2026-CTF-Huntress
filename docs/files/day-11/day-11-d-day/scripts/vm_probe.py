#!/usr/bin/env python3
"""Runs ON the Homebase VM. Probes the VM-side (SSH-identified, token-free) GM path for the D-Day
timed routes: does it see the same attempt state and the same pool depth as our bearer path?

usage: python3 vm_probe.py [challenge-base-id]
ASCII only, stdlib only, read ops first then ONE write op per route.
"""
import json
import sys
import urllib.request
import urllib.error

PROXY = "http://[ip]/huntress-ctf-proxy"
BASE = sys.argv[1] if len(sys.argv) > 1 else "binary-reverse-engineering-day-11-d-collection-planner"
SCALARS = ("result", "error", "mode", "deadline", "started_at", "attempt_id",
           "unique_attempts_remaining", "hall_of_fame_eligible", "next_op")


def call(method, params=None, payload=None):
    url = PROXY
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None
    hdr = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def brief(code, raw, label):
    try:
        j = json.loads(raw)
    except Exception:
        print("%-22s HTTP %s RAW %r" % (label, code, raw[:160]))
        return None
    d = {k: j[k] for k in SCALARS if k in j}
    d["n_answer_ids"] = len(j.get("answer_ids") or [])
    d["n_questions"] = len(j.get("questions") or [])
    print("%-22s HTTP %s %s" % (label, code, json.dumps(d)))
    return j


print("=== VM-side GM (token-free, SSH-identified) ===")
for mode in ("", "/time_trial", "/mastery"):
    c = BASE + mode
    code, raw = call("GET", {"op": "status", "challenge": c})
    j = brief(code, raw, "status" + (mode or "/single"))
    if j and mode == "/mastery":
        qs = j.get("questions") or []
        if qs:
            print("   mastery id shape:", [q.get("id") for q in qs[:3]], "... total", len(qs))

print("=== ONE write op per timed route (practice draws from the untimed pool) ===")
for mode in ("/time_trial",):
    c = BASE + mode
    for op in ("practice", "retry"):
        code, raw = call("POST", None, {"op": op, "challenge": c})
        brief(code, raw, op + mode)
