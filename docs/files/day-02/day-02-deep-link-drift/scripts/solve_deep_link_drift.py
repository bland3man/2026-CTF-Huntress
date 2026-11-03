#!/usr/bin/env python3
"""
Deep Link Drift - deterministic Game Master solver (Huntress CTF 2026, Day 02).

WHY THIS EXISTS
---------------
The static/public APK (deep_link_drift.apk) proved the mechanic deterministically:
  assets/huntress_puzzle.json = {"codec":"reverse","data":"94AEE0A765B0097A-SNA", ...}
  ChallengeActivity reads deep-link query params `answer` + `case_id` and submits the
  `answer` as `proof` to the evidence validator. The required `answer`/`proof` is the
  puzzle `data` run through the declared `codec`.
For the PUBLIC artifact: reverse("94AEE0A765B0097A-SNA") == "ANS-A7900B567A0EEA49".

BUT the 2026 arena is DYNAMIC per attempt: in Time Trial / Mastery the Game Master
hands you a *different* artifact whose `data` differs. So this solver does NOT hardcode
the answer. It downloads the attempt's own artifact, extracts the puzzle JSON, reads the
codec, computes the answer, and submits it under the exact answer_ids the GM returns.

WHERE TO RUN
------------
Inside the Homebase VM (the Game Master at [ip] is only reachable on the VM's
internal network). Over VPN with the VM running, set HUNTRESS_GAME_MASTER_URL to the
same base. No trailing slash on the base URL (a trailing '/' causes 404).

USAGE
-----
  python3 solve_deep_link_drift.py              # auto-discover the day-2 challenge id
  python3 solve_deep_link_drift.py --challenge deep-link-drift
  python3 solve_deep_link_drift.py --dry-run    # decode only, do not submit
It is idempotent/safe to re-run: re-`start` resumes the SAME attempt (no fresh timer).
"""

import argparse
import io
import json
import os
import re
import sys
import zipfile
import urllib.request
import urllib.parse

# Dependency-free on purpose: uses only the stdlib so it runs in the Homebase VM
# with no pip install. (urllib, not requests.)

GM = os.environ.get("HUNTRESS_GAME_MASTER_URL", "http://[ip]/huntress-ctf-proxy").rstrip("/")
TIMEOUT = 30
NAME_HINT = re.compile(r"deep[\s_-]*link[\s_-]*drift", re.I)


# ---------- codecs (chosen by the puzzle JSON's own "codec" field) ----------
def apply_codec(codec, data):
    codec = (codec or "").strip().lower()
    if codec in ("reverse", "rev"):
        return data[::-1]
    if codec in ("rot13", "rot-13"):
        import codecs as _c
        return _c.encode(data, "rot13")
    if codec in ("base64", "b64"):
        import base64
        return base64.b64decode(data).decode("utf-8", "replace")
    if codec in ("hex",):
        return bytes.fromhex(data).decode("utf-8", "replace")
    if codec in ("identity", "none", "plain", ""):
        return data
    raise ValueError("Unknown codec %r - inspect the artifact and extend apply_codec()" % codec)


def extract_puzzle(blob):
    """Return the huntress_puzzle.json dict from either a raw JSON blob or an APK zip."""
    # raw JSON?
    try:
        j = json.loads(blob)
        if isinstance(j, dict) and "data" in j:
            return j
    except Exception:
        pass
    # APK / zip?
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        for name in z.namelist():
            if name.endswith("huntress_puzzle.json"):
                return json.loads(z.read(name))
    except Exception:
        pass
    raise ValueError("Could not locate huntress_puzzle.json in the artifact")


def compute_answer(puzzle):
    ans = apply_codec(puzzle.get("codec"), puzzle["data"])
    print("[*] codec=%s  data=%r  ->  answer=%r" % (puzzle.get("codec"), puzzle["data"], ans))
    return ans


# ---------- Game Master plumbing (stdlib urllib) ----------
def _http(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def gm_get(params):
    url = GM + "?" + urllib.parse.urlencode(params)
    return json.loads(_http(url))


def gm_post(body):
    raw = _http(GM, data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"})
    return json.loads(raw)


def discover_challenge_id(explicit):
    if explicit:
        return explicit
    data = gm_get({"op": "list", "day": 2})
    items = data.get("challenges", data if isinstance(data, list) else data.get("items", []))
    for it in items:
        blob = json.dumps(it)
        if NAME_HINT.search(blob):
            cid = it.get("challenge") or it.get("id") or it.get("slug")
            if cid:
                print("[*] discovered challenge id: %s" % cid)
                return cid
    sys.exit("Could not auto-discover Deep Link Drift in day-2 list; pass --challenge <id>.\n"
             "Raw list: %s" % json.dumps(data)[:2000])


def start_attempt(cid):
    res = gm_post({"op": "start", "challenge": cid})
    if res.get("status") == "flag_unavailable":
        print("[!] flag_unavailable -> retry then start (per workflow lesson)")
        gm_post({"op": "retry", "challenge": cid})
        res = gm_post({"op": "start", "challenge": cid})
    return res


def fetch_artifact(cid, start_res):
    # Prefer a download URL the start response gave us; else op=artifact.
    url = start_res.get("download") or start_res.get("artifact")
    if url and str(url).startswith("http"):
        return _http(url)
    return _http(GM + "?" + urllib.parse.urlencode({"op": "artifact", "challenge": cid}))


def answer_ids(start_res):
    ids = start_res.get("answer_ids") or start_res.get("answerIds") or []
    if isinstance(ids, dict):
        ids = list(ids.keys())
    return ids


def submit(cid, ids, answer):
    answers = {aid: answer for aid in ids} if ids else {"answer": answer}
    res = gm_post({"challenge": cid, "answers": answers})
    print("[*] submit -> %s" % json.dumps(res))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge", help="GM challenge id (default: auto-discover)")
    ap.add_argument("--dry-run", action="store_true", help="decode artifact only, do not submit")
    args = ap.parse_args()

    print("[*] Game Master base: %s" % GM)
    cid = discover_challenge_id(args.challenge)
    start_res = start_attempt(cid)
    print("[*] start -> %s" % json.dumps(start_res)[:800])
    if start_res.get("deadline"):
        print("[*] server deadline (UTC, authoritative): %s" % start_res["deadline"])

    blob = fetch_artifact(cid, start_res)
    puzzle = extract_puzzle(blob)
    answer = compute_answer(puzzle)

    if args.dry_run:
        print("[dry-run] would submit answer=%r to ids=%s" % (answer, answer_ids(start_res)))
        return

    res = submit(cid, answer_ids(start_res), answer)
    result = (res.get("result") or res.get("status") or "").lower()
    if result in ("correct", "accepted", "complete", "completed", "pending"):
        print("[+] FLAG/COMPLETION: %s" % json.dumps(res))
        rem = res.get("remaining")
        if rem:
            print("[*] Mastery remaining tasks: %s (re-run / submit each remaining answer_id)" % rem)
    elif result == "expired":
        print("[!] attempt expired -> POST retry then re-run this script")
    else:
        print("[!] unexpected result; inspect raw response above")


if __name__ == "__main__":
    main()
