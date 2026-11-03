#!/usr/bin/env python3
"""WebView Bridge (Day 07): huntress_puzzle.json codec=caesar (ASCII shift -key) -> ANS-<16 hex>.
Usage: solve_webview_bridge.py <mode entry id> [...]   (derives from each attempt's own APK)"""
import sys, io, json, zipfile, codecs, base64
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM, solve_mode


def apply_codec(p):
    c = (p.get("codec") or "").lower(); d = p["data"]
    if c == "caesar":
        k = int(p.get("key", 0)); return "".join(chr(ord(x) - k) for x in d)
    if c in ("reverse", "rev"): return d[::-1]
    if c == "rot13": return codecs.encode(d, "rot13")
    if c in ("base64", "b64"): return base64.b64decode(d).decode()
    if c == "hex": return bytes.fromhex(d).decode()
    if c in ("plain", "identity", "none", ""): return d
    raise ValueError("unknown codec %r" % c)


def puzzle(blob):
    z = zipfile.ZipFile(io.BytesIO(blob))
    n = [x for x in z.namelist() if x.endswith("huntress_puzzle.json")][0]
    return json.loads(z.read(n))


def compute(start, blobs):
    ans = [apply_codec(puzzle(b)) for b in blobs]
    ids = start["answer_ids"]
    return {aid: ans[min(i, len(ans) - 1)] for i, aid in enumerate(ids)}


if __name__ == "__main__":
    gm = GM()
    for ch in sys.argv[1:]:
        r = solve_mode(gm, ch, compute)
        print(ch, str(r.get("result")), json.dumps(r)[:300])
