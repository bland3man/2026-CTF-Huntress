#!/usr/bin/env python3
"""Static solver: decode assets/huntress_puzzle.json from the APK (no GM contact)."""
import base64, json, sys, zipfile
apk = sys.argv[1] if len(sys.argv) > 1 else "pending_intent_relay.apk"
p = json.loads(zipfile.ZipFile(apk).read("assets/huntress_puzzle.json"))
assert p["codec"] == "xor", p
raw = base64.b64decode(p["data"])
print(bytes(b ^ p["key"] for b in raw).decode())
