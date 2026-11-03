#!/usr/bin/env python3
"""Static: list every CRC-valid HGAU record in the d31 ELF member (backward scan)."""
import sys, json, zlib
sys.path.insert(0, "[local path]")
from ctf_gm import unzip
files = unzip(open(sys.argv[1], "rb").read())
for n, b in files:
    if not n.split("/")[-1].startswith("d31--"):
        continue
    print(n, len(b), b[:4])
    i = b.rfind(b"HGAU")
    while i >= 0:
        ln = b[i + 6] | b[i + 7] << 8
        crc = int.from_bytes(b[i + 8:i + 12], "little")
        p = bytes(x ^ b[i + 5] for x in b[i + 12:i + 12 + ln])
        ok = zlib.crc32(p) == crc
        print(" HGAU at", i, "ver", b[i + 4], "key 0x%02x" % b[i + 5], "len", ln, "crc 0x%08x" % crc, "valid", ok, "ends_at", i + 12 + ln)
        if ok:
            print(json.dumps(json.loads(p), indent=1)[:2500])
        i = b.rfind(b"HGAU", 0, i)
