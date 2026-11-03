#!/usr/bin/env python3
"""Binary lane catalog: the PACKED OVERLAY carrier (Day 19 'Jack in the Box', 2026-10-19).

Day 19 stopped putting the HCFG record in the file at all. The member is a normal ELF with a stub appended AFTER the
end of the real file - "a payload hiding inside this binary, and a little decoder stub wound up to pop it out":

    +0  magic (4 bytes, the unit names it: PK19 for Day 19, RS20 for Day 20)
    +5  k1        +6  k2        +8  packed length u32le
    +12 SHA-256 of the UNPACKED bytes (32)       +44 packed bytes (run to EOF)
    unpack: for every packed byte -> ror8(byte XOR k2, 3) XOR k1 ; the unpacked bytes hold the HCFG record at 0.

This test uses an INDEPENDENT parse (struct.unpack, no code shared with autosolve_binary) and requires the adapter to
agree on the real staged member, on a re-packed overlay under NEXT day's magic (the magic must come from the bytes,
never a hardcoded 'PK19'), and to invent nothing when the SHA-256 does not verify. It also guards the scan cost: the
first implementation sliced the payload before bounds-checking the declared length and took 133 s on the 67 MB d08
member, which stalled a timed window. Offline, no GM. Run with WSL python3 (needs the staged artifacts).
"""
import glob
import hashlib
import os
import struct
import sys
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
import autosolve_binary as ab  # noqa: E402
from ctf_gm import unzip  # noqa: E402

bad = 0


def check(name, ok, detail=""):
    global bad
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""))
    bad += (not ok)


def ror8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xFF


def independent_overlay(b, magic):
    """A deliberately separate parse: the LAST occurrence of magic whose declared length ends at EOF and whose
    embedded SHA-256 matches the unpacked bytes."""
    i = b.rfind(magic)
    while i >= 0:
        if i + 44 <= len(b):
            ln, = struct.unpack_from("<I", b, i + 8)
            if i + 44 + ln == len(b):
                k1, k2 = b[i + 5], b[i + 6]
                out = bytes(ror8(x ^ k2, 3) ^ k1 for x in b[i + 44:])
                if hashlib.sha256(out).digest() == b[i + 12:i + 44]:
                    return {"off": i, "size": len(b) - i, "unpacked": out}
        i = b.rfind(magic, 0, i)
    return None


def independent_hcfg(b, pos=0):
    magic, ver, key, ln, crc = struct.unpack_from("<4sBBHI", b, pos)
    if magic != b"HCFG":
        return None
    pay = bytes(x ^ key for x in b[pos + 12:pos + 12 + ln])
    if len(pay) != ln or zlib.crc32(pay) & 0xFFFFFFFF != crc:
        return None
    import json
    return {"ver": ver, "key": key, "crc": crc, "cfg": json.loads(pay)}


def repack(payload, magic, k1, k2):
    """Build a fresh overlay carrying payload, the way the generator does."""
    packed = bytes(ror8(x ^ k1, 5) ^ k2 for x in payload)   # inverse of ror8(b ^ k2, 3) ^ k1
    return (magic + b"\x01" + bytes([k1, k2]) + b"\x00" + struct.pack("<I", len(packed))
            + hashlib.sha256(payload).digest() + packed)


# ---- 1. the real staged Day 19 member ------------------------------------------------------------
real = None
for art in sorted(glob.glob(os.path.join(ROOT, "challenges", "Day *", "_stage", "*", "artifact_*.bin"))):
    try:
        members = unzip(open(art, "rb").read())
    except Exception:
        continue
    for name, b in members:
        for mg in (b"PK19", b"RS20"):
            r = independent_overlay(b, mg)
            if r:
                real = (art, name, b, mg, r)
                break
        if real:
            break
    if real:
        break

if real is None:
    print("SKIP: no staged member carrying a verified packed overlay found")
    print("RESULT: SKIP (not run: 0 checks executed)")
    sys.exit(2)

art, name, blob, magic, ind = real
print("real overlay: %s member %s, magic %s at %d, %d bytes to EOF"
      % (os.path.basename(os.path.dirname(art)), name, magic.decode(), ind["off"], ind["size"]))

got = ab._overlay(blob)
check("adapter finds the real overlay", bool(got))
check("adapter overlay offset == independent parse", bool(got) and got["off"] == ind["off"],
      "adapter %r vs %r" % (got and got.get("off"), ind["off"]))
check("adapter overlay size (member length - offset) == independent parse",
      bool(got) and got["size"] == ind["size"], "adapter %r vs %r" % (got and got.get("size"), ind["size"]))
check("adapter unpacked bytes == independent unpack (SHA-256 verified both sides)",
      bool(got) and got["unpacked"] == ind["unpacked"])
check("adapter reads the magic from the bytes, not a constant",
      bool(got) and got["magic"].encode() == magic, got and got.get("magic"))

ih = independent_hcfg(ind["unpacked"], 0)
check("the unpacked bytes carry a CRC32-valid HCFG record at offset 0", bool(ih))
cur = ab.config(blob, "elf")
check("adapter config() recovers that record through the overlay",
      bool(ih) and cur.get("cfg") == ih["cfg"] and cur.get("crc") == ih["crc"] and cur.get("key") == ih["key"])
check("hcfg version matches the independent parse", bool(ih) and cur.get("ver") == ih["ver"])

# ---- 2. NEXT day's magic, re-packed with different keys (the layer must not be day-specific) -----
nxt = repack(ind["unpacked"], b"RS20", 0x5a, 0xc3)
synth = blob[:ind["off"]] + nxt
s_ind = independent_overlay(synth, b"RS20")
s_got = ab._overlay(synth)
check("a re-packed RS20 overlay with new keys is found at the same offset",
      bool(s_ind) and bool(s_got) and s_got["off"] == s_ind["off"] == ind["off"])
check("RS20 overlay unpacks to the same payload", bool(s_got) and s_got["unpacked"] == ind["unpacked"])
check("RS20 magic is reported from the bytes", bool(s_got) and s_got["magic"] == "RS20")
check("config() recovers the record through the RS20 overlay",
      bool(ih) and ab.config(synth, "elf").get("cfg") == ih["cfg"])

# ---- 3. nothing is invented -----------------------------------------------------------------------
corrupt = bytearray(synth)
corrupt[ind["off"] + 12] ^= 0xFF                      # break the embedded SHA-256
check("an overlay whose SHA-256 does not verify is NOT accepted", ab._overlay(bytes(corrupt)) is None)
plain = blob[:ind["off"]]
check("the same member without its overlay yields no overlay", ab._overlay(plain) is None)
check("a member with no overlay and no record invents no config",
      ab._overlay(b"\x7fELF" + b"PK19 not a stub " * 500) is None)

# ---- 4. scan cost on a big member (the 133 s stall that lost a timed window) ----------------------
big = (b"PK19" + os.urandom(1020)) * 65536             # 64 MiB, ~65k magic matches, no valid overlay
t = time.time()
r = ab._overlay(big)
dt = time.time() - t
check("scanning a 64 MiB member with ~65k magic matches stays under 5 s", dt < 5.0 and r is None,
      "%.2fs" % dt)

total = 16
print("COVERAGE: %.0f%% (%d/%d)" % (100.0 * (total - bad) / total, total - bad, total))
try:
    import adapter_coverage as AC
    AC.record("binary_packed_overlay", total - bad, total, not bad)
except Exception:
    pass
print("RESULT:", "PASS" if not bad else "FAIL")
