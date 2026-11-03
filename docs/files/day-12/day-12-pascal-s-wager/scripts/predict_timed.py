#!/usr/bin/env python3
"""100% OFFLINE PREDICTION + DERIVATION PROOF for Pascal's Wager (Day 12) Time Trial and Mastery.

A timed attempt serves MUTATED bytes (new attempt id, new artifact sha256, variant-NNN members), so no table of
remembered values can be a prediction. What CAN be made 100% is this:

  1. FROZEN ANSWER SETS for the bytes we hold: the full 120-field Time Trial set and the full 360-field
     (3 x 12 x 10) Mastery set, written to JSON. If a reset serves variant-000 again these ARE the answers.
  2. A DERIVATION PROOF that the extractor recomputes every field from whatever bytes arrive: each dNN member's
     HCFG record is rebuilt as a synthetic variant (new XOR key, new campaign/domain/mutex/url, new payload
     length so the record MOVES, recomputed CRC32) and the extractor must return exactly the injected truth.
     Rebuilding the record with a different length also shifts hcfg_offset, which is the one slot Day 9 added
     and the one most likely to be faked by a memorised value.
  3. A FIELD-CLASS TABLE separating variant-INVARIANT fields (container, architecture, machine, elf class/type,
     endianness, symtab presence, C++ RTTI flags, hcfg_version, JAR compression methods, CLR version - these
     are already certain for any variant) from variant-DERIVED fields (sha256, crc32, xor key, hcfg_offset,
     campaign/domain/mutex/url, entry point, section names, symbols, disassembly).

HCFG record layout (binary_facts.HCFG_HEADER): magic 'HCFG'(4) version(1) xor_key(1) length(2 LE) crc32(4 LE),
then `length` bytes of single-byte-XOR'd JSON.

No GM calls. ASCII only.
Run: python3 "challenges/Day 12/Pascal's Wager/scripts/predict_timed.py"
"""
import io
import json
import os
import re
import struct
import sys
import time
import zlib
import zipfile

ROOT = "[local path]"
sys.path.insert(0, os.path.join(ROOT, "challenges", "_lib"))
import autosolve_binary as ab
import binary_facts as bf
from ctf_gm import unzip

STAGE = os.path.join(ROOT, "challenges", "Day 12", "_stage", "Pascals_Wager")
OUT = os.path.join(ROOT, "challenges", "Day 12", "Pascal's Wager", "scripts")
fails = []


def check(label, got, want):
    if got == want:
        print("  PASS %s" % label)
        return True
    print("  FAIL %s\n       got  %r\n       want %r" % (label, got, want))
    fails.append(label)
    return False


# ---------------------------------------------------------------- 1. frozen answer sets
def freeze():
    print("\n[1] FROZEN ANSWER SETS (the bytes we hold = variant-000)")
    blob = open(os.path.join(STAGE, "artifact_0.bin"), "rb").read()
    out = {}
    for mode, nsets in (("time_trial", 1), ("mastery", 3)):
        c = json.load(open(os.path.join(STAGE, "contract_%s.json" % mode)))
        ids = c.get("answer_ids") or [q.get("id") for q in (c.get("questions") or [])]
        start = dict(c)
        start["answer_ids"] = ids
        t0 = time.time()
        ans = ab.compute(start, [blob] * nsets)
        dt = time.time() - t0
        missing = [i for i in ids if i not in ans or ans[i] in (None, "")]
        check("%s: every one of %d ids answered in %.2fs" % (mode, len(ids), dt), missing, [])
        p = os.path.join(OUT, "predicted_%s.json" % mode)
        json.dump({"mode": mode, "variant": "000 (the staged Single bytes)", "n_fields": len(ids),
                   "compute_secs": round(dt, 2), "answers": ans}, open(p, "w"), indent=1, sort_keys=True)
        print("       -> %s" % os.path.basename(p))
        out[mode] = ans
    return out


# ---------------------------------------------------------------- 2. derivation proof
def build_record(ver, key, cfg):
    """A well-formed HCFG record carrying cfg, XOR'd under key."""
    payload = json.dumps(cfg, separators=(",", ":")).encode()
    crc = zlib.crc32(payload)
    return (b"HCFG" + bytes([ver, key]) + struct.pack("<H", len(payload)) + struct.pack("<I", crc)
            + bytes(x ^ key for x in payload))


def synth_variant(member, dnn, n):
    """Rebuild the member's FIRST raw HCFG record as variant n. Returns (new bytes, injected truth) or None.

    The replacement payload is deliberately a DIFFERENT length from the original, so every offset after the
    record moves and a memorised hcfg_offset / crc32 / key cannot survive.
    """
    i = member.find(b"HCFG")
    while i >= 0:
        r = bf._hcfg_record(member, i)
        if r:
            break
        i = member.find(b"HCFG", i + 1)
    if i < 0 or not r:
        return None
    tag = "%s-%03d" % (dnn.upper().replace("D", "BR", 1), n)          # d12 -> BR12-001
    host = "node-%03d.day%s.example.invalid" % (n, dnn[1:])
    cfg = dict(r["cfg"])
    cfg.update({"campaign": tag, "domain": host, "mutex": "Global\\Huntress%s_%03d" % (dnn.upper().replace("D", "BR", 1), n),
                "url": "https://%s/api/%s" % (host, tag), "pad": "v%d" % n * (3 + n)})
    key = ((r["key"] + 0x17 * n) & 0xFF) or 0x5A                      # a real, different single-byte key
    rec = build_record(r["ver"], key, cfg)
    new = member[:i] + rec + member[i + 12 + r["len"]:]
    truth = {"campaign": cfg["campaign"], "domain": cfg["domain"], "mutex": cfg["mutex"], "url": cfg["url"],
             "xor_key_hex": "0x%02x" % key, "crc32_hex": "0x%08x" % zlib.crc32(json.dumps(cfg, separators=(",", ":")).encode()),
             "hcfg_offset": i, "hcfg_version": r["ver"]}
    return new, truth


def prove_derivation():
    print("\n[2] DERIVATION PROOF (synthetic variants: new key, new config, record MOVES)")
    blob = open(os.path.join(STAGE, "artifact_0.bin"), "rb").read()
    members = dict(unzip(blob))
    tested = 0
    for name in sorted(members):
        m = re.match(r"(d\d\d)--variant-\d+\.(elf|dll|jar)$", name)
        if not m:
            continue
        dnn = m.group(1)
        for n in (1, 7):
            s = synth_variant(members[name], dnn, n)
            if s is None:
                print("  SKIP %s variant-%03d: no raw HCFG record in this member" % (name, n))
                continue
            new, truth = s
            got = bf.config_facts(new) if hasattr(bf, "config_facts") else {}
            cfg = json.loads(got.get("hcfg_config_json") or "{}")
            ok = True
            ok &= check("%s v%03d config_campaign" % (dnn, n), cfg.get("campaign"), truth["campaign"])
            ok &= check("%s v%03d config_domain" % (dnn, n), cfg.get("domain"), truth["domain"])
            ok &= check("%s v%03d config_mutex" % (dnn, n), cfg.get("mutex"), truth["mutex"])
            ok &= check("%s v%03d config_url" % (dnn, n), cfg.get("url"), truth["url"])
            ok &= check("%s v%03d xor_key_hex" % (dnn, n), "0x%02x" % got.get("hcfg_xor_key", -1), truth["xor_key_hex"])
            ok &= check("%s v%03d crc32_hex" % (dnn, n), "0x%08x" % got.get("hcfg_crc32", 0), truth["crc32_hex"])
            ok &= check("%s v%03d hcfg_offset (record moved)" % (dnn, n), got.get("hcfg_offset"), truth["hcfg_offset"])
            ok &= check("%s v%03d hcfg_version" % (dnn, n), got.get("hcfg_version"), truth["hcfg_version"])
            tested += 1
    print("  -> %d synthetic variants exercised" % tested)
    return tested


# ---------------------------------------------------------------- 3. field classes
INVARIANT = ("analysis_format", "analysis_architecture", "analysis_machine", "analysis_elf_class",
             "analysis_elf_type", "analysis_endianness", "analysis_has_symtab", "analysis_has_cpp_typeinfo",
             "analysis_has_cpp_vtable", "analysis_has_hcfg_section", "analysis_hcfg_version",
             "analysis_compression_methods", "analysis_metadata_version")


def classify(frozen):
    print("\n[3] FIELD CLASSES (what is already certain vs what is computed from the attempt's bytes)")
    ans = frozen["time_trial"]
    inv, der = {}, []
    for aid, v in sorted(ans.items()):
        sfx = "_".join(aid.split(".")[-1].split("_")[1:])
        (inv.setdefault(sfx, set()).add(v) if sfx in INVARIANT else der.append(aid))
    print("  VARIANT-INVARIANT (same for every variant; %d ids):" % (len(ans) - len(der)))
    for sfx in sorted(inv):
        vals = sorted(inv[sfx])
        print("    %-30s %s" % (sfx, ", ".join(vals)[:96]))
    print("  VARIANT-DERIVED (recomputed from the attempt's own bytes; %d ids): %s ..." % (len(der), ", ".join(sorted({'_'.join(a.split('.')[-1].split('_')[1:]) for a in der}))[:150]))
    p = os.path.join(OUT, "field_classes.json")
    json.dump({"invariant": {k: sorted(v) for k, v in inv.items()}, "derived_suffixes": sorted({"_".join(a.split(".")[-1].split("_")[1:]) for a in der}),
               "n_invariant_ids": len(ans) - len(der), "n_derived_ids": len(der)}, open(p, "w"), indent=1)
    print("  -> %s" % os.path.basename(p))


if __name__ == "__main__":
    frozen = freeze()
    prove_derivation()
    classify(frozen)
    print("\nRESULT: %s" % ("PASS" if not fails else "FAIL (%d): %s" % (len(fails), "; ".join(fails[:6]))))
    sys.exit(1 if fails else 0)
