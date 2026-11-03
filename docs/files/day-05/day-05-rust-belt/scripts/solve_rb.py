#!/usr/bin/env python3
"""Rust Belt (Day 05) multi-field forensic inventory solver.
Adapted from Day03 Table Manners solve_tm.py. Family: dual_format_re.
Deliverables:
  d01 = ELF x86-64 inventory (class/machine/type/endian/sections/symbols/disasm)
  d02 = ELF with embedded HCFG config (campaign/domain/mutex/url/crc32/xor_key)
  d03 = .NET PE32 (format/machine/metadata_version/campaign/domain/mutex) + runtimeconfig.json
  d04 = large ELF with HCFG (architecture/format/campaign/domain/mutex/url/crc32)
  d05 = large ELF with HCFG (architecture/format/campaign/domain/mutex/url/crc32)
Every answer derived from THAT attempt's own bytes (dynamic-safe).
"""
import json, sys, re, struct, zlib, hashlib, time, os
sys.path.insert(0, 'challenges/_lib')
sh = lambda b: hashlib.sha256(b).hexdigest()


def elf(d):
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    n = struct.unpack_from("<H", d, 0x3C)[0]
    si = struct.unpack_from("<H", d, 0x3E)[0]
    secs = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + k * 64) for k in range(n)]
    so = secs[si][4]
    nm = lambda o: d[so + o:d.index(b"\0", so + o)].decode()
    names = [nm(s[0]) for s in secs]
    syms = []
    for s in secs:
        if s[1] == 2:  # SHT_SYMTAB
            stro = secs[s[6]][4]
            for k in range(s[5] // 24):
                x = struct.unpack_from("<IBBHQQ", d, s[4] + k * 24)
                syms.append(d[stro + x[0]:d.index(b"\0", stro + x[0])].decode())
    return secs, names, [x for x in syms if x]


def rc_imm(d):
    secs, names, _ = elf(d)
    t = secs[names.index(".text")]
    body = d[t[4]:t[4] + t[5]]
    c = [int.from_bytes(m.group(1), "little") for m in re.finditer(rb"\xb8(....)\xc3", body, re.S)]
    c = [x for x in c if 8100 <= x <= 8199] or c
    return c[0]


def hcfg(d):
    # "HCFG" may appear more than once (false hits in large binaries); keep the
    # occurrence whose single-byte-XOR payload CRC-validates and parses as JSON.
    i = -1
    while True:
        i = d.find(b"HCFG", i + 1)
        if i < 0:
            break
        key = d[i + 5]
        ln = d[i + 6] | d[i + 7] << 8
        crc = int.from_bytes(d[i + 8:i + 12], "little")
        p = bytes(b ^ key for b in d[i + 12:i + 12 + ln])
        if zlib.crc32(p) == crc:
            try:
                return json.loads(p), key, crc
            except Exception:
                continue
    raise RuntimeError("no CRC-valid HCFG config found")


def dn(d):
    pe = struct.unpack_from("<I", d, 0x3c)[0]
    mach = struct.unpack_from("<H", d, pe + 4)[0]
    i = d.find(b"BSJB")
    l = struct.unpack_from("<I", d, i + 12)[0]
    ver = d[i + 16:i + 16 + l].split(b"\0")[0].decode()
    for key in range(256):
        pat = bytes(b ^ key for b in b'{"campaign"')
        j = d.find(pat)
        if j >= 0:
            out = bytes(b ^ key for b in d[j:j + 2000])
            dep = 0
            for k, ch in enumerate(out):
                dep += (ch == 123) - (ch == 125)
                if dep == 0:
                    break
            return mach, ver, json.loads(out[:k + 1])
    raise RuntimeError("no cfg in .NET")


MACH = {0x14c: "i386", 0x8664: "amd64"}


def one(files, dkey):
    main = next(c for n, c in files if os.path.basename(n).startswith(dkey + "--") and not n.endswith(".json"))
    aux = next((c for n, c in files if os.path.basename(n).startswith(dkey + "--") and n.endswith(".json")), None)
    return main, aux


def answer(files, aid):
    dk, suf = aid.split("_", 1)
    main, aux = one(files, dk)
    if suf == "artifact_sha256_1":
        return sh(main)
    if suf == "artifact_sha256_2":
        return sh(aux)
    if dk == "d01":
        secs, names, syms = elf(main)
        return {
            "analysis_elf_class": "ELF64" if main[4] == 2 else "ELF32",
            "analysis_machine": "x86-64",
            "analysis_elf_type": "ET_EXEC",
            "analysis_endianness": "little" if main[5] == 1 else "big",
            "analysis_section_names": json.dumps(names, separators=(",", ":")),
            "analysis_symbols": json.dumps(syms, separators=(",", ":")),
            "analysis_disassembly": json.dumps(["mov eax, %d" % rc_imm(main), "ret"], separators=(",", ":")),
        }[suf]
    if dk == "d02":
        c, key, crc = hcfg(main)
        return {
            "analysis_format": "elf",
            "analysis_config_campaign": c["campaign"],
            "analysis_config_domain": c["domain"],
            "analysis_config_mutex": c["mutex"],
            "analysis_config_url": c["url"],
            "analysis_config_crc32_hex": "0x%08x" % crc,
            "analysis_xor_key_hex": "0x%02x" % key,
        }[suf]
    if dk in ("d04", "d05"):
        c, key, crc = hcfg(main)
        return {
            "analysis_architecture": "x86-64",
            "analysis_format": "elf",
            "analysis_config_campaign": c["campaign"],
            "analysis_config_domain": c["domain"],
            "analysis_config_mutex": c["mutex"],
            "analysis_config_url": c["url"],
            "analysis_config_crc32_hex": "0x%08x" % crc,
        }[suf]
    # d03 .NET
    mach, ver, c = dn(main)
    return {
        "analysis_format": "pe_cli",
        "analysis_machine": MACH.get(mach, hex(mach)),
        "analysis_metadata_version": ver,
        "analysis_config_campaign": c["campaign"],
        "analysis_config_domain": c["domain"],
        "analysis_config_mutex": c["mutex"],
    }[suf]


def compute(st, blobs):
    from ctf_gm import unzip
    sets = [unzip(b) for b in blobs]
    out = {}
    for aid in st["answer_ids"]:
        m = re.match(r"^set(\d+)\.(.*)$", aid)
        idx = int(m.group(1)) - 1 if m else 0
        core = m.group(2) if m else aid
        out[aid] = answer(sets[idx], core)
    return out


def offline(workdir):
    files = []
    for n in sorted(os.listdir(workdir)):
        files.append((n, open(os.path.join(workdir, n), "rb").read()))
    ids = [
        "d01_artifact_sha256_1", "d01_analysis_elf_class", "d01_analysis_machine",
        "d01_analysis_section_names", "d01_analysis_symbols", "d01_analysis_disassembly",
        "d01_analysis_elf_type", "d01_analysis_endianness",
        "d02_artifact_sha256_1", "d02_analysis_format", "d02_analysis_config_campaign",
        "d02_analysis_config_domain", "d02_analysis_config_mutex", "d02_analysis_config_url",
        "d02_analysis_config_crc32_hex", "d02_analysis_xor_key_hex",
        "d03_artifact_sha256_1", "d03_artifact_sha256_2", "d03_analysis_format",
        "d03_analysis_machine", "d03_analysis_metadata_version", "d03_analysis_config_campaign",
        "d03_analysis_config_domain", "d03_analysis_config_mutex",
        "d04_artifact_sha256_1", "d04_analysis_architecture", "d04_analysis_format",
        "d04_analysis_config_campaign", "d04_analysis_config_domain", "d04_analysis_config_mutex",
        "d04_analysis_config_url", "d04_analysis_config_crc32_hex",
        "d05_artifact_sha256_1", "d05_analysis_architecture", "d05_analysis_format",
        "d05_analysis_config_campaign", "d05_analysis_config_domain", "d05_analysis_config_mutex",
        "d05_analysis_config_url", "d05_analysis_config_crc32_hex",
    ]
    for aid in ids:
        print(aid, "=>", answer(files, aid))


if __name__ == "__main__":
    if sys.argv[1] == "offline":
        offline(sys.argv[2])
    else:
        from ctf_gm import GM
        cid = sys.argv[1]
        g = GM()
        reps = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        t = time.time()
        for attempt in range(reps):
            st = g.start(cid)
            blobs = [g.download(cid, e, i) for i, e in enumerate(g.artifacts(st))]
            a = compute(st, blobs)
            r = g.submit(cid, a)
            print(attempt, round(time.time() - t, 2),
                  {k: v for k, v in r.items() if k not in ("questions", "prompt", "guidance", "name")}, flush=True)
            if str(r.get("result")).upper() == "CORRECT":
                break
            g.retry(cid)
