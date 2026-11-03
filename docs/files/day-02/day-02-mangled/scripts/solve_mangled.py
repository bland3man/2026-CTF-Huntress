#!/usr/bin/env python3
"""
Mangled (Huntress CTF 2026, Day 02) - deterministic solver.

Recovers the hidden campaign config from a day02-cpp.elf lab sample.

Method (attempt-independent):
  1. zip password is "infected" (WinZip AES-256). Extract day02-cpp.elf.
  2. The ELF carries a custom ".hcfg" section: 4-byte magic "HCFG",
     1-byte version, 1-byte XOR key (byte offset 5), then a short
     header and the XOR-encoded JSON config.
  3. The XOR key is self-describing (header byte 5), but we recover it
     robustly by brute-forcing the single byte that yields JSON whose
     first object key is "campaign". Works regardless of per-attempt
     numbering (BR02-NNN / node-NNN / varying IP).

Usage:
  python3 solve_mangled.py <path-to day02-cpp.elf>   # reads .hcfg via objcopy if available,
                                                       # else parses the ELF section table directly.
"""
import sys, json, struct, subprocess, tempfile, os

def read_section(elf_path, name):
    """Return raw bytes of a named section, parsing the ELF64 section table (no external tools)."""
    data = open(elf_path, "rb").read()
    assert data[:4] == b"\x7fELF", "not an ELF"
    assert data[4] == 2, "not ELF64"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]
    def sh(i):
        off = e_shoff + i * e_shentsize
        nameoff, sh_type = struct.unpack_from("<II", data, off)
        sh_offset = struct.unpack_from("<Q", data, off + 0x18)[0]
        sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
        return nameoff, sh_offset, sh_size
    _, str_off, str_sz = sh(e_shstrndx)
    shstr = data[str_off:str_off + str_sz]
    for i in range(e_shnum):
        nameoff, sh_offset, sh_size = sh(i)
        end = shstr.find(b"\x00", nameoff)
        secname = shstr[nameoff:end].decode("latin1")
        if secname == name:
            return data[sh_offset:sh_offset + sh_size]
    raise KeyError(name + " section not found")

def recover_config(hcfg):
    # hcfg may be the whole file (PE/ELF/raw): locate the HCFG blob by magic.
    i = hcfg.find(b"HCFG")
    if i != -1:
        hcfg = hcfg[i:]
    # Brute single-byte XOR; accept the key that yields JSON with a 'campaign' field.
    for key in range(256):
        dec = bytes(b ^ key for b in hcfg)
        start = dec.find(b'{"campaign"')
        if start == -1:
            continue
        end = dec.find(b"}", start)
        if end <= start:
            continue
        chunk = dec[start:end + 1]
        try:
            cfg = json.loads(chunk.decode("latin1"))
        except Exception:
            continue
        return key, cfg
    raise ValueError("could not recover config")

def load_blob(path):
    """Return bytes to search for the HCFG blob, format-agnostic (ELF .hcfg, PE section, or raw)."""
    data = open(path, "rb").read()
    if data.find(b"HCFG") != -1:
        return data               # magic present somewhere -> scan the whole file
    try:
        return read_section(path, ".hcfg")  # ELF fallback (section name only)
    except Exception:
        return data

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "day02-cpp.elf"
    blob = load_blob(path)
    key, cfg = recover_config(blob)
    print("xor_key: 0x%02x" % key)
    print(json.dumps(cfg, indent=2))

if __name__ == "__main__":
    main()
