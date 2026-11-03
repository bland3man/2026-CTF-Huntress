#!/usr/bin/env python3
"""Binary lane UNIVERSE test (2026-10-15): every field shape the lane can be asked, on REAL binaries, against INDEPENDENT oracles.

Why: Day 15 held at T+9 and was CORRECT only at T+277 because the question set grows by one layer a day (a new toolchain, a new format, a new field, a new
packaging - Day 15: the member tag moved into the field id). This test enumerates the shapes ahead of time instead of waiting for the next layer:
ELF32/64 x little/big x x86/x86-64/arm/aarch64/mips/ppc/riscv/s390, static/dynamic/PIE/shared/relocatable, stripped/unstripped/headerless, DWARF, rpath, build-id,
a REAL UPX-packed stub, C++ (vtable / typeinfo), hand-built PE32 / PE32+ / ARM64 PE, Mach-O, a jar, the hcfg-style config block, PAIRS of members (tag in the field id)
and cumulative d01..dNN bundles, plus a synthetic Day 16 block of brand-new field names.

Contract checked per field (outcome = CORRECT | HELD | WRONG):
  WRONG   = the adapter answered "sure" with a value outside the oracle's accepted set (or any sure answer where the oracle says the label is not graded-known) - always a failure;
  HELD    = probe / unknown (never sent): fine, EXCEPT for the MUST-ANSWER set (deterministic structure: class, endianness, e_type, machine code, entry point, symtab, sections, config);
  CORRECT = sure and inside the accepted set.
Oracles are readelf / sha256sum / pefile / file / python zipfile / pyelftools run at REGEN time and frozen into fixtures/real_binaries/<name>.expected.json; a normal run replays the
frozen fixtures and needs NO compiler. `--regen` rebuilds them when the tools exist (skipped silently otherwise). Offline, no GM. Run with WSL python3.
"""
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if os.environ.get("UNIV_ADAPTER_DIR"):         # measure an OLDER copy of the adapter (e.g. the Day 15 _solvers snapshot) against the same universe: "failures before"
    sys.path.insert(0, os.environ["UNIV_ADAPTER_DIR"])
import autosolve_binary as ab  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "real_binaries")
REGEN = "--regen" in sys.argv
bad = passes = 0
failures = []


def check(name, ok, detail=""):
    global bad, passes
    passes += bool(ok)
    bad += (not ok)
    if not ok:
        failures.append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" (%s)" % detail) if detail else ""))


TXT = {"kind": "exact_text", "syntax": "exact artifact-derived value only, without quotes or explanatory text unless quotes are part of the value; use the literal none only when the requested field is absent"}
INT = {"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"}
BOOL = {"kind": "enum", "accepted_values": ["true", "false"]}
HEX = {"kind": "pattern", "syntax": "lowercase hexadecimal with a 0x prefix and no explanatory text"}
JSN = {"kind": "json", "syntax": "compact valid JSON array with exact values and order; no Markdown or explanatory text"}
MACH = {"kind": "pattern", "syntax": "executable-header machine architecture label or its equivalent decimal or hexadecimal code; common file, readelf, and objdump labels are accepted"}
ARCH = {"kind": "pattern", "syntax": "processor architecture name, standard tool or symbolic label, or equivalent executable-header machine code"}
ETYPE = {"kind": "pattern", "syntax": "ELF e_type symbolic constant, readelf label, or equivalent decimal or hexadecimal code"}
ENDIAN = {"kind": "pattern", "syntax": "ELF byte-order name, readelf description, EI_DATA symbolic constant, or equivalent decimal or hexadecimal code"}
FMT = {"kind": "pattern", "syntax": "ELF or PE; letter case is ignored and ELF32, ELF64, PE32, PE32+, or Portable Executable are accepted when they identify the same container"}
SECN = {"kind": "json", "syntax": "JSON array of section-name strings in section-header-table order; an optional leading empty string represents section index 0"}

# suffix -> answer_format.  MUST = the field is deterministic structure the adapter has to answer for an ELF carrying that structure.
FIELDS = {
    "artifact_sha256_1": TXT, "analysis_format": FMT, "analysis_elf_class": TXT, "analysis_endianness": ENDIAN, "analysis_elf_type": ETYPE, "analysis_machine": MACH,
    "analysis_architecture": ARCH, "analysis_entry_point": HEX, "analysis_has_symtab": BOOL, "analysis_section_names": SECN, "analysis_symbols": JSN, "analysis_disassembly": JSN,
    "analysis_config_campaign": TXT, "analysis_config_domain": TXT, "analysis_config_url": TXT, "analysis_config_mutex": TXT, "analysis_config_crc32_hex": HEX,
    "analysis_xor_key_hex": HEX, "analysis_hcfg_version": INT, "analysis_hcfg_offset": INT, "analysis_has_hcfg_section": BOOL, "analysis_has_cpp_typeinfo": BOOL,
    "analysis_has_cpp_vtable": BOOL, "analysis_compression_methods": JSN,
}
# generic by-name fields (readelf-style facts): either answered correctly or HELD, never wrong
GENERIC = {"analysis_section_count": INT, "analysis_program_header_count": INT, "analysis_interpreter": TXT, "analysis_build_id": TXT, "analysis_soname": TXT,
           "analysis_rpath": TXT, "analysis_runpath": TXT, "analysis_needed_libs": JSN, "analysis_has_dwarf": BOOL, "analysis_has_dynamic": BOOL}


# ----------------------------------------------------------------------------------------------------------------- bundle helpers
def bundle(members):
    """members = [(name, bytes)] -> the Game Master evidence-zip shape (AES-256, password infected)."""
    import pyzipper
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        for n, b in members:
            z.writestr(n, b)
    return buf.getvalue()


def save_fixture(name, data, expected):
    os.makedirs(FIX, exist_ok=True)
    with zipfile.ZipFile(os.path.join(FIX, name + ".zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name + ".bin", data)
    json.dump(expected, open(os.path.join(FIX, name + ".expected.json"), "w"), indent=1, sort_keys=True)


def load_fixtures():
    out = {}
    if not os.path.isdir(FIX):
        return out
    for f in sorted(os.listdir(FIX)):
        if f.endswith(".zip"):
            n = f[:-4]
            ep = os.path.join(FIX, n + ".expected.json")
            if os.path.exists(ep):
                z = zipfile.ZipFile(os.path.join(FIX, f))
                out[n] = (z.read(z.namelist()[0]), json.load(open(ep)))
    return out


# ----------------------------------------------------------------------------------------------------------------- oracles (REGEN time only)
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout


def hcfg_record(tag, key=0xB1, ver=1):
    cfg = {"campaign": "BR16-%s" % tag, "domain": "node-%s.day16.example.invalid" % tag, "ipv4": "198.51.100.16", "url": "https://node-%s.day16.example.invalid/api" % tag,
           "mutex": "Global\\HuntressBR16_%s" % tag}
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    return b"HCFG" + bytes([ver, key]) + len(plain).to_bytes(2, "little") + zlib.crc32(plain).to_bytes(4, "little") + bytes(x ^ key for x in plain), cfg, key, ver, zlib.crc32(plain)


def cfg_oracle(tag, data, in_member=False):
    """The config block a fixture was BUILT with (test-side constants), frozen next to the tool oracle output."""
    rec, cfg, key, ver, crc = hcfg_record(tag)
    return {"config": cfg, "xor_key": key, "crc32": crc, "hcfg_version": ver, "hcfg_offset": 0 if in_member else data.find(b"HCFG")}


def oracle_elf(path, data):
    """Everything the adapter is asked about an ELF, read by readelf (+ pyelftools cross-check) - never by autosolve_binary."""
    exp = {"sha256": __import__("hashlib").sha256(data).hexdigest(), "kind": "elf"}
    h = sh("readelf", "-hW", path)
    g = lambda pat: (re.search(pat, h, re.M) or [None, None])[1]
    exp["elf_class"] = {"ELF32": "ELF32", "ELF64": "ELF64"}[g(r"^\s*Class:\s+(\S+)")]
    exp["endianness"] = "little" if "little endian" in g(r"^\s*Data:\s+(.*)$") else "big"
    exp["e_type"] = {"REL": "ET_REL", "EXEC": "ET_EXEC", "DYN": "ET_DYN", "CORE": "ET_CORE", "NONE": "ET_NONE"}[g(r"^\s*Type:\s+(\w+)")]
    exp["machine_label"] = g(r"^\s*Machine:\s+(.*)$").strip()
    exp["entry"] = int(g(r"Entry point address:\s+(0x[0-9a-f]+)"), 16)
    exp["shnum"] = int(g(r"Number of section headers:\s+(\d+)"))
    exp["phnum"] = int(g(r"Number of program headers:\s+(\d+)"))
    from elftools.elf.elffile import ELFFile
    ef = ELFFile(io.BytesIO(data))
    exp["e_machine"] = ef.header["e_machine"]
    from elftools.elf.constants import E_FLAGS  # noqa: F401  (import proves pyelftools is the second oracle)
    from elftools.elf.enums import ENUM_E_MACHINE
    exp["e_machine_num"] = struct.unpack_from(("<" if exp["endianness"] == "little" else ">") + "H", data, 18)[0]
    exp["e_machine_name"] = ef.header["e_machine"]
    exp["machine_num_check"] = ENUM_E_MACHINE.get(ef.header["e_machine"], None)
    s = sh("readelf", "-SW", path)
    names = re.findall(r"^\s*\[\s*\d+\]\s+(\S*)\s+(?:NULL|PROGBITS|NOBITS|SYMTAB|STRTAB|DYNSYM|DYNAMIC|NOTE|REL|RELA|HASH|INIT_ARRAY|FINI_ARRAY|GNU_HASH|VERNEED|VERSYM|MIPS_\w+|ARM_\w+|\w+)\s", s, re.M)
    pn = [sec.name for sec in ef.iter_sections()]
    exp["section_names"] = pn
    exp["section_names_readelf_agree"] = (names == pn[:len(names)] or [n for n in names if n] == [n for n in pn if n])
    exp["has_symtab"] = ef.get_section_by_name(".symtab") is not None
    syms = []
    st = ef.get_section_by_name(".symtab")
    if st is not None:
        syms = [x.name for x in st.iter_symbols() if x.name]
    rs = sh("readelf", "-sW", path)
    m = re.search(r"Symbol table '\.symtab'.*?\n(.*?)(?:\n\n|\Z)", rs, re.S)
    rnames = []
    if m:
        for line in m.group(1).splitlines()[1:]:
            parts = line.split(None, 7)
            if len(parts) == 8:
                rnames.append(parts[7].strip())
    exp["symbols"] = syms
    exp["symbols_readelf_agree"] = (rnames == syms)
    exp["has_hcfg_section"] = ef.get_section_by_name(".hcfg") is not None
    hs = ef.get_section_by_name(".hcfg")
    if hs is not None:
        raw = hs.data()
        ver, key, ln = raw[4], raw[5], raw[6] | raw[7] << 8
        crc = int.from_bytes(raw[8:12], "little")
        plain = bytes(b ^ key for b in raw[12:12 + ln])
        assert zlib.crc32(plain) == crc
        exp["config"] = json.loads(plain)
        exp["xor_key"], exp["crc32"], exp["hcfg_version"] = key, crc, ver
        exp["hcfg_offset"] = data.find(b"HCFG")
    nm = sh("nm", path)
    exp["has_cpp_vtable"] = "_ZTV" in nm
    exp["has_cpp_typeinfo"] = "_ZTI" in nm
    exp["recover_code"] = None
    if "recover_code" in syms:
        od = sh("objdump", "-d", "-M", "intel", "--no-show-raw-insn", path)
        mm = re.search(r"<recover_code>:\n((?:\s+[0-9a-f]+:\t.*\n)+)", od)
        if mm:
            exp["recover_code"] = [re.sub(r"\s+", " ", ln.split("\t", 1)[1].strip()) for ln in mm.group(1).splitlines()]
    d = sh("readelf", "-dW", path)
    exp["needed"] = re.findall(r"\(NEEDED\)\s+Shared library: \[(.*?)\]", d)
    exp["soname"] = (re.findall(r"\(SONAME\)\s+Library soname: \[(.*?)\]", d) or ["none"])[0]
    exp["rpath"] = (re.findall(r"\(RPATH\)\s+Library rpath: \[(.*?)\]", d) or ["none"])[0]
    exp["runpath"] = (re.findall(r"\(RUNPATH\)\s+Library runpath: \[(.*?)\]", d) or ["none"])[0]
    exp["has_dynamic"] = ef.get_section_by_name(".dynamic") is not None
    ph = sh("readelf", "-lW", path)
    im = re.search(r"Requesting program interpreter: (\S+?)\]", ph)
    exp["interpreter"] = im.group(1) if im else "none"
    n = sh("readelf", "-nW", path)
    bm = re.search(r"Build ID: ([0-9a-f]+)", n)
    exp["build_id"] = bm.group(1) if bm else "none"
    exp["has_dwarf"] = any(x.startswith(".debug_") for x in pn)
    return exp


def oracle_pe(path, data):
    import pefile
    pe = pefile.PE(data=data)
    return {"sha256": __import__("hashlib").sha256(data).hexdigest(), "kind": "pe", "pe_machine": pe.FILE_HEADER.Machine, "pe_magic": pe.OPTIONAL_HEADER.Magic,
            "pe_sections": [s.Name.rstrip(b"\0").decode() for s in pe.sections], "pe_symptr": pe.FILE_HEADER.PointerToSymbolTable}


def oracle_other(path, data, kind):
    import hashlib
    exp = {"sha256": hashlib.sha256(data).hexdigest(), "kind": kind, "file": sh("file", "-b", path).strip()}
    if kind == "jar":
        exp["compression_methods"] = sorted({i.compress_type for i in zipfile.ZipFile(io.BytesIO(data)).infolist()})
    return exp


# ----------------------------------------------------------------------------------------------------------------- hand-built ELF (any class / byte order / machine)
def build_elf(bits, big, machine, etype=2, symtab=True, hcfg=True, recover=False, shdrs=True, tag="000"):
    """A minimal but fully valid ELF: header, one PT_LOAD, .text, [.hcfg], [.symtab+.strtab], .shstrtab, section headers. Validated by readelf at regen time, never by the adapter."""
    e = ">" if big else "<"
    w = (lambda v: struct.pack(e + "Q", v)) if bits == 64 else (lambda v: struct.pack(e + "I", v))
    ehsz, phsz, shsz = (64, 56, 64) if bits == 64 else (52, 32, 40)
    text = bytes([0x90] * 16)
    rec = hcfg_record(tag)[0] if hcfg else b""
    strtab = b"\0t.c\0recover_code\0main\0" if symtab else b""
    syms = []
    if symtab:
        symsz = 24 if bits == 64 else 16

        def sym(name, info, shndx, val, size):
            if bits == 64:
                return struct.pack(e + "IBBHQQ", name, info, 0, shndx, val, size)
            return struct.pack(e + "IIIBBH", name, val, size, info, 0, shndx)
        syms = [sym(0, 0, 0, 0, 0), sym(1, 4, 0xfff1, 0, 0), sym(5, 0x12, 1, 0x400100, 8) if recover else sym(18, 0x12, 1, 0x400100, 16)]
        if recover:
            syms.append(sym(18, 0x12, 1, 0x400108, 8))
    symdata = b"".join(syms)
    shstr = b"\0.text\0" + (b".hcfg\0" if hcfg else b"") + (b".symtab\0.strtab\0" if symtab else b"") + b".shstrtab\0"

    def soff(n):
        return shstr.index(b"\0" + n + b"\0") + 1
    off = ehsz + phsz
    parts = {".text": (off, text)}
    off += len(text)
    if hcfg:
        parts[".hcfg"] = (off, rec)
        off += len(rec)
    if symtab:
        off = (off + 7) & ~7
        parts[".symtab"] = (off, symdata)
        off += len(symdata)
        parts[".strtab"] = (off, strtab)
        off += len(strtab)
    parts[".shstrtab"] = (off, shstr)
    off += len(shstr)
    off = (off + 7) & ~7
    shoff = off if shdrs else 0
    order = [".text"] + ([".hcfg"] if hcfg else []) + ([".symtab", ".strtab"] if symtab else []) + [".shstrtab"]
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for n in order:
        o, d = parts[n]
        typ = {".symtab": 2, ".strtab": 3, ".shstrtab": 3}.get(n, 1)
        link = (order.index(".strtab") + 1) if n == ".symtab" else 0
        info = len(syms) if n == ".symtab" else 0
        ent = (24 if bits == 64 else 16) if n == ".symtab" else 0
        addr = 0x400000 + o if n in (".text", ".hcfg") else 0
        secs.append((soff(n.encode()), typ, 6 if n == ".text" else 2 if n == ".hcfg" else 0, addr, o, len(d), link, info, 1, ent))
    shnum = len(secs) if shdrs else 0
    shstrndx = len(secs) - 1 if shdrs else 0
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 2 if big else 1, 1, 0]) + b"\0" * 8
    entry = 0x400000 + ehsz + phsz
    if bits == 64:
        hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", etype, machine, 1, entry, ehsz, shoff, 0, ehsz, phsz, 1, shsz, shnum, shstrndx)
        ph = struct.pack(e + "IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, off, off, 0x1000)
    else:
        hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", etype, machine, 1, entry, ehsz, shoff, 0, ehsz, phsz, 1, shsz, shnum, shstrndx)
        ph = struct.pack(e + "IIIIIIII", 1, 0, 0x400000, 0x400000, off, off, 5, 0x1000)
    body = bytearray(hdr + ph)
    for n in order:
        o, d = parts[n]
        body.extend(b"\0" * (o - len(body)))
        body.extend(d)
    if shdrs:
        body.extend(b"\0" * (shoff - len(body)))
        for s in secs:
            body.extend(struct.pack(e + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"), *s))
    return bytes(body)


def build_pe(machine, pe32plus, tag="000"):
    rec = hcfg_record(tag)[0]
    opt_size = 0xF0 if pe32plus else 0xE0
    raw = rec + b"\0" * (512 - len(rec))
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0x5F000000, 0, 0, opt_size, 0x22)
    opt = struct.pack("<HBBIIIII", 0x20B if pe32plus else 0x10B, 14, 0, 512, 0, 0, 0x1000, 0x1000)
    if not pe32plus:
        opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<Q" if pe32plus else "<I", 0x140000000 if pe32plus else 0x400000)
    opt += struct.pack("<IIHHHHHHIIIIHHQQQQ" if pe32plus else "<IIHHHHHHIIIIHHIIII", 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x8160,
                       0x100000, 0x1000, 0x100000, 0x1000) if pe32plus else struct.pack("<IIHHHHHHIIIIHHIIII", 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x8140,
                                                                                         0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\0" * (16 * 8)
    opt = opt.ljust(opt_size, b"\0")
    sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 512, 0x1000, 512, 0x200, 0, 0, 0, 0, 0x60000020)
    hdrs = (dos + coff + opt + sec).ljust(0x200, b"\0")
    return hdrs + raw


def build_macho(cpu, tag="000"):
    rec = hcfg_record(tag)[0]
    return struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 3, 2, 0, 0, 0, 0) + rec.ljust(256, b"\0")


def build_jar():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("META-INF/MANIFEST.MF"), "Manifest-Version: 1.0\n", zipfile.ZIP_STORED)
        z.writestr("Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"X" * 300, zipfile.ZIP_DEFLATED)
        rec = hcfg_record("jar")[0]
        z.writestr("res.bin", rec, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def _leb(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def build_wasm(tag, memory64=False):
    """Day 16 (Wasm Up) shape: a minimal valid WebAssembly module - type / function / memory / export / code / data -
    with the HCFG record as the active data segment, exactly where the real d16 members carry it. The memory type's
    limits flags carry the memory64 bit for the wasm64 variant, which is the only address-width evidence a module has."""
    rec = hcfg_record(tag)[0]

    def sec(sid, payload):
        return bytes([sid]) + _leb(len(payload)) + payload

    body = b"\x00\x0b"                                           # 0 local groups, end
    off = (b"\x42\x00\x0b" if memory64 else b"\x41\x00\x0b")      # i64.const 0 / i32.const 0, end
    return (b"\x00asm\x01\x00\x00\x00"
            + sec(1, b"\x01\x60\x00\x00")                          # one type: () -> ()
            + sec(3, b"\x01\x00")                                  # one function of type 0
            + sec(5, b"\x01" + bytes([0x04 if memory64 else 0x00, 1]))
            + sec(7, b"\x01\x06memory\x02\x00")                    # export the memory
            + sec(10, b"\x01" + _leb(len(body)) + body)
            + sec(11, b"\x01\x00" + off + _leb(len(rec)) + rec))


C_SRC = ('__attribute__((section(".huntress"), used)) static const char huntress_marker[] = "BR16-UNIVERSE";\n'
         '__attribute__((section(".hcfg"), used)) static const unsigned char hcfg[] = {%s};\n'
         "int recover_code(void) { return %d; }\nint main(void) { return recover_code() == 0 ? hcfg[0] * 0 : 1; }\n")
CPP_SRC = ('__attribute__((section(".hcfg"), used)) static const unsigned char hcfg[] = {%s};\n'
           "struct Engine { virtual ~Engine() {} virtual int score(const char* s) const { return s && *s ? 6 : 1; } };\n"
           "int main(int c, char** v) { Engine* e = new Engine(); int r = e->score(c > 1 ? v[1] : \"\"); delete e; return r * 0 + hcfg[0] * 0; }\n")


def regen():
    """Rebuild every fixture with the real toolchains. Skips (prints SKIP) anything whose tool is missing; never needed for a normal run."""
    tmp = tempfile.mkdtemp(prefix="binuniv_")
    made = []
    have = lambda t: shutil.which(t) is not None

    def done(name, data, exp):
        save_fixture(name, data, exp)
        made.append(name)

    arr = ",".join(str(x) for x in hcfg_record("gcc")[0])

    def gcc(name, flags, cxx=False, strip=False, code=8100, post=None):
        if not have("g++" if cxx else "gcc"):
            print("SKIP regen %s: no compiler" % name)
            return
        src = os.path.join(tmp, name + (".cpp" if cxx else ".c"))
        open(src, "w").write((CPP_SRC % arr) if cxx else (C_SRC % (arr, code)))
        out = os.path.join(tmp, name)
        r = subprocess.run(["g++" if cxx else "gcc"] + flags + ["-o", out, src], capture_output=True, text=True)
        if r.returncode:
            print("SKIP regen %s: %s" % (name, r.stderr.strip()[:90]))
            return
        if strip:
            subprocess.run(["strip", out], check=True)
        if post:
            post(out)
        data = open(out, "rb").read()
        done(name, data, oracle_elf(out, data))

    gcc("gcc_pie_O2", ["-O2"])
    gcc("gcc_nopie_O0", ["-O0", "-no-pie"])
    gcc("gcc_pie_stripped", ["-O2"], strip=True)
    gcc("gcc_nopie_static", ["-O2", "-no-pie", "-static"])
    gcc("gcc_dwarf_rpath", ["-O1", "-g", "-Wl,-rpath,/opt/univ/lib", "-Wl,--build-id=sha1"])
    gcc("gcc_shared", ["-O2", "-shared", "-fPIC", "-Wl,-soname,libuniv.so.1"])
    gcc("gcc_object", ["-O2", "-c"])
    gcc("gpp_vtable", ["-O0"], cxx=True)

    def upx(out):
        subprocess.run(["upx", "--best", "-q", "-q", "-f", out], capture_output=True)
    if have("upx"):
        gcc("gcc_upx_packed", ["-O2", "-no-pie", "-static"], post=upx)
    else:
        print("SKIP regen upx: no upx")
    if have("as") and have("ld"):
        asm = os.path.join(tmp, "e32.s")
        open(asm, "w").write('.globl _start\n.globl recover_code\n.type recover_code,@function\n.text\n_start:\n mov $1,%eax\n xor %ebx,%ebx\n int $0x80\nrecover_code:\n mov $8100,%eax\n ret\n.size recover_code,.-recover_code\n'
                             '.section .hcfg,"a"\n.byte ' + arr + "\n")
        o, x = os.path.join(tmp, "e32.o"), os.path.join(tmp, "e32")
        if subprocess.run(["as", "--32", "-o", o, asm], capture_output=True).returncode == 0 and subprocess.run(["ld", "-m", "elf_i386", "-o", x, o], capture_output=True).returncode == 0:
            data = open(x, "rb").read()
            done("asld_elf32_x86", data, oracle_elf(x, data))
    # hand-built ELF family (validated by readelf + pyelftools)
    for bits, big, mach, mname in ((32, False, 40, "arm"), (64, False, 183, "aarch64"), (32, True, 8, "mips_be"), (32, True, 20, "ppc_be"), (64, True, 21, "ppc64_be"),
                                   (64, False, 243, "riscv64"), (64, True, 22, "s390x_be"), (32, False, 3, "x86_32le"), (64, False, 62, "x86_64le"), (32, True, 40, "arm_be")):
        for variant, kw in (("sym", dict(symtab=True, recover=(mname in ("arm", "aarch64", "x86_32le", "x86_64le")))), ("nosym", dict(symtab=False))):
            n = "hand_%s_%s" % (mname, variant)
            data = build_elf(bits, big, mach, tag=mname, **kw)
            p = os.path.join(tmp, n)
            open(p, "wb").write(data)
            done(n, data, oracle_elf(p, data))
    for n, kw in (("hand_x86_64_noshdr", dict(shdrs=False, bits=64, big=False, machine=62)), ("hand_x86_64_rel", dict(etype=1, bits=64, big=False, machine=62)),
                  ("hand_x86_64_dyn", dict(etype=3, bits=64, big=False, machine=62))):
        data = build_elf(tag="x", **kw)
        p = os.path.join(tmp, n)
        open(p, "wb").write(data)
        try:
            exp = oracle_elf(p, data)
            if "config" not in exp:
                exp.update(cfg_oracle("x", data))
            exp["noshdr"] = (n == "hand_x86_64_noshdr")
            done(n, data, exp)
        except Exception as ex:           # a header-less ELF has no section table for readelf: freeze only what the file header says
            exp = {"sha256": __import__("hashlib").sha256(data).hexdigest(), "kind": "elf", "noshdr": True, "elf_class": "ELF64", "endianness": "little", "e_type": "ET_EXEC",
                   "e_machine_num": 62, "entry": struct.unpack_from("<Q", data, 24)[0], "has_symtab": False, "has_hcfg_section": False, "oracle_note": str(ex)[:60]}
            exp.update(cfg_oracle("x", data))
            done(n, data, exp)
    # PE / Mach-O / jar
    try:
        for n, mach, plus in (("hand_pe32_i386", 0x14C, False), ("hand_pe32plus_amd64", 0x8664, True), ("hand_pe32plus_arm64", 0xAA64, True)):
            data = build_pe(mach, plus, tag=n)
            done(n, data, dict(oracle_pe(n, data), **cfg_oracle(n, data)))
    except ImportError:
        print("SKIP regen pe: no pefile")
    for n, cpu in (("hand_macho_x86_64", 0x01000007), ("hand_macho_arm64", 0x0100000C)):
        data = build_macho(cpu, tag=n)
        p = os.path.join(tmp, n)
        open(p, "wb").write(data)
        done(n, data, dict(oracle_other(p, data, "macho"), **cfg_oracle(n, data)))
    data = build_jar()
    p = os.path.join(tmp, "univ.jar")
    open(p, "wb").write(data)
    done("jar_mixed_methods", data, dict(oracle_other(p, data, "jar"), **cfg_oracle("jar", data, in_member=True)))
    shutil.rmtree(tmp, ignore_errors=True)
    print("regen: %d fixtures written to %s" % (len(made), FIX))


# ----------------------------------------------------------------------------------------------------------------- expected answers from frozen oracle output
def accepted(exp, suf, fm):
    """-> (set of acceptable answer strings or None when the label vocabulary is not graded-known [must be HELD], must_answer bool)"""
    k = exp["kind"]
    if suf == "artifact_sha256_1":
        return {exp["sha256"]}, True
    if k == "elf":
        mach = exp.get("e_machine_num")
        sec_ok = not exp.get("noshdr") and exp.get("shnum") != 0
        if suf == "analysis_format":
            return {"elf"}, True
        if suf == "analysis_elf_class":
            return {exp["elf_class"]}, True
        if suf == "analysis_endianness":
            return {exp["endianness"]}, True
        if suf == "analysis_elf_type":
            return {exp["e_type"], {"ET_REL": "1", "ET_EXEC": "2", "ET_DYN": "3"}.get(exp["e_type"], "?")}, True
        if suf == "analysis_machine":
            s = {str(mach), hex(mach)}
            if mach == 62:
                s |= {"x86-64"}
            return s, True
        if suf == "analysis_architecture":
            return ({"x86-64"} if mach == 62 else None), False
        if suf == "analysis_entry_point":
            return {"0x%x" % exp["entry"]}, True
        if suf == "analysis_has_symtab":
            return {"true" if exp["has_symtab"] else "false"}, True
        if suf == "analysis_section_names":
            if not sec_ok:
                return None, False
            return {json.dumps(exp["section_names"], separators=(",", ":")), json.dumps([x for x in exp["section_names"] if x != ""][:0] + exp["section_names"], separators=(",", ":"))}, True
        if suf == "analysis_symbols":
            if not sec_ok:
                return None, False
            return {json.dumps(exp["symbols"], separators=(",", ":"))}, True
        if suf == "analysis_disassembly":
            rc = exp.get("recover_code")
            if "recover_code" not in exp.get("symbols", []):
                return {"[]"}, True
            if mach in (3, 62) and rc and len(rc) == 2 and re.fullmatch(r"mov eax,0x[0-9a-f]+", rc[0]) and rc[1] == "ret":
                return {json.dumps(["mov eax, %d" % int(rc[0].split(",")[1], 16), "ret"], separators=(",", ":"))}, False   # the one graded-known spelling (decimal immediate)
            return None, False                     # compiler-shaped body / another architecture: spelling not graded-known -> must be HELD
        has = exp.get("has_hcfg_section")
        cfg = exp.get("config")
        if suf == "analysis_has_hcfg_section":
            if exp.get("noshdr") or exp.get("shnum") == 0:
                return None, False                 # no section header table: "is there a .hcfg SECTION" cannot be read -> HELD
            return {"true" if has else "false"}, True
        if suf.startswith("analysis_config_") and suf not in ("analysis_config_crc32_hex",):
            return (({cfg[suf[len("analysis_config_"):]]} if cfg else None), bool(cfg))
        if suf == "analysis_config_crc32_hex":
            return (({"0x%08x" % exp["crc32"]} if cfg else None), bool(cfg))
        if suf == "analysis_xor_key_hex":
            return (({"0x%02x" % exp["xor_key"]} if cfg else None), bool(cfg))
        if suf == "analysis_hcfg_version":
            return (({str(exp["hcfg_version"])} if cfg else None), bool(cfg))
        if suf == "analysis_hcfg_offset":
            return (({str(exp["hcfg_offset"])} if cfg else None), bool(cfg))
        if suf in ("analysis_has_cpp_vtable", "analysis_has_cpp_typeinfo"):
            return {"true" if exp[suf[len("analysis_"):]] else "false"}, True
        if suf == "analysis_compression_methods":
            return None, False
        g = {"analysis_section_count": exp.get("shnum"), "analysis_program_header_count": exp.get("phnum"), "analysis_interpreter": exp.get("interpreter"),
             "analysis_build_id": exp.get("build_id"), "analysis_soname": exp.get("soname"), "analysis_rpath": exp.get("rpath"), "analysis_runpath": exp.get("runpath"),
             "analysis_needed_libs": exp.get("needed"), "analysis_has_dwarf": exp.get("has_dwarf"), "analysis_has_dynamic": exp.get("has_dynamic")}
        if suf in g:
            v = g[suf]
            if v is None:
                return None, False
            if isinstance(v, bool):
                return {"true" if v else "false"}, False
            if isinstance(v, list):
                return {json.dumps(v, separators=(",", ":"))}, False
            return {str(v)}, False
        return None, False
    cfgx = exp.get("config")
    if k in ("pe", "macho", "jar") and cfgx:
        # the HCFG record is a raw byte structure: its decode is format independent (and GM-graded on native PE / jar days)
        m_ = {"analysis_config_campaign": cfgx["campaign"], "analysis_config_domain": cfgx["domain"], "analysis_config_url": cfgx["url"], "analysis_config_mutex": cfgx["mutex"],
              "analysis_config_crc32_hex": "0x%08x" % exp["crc32"], "analysis_xor_key_hex": "0x%02x" % exp["xor_key"], "analysis_hcfg_version": str(exp["hcfg_version"]),
              "analysis_hcfg_offset": str(exp["hcfg_offset"]), "analysis_has_hcfg_section": "true"}
        if suf in m_:
            return {m_[suf]}, False
    if k == "pe":
        if suf == "analysis_format":
            return {"pe"}, False
        if suf == "analysis_machine":
            return {str(exp["pe_machine"]), hex(exp["pe_machine"])}, False
        if suf == "analysis_architecture":
            return ({"x86-64"} if exp["pe_machine"] == 0x8664 else None), False
        if suf in ("analysis_has_cpp_typeinfo", "analysis_has_cpp_vtable"):
            return {"false"}, False                # no Itanium _ZTI/_ZTV names anywhere in the image (the builder emits none)
        if suf == "analysis_section_count":
            return {str(len(exp["pe_sections"]))}, False
        if suf == "analysis_section_names":
            # the adapter parses the PE section table from the COFF header (GM-accepted on Day 17 d04 PE);
            # the hand PE carries exactly its own section list, so that is the graded-correct answer.
            return {json.dumps(exp["pe_sections"], separators=(",", ":"))}, False
        if suf == "analysis_config_campaign":
            return {"BR16-" + exp.get("tag", "")} if False else None, False
        return None, False
    if k == "jar":
        if suf == "analysis_format":
            return {"jar"}, False
        if suf == "analysis_compression_methods":
            return {json.dumps(exp["compression_methods"], separators=(",", ":"))}, True
        return None, False
    return None, False                       # macho / unknown containers: no graded vocabulary -> every field must be HELD (or equal the format token if one is ever sure)


def run_block(name, members, exp_by_member, dk="d16", fields=None, pair_tags=None):
    """One dNN block over `members` (a list of (filename, bytes)); returns (correct, held, wrong list, missed list)."""
    fields = fields or dict(FIELDS, **GENERIC)
    ids, fmt, truth = [], {}, {}
    if pair_tags:                          # PAIR: ids carry the member tag; truth comes from that member's oracle
        for tag, ex in pair_tags.items():
            for suf, af in fields.items():
                if suf in ("artifact_sha256_1",):
                    continue
                if suf.startswith("analysis_"):
                    aid = "%s_analysis_%s_%s" % (dk, tag, suf[len("analysis_"):])
                    ids.append(aid)
                    fmt[aid] = af
                    truth[aid] = (ex, suf)
        for i, (tag, ex) in enumerate(pair_tags.items(), 1):
            aid = "%s_artifact_sha256_%d" % (dk, i)
            ids.append(aid)
            fmt[aid] = TXT
            truth[aid] = (ex, "artifact_sha256_1")
    else:
        ex = exp_by_member
        for suf, af in fields.items():
            aid = "%s_%s" % (dk, suf)
            ids.append(aid)
            fmt[aid] = af
            truth[aid] = (ex, suf)
    start = {"answer_ids": ids, "questions": [{"id": a, "answer_format": fmt[a]} for a in ids]}
    sure, probe, unknown = ab.analyse(start, [bundle(members)])
    correct = held = 0
    wrong, missed = [], []
    for aid in ids:
        ex, suf = truth[aid]
        acc, must = accepted(ex, suf, fmt[aid])
        if aid in sure:
            if acc is not None and sure[aid] in acc:
                correct += 1
            else:
                wrong.append("%s=%r want %s" % (aid, sure[aid][:50], None if acc is None else sorted(acc)[:2]))
        else:
            held += 1
            if must and acc is not None:
                missed.append(aid)
    return correct, held, wrong, missed, sure, probe, unknown


def main():
    if REGEN:
        if not (shutil.which("readelf") and shutil.which("gcc")):
            print("SKIP regen: toolchain missing")
        else:
            regen()
    fixtures = load_fixtures()
    if not fixtures:
        print("SKIP: no fixtures under %s (run with --regen where gcc/readelf exist)" % FIX)
        print("RESULT: PASS")
        return 0
    tot_correct = tot_held = 0
    shapes = 0
    for name, (data, exp) in fixtures.items():
        ext = ".jar" if exp["kind"] == "jar" else ".exe" if exp["kind"] == "pe" else ".elf" if exp["kind"] == "elf" else ".bin"
        t0 = time.time()
        try:
            c, h, wrong, missed, *_ = run_block(name, [("d16--variant-000" + ext, data)], exp)
        except Exception as ex:                # an adapter that raises out of analyse() takes the WHOLE batch down: that is a failure of the shape, reported, not a test crash
            check("%-24s CRASH in analyse(): %s" % (name, type(ex).__name__), False, str(ex)[:80])
            continue
        shapes += 1
        tot_correct += c
        tot_held += h
        check("%-24s %3d correct %3d held, 0 wrong, 0 must-answer missed (%.2fs)" % (name, c, h, time.time() - t0), not wrong and not missed,
              "WRONG=%s MISSED=%s" % (wrong[:3], missed[:4]))

    # ---- PAIRS: the member tag is in the field id (Day 15 shape), for every pair of distinct shapes
    elfs = [(n, d, e) for n, (d, e) in fixtures.items() if e["kind"] == "elf" and not e.get("noshdr")]
    pairs = [("gcc_pie_O2", "gcc_pie_stripped"), ("hand_arm_sym", "hand_mips_be_nosym"), ("hand_aarch64_sym", "hand_ppc64_be_sym"), ("gcc_nopie_O0", "hand_riscv64_sym")]
    for a, b in pairs:
        if a not in fixtures or b not in fixtures:
            continue
        (da, ea), (db, eb) = fixtures[a], fixtures[b]
        # the second member's tag is in its file name; the pair's evidence-zip order is symbolized-then-stripped style (first, second)
        members = [("d16--variant-000-first.elf", da), ("d16--variant-000-second.elf", db)]
        c, h, wrong, missed, *_ = run_block(a + "+" + b, members, None, pair_tags={"first": ea, "second": eb})
        shapes += 1
        tot_correct += c
        tot_held += h
        check("PAIR %-40s %3d correct %3d held, 0 wrong, 0 missed" % (a + "+" + b, c, h), not wrong and not missed, "WRONG=%s MISSED=%s" % (wrong[:3], missed[:4]))
    # sha order and a fixture-name-independent tag without the 'variant-NNN-' infix
    if "gcc_pie_O2" in fixtures and "gcc_pie_stripped" in fixtures:
        da, ea = fixtures["gcc_pie_O2"]
        db, eb = fixtures["gcc_pie_stripped"]
        st = {"answer_ids": ["d16_artifact_sha256_1", "d16_artifact_sha256_2", "d16_analysis_stripped_machine", "d16_analysis_symbolized_has_symtab", "d16_analysis_stripped_has_symtab"],
              "questions": [{"id": "d16_analysis_stripped_machine", "answer_format": INT}, {"id": "d16_analysis_symbolized_has_symtab", "answer_format": BOOL},
                            {"id": "d16_analysis_stripped_has_symtab", "answer_format": BOOL}]}
        sure, probe, unk = ab.analyse(st, [bundle([("d16--symbolized.elf", da), ("d16--stripped.elf", db)])])
        check("pair with a bare tag ('d16--stripped.elf'): sha order + member routing",
              sure.get("d16_artifact_sha256_1") == ea["sha256"] and sure.get("d16_artifact_sha256_2") == eb["sha256"] and sure.get("d16_analysis_stripped_machine") == "62"
              and sure.get("d16_analysis_symbolized_has_symtab") == "true" and sure.get("d16_analysis_stripped_has_symtab") == "false", str(sorted(sure.items()))[:200])
        tg = {"answer_ids": ["d16_artifact_sha256_3"]}
        sure3, _, unk3 = ab.analyse(tg, [bundle([("d16--variant-000-a.elf", da), ("d16--variant-000-b.elf", db), ("d16--variant-000-c.elf", da)])])
        check("artifact_sha256_3 is the third member in zip order", sure3.get("d16_artifact_sha256_3") == ea["sha256"])
        sure_, probe_, unk_ = ab.analyse({"answer_ids": ["d16_artifact_sha256_3"]}, [bundle([("d16--variant-000-a.elf", da), ("d16--variant-000-b.elf", db)])])
        check("artifact_sha256_3 with two members is HELD, not guessed", "d16_artifact_sha256_3" not in sure_ and ("d16_artifact_sha256_3" in unk_ or "d16_artifact_sha256_3" in probe_))

    # ---- CUMULATIVE d01..d16 blocks, each over a different shape: every block answers about ITS OWN member only
    names = [n for n in ("gcc_pie_O2", "gcc_nopie_O0", "hand_arm_sym", "hand_aarch64_sym", "hand_mips_be_sym", "hand_ppc_be_sym", "gpp_vtable", "gcc_pie_stripped", "gcc_nopie_static",
                         "hand_riscv64_sym", "gcc_dwarf_rpath", "gcc_shared", "hand_x86_32le_sym", "gcc_object", "hand_s390x_be_sym", "hand_ppc64_be_sym") if n in fixtures]
    if len(names) >= 6:
        members, ids, fmt, truth = [], [], {}, {}
        for i, n in enumerate(names, 1):
            dk = "d%02d" % i
            data, exp = fixtures[n]
            members.append(("%s--variant-000.elf" % dk, data))
            for suf, af in FIELDS.items():
                aid = "%s_%s" % (dk, suf)
                ids.append(aid)
                fmt[aid] = af
                truth[aid] = (exp, suf)
        st = {"answer_ids": ids, "questions": [{"id": a, "answer_format": fmt[a]} for a in ids]}
        t0 = time.time()
        sure, probe, unknown = ab.analyse(st, [bundle(members)])
        el = time.time() - t0
        wrong = missed = c = 0
        for aid in ids:
            ex, suf = truth[aid]
            acc, must = accepted(ex, suf, fmt[aid])
            if aid in sure:
                if acc is not None and sure[aid] in acc:
                    c += 1
                else:
                    wrong += 1
                    print("   WRONG", aid, sure[aid][:60])
            elif must and acc is not None:
                missed += 1
                print("   MISSED", aid)
        check("cumulative d01..d%02d bundle (%d ids, %d correct) 0 wrong 0 missed (%.2fs)" % (len(names), len(ids), c, el), not wrong and not missed)
        # a MASTERY-shaped request: the same bundle as 3 sets
        mids = ["set%d.%s" % (s, a) for s in (1, 2, 3) for a in ids]
        msure, _, _ = ab.analyse({"answer_ids": mids, "questions": [{"id": "set%d.%s" % (s, a), "answer_format": fmt[a]} for s in (1, 2, 3) for a in ids]}, [bundle(members)] * 3)
        check("mastery-shaped 3 sets: every set answers exactly like the single set", all(msure.get("set%d.%s" % (s, a)) == sure.get(a) for s in (1, 2, 3) for a in ids if a in sure))

    # ---- SYNTHETIC DAY 16: brand-new field names -> the generic by-name route answers what it can, holds the rest
    if "gcc_pie_O2" in fixtures:
        data, exp = fixtures["gcc_pie_O2"]
        d16 = {
            "d16_analysis_section_count": (INT, str(exp["shnum"])),
            "d16_analysis_program_header_count": (INT, str(exp["phnum"])),
            "d16_analysis_interpreter": (TXT, exp["interpreter"]),
            "d16_analysis_build_id": (TXT, exp["build_id"]),
            "d16_analysis_has_dwarf": (BOOL, "true" if exp["has_dwarf"] else "false"),
            "d16_analysis_needed_libs": (JSN, json.dumps(exp["needed"], separators=(",", ":"))),
            "d16_triage_section_count": (INT, str(exp["shnum"])),            # a NEW family token, same fact name
            "d16_analysis_frobnicate_level": (TXT, None),                    # nothing in the file maps to this: HELD
            "d16_analysis_entropy_score": (INT, None),
            "d16_triage_verdict": (TXT, None),
        }
        ids = list(d16)
        st = {"answer_ids": ids, "questions": [{"id": a, "answer_format": d16[a][0]} for a in ids]}
        sure, probe, unknown = ab.analyse(st, [bundle([("d16--variant-000.elf", data)])])
        ok_ans = [a for a in ids if d16[a][1] is not None]
        ok_held = [a for a in ids if d16[a][1] is None]
        check("synthetic Day 16: generic route answers %d known-name fields correctly" % len(ok_ans), all(sure.get(a) == d16[a][1] for a in ok_ans),
              str({a: sure.get(a) for a in ok_ans if sure.get(a) != d16[a][1]}))
        check("synthetic Day 16: %d unknown fields HELD with the exact id list (never sure)" % len(ok_held),
              all(a not in sure for a in ok_held) and set(ok_held) <= set(probe) | set(unknown), "sure=%s" % [a for a in ok_held if a in sure])
        residue = sorted(set(probe) | set(unknown))
        check("synthetic Day 16: residue is exactly the ids nothing maps to", residue == sorted(ok_held) or set(ok_held) <= set(residue), str(residue))
        # a pair with new field names: tag routing + generic route together
        if "gcc_pie_stripped" in fixtures:
            db, eb = fixtures["gcc_pie_stripped"]
            st = {"answer_ids": ["d16_analysis_stripped_section_count", "d16_analysis_symbolized_section_count"],
                  "questions": [{"id": "d16_analysis_stripped_section_count", "answer_format": INT}, {"id": "d16_analysis_symbolized_section_count", "answer_format": INT}]}
            s2, _, _ = ab.analyse(st, [bundle([("d16--variant-000-symbolized.elf", data), ("d16--variant-000-stripped.elf", db)])])
            check("synthetic Day 16 pair: new field name routed to the right member",
                  s2.get("d16_analysis_stripped_section_count") == str(eb["shnum"]) and s2.get("d16_analysis_symbolized_section_count") == str(exp["shnum"]), str(s2))

    # ---- WASM (Day 16 Wasm Up, GM-graded 2026-10-16): a direct/compact PAIR of WebAssembly modules. The d16 contract asks
    # format + architecture + the config keys per member tag and ships NO machine field, so a wasm module must answer
    # 'wasm' / 'wasm32' and route the config per tag, while analysis_machine (no such header field) stays HELD.
    wa, wb = build_wasm("000"), build_wasm("001")
    w64 = build_wasm("064", memory64=True)
    cfg_a, cfg_b = hcfg_record("000")[1], hcfg_record("001")[1]
    ids = ["d16_analysis_%s_%s" % (t, s) for t in ("direct", "compact")
           for s in ("format", "architecture", "machine", "config_campaign", "config_domain", "config_url", "config_mutex")]
    st = {"answer_ids": ids, "questions": [{"id": a, "answer_format": MACH if a.endswith("_machine") else ARCH if a.endswith("_architecture") else TXT} for a in ids]}
    sure, probe, unknown = ab.analyse(st, [bundle([("d16--variant-000-direct.wasm", wa), ("d16--variant-000-compact.wasm", wb)])])
    want = {"d16_analysis_direct_format": "wasm", "d16_analysis_compact_format": "wasm",
            "d16_analysis_direct_architecture": "wasm32", "d16_analysis_compact_architecture": "wasm32",
            "d16_analysis_direct_config_campaign": cfg_a["campaign"], "d16_analysis_compact_config_campaign": cfg_b["campaign"],
            "d16_analysis_direct_config_domain": cfg_a["domain"], "d16_analysis_compact_config_domain": cfg_b["domain"],
            "d16_analysis_direct_config_url": cfg_a["url"], "d16_analysis_compact_config_url": cfg_b["url"],
            "d16_analysis_direct_config_mutex": cfg_a["mutex"], "d16_analysis_compact_config_mutex": cfg_b["mutex"]}
    shapes += 1
    tot_correct += sum(1 for a, v in want.items() if sure.get(a) == v)
    check("WASM pair direct+compact: %d fields correct (format wasm, architecture wasm32, config per tag)" % len(want),
          all(sure.get(a) == v for a, v in want.items()), str({a: sure.get(a) for a, v in want.items() if sure.get(a) != v})[:200])
    held = [a for a in ids if a.endswith("_machine")]
    tot_held += len(held)
    check("WASM: analysis_machine has no header field -> HELD, never guessed",
          all(a not in sure for a in held) and set(held) <= set(probe) | set(unknown), "sure=%s" % [a for a in held if a in sure])
    s64, _, _ = ab.analyse({"answer_ids": ["d16_analysis_architecture", "d16_analysis_format"],
                            "questions": [{"id": "d16_analysis_architecture", "answer_format": ARCH}, {"id": "d16_analysis_format", "answer_format": FMT}]},
                           [bundle([("d16--variant-000.wasm", w64)])])
    shapes += 1
    check("WASM memory64 limits bit -> wasm64 (address width is the only arch evidence a module carries)",
          s64.get("d16_analysis_architecture") == "wasm64" and s64.get("d16_analysis_format") == "wasm", str(s64))

    # ---- robustness: garbage / truncated inputs hold fields, never crash the batch
    for label, junk in (("truncated ELF header", b"\x7fELF\x02\x01\x01" + b"\0" * 20), ("ELF with bad shoff", b"\x7fELF\x02\x01\x01\0" + b"\0" * 8 + struct.pack("<HHIQQQ", 2, 62, 1, 0, 64, 10 ** 9) + b"\0" * 40),
                        ("random bytes", bytes(range(256)) * 4), ("empty-ish MZ", b"MZ" + b"\0" * 10)):
        st = {"answer_ids": ["d16_analysis_%s" % s for s in ("elf_class", "machine", "entry_point", "section_names", "symbols", "has_symtab", "format")],
              "questions": [{"id": "d16_analysis_machine", "answer_format": MACH}]}
        try:
            sure, probe, unknown = ab.analyse(st, [bundle([("d16--variant-000.bin", junk)])])
            check("garbage '%s': no crash, no sure answer from nothing" % label, True if label != "random bytes" else not sure)
        except Exception as ex:
            check("garbage '%s': no crash" % label, False, repr(ex)[:80])

    total = passes + bad
    print("universe: %d shapes, %d field answers correct, %d held, %d checks" % (shapes, tot_correct, tot_held, total))
    try:
        import adapter_coverage as AC
        AC.record("binary_universe", passes, total, not bad)
    except Exception:
        pass
    print("RESULT:", "PASS" if not bad else "FAIL")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
