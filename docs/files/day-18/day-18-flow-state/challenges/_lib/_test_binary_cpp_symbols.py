"""_test_binary_cpp_symbols.py - Day 18 (Flow State) catalog test: the C++ symbol fields as the GM states them - a SYMBOL-TABLE TRAVERSAL (offline, no GM, no network).

Ported from the production tree's untracked _test_binary_cpp_symbols.py (written 2026-10-18 09:08, during the Day 18 release). That file called the production hot fix's private
helpers (_cpp_symbol_field, _coff_symbol_names), which this candidate replaced with the question-contract machinery (question table rule, implied table rule, exact COFF reader). This
file keeps the SAME fixtures and expectations and drives them through the public entry point autosolve_binary.answer(), once per question wording:
  stated   the question carries the Day 18 rule with the class regex
  generic  the Day 17 wording that states no rule
Shapes (the production file's own):
  1. mingw_pe64_comdat    MinGW-style PE64: section-definition symbols first (aux records interleaved, long names via the string table) -> the SECTION-PREFIXED names
  2. pe64_bare_first      the bare function symbol precedes its COMDAT section symbol in the table -> the BARE name wins (entry ORDER)
  3. coff_order           the COFF reader returns primary entries only (auxiliary records skipped), in raw table order
DELIBERATE DIFFERENCE from the production file:
  4. pe64_no_symtab       a PE with NO symbol table. The production hot fix answered the bare name with confidence from raw bytes. Here that is a spelling guess (a PE answer needs the
                          section-prefixed table name), so the value comes back as CANDIDATES (production HOLDs candidates) and never raises. Pinned by the variation suite too.
Run: python3 challenges/_lib/_test_binary_cpp_symbols.py   (must print RESULT: PASS)
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import autosolve_binary as ab                                                   # noqa: E402
import binary_facts as bf                                                       # noqa: E402

SCORE = "_ZNK15DiscoveryEngine5scoreEPKc"
TI = "_ZTI15DiscoveryEngine"
TV = "_ZTV15DiscoveryEngine"
FIELDS = (("score", "mangled_score_symbol"), ("typeinfo", "typeinfo_symbol"), ("vtable", "vtable_symbol"))
REGEX = {"score": "DiscoveryEngine.*score", "typeinfo": "ZTI.*DiscoveryEngine", "vtable": "ZTV.*DiscoveryEngine"}
STATED = "Submit the first exact remaining name matching /%s/."
GENERIC = "What is the exact analysis %s symbol value for field d02_analysis_%s in the delivered evidence set?"


def coff_symtab(entries):
    """(table_bytes, string_table_bytes) for [(name, naux)] primary records in order. A name of 8 bytes or less is inlined; a longer one goes to the string table and the record
    carries its offset. Each primary record is followed by `naux` auxiliary records, which the traversal must skip (never read as names)."""
    strtab = bytearray(b"\0\0\0\0")                                             # [0:4] = size, filled in below
    recs = bytearray()
    for name, naux in entries:
        b = name.encode()
        if len(b) <= 8:
            nf = b.ljust(8, b"\0")
        else:
            nf = struct.pack("<II", 0, len(strtab))
            strtab += b + b"\0"
        recs += nf + struct.pack("<IhhBB", 0, 1, 0x20, 2, naux)
        recs += bytes(18 * naux)                                                # auxiliary records: zeroed
    struct.pack_into("<I", strtab, 0, len(strtab))
    return bytes(recs), bytes(strtab)


def build_pe_with_symtab(entries, machine=0x8664):
    """Minimal PE32+ whose COFF header points at a real symbol table built from `entries`. nsym counts EVERY record (primary + auxiliary), exactly as the COFF spec defines
    NumberOfSymbols, so a traversal that forgets to skip auxiliary records reads garbage - which is what this fixture is here to catch."""
    recs, strtab = coff_symtab(entries)
    nsym = len(recs) // 18
    hdr_len = 0x200
    body = (TI + "\0" + TV + "\0" + SCORE + "\0").encode()                      # the raw bytes the old byte scan used
    symoff = hdr_len + 0x200
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0x5F000000, symoff, nsym, 0xF0, 0x22)
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    opt += struct.pack("<Q", 0x140000000)
    opt += struct.pack("<IIHHHHHHIIIIHHQQQQ", 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\0" * (16 * 8)
    opt = opt.ljust(0xF0, b"\0")
    sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0x200, 0x1000, 0x200, hdr_len, 0, 0, 0, 0, 0x60000020)
    out = bytearray((dos + coff + opt + sec).ljust(hdr_len, b"\0"))
    out += body.ljust(0x200, b"\0")
    assert len(out) == symoff, (len(out), symoff)
    out += recs + strtab
    return bytes(out)


# MinGW PE64 COMDAT groups. The section-definition symbols come first in raw table order (as a real linker emits them), each with an auxiliary section-definition record, and their
# names are long -> string table.
MINGW = [(".text", 1), (".data", 1), (".rdata", 1), (".text$" + SCORE, 1), (".rdata$" + TI, 1), (".rdata$" + TV, 1), (SCORE, 0), (TI, 0), (TV, 0)]
BARE_FIRST = [(SCORE, 0), (TI, 0), (TV, 0), (".text$" + SCORE, 1), (".rdata$" + TI, 1), (".rdata$" + TV, 1)]
CASES = [("mingw_pe64_comdat", build_pe_with_symtab(MINGW), (".text$" + SCORE, ".rdata$" + TI, ".rdata$" + TV), True),
         ("pe64_bare_first", build_pe_with_symtab(BARE_FIRST), (SCORE, TI, TV), True),
         ("pe64_no_symtab", build_pe_with_symtab([]), (SCORE, TI, TV), False)]       # False: not a confident answer (see the module docstring)

bad = 0
for name, data, wants, confident in CASES:
    for wording in ("stated", "generic"):
        for (kind, fld), want in zip(FIELDS, wants):
            q = (STATED % REGEX[kind]) if wording == "stated" else (GENERIC % ({"score": "mangled score", "typeinfo": "typeinfo", "vtable": "vtable"}[kind], fld))
            try:
                v, cands = ab.answer([("d02--variant-000.exe", data)], "d02_analysis_" + fld, None, None, question=q)
                exc = None
            except Exception as e:                                                     # a Hold is a deliberate abstention; anything else is a bug
                v, cands, exc = None, None, e
            if confident:
                ok = exc is None and v == want and cands is None
            else:
                ok = (exc is None and cands is not None) or isinstance(exc, ab.Hold)       # candidates (HELD in production) or an explicit Hold; never a confident value, never a crash
            bad += 0 if ok else 1
            print("%-8s %-20s %-8s %-9s got=%r cands=%r exc=%s want=%r" % ("PASS" if ok else "FAIL", name, wording, kind, v, (cands if cands is None else len(cands)), type(exc).__name__ if exc else "-", want))

# the COFF reader itself: auxiliary records must never surface as names, and the order is the raw table order
names = [s["name"] for s in bf.coff_table(build_pe_with_symtab(MINGW))["symbols"]]
want_names = [n for n, _ in MINGW]
if names != want_names:
    bad += 1
    print("FAIL     coff_order            got=%r want=%r" % (names, want_names))
else:
    print("PASS     coff_order            %d names, auxiliary records skipped" % len(names))
print("RESULT: %s (%d case-assertions, %d bad)" % ("PASS" if not bad else "FAIL", len(CASES) * 6 + 1, bad))
sys.exit(1 if bad else 0)
