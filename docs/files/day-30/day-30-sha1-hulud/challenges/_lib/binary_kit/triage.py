"""Static fingerprint of a candidate RE binary. Decides whether this is the normal fields
lane (hand off to autosolve_binary) or a full-RE challenge, and, if full-RE, which
protections are present and which solver pipeline to run.

Everything here is read-only and deterministic. Takes ~5 ms on a 600 KB PE.

Signals checked (motivated by SHA1-Hulud, Day 30 2026-10-30):

- PE / ELF / Mach-O format and arch (so an exe mis-named .zip doesn't fool us).
- Rust runtime: panic strings, /rustc/<hash>/library/..., src\\num\\float.rs,
  cargo checkouts path, demangle references.
- VEH-based control-flow obfuscation: AddVectoredExceptionHandler import, PE sections
  with no RIP-rel LEA xrefs ("orphan" sections typical for obfuscator stash), TLS callback.
- Trap-flag single-step tracing: `9c 48 81 0c 24 00 01 00 00 9d` (pushfq / or [rsp], 0x100
  / popfq) stitched into .text.
- Inlined SHA1 cores: raw IV byte sequence  01 23 45 67 ... (SHA1 h0 h1 h2 h3 h4) stored
  as 32-bit imms in cmp/mov near the start of a round, repeated per unroll.
- Big anti-tamper loops: `cmp r9, 0x2aea540` (45 M counter) or similar `cmp reg, imm32`
  with imm >= 10M placed in .text.
- Hashed-API resolver: pattern of `mov ecx, imm32; mov edx, imm32; call <same>` repeated.
- Known obfuscator section names: .xsobf, .obf, .enigma1/2, .vmp0/1, .UPX0/1, .themida,
  .mackt (common custom obfuscators).

Returns a Recognized object. Example usage:

    from binary_kit import recognize
    r = recognize(path)
    print(r.summary())
    for action in r.plan: print("  -", action)
"""
from __future__ import annotations
import dataclasses, os, re, struct
from typing import List, Optional

SHA1_IV_LE = bytes.fromhex("01234567")                      # LE of 0x67452301
SHA1_H1_LE = bytes.fromhex("89abcdef")                      # LE of 0xefcdab89
TF_TRAP    = bytes.fromhex("9c48810c24000100009d")          # pushfq;or [rsp],0x100;popfq
HASHED_API = re.compile(                                    # mov ecx,imm32; mov edx,imm32
    rb"\xb9[\x00-\xff]{4}\xba[\x00-\xff]{4}", re.DOTALL)
BIG_LOOP   = re.compile(                                    # D32: cmp <any 64/32-bit reg>, imm32 (was r9..r11 only - missed `cmp rdx,imm`)
    rb"[\x48\x49]?\x81[\xf8-\xff][\x00-\xff]{4}", re.DOTALL)
PEB_READ   = re.compile(                                    # mov r64, gs:[0x60] (PEB) - BeingDebugged / NtGlobalFlag / heap-flag probes
    rb"\x65[\x48\x4c]\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00")
ANTI_DEBUG_APIS = (b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
                   b"ZwQueryInformationProcess", b"NtSetInformationThread", b"OutputDebugString", b"GetThreadContext",
                   b"NtGetContextThread", b"QueryPerformanceCounter", b"GetTickCount", b"FindWindow", b"GetSystemFirmwareTable")
SMC_APIS = (b"VirtualProtect", b"VirtualAlloc", b"WriteProcessMemory", b"FlushInstructionCache", b"mprotect")
OBF_SECS   = {".xsobf", ".obf", ".vmp0", ".vmp1", ".themida",
              ".enigma1", ".enigma2", ".boomerang", ".mackt",
              ".UPX0", ".UPX1", ".UPX2", "UPX!"}

@dataclasses.dataclass
class Recognized:
    path: str
    size: int
    fmt: str = "unknown"                 # pe64 / pe32 / elf / macho / unknown
    arch: str = "?"
    runtime: str = "?"                   # rust / go / c / cpp / dotnet / ?
    sections: List[str] = dataclasses.field(default_factory=list)
    obf_sections: List[str] = dataclasses.field(default_factory=list)
    rust_markers: List[str] = dataclasses.field(default_factory=list)
    veh_import: bool = False
    tls_callback: bool = False
    tf_trap_sites: int = 0
    sha1_cores: int = 0                  # count of inlined SHA1 IV sequences
    big_loop_imms: List[int] = dataclasses.field(default_factory=list)
    hashed_api_calls: int = 0
    anti_debug: List[str] = dataclasses.field(default_factory=list)   # D32: anti-debug APIs named in the file
    peb_reads: int = 0                                                 # D32: direct gs:[0x60] PEB reads
    smc_apis: List[str] = dataclasses.field(default_factory=list)      # D32: APIs that make memory executable/writable
    keyed: bool = False                                                # D32: anti-analysis folded into the check (see _plan)
    probable_full_re: bool = False
    plan: List[str] = dataclasses.field(default_factory=list)

    def summary(self) -> str:
        return (f"{os.path.basename(self.path)}  {self.fmt}/{self.arch}  "
                f"runtime={self.runtime}  secs={len(self.sections)} "
                f"obf={self.obf_sections or '-'}  veh={self.veh_import} "
                f"tls_cb={self.tls_callback}  tf_traps={self.tf_trap_sites}  "
                f"sha1_cores={self.sha1_cores}  big_loops={len(self.big_loop_imms)}  "
                f"api_hash_pairs={self.hashed_api_calls}  "
                f"anti_debug={len(self.anti_debug)} peb_reads={self.peb_reads} smc_apis={len(self.smc_apis)}  "
                f"keyed={self.keyed}  full_re={self.probable_full_re}")

def _parse_pe(data: bytes, out: Recognized):
    if data[:2] != b"MZ":
        return False
    e = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e:e+4] != b"PE\x00\x00":
        return False
    coff = e + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    opt_off = coff + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    out.fmt = "pe64" if magic == 0x20b else "pe32"
    out.arch = {0x8664: "x86_64", 0x14c: "i386", 0xaa64: "arm64"}.get(machine, hex(machine))
    sec_tbl = opt_off + (240 if magic == 0x20b else 224)
    for i in range(nsec):
        s = sec_tbl + i * 40
        name = data[s:s+8].rstrip(b"\0").decode("latin1", "replace")
        out.sections.append(name)
        if name in OBF_SECS or name.lower().startswith((".vmp", ".themida", ".enigma")):
            out.obf_sections.append(name)
    # imports: scan for AddVectoredExceptionHandler cheaply
    out.veh_import = b"AddVectoredExceptionHandler" in data
    # TLS directory
    dd_off = opt_off + (112 if magic == 0x20b else 96) + 9 * 8  # TLS = index 9
    if dd_off + 8 <= len(data):
        tls_rva, _ = struct.unpack_from("<II", data, dd_off)
        out.tls_callback = tls_rva != 0
    return True

def _detect_runtime(data: bytes, out: Recognized):
    probes = [
        ("rust", [b"/rustc/", b"rust_panic", b"panicked at", b"\\.cargo\\git\\checkouts\\"]),
        ("go",   [b"runtime.goexit", b"runtime.main", b"Go build ID: "]),
        ("dotnet", [b".NETFramework,Version=", b"BSJB"]),
        ("cpp",  [b"_ZN", b"std::__cxx11", b"__gxx_personality"]),
    ]
    for name, needles in probes:
        hits = [n for n in needles if n in data]
        if hits:
            out.runtime = name
            if name == "rust":
                out.rust_markers = [h.decode("latin1", "replace") for h in hits]
            return

def _scan_text_signals(data: bytes, out: Recognized):
    # SHA1 inlined IV: looks for the LE bytes `01 23 45 67 ... 89 ab cd ef` within 32 bytes.
    i = 0; n = 0
    while True:
        j = data.find(SHA1_IV_LE, i)
        if j < 0: break
        tail = data[j:j+64]
        if SHA1_H1_LE in tail:
            n += 1
        i = j + 1
    out.sha1_cores = n
    # TF trap sites
    out.tf_trap_sites = len(re.findall(re.escape(TF_TRAP), data))
    # Big anti-tamper loop bounds: cmp reg, imm32 with 1M <= imm <= 1G (immediate = last 4 bytes of the match)
    for m in BIG_LOOP.finditer(data):
        imm = struct.unpack_from("<i", m.group(), len(m.group()) - 4)[0]
        if 1_000_000 <= imm <= 1_000_000_000:
            out.big_loop_imms.append(imm)
    out.anti_debug = [a.decode() for a in ANTI_DEBUG_APIS if a in data]
    out.peb_reads = len(PEB_READ.findall(data))
    out.smc_apis = [a.decode() for a in SMC_APIS if a in data]
    # Hashed-API resolver pattern (bounded count)
    out.hashed_api_calls = sum(1 for _ in HASHED_API.finditer(data))

def _plan(out: Recognized):
    p = out.plan
    if out.obf_sections:
        p.append(f"obfuscator sections present ({', '.join(out.obf_sections)}): dump each section and verify no code refs them from .text (orphan sections = XOR-string stash)")
    if out.veh_import or out.tf_trap_sites or out.tls_callback:
        p.append("VEH / TLS / trap-flag obfuscation: debugging is unsafe; use binary_kit.snapshot + binary_kit.emu")
    if out.runtime == "rust":
        p.append("Rust binary: expect embre or obfstr XOR string tables; grep for crypt/src/xor.rs path and 2 x N const blocks (BYTES[N] + KEY[N])")
    if out.sha1_cores >= 2:
        p.append(f"{out.sha1_cores} inlined SHA1-shaped cores: likely input-derived key schedule; log calls through Unicorn and REPLAY the decrypted trace (not emulate the self-modifying code)")
    if out.big_loop_imms:
        p.append(f"{len(out.big_loop_imms)} anti-tamper loop(s) of ~{max(out.big_loop_imms):,} iterations: snapshot AFTER these to skip the fixed delay on every emulation run")
    if out.hashed_api_calls > 20:
        p.append(f"{out.hashed_api_calls} hashed-API resolver call sites: let the live process do the resolution, then snapshot - never try to replay from file bytes")
    probing = len(out.anti_debug) + (1 if out.peb_reads else 0)
    if probing:
        p.append(f"anti-debug probes ({', '.join(out.anti_debug) or '-'}; {out.peb_reads} PEB reads): treat every probe as a KEY INPUT, "
                 "not an exit - an emulator/debugger must answer like a clean machine or the check silently fails")
    # D32 KEYED = the check depends on the analysis environment: a probe plus a reason the answer cannot simply be read
    # (self-hash/heavy loop, self-modifying code, trap-driven flow). Then R2/R3 return garbage or time out.
    out.keyed = bool(out.veh_import or out.tf_trap_sites or out.sha1_cores >= 2 or out.hashed_api_calls > 20 or
                     (probing and (out.big_loop_imms or out.smc_apis)))
    out.probable_full_re = bool(
        out.keyed or out.obf_sections or out.big_loop_imms)
    if out.probable_full_re:
        p.append("FULL-RE: this is NOT a fields challenge; do not hand to autosolve_binary - open under binary_kit workflow")
    else:
        p.append("looks like a fields challenge: hand to autosolve_binary.run()")

def recognize(path: str) -> Recognized:
    with open(path, "rb") as f:
        data = f.read()
    out = Recognized(path=path, size=len(data))
    if not _parse_pe(data, out):
        if data[:4] == b"\x7fELF":
            out.fmt = "elf64" if data[4] == 2 else "elf32"
        elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            out.fmt = "macho"
    _detect_runtime(data, out)
    _scan_text_signals(data, out)
    _plan(out)
    return out

def main(argv=None):
    import sys
    argv = argv or sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m binary_kit.triage <exe> [<exe>...]"); return 2
    for p in argv:
        r = recognize(p); print(r.summary())
        for a in r.plan: print("  *", a)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
