"""
Emulate sha1-hulud.exe from a post-anti-tamper snapshot (snap/meta.json + regions.bin).
- Syscalls emulated by name (SSN map parsed from the snapshot's ntdll).
- Reproduces the program's VEH (0x140065baa) semantics for INT3 / single-step / AV / #UD.
- Logs reads of the input buffers and captures NtWriteFile output.
Usage: python emu.py [replacement_input]   (replacement must be same length as snapshot input)
"""
import json, os, sys, struct, time
from unicorn import *
from unicorn.x86_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = os.path.join(HERE, "snap")
meta = json.load(open(os.path.join(SNAP, "meta.json")))
blob = open(os.path.join(SNAP, "regions.bin"), "rb").read()
IMG = meta["img"]
def R(va): return va - 0x140000000 + IMG          # relocate static VA -> runtime
TOKEN = R(0x140098ae0)
VERBOSE = os.environ.get("EMU_V", "0") == "1"

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mapped = []
for r in meta["regions"]:
    mu.mem_map(r["base"], r["size"], UC_PROT_ALL)
    mu.mem_write(r["base"], blob[r["off"]:r["off"] + r["size"]])
    mapped.append((r["base"], r["base"] + r["size"]))

# optional input replacement
orig_inp = meta["input"].encode()
new_inp = sys.argv[1].encode() if len(sys.argv) > 1 else orig_inp
inp_addrs = [a for a in meta["input_addrs"] if isinstance(a, int)]
if new_inp != orig_inp:
    assert len(new_inp) == len(orig_inp), "replacement must have same length"
    for a in inp_addrs:
        mu.mem_write(a, new_inp)

# registers
rm = {"Rax": UC_X86_REG_RAX, "Rcx": UC_X86_REG_RCX, "Rdx": UC_X86_REG_RDX, "Rbx": UC_X86_REG_RBX,
      "Rsp": UC_X86_REG_RSP, "Rbp": UC_X86_REG_RBP, "Rsi": UC_X86_REG_RSI, "Rdi": UC_X86_REG_RDI,
      "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10, "R11": UC_X86_REG_R11,
      "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13, "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15,
      "Rip": UC_X86_REG_RIP}
for k, v in rm.items():
    mu.reg_write(v, meta["regs"][k])
mu.reg_write(UC_X86_REG_EFLAGS, meta["regs"]["EFlags"] & ~0x100)
for i, h in enumerate(meta["xmm"]):
    mu.reg_write(UC_X86_REG_XMM0 + i, int.from_bytes(bytes.fromhex(h), "little"))
mu.reg_write(UC_X86_REG_MXCSR, meta["regs"]["MxCsr"])
mu.msr_write(0xC0000101, meta["teb"])   # GS base

def rq(a): return struct.unpack("<Q", mu.mem_read(a, 8))[0]
def rd(a): return struct.unpack("<I", mu.mem_read(a, 4))[0]
def wq(a, v): mu.mem_write(a, struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))
def rol(x, n): x &= 0xFFFFFFFFFFFFFFFF; return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
def reg(n): return mu.reg_read(n)

# ---- SSN map from snapshot ntdll ----
ntbase = [b for n, b in meta["modules"] if n.lower() == "ntdll.dll"][0]
def parse_exports(base):
    e = rd(base + 0x3c); exp_rva = rd(base + e + 0x88)
    ex = base + exp_rva
    nnames = rd(ex + 0x18); funcs = base + rd(ex + 0x1c); names = base + rd(ex + 0x20); ords = base + rd(ex + 0x24)
    out = {}
    for i in range(nnames):
        nm = bytes(mu.mem_read(base + rd(names + 4 * i), 64)).split(b"\0")[0].decode()
        o = struct.unpack("<H", mu.mem_read(ords + 2 * i, 2))[0]
        out[nm] = base + rd(funcs + 4 * o)
    return out
nt_exports = parse_exports(ntbase)
ssn = {}
for nm, a in nt_exports.items():
    if nm.startswith("Nt") or nm.startswith("Zw"):
        stub = bytes(mu.mem_read(a, 8))
        if stub[:4] == b"\x4c\x8b\xd1\xb8":
            ssn[struct.unpack("<I", stub[4:8])[0]] = nm.replace("Zw", "Nt", 1)

out_bytes = bytearray()
stop_reason = [None]
pending = [None]
counts = {}
next_alloc = [0x7e0000000000]

def syscall_hook(uc, _):
    n = reg(UC_X86_REG_RAX) & 0xFFFF
    name = ssn.get(n, f"ssn_{n:#x}")
    counts[name] = counts.get(name, 0) + 1
    rsp = reg(UC_X86_REG_RSP)
    a1, a2, a3, a4 = reg(UC_X86_REG_R10), reg(UC_X86_REG_RDX), reg(UC_X86_REG_R8), reg(UC_X86_REG_R9)
    def arg(i): return rq(rsp + 8 * i)   # arg5 at [rsp+0x28]
    st = 0
    if name == "NtWriteFile":
        buf, ln, iosb = arg(6), arg(7) & 0xFFFFFFFF, arg(5)
        data = bytes(uc.mem_read(buf, ln)); out_bytes.extend(data)
        print(f"[NtWriteFile] {data!r}", flush=True)
        wq(iosb, 0); wq(iosb + 8, ln)
    elif name in ("NtTerminateProcess",):
        stop_reason[0] = f"{name}(status={a2:#x})"; uc.emu_stop()
    elif name == "NtQueryInformationProcess":
        cls, outp, olen = a2, a3, a4
        if cls in (0x7, 0x1e, 0x1f):
            if outp: uc.mem_write(outp, b"\0" * min(olen, 0x100))
            if cls == 0x1e: st = 0xC0000353
            if cls == 0x1f and outp: uc.mem_write(outp, struct.pack("<I", 1))
        else:
            print(f"[NtQIP unhandled class {cls:#x} len {olen}]", flush=True)
    elif name == "NtQuerySystemInformation":
        cls, outp, olen = a1, a2, a3
        if cls == 0x23 and outp:      # SystemKernelDebuggerInformation
            uc.mem_write(outp, b"\x00\x01")
        elif cls == 0x95 and outp:    # SystemKernelDebuggerInformationEx
            uc.mem_write(outp, b"\x00\x00\x01")
        else:
            print(f"[NtQSI class {cls:#x} len {olen}]", flush=True)
    elif name == "NtGetContextThread":
        ctxp = a2
        if ctxp:
            uc.mem_write(ctxp + 0x48, b"\0" * 0x30)   # Dr0..Dr3, Dr6, Dr7 = 0
    elif name == "NtAllocateVirtualMemory":
        pbase, psize = a2, a4
        want = rq(pbase); size = (rq(psize) + 0xFFFF) & ~0xFFFF
        if want == 0:
            want = next_alloc[0]; next_alloc[0] += size + 0x10000
            uc.mem_map(want, size, UC_PROT_ALL)
        else:
            try: uc.mem_map(want & ~0xFFF, (size + 0xFFF) & ~0xFFF, UC_PROT_ALL)
            except UcError: pass
        wq(pbase, want); wq(psize, size)
    elif name == "NtProtectVirtualMemory":
        oldp = arg(5)
        if oldp: uc.mem_write(oldp, struct.pack("<I", 0x20))
    elif name in ("NtQueryVirtualMemory",):
        st = 0
    else:
        if VERBOSE or counts[name] <= 3:
            print(f"[syscall] {name} -> 0", flush=True)
    uc.reg_write(UC_X86_REG_RAX, st)

mu.hook_add(UC_HOOK_INSN, syscall_hook, None, 1, 0, UC_X86_INS_SYSCALL)

def set_eflags_tf(on):
    f = reg(UC_X86_REG_EFLAGS)
    mu.reg_write(UC_X86_REG_EFLAGS, (f | 0x100) if on else (f & ~0x100))

def veh(code, exc_addr, info=()):
    """Return True if handled (registers updated), False if not."""
    tok = rd(TOKEN)
    rip = reg(UC_X86_REG_RIP); rsi = reg(UC_X86_REG_RSI); rdi = reg(UC_X86_REG_RDI)
    if tok == 0x7193e62b:
        if code == 0xc000001d and rip == rsi:
            mu.reg_write(UC_X86_REG_RIP, rdi); return True
        return False
    if tok == 0x0c883a7e:
        if code == 0xc0000005 and rip == rsi:
            r9 = (rol(info[0], 0x30) ^ info[1]) if len(info) >= 2 else 0
            r11 = rol((exc_addr ^ rip), 0x20) ^ r9
            mu.reg_write(UC_X86_REG_R11, r11); mu.reg_write(UC_X86_REG_RIP, rdi); return True
        return False
    if tok == 0x5b3ea749:
        if code == 0x80000004:
            d = exc_addr - rsi; lim = rdi - rsi
            if (d & 0xFFFFFFFFFFFFFFFF) <= (lim & 0xFFFFFFFFFFFFFFFF):
                mu.reg_write(UC_X86_REG_R11, exc_addr)
            set_eflags_tf((d & 0xFFFFFFFFFFFFFFFF) < (lim & 0xFFFFFFFFFFFFFFFF))
            return True
        return False
    if tok == 0xc8c291de:
        if code == 0x80000003:
            mu.reg_write(UC_X86_REG_R15, exc_addr); mu.reg_write(UC_X86_REG_RIP, exc_addr + 1); return True
        return False
    if code == 0 or code != tok:
        return False
    if code == 0xc0000008:
        mu.mem_write(R(0x140098ba9), b"\x01"); return True
    if code == 0x80000004:
        mu.mem_write(R(0x140098baa), b"\x01"); set_eflags_tf(False); return True
    if code == 0x80000003:
        mu.mem_write(R(0x140098ba8), b"\x01")
        mu.reg_write(UC_X86_REG_R15, exc_addr); mu.reg_write(UC_X86_REG_RIP, exc_addr + 1); return True
    return False

intr_log = []
from collections import deque
blocks = deque(maxlen=48)
if os.environ.get("EMU_BLOCKS", "0") == "1":
    def blk(uc, addr, size, _):
        blocks.append(addr)
    mu.hook_add(UC_HOOK_BLOCK, blk)

def intr_hook(uc, intno, _):
    rip = reg(UC_X86_REG_RIP)
    if len(intr_log) < 400:
        intr_log.append((intno, rip, rd(TOKEN), reg(UC_X86_REG_R15), reg(UC_X86_REG_RAX)))
    if intno == 3:
        if not veh(0x80000003, rip - 1):
            stop_reason[0] = f"unhandled int3 @ {rip-1:#x}"; uc.emu_stop()
    elif intno == 1:
        if not veh(0x80000004, rip):
            set_eflags_tf(False)
            if VERBOSE: print(f"[single-step unhandled @ {rip:#x}] tok={rd(TOKEN):#x}")
    else:
        stop_reason[0] = f"interrupt {intno} @ {rip:#x}"; uc.emu_stop()
mu.hook_add(UC_HOOK_INTR, intr_hook)

def bad_mem(uc, access, addr, size, value, _):
    rip = reg(UC_X86_REG_RIP)
    kind = {UC_MEM_READ_UNMAPPED: 0, UC_MEM_WRITE_UNMAPPED: 1, UC_MEM_FETCH_UNMAPPED: 8}.get(access, 0)
    exc = addr if kind == 8 else rip
    pending[0] = ("av", exc, (kind, addr))
    return False
mu.hook_add(UC_HOOK_MEM_UNMAPPED, bad_mem)

def bad_insn(uc, _):
    pending[0] = ("ud", reg(UC_X86_REG_RIP), ())
    return False
mu.hook_add(UC_HOOK_INSN_INVALID, bad_insn)

# self-modifying code: invalidate translation cache for any write into .text
TEXT_LO, TEXT_HI = IMG + 0x1000, IMG + 0x1000 + 0x7d976
smc_writes = [0]
FLUSH = os.environ.get("EMU_FLUSH", "1") == "1"
smc_log = []
smc_vals = set()
def on_text_write(uc, access, addr, size, value, _):
    smc_writes[0] += 1
    v = value & 0xFFFFFFFFFFFFFFFF
    if len(smc_vals) < 400000:
        smc_vals.add((addr - IMG, v))
    if len(smc_log) < 200:
        smc_log.append((reg(UC_X86_REG_RIP) - IMG, addr - IMG, size, v))
    if FLUSH:
        uc.ctl_remove_cache(addr, addr + size)
mu.hook_add(UC_HOOK_MEM_WRITE, on_text_write, None, TEXT_LO, TEXT_HI)

# ---- replace obfuscated SHA1-variant routines with exact replays ----
sys.path.insert(0, HERE)
from hulud_compress import parse_trace, make_runner
from capstone import Cs as _Cs, CS_ARCH_X86 as _A, CS_MODE_64 as _M
_md = _Cs(_A, _M)
ROUTINES = [0x140001080, 0x140010840, 0x14001dfc0, 0x14002b840]
replays = {}
for va in ROUTINES:
    p = os.path.join(HERE, f"trace_{va:x}.txt") if va != 0x14002b840 else os.path.join(HERE, "trace_sha1.txt")
    if os.path.exists(p):
        replays[va] = make_runner(parse_trace(p)[2])
print("preloaded replays:", [hex(v) for v in replays])
rstate = {"tracing": None, "ret": None, "ctx": None, "before": None, "trace": [], "action": None, "hook": None}
replay_calls = {}
def routine_entry(uc, addr, size, va):
    if rstate["tracing"] is not None:
        return
    ctx = reg(UC_X86_REG_RCX); rsp = reg(UC_X86_REG_RSP)
    ret = rq(rsp)
    if va in replays:
        before = bytes(uc.mem_read(ctx, 0x58))
        out = replays[va](before)
        uc.mem_write(ctx, out[:20])
        replay_calls[va] = replay_calls.get(va, 0) + 1
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)
    else:
        print(f"[trace] first call of {va:#x}: tracing to build replay", flush=True)
        rstate.update(tracing=va, ret=ret, ctx=ctx, before=bytes(uc.mem_read(ctx, 0x58)), trace=[], action="enable")
        uc.emu_stop()
def routine_trace(uc, addr, size, _):
    va = rstate["tracing"]
    if va is None:
        return
    if addr == rstate["ret"]:
        after = bytes(uc.mem_read(rstate["ctx"], 0x58))
        p = os.path.join(HERE, f"trace_{va:x}.txt")
        with open(p, "w") as f:
            f.write(f"ctx=0\nbefore={rstate['before'].hex()}\nafter={after.hex()}\n")
            for a, b in rstate["trace"]:
                ins = next(_md.disasm(b, a), None)
                f.write(f"{a-IMG:#07x}: {(ins.mnemonic + ' ' + ins.op_str) if ins else '??':45s} |\n")
        run = make_runner(parse_trace(p)[2])
        ok = run(rstate["before"])[:20] == after[:20]
        print(f"[trace] built replay for {va:#x}: self-check {'OK' if ok else 'FAIL'}", flush=True)
        replays[va] = run
        rstate["tracing"] = None; rstate["action"] = "disable"
        uc.emu_stop()
        return
    rstate["trace"].append((addr, bytes(uc.mem_read(addr, 15))))
for va in ROUTINES:
    mu.hook_add(UC_HOOK_CODE, routine_entry, va, R(va), R(va))

# ---- AVX helper emulation (Unicorn lacks AVX) ----
avx_hits = {}
def _ret():
    rsp = reg(UC_X86_REG_RSP)
    mu.reg_write(UC_X86_REG_RIP, rq(rsp)); mu.reg_write(UC_X86_REG_RSP, rsp + 8)
def h_memset_fill():          # rcx=dst, r8=count, fill byte broadcast in xmm0
    dst = reg(UC_X86_REG_RCX); n = reg(UC_X86_REG_R8); b = reg(UC_X86_REG_XMM0) & 0xFF
    if n: mu.mem_write(dst, bytes([b]) * n)
    _ret()
AVX_HELPERS = {0x7ff8e9768370 - ntbase: h_memset_fill}   # keyed by ntdll RVA

# entry-point replacements for ntdll string/memory routines (avoid AVX paths entirely)
def _cstrlen(p, wide=False, maxn=1 << 20):
    n = 0; step = 2 if wide else 1
    while n < maxn:
        chunk = bytes(mu.mem_read(p + n * step, 256 * step))
        for i in range(0, len(chunk), step):
            if chunk[i:i + step] == b"\0" * step:
                return n + i // step
        n += 256
    return maxn
def e_wcslen(uc, *_):
    uc.reg_write(UC_X86_REG_RAX, _cstrlen(reg(UC_X86_REG_RCX), True)); _ret()
def e_wcsnlen(uc, *_):
    uc.reg_write(UC_X86_REG_RAX, min(_cstrlen(reg(UC_X86_REG_RCX), True, reg(UC_X86_REG_RDX) + 1), reg(UC_X86_REG_RDX))); _ret()
def e_strlen(uc, *_):
    uc.reg_write(UC_X86_REG_RAX, _cstrlen(reg(UC_X86_REG_RCX))); _ret()
def e_strnlen(uc, *_):
    uc.reg_write(UC_X86_REG_RAX, min(_cstrlen(reg(UC_X86_REG_RCX), False, reg(UC_X86_REG_RDX) + 1), reg(UC_X86_REG_RDX))); _ret()
def e_memset(uc, *_):
    d, v, n = reg(UC_X86_REG_RCX), reg(UC_X86_REG_RDX) & 0xFF, reg(UC_X86_REG_R8)
    if n: uc.mem_write(d, bytes([v]) * n)
    uc.reg_write(UC_X86_REG_RAX, d); _ret()
def e_memmove(uc, *_):
    d, s, n = reg(UC_X86_REG_RCX), reg(UC_X86_REG_RDX), reg(UC_X86_REG_R8)
    if n: uc.mem_write(d, bytes(uc.mem_read(s, n)))
    uc.reg_write(UC_X86_REG_RAX, d); _ret()
def e_memcmp(uc, *_):
    a, b, n = reg(UC_X86_REG_RCX), reg(UC_X86_REG_RDX), reg(UC_X86_REG_R8)
    x, y = bytes(uc.mem_read(a, n)), bytes(uc.mem_read(b, n)); r = 0
    for i in range(n):
        if x[i] != y[i]: r = (x[i] - y[i]) & 0xFFFFFFFFFFFFFFFF; break
    uc.reg_write(UC_X86_REG_RAX, r); _ret()
REPL = {"wcslen": e_wcslen, "wcsnlen": e_wcsnlen, "strlen": e_strlen, "strnlen": e_strnlen,
        "memset": e_memset, "memcpy": e_memmove, "memmove": e_memmove, "memcmp": e_memcmp,
        "RtlCopyMemory": e_memmove, "RtlMoveMemory": e_memmove}
_hooked = set()
for nm, fn in REPL.items():
    a = nt_exports.get(nm)
    if a and a not in _hooked:
        mu.hook_add(UC_HOOK_CODE, fn, None, a, a); _hooked.add(a)
print("ntdll entry replacements:", sorted(n for n in REPL if nt_exports.get(n)))
def try_avx(rip):
    rva = rip - ntbase
    h = AVX_HELPERS.get(rva)
    if h:
        avx_hits[hex(rva)] = avx_hits.get(hex(rva), 0) + 1
        h(); return True
    return False

def apply_action():
    a = rstate["action"]; rstate["action"] = None
    if a == "enable":
        rstate["hook"] = mu.hook_add(UC_HOOK_CODE, routine_trace, None, TEXT_LO, TEXT_HI)
        mu.ctl_remove_cache(TEXT_LO, TEXT_HI)
        return True
    if a == "disable":
        if rstate["hook"] is not None:
            mu.hook_del(rstate["hook"]); rstate["hook"] = None
        mu.ctl_remove_cache(TEXT_LO, TEXT_HI)
        return True
    return False

# input read logging
reads = []
def on_read(uc, access, addr, size, value, _):
    rip = reg(UC_X86_REG_RIP)
    if len(reads) < 5000:
        reads.append((rip, addr, size))
for a in inp_addrs:
    mu.hook_add(UC_HOOK_MEM_READ, on_read, None, a, a + len(orig_inp) - 1)

t0 = time.time()
pc = reg(UC_X86_REG_RIP)
restarts = 0
while stop_reason[0] is None and time.time() - t0 < 600:
    pending[0] = None
    try:
        mu.emu_start(pc, 0, timeout=0, count=0)
    except UcError as e:
        p = pending[0]
        if p and p[0] == "av":
            if not veh(0xc0000005, p[1], p[2]):
                stop_reason[0] = f"unhandled AV @ {reg(UC_X86_REG_RIP):#x} addr={p[2][1]:#x} kind={p[2][0]}"; break
        elif p and p[0] == "ud":
            if try_avx(p[1]):
                pass
            elif not veh(0xc000001d, p[1]):
                stop_reason[0] = f"unhandled #UD @ {p[1]:#x}"; break
        else:
            stop_reason[0] = f"UcError {e} @ {reg(UC_X86_REG_RIP):#x}"; break
        restarts += 1
    pc = reg(UC_X86_REG_RIP)
    if stop_reason[0] is None and pending[0] is None:
        if apply_action():
            continue
        stop_reason[0] = stop_reason[0] or f"emu_start returned @ {pc:#x}"

print(f"\n=== stopped: {stop_reason[0]} after {time.time()-t0:.1f}s, restarts={restarts}")
print(f"=== intr events: {len(intr_log)} (first/last 12)")
for e in intr_log[:12] + [("...",)] + intr_log[-12:]:
    if e[0] == "...": print("   ..."); continue
    n, rip, tok, r15, rax = e
    print(f"   int{n} rip={rip:#x} (RVA {rip-IMG:#x}) tok={tok:#x} r15={r15:#x} rax={rax:#x}")
if blocks:
    print("=== last blocks:", " ".join(f"{b-IMG:#x}" for b in blocks))
print(f"=== replayed routine calls: { {hex(k): v for k, v in replay_calls.items()} }")
print(f"=== avx helper hits: {avx_hits}")
print(f"=== smc writes: {smc_writes[0]}, unique (addr,val): {len(smc_vals)}")
pats = {"rdtsc": b"\x0f\x31", "rdtscp": b"\x0f\x01\xf9", "cpuid": b"\x0f\xa2", "rdrand": b"\x0f\xc7"}
hits = {k: 0 for k in pats}
for a, v in smc_vals:
    bb = v.to_bytes(8, "little")
    for k, p in pats.items():
        if p in bb: hits[k] += 1
print("   decrypted-code pattern hits:", hits)
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    rip = reg(UC_X86_REG_RIP); code = bytes(mu.mem_read(rip - 0x10, 0x30))
    print("=== code at stop:")
    for ins in Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, rip - 0x10):
        print(f"   {ins.address - IMG:#x}: {ins.mnemonic} {ins.op_str}{'   <== RIP' if ins.address == rip else ''}")
    print("=== regs:", {n: hex(reg(r)) for n, r in [("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX), ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX), ("rbp", UC_X86_REG_RBP), ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI), ("r8", UC_X86_REG_R8), ("r15", UC_X86_REG_R15)]})
except Exception as e:
    print("disasm err", e)
from collections import Counter as _C
print("   write sites (rip -> target):", _C((a, b) for a, b, _, _ in smc_log).most_common(12))
print("   last writes:", [(hex(a), hex(b), hex(v)) for a, b, _, v in smc_log[-6:]])
print(f"=== stdout: {bytes(out_bytes)!r}")
print(f"=== syscalls: {counts}")
print(f"=== input reads: {len(reads)}")
from collections import Counter
for (rip, n) in Counter(r[0] for r in reads).most_common(25):
    print(f"   rip {rip:#x} (RVA {rip-IMG:#x}) x{n}")
json.dump({"reads": reads[:5000]}, open(os.path.join(SNAP, "reads.json"), "w"))
