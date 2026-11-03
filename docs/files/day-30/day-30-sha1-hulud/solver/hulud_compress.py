"""
Build an exact replay of the obfuscated SHA1-variant compression from its decrypted trace.
Data path = ops on 32-bit regs and on [rcx±d] / [r15+d] memory. Verified against traced I/O.
"""
import os, re, struct

HERE = os.path.dirname(os.path.abspath(__file__))
R32 = {"eax", "edx", "r8d", "r9d", "r10d", "r11d", "ecx", "ebx", "esi", "edi", "r12d", "r13d"}
MEMRE = re.compile(r"(dword|qword) ptr \[(rcx|r15)(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")

def parse_trace(path):
    lines = open(path).read().splitlines()
    before = bytes.fromhex(lines[1].split("=", 1)[1]); after = bytes.fromhex(lines[2].split("=", 1)[1])
    ops = []
    for l in lines[3:]:
        s = l.split("|")[0].split(": ", 1)[1].strip()
        if not s or s.startswith("nop"):
            continue
        m = s.split(None, 1); mn = m[0]; args = [a.strip() for a in m[1].split(",")] if len(m) > 1 else []
        uses_mem = any(MEMRE.search(a) for a in args)
        uses_r32 = any(a in R32 for a in args)
        is_qmove = mn == "mov" and len(args) == 2 and (("rdx" in args) and any("qword ptr [rcx" in a for a in args))
        if mn == "mov" and args and args[0] == "r14d":
            continue
        if uses_r32 or (uses_mem and (mn != "xor" or "r11" not in s)) or is_qmove:
            if "[r11" in s:  # decryptor
                continue
            ops.append((mn, args, s))
    return before, after, ops

def memref(a):
    m = MEMRE.search(a)
    base = m.group(2); off = int(m.group(4), 16) if m.group(4) else 0
    if m.group(3) == "-": off = -off
    return base, off, (4 if m.group(1) == "dword" else 8)

def make_runner(ops):
    def run(ctx: bytes) -> bytes:
        ctx = bytearray(ctx)
        frame = {}
        regs = {}
        def rd(base, off, n):
            if base == "r15":
                return int.from_bytes(ctx[off:off + n], "little")
            return int.from_bytes(bytes(frame.get(off + i, 0) for i in range(n)), "little")
        def wr(base, off, n, v):
            b = (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
            if base == "r15":
                ctx[off:off + n] = b
            else:
                for i in range(n): frame[off + i] = b[i]
        def val(a):
            if a in R32 or a == "rdx": return regs.get(a, 0)
            if MEMRE.search(a):
                b, o, n = memref(a); return rd(b, o, n)
            return int(a, 16) if a.startswith("0x") else int(a)
        def setr(a, v):
            if MEMRE.search(a):
                b, o, n = memref(a); wr(b, o, n, v)
            else:
                regs[a] = v & (0xFFFFFFFFFFFFFFFF if a == "rdx" else 0xFFFFFFFF)
                if a == "edx": regs["rdx"] = regs[a]
                if a == "rdx": regs["edx"] = regs[a] & 0xFFFFFFFF
        for mn, args, s in ops:
            if mn == "mov":
                setr(args[0], val(args[1]))
            elif mn in ("and", "or", "xor", "add", "sub"):
                x, y = val(args[0]), val(args[1])
                r = {"and": x & y, "or": x | y, "xor": x ^ y, "add": x + y, "sub": x - y}[mn]
                setr(args[0], r)
            elif mn == "not":
                setr(args[0], ~val(args[0]))
            elif mn in ("rol", "ror"):
                x = val(args[0]) & 0xFFFFFFFF; n = val(args[1]) & 31
                r = ((x << n) | (x >> (32 - n))) if mn == "rol" else ((x >> n) | (x << (32 - n)))
                setr(args[0], r)
            else:
                raise ValueError("unhandled: " + s)
        return bytes(ctx)
    return run

if __name__ == "__main__":
    before, after, ops = parse_trace(os.path.join(HERE, "trace_sha1.txt"))
    kinds = {}
    for mn, a, s in ops: kinds[mn] = kinds.get(mn, 0) + 1
    print("data-path ops:", len(ops), kinds)
    run = make_runner(ops)
    got = run(before)
    print("before state:", before[:20].hex())
    print("after  state:", after[:20].hex())
    print("replay state:", got[:20].hex())
    print("MATCH" if got[:20] == after[:20] else "MISMATCH")
