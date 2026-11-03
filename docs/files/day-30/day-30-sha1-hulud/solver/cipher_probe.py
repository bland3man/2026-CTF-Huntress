"""
Run the faithful emulation and instrument the input block cipher (main fn 0x140058431..0x14005868d):
log plaintext block, keys, output block for every invocation, and record who reads the
output afterwards (to locate the comparison against expected values).
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("EMU_FLUSH", "0")
src = open(os.path.join(HERE, "emu.py")).read()
cut = src.index("t0 = time.time()\npc = reg(UC_X86_REG_RIP)")
tail = src[cut:]
g = {"__file__": os.path.join(HERE, "emu.py"), "__name__": "emu_lib"}
argv_in = sys.argv[1:]
sys.argv = [sys.argv[0]] + argv_in
exec(compile(src[:cut], "emu.py", "exec"), g)
mu = g["mu"]; R = g["R"]; reg = g["reg"]; rq = g["rq"]; IMG = g["IMG"]
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.x86_const import *

events = []
cur = {}
def h_load_done(uc, addr, size, _):          # 0x1400584d1: plaintext block assembled at [rbp+0xd10]
    rbp = reg(UC_X86_REG_RBP)
    cur["pt"] = (rq(rbp + 0xd10), rq(rbp + 0xd18)); cur["rbp"] = rbp
    cur["pos"] = (reg(UC_X86_REG_RDI), reg(UC_X86_REG_RSI))
def h_cipher_start(uc, addr, size, _):       # 0x140058548
    rbp = reg(UC_X86_REG_RBP)
    cur["key"] = (rq(rbp + 0x710), rq(rbp + 0x718), rq(rbp + 0x720))
    cur["in"] = (rq(rbp + 0xcc0), rq(rbp + 0xcc8))
def h_cipher_end(uc, addr, size, _):         # 0x14005868d
    rbp = reg(UC_X86_REG_RBP)
    cur["out"] = (rq(rbp + 0xd10), rq(rbp + 0xd18))
    events.append(dict(cur))
    # watch who reads the output copy later
    out_addr = rbp + 0x680
    watch.append(out_addr)
for va, fn in [(0x1400584d1, h_load_done), (0x140058548, h_cipher_start), (0x14005868d, h_cipher_end)]:
    mu.hook_add(UC_HOOK_CODE, fn, None, R(va), R(va))

watch = []

exec(compile(tail.replace("json.dump(", "_ = (").replace("open(os.path.join(SNAP, \"reads.json\"), \"w\"))", "None)"), "emu_tail", "exec"), g)

print(f"\n### cipher invocations: {len(events)}")
for i, e in enumerate(events):
    pt = e.get("pt", (0, 0)); k = e.get("key", (0, 0, 0)); o = e["out"]; ci = e.get("in", (0, 0))
    ptb = struct.pack("<QQ", *pt)
    print(f" [{i}] pt={ptb!r} in={ci[0]:016x}{ci[1]:016x} key={k[0]:016x},{k[1]:016x} out={o[0]:016x},{o[1]:016x} pos={tuple(hex(x) for x in e.get('pos', ()))}")
