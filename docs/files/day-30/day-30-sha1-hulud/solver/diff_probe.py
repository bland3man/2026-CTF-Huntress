"""
Log operands of the byte comparison (0x140059cd9: xor bl,sil; xor bl,dl; or [rbp+0xca8],bl)
and the triangular-loop compares (0x14004a8ab: cmp rax,rcx).
Usage: python3 diff_probe.py [replacement_input_same_length]
"""
import os, sys, struct, json
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
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
cmp_bytes = []
groups = []
def h_byte(uc, addr, size, _):
    bl = reg(UC_X86_REG_RBX) & 0xFF; sil = reg(UC_X86_REG_RSI) & 0xFF; dl = reg(UC_X86_REG_RDX) & 0xFF
    cmp_bytes.append((bl, sil, dl))
def h_group_end(uc, addr, size, _):
    rbp = reg(UC_X86_REG_RBP)
    groups.append((list(cmp_bytes), bytes(uc.mem_read(rbp + 0xca8, 1)).hex()))
    cmp_bytes.clear()
tri = []
def h_tri(uc, addr, size, _):
    rbp = reg(UC_X86_REG_RBP)
    tri.append((rq(rbp + 0x7c8), rq(rbp + 0x1058), reg(UC_X86_REG_RAX), reg(UC_X86_REG_RCX)))
mu.hook_add(UC_HOOK_CODE, h_byte, None, R(0x140059cd9), R(0x140059cd9))
mu.hook_add(UC_HOOK_CODE, h_group_end, None, R(0x140059ce9), R(0x140059ce9))
mu.hook_add(UC_HOOK_CODE, h_tri, None, R(0x14004a8ab), R(0x14004a8ab))
exec(compile(tail.replace("json.dump(", "_ = (").replace("open(os.path.join(SNAP, \"reads.json\"), \"w\"))", "None)"), "emu_tail", "exec"), g)
print("\n### byte-compare groups:", len(groups))
for gi, (bs, d) in enumerate(groups):
    a = bytes(b for b, _, _ in bs); s = bytes(x for _, x, _ in bs); c = bytes(z for _, _, z in bs)
    print(f" group {gi}: n={len(bs)} diff={d}\n    bl ={a.hex()}\n    sil={s.hex()}\n    dl ={c.hex()}")
print("### triangular compares (first 40 + matches):")
for t in tri[:40]:
    print("  ", t[0], t[1], hex(t[2]), hex(t[3]), "MATCH" if t[2] == t[3] else "")
print("   total", len(tri), "matches", sum(1 for t in tri if t[2] == t[3]))
json.dump({"groups": [[list(x) for x in bs] for bs, _ in groups]}, open(os.path.join(HERE, "snap", "diff_groups.json"), "w"))
