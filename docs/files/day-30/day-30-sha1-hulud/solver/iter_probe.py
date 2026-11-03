"""Log iterated byte (0x140058b0f edx), ks1 (0x1400590fb dl), and compare operands, per group."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("EMU_FLUSH", "0")
src = open(os.path.join(HERE, "emu.py")).read()
cut = src.index("t0 = time.time()\npc = reg(UC_X86_REG_RIP)")
tail = src[cut:]
g = {"__file__": os.path.join(HERE, "emu.py"), "__name__": "emu_lib"}
argv_in = sys.argv[1:]
sys.argv = [sys.argv[0]] + argv_in
exec(compile(src[:cut], "emu.py", "exec"), g)
mu = g["mu"]; R = g["R"]; reg = g["reg"]; rq = g["rq"]
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
cur = {"it": [], "k1": [], "cmp": []}; groups = []
def h_it(uc, a, s, _): cur["it"].append(reg(UC_X86_REG_RDX) & 0xFF)
def h_k1(uc, a, s, _): cur["k1"].append((reg(UC_X86_REG_RBX) & 0xFF, reg(UC_X86_REG_RDX) & 0xFF))
def h_cmp(uc, a, s, _): cur["cmp"].append((reg(UC_X86_REG_RBX) & 0xFF, reg(UC_X86_REG_RSI) & 0xFF, reg(UC_X86_REG_RDX) & 0xFF))
def h_end(uc, a, s, _):
    groups.append({k: list(v) for k, v in cur.items()})
    for v in cur.values(): v.clear()
for va, fn in [(0x140058b0f, h_it), (0x1400590fb, h_k1), (0x140059cd9, h_cmp), (0x140059ce9, h_end)]:
    mu.hook_add(UC_HOOK_CODE, fn, None, R(va), R(va))
exec(compile(tail.replace("json.dump(", "_ = (").replace("open(os.path.join(SNAP, \"reads.json\"), \"w\"))", "None)"), "emu_tail", "exec"), g)
print("\n### groups:", len(groups))
for i, gg in enumerate(groups):
    it = bytes(gg["it"]); k1 = bytes(d for _, d in gg["k1"]); bl_after = bytes(b for b, _, _ in gg["cmp"])
    print(f" group {i}: n_it={len(it)} n_k1={len(gg['k1'])} n_cmp={len(gg['cmp'])}")
    print(f"    iter={it.hex()}")
    print(f"    ks1 ={k1.hex()}")
tag = sys.argv[1] if len(sys.argv) > 1 else "A"
json.dump(groups, open(os.path.join(HERE, "snap", f"iter_{'A' if len(sys.argv) < 2 else 'X'}.json"), "w"))
