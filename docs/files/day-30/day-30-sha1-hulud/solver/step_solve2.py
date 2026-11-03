"""
Block-by-block recovery using keys logged in the SAME run.
Logs: stage-A key per block index, stage-B (key, rc0) per block index, and per-group compare data.
Inverts every group's target with this run's keys and prints decoded messages.
Usage: python3 step_solve2.py "<input of the target length>"
"""
import os, sys, json, struct
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

keyA = {}; parB = {}; cur = {"it": [], "cmp": []}; groups = []; st = {"pos": None}
def h_load(uc, a, s, _): st["pos"] = reg(UC_X86_REG_RSI)
def h_cA(uc, a, s, _):
    rbp = reg(UC_X86_REG_RBP); i = st["pos"]
    keyA.setdefault(i, (rq(rbp + 0x710), rq(rbp + 0x718)))
def h_rB(uc, a, s, _):
    rbp = reg(UC_X86_REG_RBP); i = rq(rbp + 0xd28) // 16
    parB.setdefault(i, ((rq(rbp + 0xd10), rq(rbp + 0xd18)), reg(UC_X86_REG_RDX), rq(rbp + 0xd20)))
def h_it(uc, a, s, _): cur["it"].append(reg(UC_X86_REG_RDX) & 0xFF)
def h_cmp(uc, a, s, _): cur["cmp"].append((reg(UC_X86_REG_RBX) & 0xFF, reg(UC_X86_REG_RSI) & 0xFF, reg(UC_X86_REG_RDX) & 0xFF))
def h_end(uc, a, s, _):
    groups.append({k: list(v) for k, v in cur.items()})
    for v in cur.values(): v.clear()
for va, fn in [(0x1400584d1, h_load), (0x140058548, h_cA), (0x14005887a, h_rB),
               (0x140058b0f, h_it), (0x140059cd9, h_cmp), (0x140059ce9, h_end)]:
    mu.hook_add(UC_HOOK_CODE, fn, None, R(va), R(va))
exec(compile(tail.replace("json.dump(", "_ = (").replace("open(os.path.join(SNAP, \"reads.json\"), \"w\"))", "None)"), "emu_tail", "exec"), g)

sys.path.insert(0, HERE)
from hulud_model import A, B, M
print("\n### keys this run")
for i in sorted(keyA): print(f"  A[{i}] = {keyA[i][0]:016x},{keyA[i][1]:016x}")
for i in sorted(parB): print(f"  B[{i}] key={parB[i][0][0]:016x},{parB[i][0][1]:016x} rc0={parB[i][1]:016x} inner={parB[i][2]:016x}")

def blocks_of(b): return [struct.unpack("<QQ", b[16 * i:16 * i + 16]) for i in range(len(b) // 16)]
def invert(target):
    ob = blocks_of(target); n = len(ob); oa = [None] * n
    for i in range(n):
        if i not in parB: return None
        k, rc0, _ = parB[i]
        x = B.dec(ob[i], k, rc0)
        oa[i] = x if i == n - 1 else (x[0] ^ ob[i + 1][0], x[1] ^ ob[i + 1][1])
    msg = []; prev = (0, 0)
    for i in range(n):
        if i not in keyA: return None
        y = A.dec(oa[i], keyA[i]); msg.append((y[0] ^ prev[0], y[1] ^ prev[1])); prev = oa[i]
    return b"".join(struct.pack("<QQ", *m) for m in msg)

print("\n### decoded per group")
for gi, gg in enumerate(groups):
    it = bytes(gg["it"]); bl = bytes(x[0] for x in gg["cmp"]); sil = bytes(x[1] for x in gg["cmp"]); dl = bytes(x[2] for x in gg["cmp"])
    ks1 = bytes(a ^ b for a, b in zip(bl, it))
    target = bytes(a ^ b ^ c for a, b, c in zip(ks1, sil, dl))
    msg = invert(target) if len(target) % 16 == 0 else None
    if msg is None:
        print(f" group {gi} L={len(target)}: missing keys"); continue
    ln = struct.unpack("<Q", msg[:8])[0]
    print(f" group {gi} L={len(target)} len={ln} msg={msg[8:]!r}")
