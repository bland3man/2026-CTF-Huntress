"""
Invert the SHA1-Hulud check. For each compare group g (length L = 16*n):
    target_g = ks1 ^ sil ^ dl_g            (all constants, logged from the emulator)
    stageB(stageA(len||input)) == target_g
Invert stage B (reverse-CBC) then stage A (CBC) with the verified model, and decode len||input.
"""
import os, json, struct
from hulud_model import A, B, KEY_A, KEY_B, rcB, M
HERE = os.path.dirname(os.path.abspath(__file__))
groups = json.load(open(os.path.join(HERE, "snap", "diff_groups_A.json")))["groups"]   # per byte (bl, sil, dl), input A run
iters = json.load(open(os.path.join(HERE, "snap", "iter_A.json")))                    # per group: it (raw outB bytes)

def blocks_of(b): return [struct.unpack("<QQ", b[16 * i:16 * i + 16]) for i in range(len(b) // 16)]

def invert(target: bytes):
    ob = blocks_of(target); n = len(ob)
    oa = [None] * n
    for i in range(n):
        x = B.dec(ob[i], KEY_B, rcB(i))
        oa[i] = x if i == n - 1 else (x[0] ^ ob[i + 1][0], x[1] ^ ob[i + 1][1])
    msg = []; prev = (0, 0)
    for i in range(n):
        y = A.dec(oa[i], KEY_A[i])
        msg.append((y[0] ^ prev[0], y[1] ^ prev[1])); prev = oa[i]
    return b"".join(struct.pack("<QQ", *m) for m in msg)

for gi, g in (enumerate(groups) if __name__ == "__main__" else []):
    bl = bytes(x[0] for x in g); sil = bytes(x[1] for x in g); dl = bytes(x[2] for x in g)
    it = bytes(iters[gi]["it"])
    ks1 = bytes(a ^ b for a, b in zip(bl, it))
    target = bytes(a ^ b ^ c for a, b, c in zip(ks1, sil, dl))
    msg = invert(target)
    ln = struct.unpack("<Q", msg[:8])[0]
    body = msg[8:8 + ln] if ln <= len(msg) - 8 else msg[8:]
    pad = msg[8 + ln:] if ln <= len(msg) - 8 else b""
    ok = ln <= len(msg) - 8 and all(p == 0 for p in pad)
    print(f"group {gi} (L={len(target)}): len={ln} pad_ok={ok}  body={body!r}")
