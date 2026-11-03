"""Full forward model: message -> stage A (CBC) -> stage B (reverse CBC). Verify vs emulator logs."""
import os, struct, json
from hulud_cipher import Cipher, ROT_A, ROT_B, A, M
HERE = os.path.dirname(os.path.abspath(__file__))

KEY_A = {0: (0x1adbcaa93d1bf465, 0x484515c303bb9651), 1: (0x56227e2b72806742, 0xa322a84e95ec1453),
         2: (0xfd980847fac21a54, 0x2d64614d57b61bfd), 3: (0xd35803468792fbbe, 0x16ccd3562f4a0159),
         4: (0xba292806bed27651, 0x9fc88b798f3effd9), 5: (0x5566c52419c3d9fd, 0xeca6364d2ba2c589),
         6: (0xa865d92d269e8660, 0x5f7b49335165a04a)}
KEY_B = (0x7ef96646bae488c9, 0xfae90d4f818e50df)
B = Cipher(None, 0x633c3366c503e172, 0xb19e19b36281f0b9, ROT_B, ((30, 26), (24, 29)))
def rcB(i): return (0xb19e19b36281f0b9 + i * 0x33c3366c503e1720) & M

def message(inp: bytes, nblocks=None):
    m = struct.pack("<Q", len(inp)) + inp
    n = (len(m) + 15) // 16 if nblocks is None else nblocks
    m = m + b"\0" * (16 * n - len(m))
    return [struct.unpack("<QQ", m[16 * i:16 * i + 16]) for i in range(n)]

def stageA(blocks):
    out = []; prev = (0, 0)
    for i, (a, b) in enumerate(blocks):
        o = A.enc((a ^ prev[0], b ^ prev[1]), KEY_A[i]); out.append(o); prev = o
    return out
def stageB(oa):
    n = len(oa); ob = [None] * n; nxt = None
    for i in reversed(range(n)):
        x = oa[i] if nxt is None else (oa[i][0] ^ nxt[0], oa[i][1] ^ nxt[1])
        ob[i] = B.enc(x, KEY_B, rcB(i)); nxt = ob[i]
    return ob
def to_bytes(blocks): return b"".join(struct.pack("<QQ", *b) for b in blocks)

if __name__ == "__main__":
    inpA = b"flag{0123456789abcdef0123456789abcdef}"
    inpB = b"flag{ffffffffffffffffffffffffffffffff}"
    oa = stageA(message(inpA)); ob = stageB(oa)
    print("stageA outs:", [f"{x:016x},{y:016x}" for x, y in oa])
    print("stageB outs:", [f"{x:016x},{y:016x}" for x, y in ob])
    print("expected B (log): block2 10c5740d74836470,1787069fb16a95f1  block1 dd4ed3b0dfe27915,2fb49c93f983bdfd  block0 8090f30abe72e33f,a9318f2ece9ed5e2")
    blA = bytes.fromhex("f636a28ef9a85dcff542b49d8731c7251ce8b9955b5bb0708d127e8861c61c58ea44ec0f0e033c6f45c791c5da395b9c")
    blB = bytes.fromhex("07ddf26c13b5ecd6fc00e83e6add0b551168ed8d36bd0dc576f45a14e71692927b812356af98d94b55bcb86bb33ce86d")
    XA = bytes(x ^ y for x, y in zip(blA, to_bytes(ob)))
    XB = bytes(x ^ y for x, y in zip(blB, to_bytes(stageB(stageA(message(inpB))))))
    print("mask A:", XA.hex()); print("mask B:", XB.hex()); print("mask constant:", XA == XB)
