"""
Python model of the SHA1-Hulud block cipher stages (ARX + Klimov-Shamir T-function), with inverses.
Stage A: forward CBC pass  (round const 0x40714d53b9553253, step 0x80e29aa772aa64a6, rot table 0x140087e40,
          xorshift (a>>10,<<21) / (b<<14,>>33))
Stage B: reverse pass      (round const from key, inner step 0xb19e19b36281f0b9, step 0x633c3366c503e172,
          rot table 0x140087ee8, xorshift (a>>30,<<26) / (b<<24,>>29))
"""
import os, struct
M = (1 << 64) - 1
HERE = os.path.dirname(os.path.abspath(__file__))
EXE = open(os.path.join(HERE, "ext", "sha1-hulud.exe"), "rb").read()
def raw(va): return va - 0x14007f000 + 0x7de00   # .rdata
ROT_A = EXE[raw(0x140087e40):raw(0x140087e40) + 16 * 8]
ROT_B = EXE[raw(0x140087ee8):raw(0x140087ee8) + 16 * 8]

def rol(x, n): n &= 63; return ((x << n) | (x >> (64 - n))) & M
def ror(x, n): n &= 63; return ((x >> n) | (x << (64 - n))) & M
def mix(k):
    t = (k ^ (k >> 29)) & M; t = (t * 0xb89294a129ad1091) & M
    t ^= t >> 35; t = (t * 0xf6e2e6bfab39e8f7) & M; t ^= t >> 26
    return t
def ks(x): return ((x * x) | 5) + x & M          # Klimov-Shamir T-function
def ks_inv(y):
    x = 0
    for bit in range(64):
        mask = (1 << (bit + 1)) - 1
        if (ks(x) ^ y) & mask:
            x |= 1 << bit
    assert ks(x) == y
    return x
def xs_r(x, a, b):        # t = x ^ (x >> a); return t ^ (t << b)
    t = x ^ (x >> a); return (t ^ (t << b)) & M
def xs_l(x, a, b):        # t = x ^ (x << a); return t ^ (t >> b)
    t = (x ^ (x << a)) & M; return t ^ (t >> b)
def inv_xorshift_right(y, a):   # invert y = x ^ (x >> a)
    x = y
    for _ in range(64 // a + 1): x = y ^ (x >> a)
    return x & M
def inv_xorshift_left(y, a):    # invert y = x ^ (x << a)
    x = y
    for _ in range(64 // a + 1): x = (y ^ (x << a)) & M
    return x
def inv_xs_r(y, a, b):  # y = t ^ (t<<b), t = x ^ (x>>a)
    return inv_xorshift_right(inv_xorshift_left(y, b), a)
def inv_xs_l(y, a, b):  # y = t ^ (t>>b), t = x ^ (x<<a)
    return inv_xorshift_left(inv_xorshift_right(y, b), a)

class Cipher:
    def __init__(self, rc0, rc_step, inner_step, rot, xs):
        self.rc0, self.rc_step, self.inner_step, self.rot, self.xs = rc0, rc_step, inner_step, rot, xs
    def round_keys(self, key, rc0=None):
        rks = []; rdx = self.rc0 if rc0 is None else rc0
        for r in range(16):
            rcx = rdx; ks_ = []
            for j in range(2):
                ks_.append(mix(key[j] ^ rcx)); rcx = (rcx + self.inner_step) & M
            rks.append(ks_); rdx = (rdx + self.rc_step) & M
        return rks
    def enc(self, s, key, rc0=None):
        s0, s1 = s; rks = self.round_keys(key, rc0)
        (a1, b1), (a2, b2) = self.xs
        for r in range(16):
            k0, k1 = rks[r]
            s0 = ks((s0 + k0) & M); s1 = ks(s1 ^ k1)
            s0 ^= rol(s1, self.rot[8 * r]); s1 ^= rol(s0, self.rot[8 * r + 4])
            n1 = xs_r(s0, a1, b1); n0 = xs_l(s1, a2, b2)
            s0, s1 = n0, n1
        return s0, s1
    def dec(self, s, key, rc0=None):
        s0, s1 = s; rks = self.round_keys(key, rc0)
        (a1, b1), (a2, b2) = self.xs
        for r in reversed(range(16)):
            k0, k1 = rks[r]
            p1 = inv_xs_r(s1, a1, b1); p0 = inv_xs_l(s0, a2, b2)   # p0 = s0 before xs, p1 = s1 before xs
            s0, s1 = p1, p0
            s1 ^= rol(s0, self.rot[8 * r + 4]); s0 ^= rol(s1, self.rot[8 * r])
            s0 = (ks_inv(s0) - k0) & M; s1 = ks_inv(s1) ^ k1
        return s0, s1

# Stage A: xs pair: new s1 = xs_r(a, 10, 21); new s0 = xs_l(b, 14, 33)
A = Cipher(0x40714d53b9553253, 0x80e29aa772aa64a6, 0x40714d53b9553253, ROT_A, ((10, 21), (14, 33)))

if __name__ == "__main__":
    # logged block 0: in=(0x26, 0x3231307b67616c66) key=(0x1adbcaa93d1bf465,0x484515c303bb9651) out=(0x2fb8728818aa3196,0x7b60556e6ab91f2d)
    tests = [
        ((0x26, 0x3231307b67616c66), (0x1adbcaa93d1bf465, 0x484515c303bb9651), (0x2fb8728818aa3196, 0x7b60556e6ab91f2d)),
        ((0x4e814abf2e9f05a5, 0x495165080fdd7c4f), (0x56227e2b72806742, 0xa322a84e95ec1453), (0xa9c9ca82ed0d07f0, 0xb78148c42b3530f1)),
        ((0xc8f0f2b5db3833c3, 0xb78135a24e515393), (0xfd980847fac21a54, 0x2d64614d57b61bfd), (0xcf8c3bead6263b55, 0xc4d6ee7f1f647a35)),
        ((0xcf8c3bead6263b55, 0xc4d6ee7f1f647a35), (0xd35803468792fbbe, 0x16ccd3562f4a0159), (0x79a2af07e46c5a8f, 0x12442b54264713cf)),
    ]
    for i, (pin, key, out) in enumerate(tests):
        got = A.enc(pin, key)
        back = A.dec(out, key)
        print(f"block {i}: enc {'OK' if got == out else 'BAD ' + hex(got[0]) + ',' + hex(got[1])}   dec {'OK' if back == pin else 'BAD'}")
