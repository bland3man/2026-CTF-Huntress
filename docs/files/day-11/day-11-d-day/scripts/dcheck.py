import sys, io, os, re
sys.path.insert(0, "challenges/_lib")
from ctf_gm import unzip
blob = open(os.path.expanduser("[home path]"), "rb").read()
members = unzip(blob)
print("members:", [(n, len(b)) for n, b in members])
for n, b in members:
    if n.startswith("d11"):
        print("--- %s: %d bytes, magic %r" % (n, len(b), b[:4]))
        pats = [b"dmd", b"ldc", b"gdc", b"_D3std", b"_Dmain", b"druntime", b"phobos", b"TypeInfo_", b"core.", b"std.algorithm"]
        for p in pats:
            print("   %-14s x%d" % (p.decode(), b.count(p)))
        ms = re.findall(rb"_D[0-9][0-9A-Za-z_]{6,60}", b)
        print("   mangled D symbols:", len(ms), [m.decode()[:48] for m in ms[:8]])
        print("   HCFG:", b.find(b"HCFG"), "hcfg off from answers = 368272")
