"""Decode the .hcfg record of the Day 14 Objective-C ELF and list its ObjC symbols."""
import re
import struct
import sys
import zlib

sys.path.insert(0, 'challenges/_lib')
import pyzipper  # noqa: E402

ART = 'challenges/Day 14/_stage/Selective_Memory/artifact_0.bin'
with pyzipper.AESZipFile(ART) as zf:
    zf.setpassword(b'infected')
    data = zf.read('d14--variant-000.elf')

off = data.find(b'HCFG')
blob = data[off:off + 256]
print('magic', blob[:4], 'version byte', blob[4], 'next', blob[5:12].hex())

for key in range(256):
    dec = bytes(b ^ key for b in blob[12:200])
    if b'node-' in dec:
        print('xor key = 0x%02x' % key)
        print('decoded:', dec.split(b'\x00')[0][:200])
        fields = dec[:160].split(b'|')
        print('fields:', fields[:8])
        break

crc = struct.unpack_from('<I', blob, 8)[0]
print('crc32 field = 0x%08x' % crc)

# ObjC symbols from .symtab
m = re.findall(rb'[\x20-\x7e]{6,80}', data)
objc = sorted({s.decode() for s in m if b'objc' in s.lower() or s.startswith(b'_i_') or s.startswith(b'_c_')})
print('objc-ish strings (%d):' % len(objc))
for s in objc[:60]:
    print('  ', s)
