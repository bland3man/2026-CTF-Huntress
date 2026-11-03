"""Local fingerprint of the Day 14 evidence bundle (no GM calls).

Extracts the AES zip with the standard 'infected' password, lists members,
and reports the Objective-C markers in the d14 ELF member.
"""
import io
import re
import sys
import zlib

sys.path.insert(0, 'challenges/_lib')
import pyzipper  # noqa: E402

ART = 'challenges/Day 14/_stage/Selective_Memory/artifact_0.bin'

with pyzipper.AESZipFile(ART) as zf:
    zf.setpassword(b'infected')
    names = zf.namelist()
    print('members:', len(names))
    for n in sorted(names):
        info = zf.getinfo(n)
        print('  %-30s %10d bytes  method=%s' % (n, info.file_size, info.compress_type))
    d14 = [n for n in names if n.startswith('d14')]
    print('d14 members:', d14)
    for n in d14:
        data = zf.read(n)
        print('--- %s: %d bytes, magic %r' % (n, len(data), data[:4]))
        # Objective-C runtime markers
        pats = [b'__objc_classlist', b'__objc_selrefs', b'__objc_methname', b'objc_msgSend',
                b'_OBJC_CLASS_$_', b'objc_getClass', b'class_addMethod', b'sel_registerName',
                b'objc_autoreleasePoolPush', b'HCFG']
        for pat in pats:
            print('   %-28s x%d' % (pat.decode(), data.count(pat)))
        sels = sorted(set(re.findall(rb'[a-zA-Z][a-zA-Z0-9_]{3,40}:[a-zA-Z0-9_:]{0,60}', data)))
        print('   selector-looking strings:', len(sels))
        # HCFG record
        off = data.find(b'HCFG')
        print('   HCFG offset:', off)
        if off >= 0:
            rec = data[off:off + 160]
            print('   HCFG raw head:', rec[:48])
        # ELF section names
        if data[:4] == b'\x7fELF':
            import struct
            e_shoff, = struct.unpack_from('<Q', data, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3a)
            sh = e_shoff + e_shstrndx * e_shentsize
            str_off, = struct.unpack_from('<Q', data, sh + 0x18)
            secs = []
            for i in range(e_shnum):
                base = e_shoff + i * e_shentsize
                nameoff, = struct.unpack_from('<I', data, base)
                end = data.find(b'\x00', str_off + nameoff)
                secs.append(data[str_off + nameoff:end].decode('utf-8', 'replace'))
            print('   sections (%d): %s' % (len(secs), secs))
