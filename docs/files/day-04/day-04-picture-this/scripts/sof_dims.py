#!/usr/bin/env python3
"""Walk JPEG marker segments and report true SOF dimensions + other metadata.
Usage: python3 sof_dims.py <file.jpg|dir|zip> ..."""
import struct, sys, os, zipfile, hashlib

SOF = {0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF}

def parse(d):
    out = {'size': len(d), 'sha256': hashlib.sha256(d).hexdigest(), 'segments': []}
    if d[:2] != b'\xff\xd8':
        out['error'] = 'no SOI'; return out
    i = 2
    while i + 4 <= len(d):
        if d[i] != 0xFF:
            out['error'] = 'bad marker at %d' % i; break
        m = d[i+1]
        if m == 0xFF: i += 1; continue
        if m == 0xD9: break
        L = struct.unpack('>H', d[i+2:i+4])[0]
        body = d[i+4:i+2+L]
        out['segments'].append((m, i, L))
        if m in SOF:
            p, h, w, nc = struct.unpack('>BHHB', body[:6])
            out['sof'] = dict(marker=hex(m), precision=p, width=w, height=h, comps=nc)
        elif m == 0xE0: out['jfif'] = body[:14]
        elif m == 0xFE: out['comment'] = body
        elif m == 0xE1: out['app1'] = body[:200]
        elif m == 0xDA: break
        i += 2 + L
    return out

def items(paths):
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(os.listdir(p)):
                if f.lower().endswith(('.jpg', '.jpeg')):
                    yield f, open(os.path.join(p, f), 'rb').read()
        elif p.endswith('.zip'):
            z = zipfile.ZipFile(p)
            for n in sorted(z.namelist()):
                if n.lower().endswith(('.jpg', '.jpeg')): yield n, z.read(n)
        else:
            yield os.path.basename(p), open(p, 'rb').read()

if __name__ == '__main__':
    for name, d in items(sys.argv[1:]):
        r = parse(d)
        print(name, r['size'], r['sha256'])
        print('  markers:', ' '.join('%02X@%d(%d)' % s for s in r['segments']))
        s = r.get('sof')
        if s: print('  SOF %s: %dx%d (WxH) prec=%d comps=%d' % (s['marker'], s['width'], s['height'], s['precision'], s['comps']))
        for k in ('jfif', 'comment', 'app1', 'error'):
            if k in r: print('  %s: %r' % (k, r[k]))
