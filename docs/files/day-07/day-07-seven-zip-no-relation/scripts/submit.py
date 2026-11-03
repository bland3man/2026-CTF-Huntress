import sys, struct, zipfile, io
sys.path.insert(0, '[local path]')
from ctf_gm import GM, solve_mode

CH = 'metadata-forensics-day-07-seven-zip-no-relation'

def eocd_total(data):
    k = data.rfind(b'PK\x05\x06')
    return struct.unpack('<4sHHHHIIH', data[k:k+22])[4]

def compute(start, blobs):
    z = zipfile.ZipFile(io.BytesIO(blobs[0]))
    z.setpassword(b'infected')
    inner = [i for i in z.infolist() if i.filename == 'evidence-drop-001.zip'][0]
    n = eocd_total(z.read(inner))
    return {aid: n for aid in start['answer_ids']}

gm = GM()
res = solve_mode(gm, CH, compute)
print({k: v for k, v in res.items() if k in ('result', 'remaining', 'status')})
