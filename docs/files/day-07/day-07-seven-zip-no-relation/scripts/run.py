import sys, io, re, json, struct
sys.path.insert(0, 'challenges/_lib')
from ctf_gm import GM, unzip

CH = sys.argv[1] if len(sys.argv) > 1 else 'metadata-forensics-day-07-seven-zip-no-relation'

def eocd_total(b):
    i = b.rfind(b'PK\x05\x06')
    return struct.unpack('<H', b[i+10:i+12])[0]

def find_questions(o, out):
    if isinstance(o, dict):
        if 'id' in o and 'question' in o:
            out.append(o)
        for v in o.values():
            find_questions(v, out)
    elif isinstance(o, list):
        for v in o:
            find_questions(v, out)

def compute(st, blobs):
    inner = {}
    def walk(blob):
        try:
            items = unzip(blob)
        except Exception:
            return
        for n, d in items:
            if d[:2] == b'PK':
                inner[n.split('/')[-1]] = d
                walk(d)
    for b in blobs:
        walk(b)
    print('inner files:', list(inner), file=sys.stderr)
    qs = []
    find_questions(st, qs)
    ids = st.get('answer_ids')
    byid = {q['id']: q['question'] for q in qs}
    ans = {}
    for aid in ids:
        text = byid.get(aid, '')
        m = re.findall(r'[\w\-]+\.zip', text)
        name = m[0] if m else None
        if name not in inner:
            name = list(inner)[0]
        print(aid, text, '->', name, file=sys.stderr)
        ans[aid] = str(eocd_total(inner[name]))
    return ans

if __name__ == '__main__':
    gm = GM()
    st = gm.start(CH)
    blobs = [gm.download(CH, e, i) for i, e in enumerate(gm.artifacts(st))]
    a = compute(st, blobs)
    print('answers', a, file=sys.stderr)
    r = gm.submit(CH, a)
    print(json.dumps(r)[:400])
