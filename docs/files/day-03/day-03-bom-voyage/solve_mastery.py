import sys, json, zipfile, io, re
sys.path.insert(0, ".")
from ctf_gm import GM, solve_mode
gm = GM()
cid = "metadata-forensics-day-03-bom-voyage/mastery"
def compute(st, blobs):
    print("DBG", st["answer_ids"], len(blobs), [b[:4] for b in blobs], flush=True)
    ans = {}
    for aid in st["answer_ids"]:   # answer_ids (not the decoy 'questions' text) are authoritative
        s = int(re.match(r"set(\d+)\.", aid).group(1))
        z = zipfile.ZipFile(io.BytesIO(blobs[s-1]))
        d = z.read(z.namelist()[0])
        ans[aid] = "true" if d.startswith(b"\xef\xbb\xbf") else "false"
    print("ANSWERS", ans, flush=True)
    return ans
r = solve_mode(gm, cid, compute); r.pop("guidance", None); r.pop("prompt", None); print(json.dumps(r))
