import sys, json
sys.path.insert(0, 'challenges/_lib')
from ctf_gm import GM
gm = GM()
cid = "binary-reverse-engineering-day-11-d-collection-planner"
for route in (cid, cid + "/time_trial", cid + "/mastery"):
    try:
        st = gm.status(route)
        d = {k: v for k, v in st.items() if k not in ("prompt", "guidance", "description", "questions", "answer_ids", "artifacts")}
        print(route, "->", json.dumps(d)[:1200])
    except Exception as e:
        print(route, "-> ERR", str(e)[:300])
