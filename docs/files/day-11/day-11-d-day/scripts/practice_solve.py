#!/usr/bin/env python3
"""ONE automated run of a timed route via op=practice (the GM's own next_op once
unique_attempts_remaining hits 0). Mirrors autosolve_binary._run_once but starts
the attempt with op=practice instead of op=start. Derives every answer from the
attempt's OWN bytes; no experimentation between start and submit."""
import json, os, sys, time
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM
import autosolve_binary as ab

cid = sys.argv[1]
DRY = "--dry" in sys.argv


def practice_start(gm, cid):
    return ab._gm(gm._post, )  # placeholder, replaced below


def main():
    gm = GM()
    t0 = time.time()
    st = ab._gm(lambda: gm._post(op="practice", challenge=cid))
    print("PRACTICE start keys:", sorted(st.keys()), flush=True)
    print("  result=%r mode=%r deadline=%r answer_ids=%d uniq_rem=%r hof=%r next_op=%r" % (
        st.get("result"), st.get("mode"), st.get("deadline"),
        len(st.get("answer_ids") or []), st.get("unique_attempts_remaining"),
        st.get("hall_of_fame_eligible"), st.get("next_op")), flush=True)
    if not (st.get("answer_ids")):
        print("NO answer_ids -> payload:", json.dumps({k: v for k, v in st.items() if k not in ("prompt", "guidance", "questions")})[:800])
        return
    arts = gm.artifacts(st)
    if len(arts) > 1:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=len(arts)) as ex:
            blobs = list(ex.map(lambda ie: ab._gm(GM().download, cid, ie[1], ie[0]), enumerate(arts)))
    else:
        blobs = [ab._gm(gm.download, cid, e, i) for i, e in enumerate(arts)]
    print("  downloaded %d blob(s) %s in %.1fs" % (len(blobs), [len(b) for b in blobs], time.time() - t0), flush=True)
    sure, probe, unknown = ab.analyse(st, blobs)
    print("  analyse: %d sure, %d probe, %d unknown (%.1fs)" % (len(sure), len(probe), len(unknown), time.time() - t0), flush=True)
    if unknown:
        print("  UNKNOWN ids:", sorted(unknown)[:40], flush=True)
    if probe:
        print("  PROBE ids:", {a: c[:3] for a, c in list(probe.items())[:20]}, flush=True)
    # keep the bytes for offline post-mortem
    ab._save(cid, blobs)
    if DRY:
        print("DRY: not submitting"); return
    res = ab._submit_all(gm, cid, print, t0, sure, probe, unknown)
    print("RESULT", json.dumps({k: v for k, v in res.items()
                                if k in ("result", "remaining", "seconds", "wrong", "unknown", "flag", "solved_by")})[:1500], flush=True)
    if str(res.get("result", "")).lower() != "correct":
        acc = res.get("accepted_ids") or []
        miss = [a for a in (st.get("answer_ids") or []) if a not in acc]
        print("MISSING ids (%d):" % len(miss), miss[:60], flush=True)


main()
