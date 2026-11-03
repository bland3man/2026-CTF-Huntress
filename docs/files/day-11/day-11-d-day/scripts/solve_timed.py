#!/usr/bin/env python3
"""D-Day (Day 11, binary lane) timed-mode solver.

Context: the ranked time_trial attempt opened at 13:00:10Z with a 30s window and expired while the
release-storm 429 backoff was sleeping. The route is now result=expired, unique_attempts_remaining=0,
next_op=practice, and BOTH op=retry and op=practice answer 409 retry_variants_unavailable (no fresh
variant provisioned). Offline post-mortem on the expired attempt's own saved bytes proves the banked
solver is complete for today's variant: analyse() -> 110 sure / 0 probe / 0 unknown in 2.15s, so a
fresh attempt only needs ~5s end to end inside a 30s window.

So: poll for a variant (a 409 consumes nothing) and the instant one is handed out, run ONE fully
automated start -> download -> analyse -> submit with no experimentation in between.

usage: solve_timed.py <challenge-route> [max_minutes] [poll_seconds]
"""
import json, os, sys, time
sys.path.insert(0, "challenges/_lib")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctf_gm import GM
import autosolve_binary as ab
import rehearse                      # the LOCAL rehearsal gate (zero GM calls) - see below

# REHEARSE BEFORE YOU START (user rule 2026-10-11 ~14:0x): "you are not to have anything start anything until
# it actually attempted to solve first, because if anything is trying to solve itself that will take so long
# that our window will never ever get an entry submitted." A successful op=start opens a ~30 s window
# IMMEDIATELY, so a solver that is broken, slow, or would be refused by the format gate must be caught BEFORE
# the clock exists, not inside it. Every tick therefore solves the route offline on bytes we already hold and
# only a PASS earns the write call. A failure SKIPS the tick - it never spends an attempt to discover a bug.
STATE = "challenges/Day 11/D-Day/state.json"
FLAG = "challenges/Day 11/_board/agent-2-rehearsal.needuser"   # *.needuser: commander_watch surfaces it


def _note(step, blocker=None):
    """Best-effort state.json update. The prober must never die because a note failed to write."""
    try:
        d = json.load(open(STATE))
        d["current_step"], d["blocker"] = step, blocker
        d["updated_by"], d["updated_t"] = "agent-2", int(time.time())
        json.dump(d, open(STATE, "w"), indent=1)
    except Exception:
        pass


def _flag(text):
    try:
        open(FLAG, "w").write(text + "\n")
    except OSError:
        pass


def _unflag():
    try:
        os.remove(FLAG)
    except OSError:
        pass

ROUTE = sys.argv[1]
MAX_MIN = float(sys.argv[2]) if len(sys.argv) > 2 else 45.0
POLL = float(sys.argv[3]) if len(sys.argv) > 3 else 25.0
STALE = set()          # attempt_ids already known to be expired/used


def post(gm, **pl):
    """One POST, 429-aware, returning (status_ok, parsed). Never raises on a GM 4xx.

    NO HALL-OF-FAME ENTRY, EVER (user directive 2026-10-11). This helper predates the fleet policy and
    writes its own body, so it bypasses ctf_gm.GM._post's choke point that strips run_for_time. Strip it
    here too, so compliance is STRUCTURAL rather than merely incidental on "we happen not to pass it":
    every request this script makes is the plain legacy start, ranked or untimed intent never stated.
    """
    import urllib.parse
    pl = {k: v for k, v in pl.items() if k != "run_for_time"}
    body = json.dumps(dict(pl), separators=(",", ":"))
    hdr = {"Content-Type": "application/json"}
    if gm._tok:
        hdr["Authorization"] = "Bearer " + gm._tok
    for i in range(10):
        gm._reconnect()
        gm._c.request("POST", gm.path, body=body, headers=hdr)
        r = gm._c.getresponse()
        d = r.read()
        if r.status == 429:
            time.sleep(1.0 + 0.7 * i); continue
        try:
            return r.status, json.loads(d)
        except Exception:
            return r.status, {"error": d[:200].decode("utf-8", "replace")}
    return r.status, {"error": "rate_limited_persisted"}


def fresh(st):
    """Is this start payload a usable, live attempt (not the stale expired one)?"""
    if not st or not st.get("answer_ids"):
        return False
    if str(st.get("result", "")).lower() in ("expired", "flag_unavailable"):
        return False
    if st.get("attempt_id") in STALE:
        return False
    return True


def solve(gm, st, t0):
    arts = gm.artifacts(st)
    if len(arts) > 1:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=len(arts)) as ex:
            blobs = list(ex.map(lambda ie: GM().download(ROUTE, ie[1], ie[0]), enumerate(arts)))
    else:
        blobs = [gm.download(ROUTE, e, i) for i, e in enumerate(arts)]
    log("downloaded %s in %.1fs" % ([len(b) for b in blobs], time.time() - t0))
    sure, probe, unknown = ab.analyse(st, blobs)
    log("analyse: %d sure / %d probe / %d unknown of %d ids (%.1fs)"
        % (len(sure), len(probe), len(unknown), len(st.get("answer_ids") or []), time.time() - t0))
    ab._save(ROUTE, blobs)
    answers = dict(sure)
    answers.update({a: c[0] for a, c in probe.items()})
    res = gm.submit(ROUTE, answers)
    log("submit (%.1fs) -> %s" % (time.time() - t0, json.dumps(
        {k: v for k, v in res.items() if k in ("result", "remaining", "flag", "solved_by")})[:400]))
    if str(res.get("result", "")).lower() != "correct":
        acc = set(res.get("accepted_ids") or [])
        miss = [a for a in (st.get("answer_ids") or []) if a not in acc]
        log("MISSING (%d): %s" % (len(miss), miss[:60]))
        # fall back to the adapter's isolate-by-halving path so partial credit + the wrong ids are visible
        if unknown or probe:
            try:
                res = ab._submit_all(gm, ROUTE, log, t0, sure, probe, unknown)
                log("after _submit_all -> %s" % json.dumps({k: v for k, v in res.items()
                                                            if k in ("result", "remaining", "wrong")})[:300])
            except Exception as e:
                log("_submit_all raised %s" % str(e)[:160])
    return res


def log(m):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), m), flush=True)


def mark(route):
    """Mark the mode on the board (never without an accepted GM result)."""
    try:
        sys.path.insert(0, "challenges/_lib")
        import board
        board.mark(11, route)
        log("board marked %s" % route)
    except Exception as e:
        log("board.mark failed: %s" % str(e)[:160])


def run_route(gm, route, t_end):
    """Poll `route` until the GM provisions a variant, then one automated solve. True once CORRECT."""
    global ROUTE
    ROUTE = route
    n = 0
    while time.time() < t_end:
        n += 1
        # THE GATE: rehearse offline FIRST; only a PASS earns this tick's write calls.
        reh = rehearse.rehearse(ROUTE, None)
        if not reh["ok"]:
            msg = ("agent-2 D-Day: REHEARSAL FAILED, write calls SKIPPED this tick (no attempt spent) - %s"
                   % reh["why"])
            log("REHEARSAL FAILED -> skipping the write calls for this tick: %s" % reh["why"])
            _flag(msg + "\nRoute: %s. The prober keeps rehearsing every %.0fs and resumes probing the GM the "
                        "moment the rehearsal passes again; it will NOT open a window on a solver it cannot "
                        "prove offline, because a bad start spends the attempt to discover the bug."
                  % (route, POLL))
            _note("prober HOLDING: rehearsal fails, so no op=start is made (route %s)" % route, reh["why"])
            time.sleep(POLL)
            continue
        if n == 1 or not reh["cached"]:
            log("rehearsal PASS (%d fields, %.2fs%s) - write calls allowed this tick"
                % (reh["fields"], reh["secs"], ", cached" if reh["cached"] else ""))
            _unflag()
        # GENTLE: still ONE GM call per cycle. practice and retry both draw from this route's single
        # pool (measured identical today) and op=start only RESUMES the dead attempt, so one call is
        # enough to detect a refill - but alternate practice/retry across polls so that if only one
        # of them starts working after a reset, we catch it. Do not hammer the GM.
        # op=start FIRST: for a never-started route (mastery: status=start_required) it is the ONLY
        # op that can open an attempt, and practice/retry just answer retry_variants_unavailable.
        # For an expired route (time_trial) start only RESUMES, fresh() rejects it, and the
        # alternating renewal op does the work. Two calls per cycle, still gentle at 5 minutes.
        for op, extra in (("start", {}), ("practice" if n % 2 else "retry", {})):
            code, st = post(gm, op=op, challenge=ROUTE, **extra)
            err = st.get("error")
            if fresh(st):
                log("%s op=%s HTTP %s -> FRESH attempt %s deadline=%s uniq_rem=%s"
                    % (route, op, code, str(st.get("attempt_id"))[:8], st.get("deadline"),
                       st.get("unique_attempts_remaining")))
                t0 = time.time()
                try:
                    res = solve(gm, st, t0)
                except Exception as e:
                    log("solve raised %s" % str(e)[:200]); continue
                if str(res.get("result", "")).lower() == "correct":
                    log("CORRECT flag=%s" % res.get("flag"))
                    print("SOLVED " + route, flush=True)
                    mark(route)
                    return True
                STALE.add(st.get("attempt_id"))
                continue
            if st.get("answer_ids") and str(st.get("result", "")).lower() == "expired":
                STALE.add(st.get("attempt_id"))
            if n == 1 or n % 20 == 0 or POLL >= 300:
                log("%s op=%s HTTP %s err=%r result=%r uniq_rem=%r"
                    % (route, op, code, err, st.get("result"), st.get("unique_attempts_remaining")))
        if n % 20 == 0 and POLL < 300:
            log("%s poll %d: still no variant (%.0f min left)" % (route, n, (t_end - time.time()) / 60.0))
        time.sleep(POLL)
    log("%s: gave up, no variant was ever provisioned" % route)
    return False


def main():
    """Time Trial first, then Mastery (which the GM gates behind it with prerequisite_required)."""
    gm = GM()
    t_end = time.time() + MAX_MIN * 60
    base = ROUTE.rsplit("/", 1)[0] if ROUTE.endswith(("/time_trial", "/mastery")) else ROUTE
    todo = [ROUTE] if ROUTE.endswith("/mastery") else [base + "/time_trial", base + "/mastery"]
    for route in todo:
        if not run_route(gm, route, t_end):
            return 2
    log("every timed mode CORRECT")
    return 0


sys.exit(main())
