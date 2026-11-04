#!/usr/bin/env python3
"""Commander one-command Web-lane driver: solve EVERY mode of one Web challenge.

    python3 challenges/_lib/web_solve_all.py <challenge-slug> [options]

    options:
      --modes single,time_trial,mastery   which modes (default: all three, in order)
      --recon                             fingerprint every target and print the ladder
                                          trace + /api/clues + /api/state-format + robots,
                                          then STOP. No submit, no ranked window opened.
      --dry                               derive every proof but do not submit
      --no-hof                            start timed modes as REGULAR (no run_for_time);
                                          by default timed modes request the ranked/HOF slot
      --retry-expired                     if a timed start comes back expired / no targets,
                                          call op=retry ONCE to advance to a fresh variant
                                          (prints a warning: retry => regular, HOF lost)
      --workers N                         parallel target recovery threads (default 8)

For each mode: start (reconnect; timed modes use the sanctioned Commander override
HUNTRESS_TIMED_START=commander-override and, by default, run_for_time=True for a ranked
Hall-of-Fame attempt) -> poll until the live target(s) are active -> recover each Target's
proof IN PARALLEL with web_proof_recon.recover (the deterministic multi-family ladder:
clues / serialized-state / GET-SQLi / stored-filter / activity-IDOR / SSTI / robots /
traversal / ...) -> submit all answers in ONE batch. It HOLDs (never submits a partial or
guessed batch) when the ladder cannot derive every Target, and prints the per-step trace so
the missing family can be added to the ladder.

GET-only reconnaissance for the GET families; the POST families (serialized-state trust,
stored LIKE-filter) use the ladder's scope-locked POST helper and are Commander-only (the
daily agents' session is GET-only by design). `start` reconnects to the same attempt, so a
HOLD + re-run costs no unique attempt; only `retry` (opt-in) spends one.

This is a Commander new-lane convenience, NOT on the daily agents' critical path.

HOF rule baked in: run this on the FIRST ranked touch of a timed mode. Recon belongs on the
untimed Single (`--recon` or `--modes single`); a ranked window spent on recon is forfeited,
and a solved mode can no longer be re-ranked.
"""
import sys, os, time, json, threading
sys.path.insert(0, os.path.dirname(__file__))
import ctf_gm
import web_proof_recon as W

MODES = ["single", "time_trial", "mastery"]
_RECON_PATHS = ["/", "/api/clues", "/api/state-format", "/robots.txt"]


def _route(slug, mode):
    return slug if mode == "single" else slug + "/" + mode


def _timed(mode):
    return mode in ("time_trial", "mastery")


def _poll(g, route, timeout=120):
    """Return the status dict once targets[] are active (web reports 'preparing' first)."""
    end = time.time() + timeout
    st = None
    while time.time() < end:
        st = g.status(route)
        res = str(st.get("result") or st.get("status") or "").lower()
        if (st.get("targets") or []) and res not in ("preparing", "expired"):
            return st
        if res == "expired":
            return st
        time.sleep(3)
    return st


def _targets_of(st):
    targets = st.get("targets") or []
    url_by = {t.get("id"): t.get("url") for t in targets if isinstance(t, dict)}
    return targets, url_by


def _start_live(g, route, hof, retry_expired):
    """Start (ranked when hof & timed), poll to active; optionally retry one expired attempt.
    Returns the live status dict (may still be empty/expired if the GM never readied one)."""
    timed = route.endswith(("/time_trial", "/mastery"))

    def _ready(s):
        """Poll a preparing / not-yet-targeted attempt to active; leave expired/solved as-is."""
        r = str(s.get("result") or "").lower()
        if r in ("correct", "accepted", "expired"):
            return s
        if r == "preparing" or not (s.get("targets") or []):
            return _poll(g, route)
        return s

    st = g.start(route, for_time=(hof and timed))
    res = str(st.get("result") or "").lower()
    if res in ("correct", "accepted"):
        return st
    # Advance an expired timed attempt BEFORE polling (polling a dead attempt only wastes the clock).
    if timed and res == "expired" and retry_expired:
        print("  [retry] attempt expired -> op=retry for a fresh variant "
              "(WARNING: retry yields a REGULAR attempt; the ranked/HOF slot is not carried)", flush=True)
        g.retry(route)
        st = g.start(route, for_time=(hof and timed))
    st = _ready(st)
    res = str(st.get("result") or "").lower()
    # A poll that ended expired (the window died while preparing): one opt-in retry.
    if timed and retry_expired and res == "expired":
        print("  [retry] attempt expired after prepare -> op=retry (REGULAR; HOF slot not carried)", flush=True)
        g.retry(route)
        st = _ready(g.start(route, for_time=(hof and timed)))
    return st


def _recover_parallel(targets, url_by, questions, workers=8):
    """Recover every question's proof concurrently. Returns {qid: proof|None}, {qid: trace}."""
    answers, traces = {}, {}
    sem = threading.Semaphore(max(1, workers))

    def work(qid, base):
        with sem:
            tr = []
            try:
                answers[qid] = W.recover(base, trace=tr)
            except W.NoProof:
                answers[qid] = None
            except Exception as e:
                answers[qid] = None
                tr.append(("EXC", type(e).__name__ + ":" + str(e)[:80]))
            traces[qid] = tr

    ths = []
    for q in questions:
        qid = q.get("id"); art = q.get("artifact", "Target 1")
        base = url_by.get(art) or (targets[0].get("url") if targets else None)
        if not base:
            answers[qid] = None; traces[qid] = [("no_target_url", art)]
            continue
        th = threading.Thread(target=work, args=(qid, base.rstrip("/")))
        th.start(); ths.append(th)
    for th in ths:
        th.join(timeout=150)
    return answers, traces


def recon_mode(g, slug, mode, hof=False):
    """Dump every target's fingerprint + ladder trace; never submit, never open a ranked window
    (recon forces --no-hof so it cannot burn the HOF slot)."""
    route = _route(slug, mode)
    print("\n=== RECON %s ===" % route, flush=True)
    st = _start_live(g, route, hof=False, retry_expired=False)
    targets, url_by = _targets_of(st)
    print("result=%s targets=%d deadline=%s" % (st.get("result"), len(targets), st.get("deadline")), flush=True)
    sess = W._S(allowed_hosts=[])
    for t in targets:
        base = (t.get("url") or "").rstrip("/")
        if not base:
            continue
        host = base.split("//", 1)[-1].split("/", 1)[0]
        sess.allowed = {host.lower()}
        print("\n--- %s  %s" % (t.get("id"), base), flush=True)
        for p in _RECON_PATHS:
            try:
                code, _h, body = sess.get(base + p)
            except Exception as e:
                print("  GET %-18s EXC %s" % (p, e)); continue
            txt = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
            if p == "/":
                import re
                title = (re.search(r"<title>([^<]*)</title>", txt) or [None, ""])[1]
                print("  GET /                 %s  <title>%s</title>" % (code, title))
            else:
                print("  GET %-18s %s  %s" % (p, code, txt[:220].replace("\n", " ")))
        tr = []
        try:
            v = W.recover(base, trace=tr)
            print("  LADDER -> %s  [%s]" % (v, ",".join("%s=%s" % x for x in tr)))
        except W.NoProof:
            print("  LADDER -> NoProof  [%s]" % ",".join("%s=%s" % x for x in tr))
    return True


def solve_mode(g, slug, mode, dry=False, hof=True, retry_expired=False, workers=8):
    route = _route(slug, mode)
    print("\n=== %s ===" % route, flush=True)
    st = _start_live(g, route, hof=hof, retry_expired=retry_expired)
    res = str(st.get("result") or "").lower()
    if res in ("correct", "accepted"):
        print("already solved", flush=True)
        return True
    targets, url_by = _targets_of(st)
    questions = st.get("questions") or []
    ranked = bool(st.get("hall_of_fame_eligible")) or (bool(st.get("deadline")) and hof and _timed(mode))
    print("targets=%d questions=%d deadline=%s ranked=%s" %
          (len(targets), len(questions), st.get("deadline"), ranked), flush=True)
    if not questions:
        print("HOLD: no questions in start response (result=%s)" % res, flush=True)
        return False
    t0 = time.time()
    answers, traces = _recover_parallel(targets, url_by, questions, workers=workers)
    for q in questions:
        qid = q.get("id"); art = q.get("artifact", "Target 1")
        tr = ",".join("%s=%s" % x for x in traces.get(qid, []))
        if answers.get(qid):
            print("  %s <- %s : %s  [%s]" % (qid, art, answers[qid], tr), flush=True)
        else:
            print("  %s <- %s : HELD  [%s]" % (qid, art, tr), flush=True)
    derived = {k: v for k, v in answers.items() if v}
    print("  recover wall-clock %.1fs (%d/%d derived)" % (time.time() - t0, len(derived), len(questions)), flush=True)
    if len(derived) != len(questions):
        print("HOLD: %d/%d derived - not submitting (add the missing family to the ladder)"
              % (len(derived), len(questions)), flush=True)
        return False
    if dry:
        print("DRY: would submit %s" % json.dumps(derived), flush=True)
        return True
    out = g.submit(route, derived)
    r = str((out or {}).get("result"))
    print("SUBMIT -> %s  (remaining=%s)" % (r, (out or {}).get("unique_attempts_remaining")), flush=True)
    return r.upper() in ("CORRECT", "ACCEPTED")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__); return 2
    slug = argv[0]
    dry = "--dry" in argv
    recon = "--recon" in argv
    hof = "--no-hof" not in argv
    retry_expired = "--retry-expired" in argv
    workers = 8
    if "--workers" in argv:
        try: workers = int(argv[argv.index("--workers") + 1])
        except Exception: pass
    modes = MODES
    if "--modes" in argv:
        modes = [m.strip() for m in argv[argv.index("--modes") + 1].split(",") if m.strip()]
    if any(_timed(m) for m in modes):
        os.environ.setdefault("HUNTRESS_TIMED_START", "commander-override")
    g = ctf_gm.GM()
    ok = {}
    for m in modes:
        try:
            ok[m] = recon_mode(g, slug, m) if recon else \
                    solve_mode(g, slug, m, dry=dry, hof=hof, retry_expired=retry_expired, workers=workers)
        except Exception as e:
            ok[m] = False
            print("  ERROR %s: %r" % (m, e), flush=True)
    print("\nSUMMARY:", {m: ("OK" if v else "HELD/FAIL") for m, v in ok.items()}, flush=True)
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
