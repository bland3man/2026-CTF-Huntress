#!/usr/bin/env python3
"""TIMED SLOT (2026-10-12; both Commanders; user: 'quicker is necessary' and 'hopefully we do not continue to hit this wall'): WHEN a timed window may be opened.

Every Day 12 timed route was a ONE-SHOT for the team (unique_attempts_remaining 0 on all 10 starts). The Game Master refused EVERYTHING (downloads and submits included) with 429 from about T+22 s to T+55 s
after the 09:00 release on both machines. Lanes whose whole window (start -> download -> solve -> submit) ended by T+13 won; the binary lane (31.9 MB) submitted at T+22, inside the refusal window, and the
attempt expired. So the rule is about WHEN the clock starts, not about volume:

  EARLY  go now, if the lane lists all three modes AND its rehearsed start->submit finishes before ~T+18 (Time Trial) / ~T+20 (Mastery; ~T+45 only once HUNTRESS_MM_EARLY_OK proves the refusal window is gone).
  LATE   everything else (a catalogue-gap lane that lists only single_solve, or a rehearsed finish later than that): wait until T+60, and go only when this machine has had NO 429 for 30 s (and no partner
         TIMED-OPEN note). Re-check every 15 s. Past ~T+140 with the GM still refusing: ESCALATE (the lane writes a .needuser, the Commanders decide); nothing opens by itself.

autosolve.attempt() calls wait_for_slot() right after the readiness gate and before the timed-start context, so no window is open while it waits (waiting costs nothing). The wait ends well inside
claim_next's autosolve cap (150 s + 30 s). Every number below is PROVISIONAL (one day of data): recalibrate from Day 13's Retry-After and header records. HUNTRESS_SLOT=off disables the shaping.
No GM call is made here: the recent-429 test reads this machine's own call ledger."""
import json, os, re, time

EARLY_DEADLINE_TT_S = 18.0            # 2026-10-13 (freeze lifted, homestation): was 13.0. Day-13 binary TT rehearsed finish was T+14.7 s, held LATE to +65.7 by the old 13 s bound (verified: NO catalogue gap, the 1.7 s miss was the only cause). 18 s is still before the Day-12 ~T+22 refusal onset, so binary TT EARLY is zero-risk.
EARLY_DEADLINE_MM_S = 20.0            # conservative Mastery bound (finishes before the ~T+22 refusal onset)
EARLY_DEADLINE_MM_RELAXED_S = 45.0   # Mastery may finish this late EARLY ONLY once a 429-audit has proven the T+22..55 refusal window is gone: opt-in via HUNTRESS_MM_EARLY_OK=1 (set by the Commander after the audit reads clean). Data-gated, never assumed.
LATE_FROM_S = 60.0
QUIET_S = 30.0
RECHECK_S = 15.0
START_RESERVE_S = 1.5          # the start call itself
DEFAULT_PROJECTED_S = 12.0     # when no rehearsal number exists: assume a slow lane so it takes the LATE slot (raised with the 18 s TT bound so an unrehearsed lane still defaults conservative)
GIVE_UP_S = 140.0              # claim_next kills autosolve at 150 + 30 s: the wait must end inside that

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LEDGER = os.environ.get("HUNTRESS_GM_LEDGER", os.path.join(os.path.expanduser("~"), "gm_calls.jsonl"))      # the same file ctf_gm.py appends to


STORM_MEMORY_S = 72 * 3600.0   # P1 (2026-10-16): the LATE wait below guards a 429 STORM (Day 12). With no 429 at all in this machine's own call ledger for this long, and none now, a cold start needs no shaping.


def decide(elapsed, projected_s, mode, gap, rec429_age, partner_open=False, mm_early_ok=False, prior_correct=False, storm_recent=True):
    """pure: -> (verdict, reason, wait_s). verdict in go | wait | escalate. elapsed = seconds since this machine saw the release (None = unknown).
    mm_early_ok: the Commander has proven (429-audit) the T+22..55 refusal window is gone, so Mastery may use the relaxed EARLY bound.
    prior_correct: the PRIOR mode of this SAME challenge is already CORRECT live (Single for a Time Trial, Time Trial for a Mastery)."""
    if elapsed is None:
        return "go", "no release time known: no shaping", 0.0
    # NO SILENT WAIT ON THE HAPPY PATH (user, 2026-10-14: "there should NEVER be a silent wait; Single -> immediately TT ->
    # immediately MM, zero idle"). A prior-mode CORRECT on this SAME challenge, obtained seconds ago through the SAME GM, is
    # strictly stronger proof than any offline rehearsal: the window is provably open right now, the GM is accepting (not in a
    # refusal storm - a storm would have failed that submit), and the next mode is the same compute on real bytes already
    # proven. So open the next mode immediately instead of holding it to the LATE slot. This erased a 39 s silent wait on
    # binary Day-14 (MM first-CORRECT T+69.6 vs TT T+21.0). The LATE slot below still guards a COLD start (no prior CORRECT:
    # a failed/absent prior, or a catalogue-gap lane) where there is no live proof the window is open.
    if prior_correct and mode in ("time_trial", "mastery"):
        return "go", "EARLY: prior mode already CORRECT live on this challenge (window open + GM accepting + same compute proven - no idle)", 0.0
    proj = DEFAULT_PROJECTED_S if not projected_s or projected_s <= 0 else float(projected_s)
    if mode == "mastery":
        deadline = EARLY_DEADLINE_MM_RELAXED_S if mm_early_ok else EARLY_DEADLINE_MM_S
    else:
        deadline = EARLY_DEADLINE_TT_S
    finish = elapsed + START_RESERVE_S + proj
    if not gap and finish <= deadline:
        return "go", "EARLY slot: rehearsed finish T+%.1f s <= T+%.0f s, before the refusal window" % (finish, deadline), 0.0
    why = "catalogue gap (lists only single_solve)" if gap else "rehearsed finish T+%.1f s is later than T+%.0f s" % (finish, deadline)
    if not storm_recent and rec429_age is None and not partner_open:
        # EVIDENCE-GATED (2026-10-16): the wait to T+60 below is a TIME rule written for the Day 12 storm (every call refused with 429 from ~T+22 to ~T+55 s); it fires on the clock alone, with no server
        # response behind it. This machine's own ledger shows no 429 for 72 h (Days 13-16: 0 of ~2,060 calls), so there is no storm to wait out. Any 429 in the ledger brings the guard back at once.
        return "go", "COLD start without shaping (%s): no 429 in this machine's GM ledger for 72 h and none now" % why, 0.0
    if elapsed < LATE_FROM_S:
        return "wait", "LATE slot (%s): waiting for T+%.0f s, now T+%.1f s" % (why, LATE_FROM_S, elapsed), LATE_FROM_S - elapsed
    if rec429_age is not None and rec429_age < QUIET_S:
        if elapsed >= GIVE_UP_S:
            return "escalate", "LATE slot (%s): a 429 %.0f s ago and T+%.0f s is past the %.0f s limit: the Commanders decide" % (why, rec429_age, elapsed, GIVE_UP_S), 0.0
        return "wait", "LATE slot (%s): a 429 %.0f s ago, need %.0f s of quiet" % (why, rec429_age, QUIET_S), min(RECHECK_S, QUIET_S - rec429_age + 0.5)
    if partner_open:
        if elapsed >= GIVE_UP_S:
            return "escalate", "LATE slot (%s): the partner machine still has a timed window open past T+%.0f s" % (why, GIVE_UP_S), 0.0
        return "wait", "LATE slot (%s): the partner machine has a timed window open" % why, RECHECK_S
    return "go", "LATE slot (%s): T+%.0f s and quiet for %s" % (why, elapsed, "30+ s" if rec429_age is not None else "the whole ledger window"), 0.0


def released_epoch(pool_dir=None):
    """when THIS machine's stager saw the release (challenges/_pool/_released.json), or None"""
    p = os.path.join(pool_dir or os.path.join(ROOT, "challenges", "_pool"), "_released.json")
    try:
        return float(json.load(open(p, encoding="utf-8"))["released_epoch"])
    except Exception:
        return None


def recent_429_age(now=None, ledger=None, window_s=600.0):
    """seconds since the newest 429 in this machine's own GM call ledger (read-only, tail only), or None when none in the last window_s"""
    now = time.time() if now is None else now
    try:
        with open(ledger or LEDGER, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 200000))
            tail = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    newest = None
    for ln in reversed(tail[-400:]):
        try:
            r = json.loads(ln)
        except Exception:
            continue
        if str(r.get("status")) == "429":
            t = float(r.get("t", 0))
            if now - t <= window_s:
                newest = t
            break
    return None if newest is None else max(0.0, now - newest)


def newest_429_age(now=None, ledger=None, window_s=STORM_MEMORY_S, max_bytes=8 * 1024 * 1024):
    """seconds since the newest 429 anywhere in the last window_s of this machine's call ledger (reads at most the last 8 MB), or None. Read-only, fail-safe: an unreadable ledger returns None
    (= no evidence), and the caller then also keeps every per-request protection in ctf_gm (a real 429 is backed off there)."""
    now = time.time() if now is None else now
    try:
        with open(ledger or LEDGER, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    newest = None
    for ln in lines:
        if "429" not in ln:
            continue
        try:
            r = json.loads(ln)
            t = float(r.get("t", 0))
        except Exception:
            continue
        if str(r.get("status")) == "429" and now - t <= window_s and (newest is None or t > newest):
            newest = t
    return None if newest is None else max(0.0, now - newest)


def lane_gap(entry_id, pool_dir=None):
    """True when the lane's pool entry says the catalogue listed it WITHOUT a time_trial entry (the catalogue gap: binary on Day 11 and Day 12). None/False when unknown or listed in full."""
    base = str(entry_id).split("/")[0]
    pd = pool_dir or os.path.join(ROOT, "challenges", "_pool")
    try:
        for f in os.listdir(pd):
            if f.startswith("_") or not f.endswith(".json"):
                continue
            e = json.load(open(os.path.join(pd, f), encoding="utf-8"))
            if (e.get("challenge") or {}).get("id") == base:
                ml = e.get("modes_listed")
                return bool(ml) and "time_trial" not in ml
    except Exception:
        pass
    return False


def prior_mode_correct(entry_id):
    """True when the PRIOR mode of this challenge is already CORRECT on the board (Day NN/_board/done.json): Single for a Time
    Trial, Time Trial for a Mastery. A live-proven readiness+safety signal that the timed window is open and the GM is accepting
    right now. Read-only, fail-safe False (unknown day/board -> no change in behaviour, the LATE slot still guards)."""
    s = str(entry_id)
    base = s.split("/")[0]
    m = re.search(r"day-0*(\d+)", base)
    if not m:
        return False
    if s.endswith("/mastery"):
        prior = base + "/time_trial"
    elif s.endswith("/time_trial"):
        prior = base                      # Single Solve is the bare base id in done.json (end_of_day MODES = ["", "/time_trial", "/mastery"])
    else:
        return False
    try:
        import board, os
        named_day = int(m.group(1))
        if prior in board._done(named_day):
            return True
        # REPLAY FIX (2026-10-20): a challenge released on a later day keeps its original id ("web-exploitation-day-04-lfi" released on Day 20),
        # so the regex above names Day 4 while reconcile wrote the CORRECT into Day 20's done.json. Fall back to scanning every day's ledger,
        # since the signal is "the prior mode is CORRECT right now" regardless of which day's board holds the record. Read-only, no fail path.
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        dd = os.path.join(root, "challenges")
        if os.path.isdir(dd):
            for name in os.listdir(dd):
                if name.startswith("Day ") and name[4:].isdigit():
                    d = int(name[4:])
                    if d != named_day and prior in board._done(d):
                        return True
        return False
    except Exception:
        return False


def projected_for(entry_id, mode):
    """the rehearsed start->submit estimate (window_s from the prebrief verdict of this challenge), or None"""
    try:
        import prebrief
        sd = prebrief.stage_dir_for(str(entry_id).split("/")[0])
        d = json.load(open(os.path.join(sd, "prebrief.json"), encoding="utf-8"))
        return float(d["modes"][mode]["window_s"])
    except Exception:
        return None


def wait_for_slot(entry, say, sleep=time.sleep, clock=time.time, pool_dir=None, ledger=None, projected=None, gap=None, released=None, partner_open=None, hard_deadline_t=None):
    """Block (no window is open) until the slot opens. -> ("go"|"escalate", reason). Prints one line when it decides and one per wait."""
    if os.environ.get("HUNTRESS_SLOT") == "off":
        return "go", "slot shaping off (HUNTRESS_SLOT=off)"
    mode = "mastery" if str(entry).endswith("/mastery") else "time_trial"
    rel = released if released is not None else released_epoch(pool_dir)
    g = lane_gap(entry, pool_dir) if gap is None else gap
    proj = projected if projected is not None else projected_for(entry, mode)
    said = False
    while True:
        now = clock()
        el = None if rel is None else now - rel
        po = False if partner_open is None else (partner_open() if callable(partner_open) else bool(partner_open))
        pc = prior_mode_correct(entry)       # re-read each loop: a prior-mode CORRECT that lands DURING the wait releases the next mode at once (no idle)
        storm = True if os.environ.get("HUNTRESS_SLOT") == "legacy" else (newest_429_age(now, ledger) is not None)       # HUNTRESS_SLOT=legacy = the pre-2026-10-16 time rule on every cold start (rollback)
        verdict, why, wait_s = decide(el, proj, mode, g, recent_429_age(now, ledger), po, os.environ.get("HUNTRESS_MM_EARLY_OK") == "1", pc, storm)
        if verdict == "go":
            say("%s: %s" % (mode, why))
            return "go", why
        if verdict == "escalate" or (hard_deadline_t is not None and now + wait_s > hard_deadline_t):
            return "escalate", why if verdict == "escalate" else why + " (out of time for this run)"
        if not said or wait_s >= 5:
            say("%s: %s (no window is open, nothing spent)" % (mode, why))
            said = True
        sleep(max(0.2, min(wait_s, 15.0)))
