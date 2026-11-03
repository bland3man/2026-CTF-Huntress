#!/usr/bin/env python3
"""PREBRIEF + READY GATE (2026-10-11, user: make the collaboration REAL for every lane BEFORE op=start; recognise the challenge, its patterns, file types and magic numbers; less guessing by agents).

One deterministic, LLM-free, free-reads-only pass over a staged day. For every staged challenge it composes what already existed but was scattered and ran per agent at claim time:
  RECOGNISE  recognize.identify / describe (type, lane, first move, zip member histogram), sha256, size
  MATCH      lane_progress.today_lines (the predictive model's candidate + 'prepared') and digest.family_matches (banked value sets)
  CONTRACT   the free questions contract of Time Trial and Mastery (GM.contract with --live, else the saved contract_<mode>.json) and the mode GEOMETRY vs the previous day's row of the same lane (kb/mode_geometry.json)
  COVERAGE   release_scan.run on the Single task; contract_preflight.evaluate on each timed contract with the Single bytes as stand-in (coverage + ctf_gm.format_gate + window estimate)
  VERDICT    per mode READY | NEEDS-REAL-BYTES (the stand-in cannot hold the files the question names: proceed) | RESIDUE (ids with NO extractor, or a format problem: do not open a timed window)
and writes Day NN/_stage/<slug>/prebrief.json. THE GATE: gate(entry) answers whether a TIMED window may be opened for that entry: ONLY a rehearsed READY / NEEDS-REAL-BYTES verdict opens it
(FAIL CLOSED since 2026-10-11, user: nothing starts until it has attempted to solve first; a missing rehearsal is re-run in-process once, then HELD 'gate unavailable'). A rehearsal slower than
the window budget is RESIDUE. It proves coverage, format and timing, NOT values (timed bytes are refused until the mode starts).

usage: python3 challenges/_lib/prebrief.py <day> [--live] [--json]      default: saved contracts, zero GM calls; --live reads each timed contract once (free op=status)
       python3 challenges/_lib/prebrief.py --gate <entry id>               prints GO / HELD and why. ASCII only."""
import concurrent.futures as cf, hashlib, json, os, re, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
MODES = ("time_trial", "mastery")
WARN_WINDOW_S = 20.0

# STANDING RULE (user, 2026-10-11): "everything is to be complete 100 percent without missing fields, ids,
# etc ... anything under 99 percent should be retried until all are optimized to actually speed up our
# solves and TT and MM. from hereon out."
#
# The gate already refused any mode with an unresolved id, so 100% was implicitly required - but the
# PERCENTAGE was never computed or recorded anywhere, which made the rule unenforceable and invisible to
# the predictive model. Now every mode carries a measured coverage_pct, a mode below MIN_COVERAGE_PCT is an
# explicit OPTIMISE target rather than a silent hold, and lane_progress / prebrief.json carry the number so
# an agent or Commander can see which adapter to improve next instead of re-deriving it.
#
# Any agent or Commander may raise this threshold when they have the coverage to back it; lowering it needs
# the user's say-so, because it trades a known gap for a faster-looking gate.
MIN_COVERAGE_PCT = 99.0


def coverage_pct(ids, unresolved):
    """-> percent of the contract's ids that HAVE an extractor (100.0 for an empty contract).

    Measured against `unresolved` (ids with NO extractor), NOT against `resolved`. The first version
    divided by resolved and so counted an id that merely NEEDS THE REAL BYTES as missing coverage - which
    turned a legitimate NEEDS-REAL-BYTES into RESIDUE and would have HELD windows that should proceed.
    The fleet's own _test_prebrief.py caught it on two assertions plus the real Day 11 metadata run. An
    id whose extractor exists and is only waiting for the right variant IS covered; what is not covered is
    an id nothing can extract.
    """
    n = len(ids) if hasattr(ids, "__len__") else int(ids or 0)
    if not n:
        return 100.0
    miss = len(unresolved) if hasattr(unresolved, "__len__") else int(unresolved or 0)
    return 100.0 * max(0, n - max(0, min(miss, n))) / n


def verdict(ids, resolved, unresolved, needs_bytes, format_problems, window_s=0.0):
    """pure: -> (verdict, reasons). RESIDUE only for a definite gap; unknown/limits never block."""
    why = []
    pct = coverage_pct(ids, unresolved)
    if unresolved:
        why.append("%d id(s) have NO extractor, e.g. %s" % (len(unresolved), ", ".join(sorted(map(str, unresolved))[:3])))
    if format_problems:
        why.append("format gate: %s" % str(format_problems[0])[:100])
    if window_s and window_s > WARN_WINDOW_S:
        # user 2026-10-11: never start a window the rehearsal says cannot be submitted inside it
        why.append("measured rehearsal (download + compute) %.1fs is above the %.0fs budget of a 30s window: too slow to submit in time" % (window_s, WARN_WINDOW_S))
    if unresolved and pct < MIN_COVERAGE_PCT:
        # Appended AFTER the specific gap, never before it: the named ids are the headline, this is the
        # standing-rule framing that turns the hold into an action. It cannot change a verdict on its own -
        # a missing extractor already decided that - so the rule adds pressure and a number, not new holds.
        why.append("OPTIMISE: only %.1f%% of ids have an extractor, below the %.1f%% standing minimum - "
                   "build the missing one(s) and re-run until 100%%; a partial contract costs the window"
                   % (pct, MIN_COVERAGE_PCT))
    if why:
        return "RESIDUE", why
    if needs_bytes:
        why.insert(0, "%d id(s) name files the stand-in does not hold (need the real variant)" % len(needs_bytes))
        return "NEEDS-REAL-BYTES", why
    return "READY", why


def stage_dir_for(entry, root=None):
    """the staged folder of a challenge id (entry may carry /time_trial or /mastery): matched on task.json id; None when not staged.

    D27 operator correction (2026-10-26) FIX 1: Web Exploitation has an INDEPENDENT sequence
    (`web-exploitation-day-01`, 02, ...); the number in a CID is the Web-sequence NOT the
    calendar release day. A Web CID like `web-exploitation-day-19-trust-the-webhook` may be
    staged under `challenges/Day 27/_stage`. Use HUNTRESS_DAY env as the AUTHORITATIVE release
    day; the id's day-N is only the last-resort fallback. For a CID with no `day-N` embedded,
    scan the current release day via HUNTRESS_DAY env or the newest day dir with a matching
    task.json."""
    base = re.sub(r"/(time_trial|mastery)$", "", str(entry))
    m = re.search(r"day-(\d+)", base)
    id_day = int(m.group(1)) if m else None
    # D27: HUNTRESS_DAY env is the authoritative calendar release day (set by Go.ps1 at
    # 08:50 and propagated through WSLENV). Falls back to id's embedded day-N only if env
    # is absent (offline tests, legacy callers).
    env_day = os.environ.get("HUNTRESS_DAY")
    try:
        env_day = int(env_day) if env_day else None
    except Exception:
        env_day = None
    primary_day = env_day if env_day is not None else id_day
    dd = os.path.join(root or ROOT, "challenges", "Day %02d" % primary_day, "_stage") if primary_day is not None else None
    try:                                              # 2026-10-23 (stage_paths.py): the repo dir is the canonical contract; resolved ONCE per task.json version (cache), and a stage that only reached [home path] (Day 22) is mirrored in additively.
        import stage_paths                            # Search HUNTRESS_DAY, then the id's day, then the newest day dirs. D27 fix: HUNTRESS_DAY is now first-preference everywhere.
        found = stage_paths.find_any(root or ROOT, base)
        if found and not found[1]:
            return found[0]
        day = found[2] if found else primary_day
        if day is None:
            return None
        dd = os.path.join(root or ROOT, "challenges", "Day %02d" % day, "_stage")
        got = stage_paths.mirror_from_wsl(base, dd, day=day)
        if got:
            return got
        return found[0] if found else None
    except Exception:
        pass
    if not dd or not os.path.isdir(dd):
        return None
    for d in sorted(os.listdir(dd)):
        tf = os.path.join(dd, d, "task.json")
        if os.path.isfile(tf):
            try:
                if json.load(open(tf, encoding="utf-8")).get("id") == base:
                    return os.path.join(dd, d)
            except Exception:
                continue
    return None


UNAVAILABLE = "gate unavailable"      # the tag commander_watch flags: a hold caused by a missing rehearsal, not by a real gap


def prev_contract(lane, mode, day, root=None):
    """-> (day, contract) of the most recent PREVIOUS day's saved contract for the same lane and mode, or (None, None). Contracts change between days (agent-2, 2026-10-11: 22 of 24 shared ids were byte-identical, TWO changed their answer
    format, and a proven spelling copied from the earlier day would have been wrong): so today's formats are always compared with the last saved ones."""
    base = os.path.join(root or ROOT, "challenges")
    try:
        days = sorted((int(m.group(1)) for d in os.listdir(base) for m in [re.match(r"Day (\d+)$", d)] if m and int(m.group(1)) < int(day)), reverse=True)
    except Exception:
        return None, None
    for d in days:
        sroot = os.path.join(base, "Day %02d" % d, "_stage")
        if not os.path.isdir(sroot):
            continue
        for slug in sorted(os.listdir(sroot)):
            try:
                t = json.load(open(os.path.join(sroot, slug, "task.json"), encoding="utf-8"))
                if t.get("lane") != lane:
                    continue
                pth = os.path.join(sroot, slug, "contract_%s.json" % mode)
                if os.path.isfile(pth):
                    return d, json.load(open(pth, encoding="utf-8"))
            except Exception:
                continue
    return None, None


def contract_diff(prev, cur):
    """INFORMATION, never a hold: which ids both contracts share, and of those which changed their answer_format; how many are new / gone."""
    def fm(c):
        return {str(q.get("id")): json.dumps(q.get("answer_format"), sort_keys=True, default=str) for q in (c.get("questions") or []) if isinstance(q, dict)}
    pf, cf = fm(prev), fm(cur)
    changed = [i for i in cf if i in pf and pf[i] != cf[i]]
    return {"shared": sum(1 for i in cf if i in pf), "n_changed": len(changed), "changed": changed[:20], "new": sum(1 for i in cf if i not in pf), "gone": sum(1 for i in pf if i not in cf)}


def cross_mode_diff(tt, mm):
    """INFORMATION: ids whose answer_format DIFFERS between the Time Trial and the Mastery contract of ONE challenge (agent-2, 2026-10-11: Mastery asked d01_analysis_machine as a pattern where the Time Trial asked exact_text, so one contract per id per challenge is wrong).
    Mastery ids carry a 'setN.' prefix; it is stripped and every set is compared with the Time Trial's format."""
    def fm(c, strip):
        d = {}
        for q in (c.get("questions") or []):
            if isinstance(q, dict):
                i = str(q.get("id"))
                if strip:
                    i = re.sub(r"^set\d+\.", "", i)
                d.setdefault(i, set()).add(json.dumps(q.get("answer_format"), sort_keys=True, default=str))
        return d
    a, m = fm(tt, False), fm(mm, True)
    changed = sorted(i for i in a if i in m and (m[i] != a[i]))
    return {"shared": sum(1 for i in a if i in m), "n_changed": len(changed), "changed": changed[:20]}


STAND_IN_BASIS = "coverage on Single stand-in (untimed bytes), NOT a solve of the timed bytes"


def timed_blobs(sd, mode):
    """REAL timed bytes held for this mode (an existing attempt's artifacts saved as timed_<mode>_*.bin in the stage folder) -> (blobs, basis text), or ([], None)"""
    try:
        fs = sorted(f for f in os.listdir(sd) if f.startswith("timed_%s_" % mode) and f.endswith(".bin"))
        bl = [open(os.path.join(sd, f), "rb").read() for f in fs]
        if bl:
            return bl, "REHEARSED on timed bytes (%d file(s), %d bytes)" % (len(bl), sum(len(x) for x in bl))
    except Exception:
        pass
    return [], None


def _rehearse_in_process(sd, entry):
    """one synchronous prebrief of this challenge (free reads, no window open) -> its mode verdicts, or {} on failure"""
    try:
        m = re.search(r"Day (\d+)", str(sd).replace("\\", "/")) or re.search(r"day-(\d+)", str(entry))      # the stage dir's own Day NN is the competition day; a Web id's number is its own sequence
        out = brief_one(sd, day=int(m.group(1)) if m else None, with_single=False)
        return (out or {}).get("modes") or {}
    except Exception:
        return {}


def _prior_mode_correct(entry):
    """True when the PRIOR mode of this challenge is already CORRECT on the board (Single for a Time Trial, Time Trial for a
    Mastery). Delegates to timed_slot (single source of truth for this signal); fail-safe False so the full gate still runs on
    any error (a cold start with no prior CORRECT is never short-circuited)."""
    try:
        import timed_slot
        return timed_slot.prior_mode_correct(entry)
    except Exception:
        return False


_LIB_SYNTAX_CHECK_CACHE = None  # D27 audit §3: cached per process, see _check_lib_syntax below


def _check_lib_syntax():
    """D27 audit §3 (user directive 2026-10-27): if a shared _lib/*.py has a SyntaxError at
    the moment a TIMED gate call runs, the generic "HELD: gate unavailable - prebrief could
    not run (SyntaxError)" message does NOT name the file. Agent-2 lost ~2 min hunting for
    the bad file on D27. Cache the first ast.parse sweep for the life of this process so a
    long-running agent pays ~0.3 s once, not per gate call.
    Returns None on clean parse, or (filename, lineno, msg) on first SyntaxError found."""
    global _LIB_SYNTAX_CHECK_CACHE
    if _LIB_SYNTAX_CHECK_CACHE is not None:
        return _LIB_SYNTAX_CHECK_CACHE if _LIB_SYNTAX_CHECK_CACHE != () else None
    import ast
    import glob
    here = os.path.dirname(os.path.abspath(__file__))
    for p in sorted(glob.glob(os.path.join(here, "*.py"))):
        if os.path.basename(p).startswith("_test_"):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                ast.parse(f.read(), p)
        except SyntaxError as e:
            _LIB_SYNTAX_CHECK_CACHE = (e.filename or p, e.lineno or 0, (e.msg or "SyntaxError")[:200])
            return _LIB_SYNTAX_CHECK_CACHE
        except Exception:
            continue
    _LIB_SYNTAX_CHECK_CACHE = ()
    return None


PRIOR_CORRECT_MAX_WAIT_S = 15.0   # bounded wait for a running prebrief when the prior mode is already CORRECT live


def gate(entry, root=None, wait_s=0.0):
    """-> (go, why, residue_ids). Only a rehearsed READY / NEEDS-REAL-BYTES verdict opens a TIMED window; everything else is HELD (FAIL CLOSED, user 2026-10-11: "you are not to have anything
    start anything until it actually attempted to solve first"). RESIDUE includes a measured rehearsal slower than the window budget.
    wait_s: a prebrief process still running for this challenge (marker younger than 120 s) is waited for, up to wait_s (no window is open, waiting is free). If no verdict exists after that, the
    rehearsal is run IN-PROCESS once before deciding; only if that also yields nothing is the window HELD with the 'gate unavailable' tag. HUNTRESS_GATE=0 is the only override."""
    if os.environ.get("HUNTRESS_GATE") == "0":
        return True, "gate disabled by HUNTRESS_GATE=0 (Commander override)", []
    mode = "time_trial" if str(entry).endswith("/time_trial") else ("mastery" if str(entry).endswith("/mastery") else "single_solve")
    if mode == "single_solve":
        return True, "Single Solve is untimed: never gated", []
    # D27 audit §3: shared-lib SyntaxError FAST-FAIL with filename+lineno so the agent fixes
    # the right file instead of grep-hunting. Cached per process -> near-zero cost after the
    # first call. HELD is correct here (FAIL CLOSED): no window is opened, no variant spent.
    _lib_err = _check_lib_syntax()
    if _lib_err is not None:
        fname, lineno, msg = _lib_err
        return False, ("HELD: shared-lib SyntaxError in %s:%d (%s); fix the file then rerun "
                       "agent_solve_cid.py - no window was opened" % (os.path.basename(fname), lineno, msg)), []
    # D29 P0-A operator correction (2026-10-28): a prior mode CORRECT does NOT authorize an
    # unverified current timed mode (SS CORRECT does not authorize TT without a TT verdict;
    # TT CORRECT does not authorize MM without an MM verdict). The audit in
    # docs/cross_station/D29_P0_TIMED_GATE_MOBILE_BINDING_REVIEW.md P0-1 documents the gap.
    #
    # Correctness over speed, BUT speed is preserved on the happy path: a VALID current-mode
    # rehearsal verdict (READY / NEEDS-REAL-BYTES) opens the window immediately, with zero wait.
    # The pre-D29 bypass that opened a window on prior CORRECT alone, regardless of the current
    # mode's contract, is removed. _test_no_idle_wait.py was updated to assert the safe form.
    fix = "run: python3 challenges/_lib/prebrief.py <day>, then rerun autosolve; HUNTRESS_GATE=0 is the only override"
    prior_ok = _prior_mode_correct(entry)                          # recorded for the HELD reason, not for a shortcut
    try:
        sd = stage_dir_for(entry, root)
        if not sd:
            if prior_ok:
                return False, "HELD: %s - prior mode CORRECT does NOT authorize %s without a verified current-mode contract; %s is not staged (D29 P0-A fail-closed; %s)" % (
                    UNAVAILABLE, mode, entry, fix), []
            return False, "HELD: %s - %s is not staged, so it was never rehearsed; no window opened (%s)" % (UNAVAILABLE, entry, fix), []
        p = os.path.join(sd, "prebrief.json")
        marker = os.path.join(sd, "prebrief.running")
        # Fast path: read the current verdict without waiting. If it is already READY or
        # NEEDS-REAL-BYTES, open the window instantly. This preserves the Single -> TT -> MM
        # no-idle-wait behavior for the happy path (operator 2026-10-14), WITHOUT the unsafe
        # prior-CORRECT bypass that opened the window on an unverified current mode.
        pb_now = {}
        try:
            pb_now = json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else {}
        except Exception:
            pb_now = {}
        m_now = (pb_now.get("modes") or {}).get(mode)
        if m_now and m_now.get("verdict") in ("READY", "NEEDS-REAL-BYTES"):
            return True, "%s [%s]: %s%s" % (
                m_now.get("verdict"), m_now.get("basis") or STAND_IN_BASIS,
                "; ".join(m_now.get("reasons") or []) or "ok",
                " (prior mode also CORRECT live)" if prior_ok else ""), []
        # No valid current verdict yet. If the prior mode is CORRECT (we would have shortcut
        # pre-D29), we now REFUSE to shortcut: HELD immediately with the specific gap, no wait.
        # The operator requirement is: unverified current mode -> HELD, not an opened window.
        # WS variant (2026-10-28): prior CORRECT never authorizes the current mode by itself, but an ABSENT verdict is not a
        # 'no' either: the prebrief subprocess spawned at Single start usually lands its verdict a few seconds after a fast SS
        # CORRECT. Fall through to the standard path below: wait (bounded by wait_s, only while that prebrief is actually running),
        # then rehearse in-process, and HELD with the specific reason unless a READY / NEEDS-REAL-BYTES verdict exists for THIS mode.
        # A RESIDUE or other verdict is re-rehearsed once and then HELD; it is never shortcut by a prior CORRECT.
        # Cold-start branch (no prior CORRECT): the pre-D29 wait + fallback rehearsal path.
        # With a prior mode already CORRECT live, only a prebrief that is actually running is worth a SHORT bounded wait (measured
        # ~3.7 s); a dead 'running' marker must not idle the timed window path for the full wait_s.
        end = time.time() + max(0.0, min(float(wait_s), PRIOR_CORRECT_MAX_WAIT_S) if prior_ok else float(wait_s))
        while True:
            pb = {}
            try:
                pb = json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else {}
            except Exception:
                pb = {}                                   # half-written file: read again
            m = (pb.get("modes") or {}).get(mode)
            running = os.path.isfile(marker) and (time.time() - os.path.getmtime(marker)) < 120
            if m or not running or time.time() >= end:
                break
            time.sleep(0.25)
        if not m:
            m = _rehearse_in_process(sd, entry).get(mode)
        if not m:
            return False, "HELD: %s - no %s rehearsal (prebrief %s, in-process rehearsal produced nothing); no window opened (%s)" % (
                UNAVAILABLE, mode, "still running after %.0fs" % wait_s if running else "verdict missing", fix), []
        if m.get("verdict") == "RESIDUE":
            fresh = _rehearse_in_process(sd, entry).get(mode)       # the file may predate what the Single just learned: never hold on a stale RESIDUE
            if fresh and fresh.get("verdict") in ("READY", "NEEDS-REAL-BYTES", "RESIDUE"):      # only a REAL verdict replaces the old hold: silence or UNKNOWN never opens a window
                m = fresh
        if m.get("verdict") == "RESIDUE":
            res = list(m.get("residue") or [])
            return False, "HELD: %s; no window opened, no variant spent" % "; ".join(m.get("reasons") or ["residue"]), res
        if m.get("verdict") not in ("READY", "NEEDS-REAL-BYTES"):
            return False, "HELD: %s - %s rehearsal verdict is %s (%s); no window opened (%s)" % (UNAVAILABLE, mode, m.get("verdict"), "; ".join(m.get("reasons") or []), fix), []
        return True, "%s [%s]: %s" % (m.get("verdict"), m.get("basis") or STAND_IN_BASIS, "; ".join(m.get("reasons") or []) or "ok"), []
    except Exception as e:
        return False, "HELD: %s - gate error (%s); no window opened (%s)" % (UNAVAILABLE, type(e).__name__, fix), []


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def history_flags(lane, day, geo, hist):
    """compare today's geometry with the most recent PREVIOUS day's row of the same lane -> list of change flags (pure)"""
    prev = None
    for d in sorted((int(k) for k in hist if str(k).isdigit() and int(k) < int(day)), reverse=True):
        for slug, g in (hist.get(str(d)) or {}).items():
            if g.get("lane") == lane:
                prev = (d, g)
                break
        if prev:
            break
    if not prev:
        return []
    d, g = prev
    out = []
    for k in ("mastery_sets",):
        if geo.get(k) is not None and g.get(k) is not None and geo[k] != g[k]:
            out.append("%s %s -> %s (was Day %s)" % (k, g[k], geo[k], d))
    return out


def _extra(lane, task, blobs, mode, **kw):
    """the OPTIONAL lane hook (agreed with the homestation 2026-10-11): autosolve_<lane>.recognise_extra(task, blobs, mode) -> {"facts": {...}, "missing_tokens": [answer ids with NO handler], "expected_next": [...]}.
    Token coverage needs NO bytes (today's metadata gap, pe.version_original_filename, was a missing token handler visible from the contract's ids alone), so a lane can report it for every mode.
    A hook that raises or returns junk is ignored: the hook can add a hold, never cause a crash.
    2026-10-21 (hs-unique-21): forwards extra kwargs (e.g. live=True, allowed_hosts=...) to a hook that accepts them; a hook without the kwarg is called the legacy way."""
    try:
        import importlib, release_scan, inspect as _ins
        name = release_scan.LANE_MODULE.get(lane)
        fn = getattr(importlib.import_module(name), "recognise_extra", None) if name else None
        if not fn and name and name.startswith("autosolve_"):      # the homestation ships its hooks as recognise_extra_<lane>.py beside the adapter
            try:
                fn = getattr(importlib.import_module("recognise_extra_" + name[len("autosolve_"):]), "recognise_extra", None)
            except ImportError:
                fn = None
        if not fn:
            return {}
        if kw:
            try:
                _sig = _ins.signature(fn)
                _accepts = any(p.kind == _ins.Parameter.VAR_KEYWORD for p in _sig.parameters.values()) or any(k in _sig.parameters for k in kw)
                r = fn(task, blobs, mode, **{k: v for k, v in kw.items() if _accepts and (any(p.kind == _ins.Parameter.VAR_KEYWORD for p in _sig.parameters.values()) or k in _sig.parameters)}) if _accepts else fn(task, blobs, mode)
            except (TypeError, ValueError):
                r = fn(task, blobs, mode)
        else:
            r = fn(task, blobs, mode)
        if not isinstance(r, dict):
            return {}
        return {"facts": r.get("facts") if isinstance(r.get("facts"), dict) else {}, "missing_tokens": [str(t) for t in (r.get("missing_tokens") or [])][:200], "expected_next": list(r.get("expected_next") or [])[:10]}
    except Exception:
        return {}


def _flush(sd, out):
    tmp = os.path.join(sd, "prebrief.json.tmp")
    json.dump(out, open(tmp, "w", encoding="ascii"), indent=1, ensure_ascii=True)
    os.replace(tmp, os.path.join(sd, "prebrief.json"))                      # atomic: a reader never sees half a file


def brief_one(sd, live=False, gm=None, hist=None, day=None, with_single=True):
    """compute one challenge's brief. The TIMED verdicts are written FIRST and one at a time (Time Trial, then Mastery), then the optional Single coverage, each flushed as soon as it exists, so the gate can
    read the Time Trial verdict seconds after the process starts instead of waiting for the slow Mastery compute."""
    marker = os.path.join(sd, "prebrief.running")
    try:
        open(marker, "w").write(str(os.getpid()))
    except OSError:
        pass
    try:
        return _brief_one(sd, live, gm, hist, day, with_single)
    finally:
        try:
            os.remove(marker)
        except OSError:
            pass


def _brief_one(sd, live, gm, hist, day, with_single):
    import contract_preflight as CP, release_scan, recognize
    task = json.load(open(os.path.join(sd, "task.json"), encoding="utf-8"))
    art = os.path.join(sd, "artifact_0.bin")
    blobs = [open(art, "rb").read()] if os.path.isfile(art) else []
    lane = task.get("lane") or ""
    out = {"name": task.get("name"), "id": task.get("id"), "lane": lane, "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "modes": {}}
    if blobs:
        ident = recognize.identify(blobs[0], "artifact_0.bin")
        out["recognise"] = {"bytes": len(blobs[0]), "sha256": _sha(blobs[0])[:16], "type": ident.get("type"), "detail": ident.get("detail"), "route": ident.get("lane"), "move": str(ident.get("move"))[:120]}
        try:
            out["recognise"]["members"] = [str(l)[:140] for l in recognize.describe(art)[1:4]]
        except Exception:
            pass
    try:
        import lane_progress
        out["model"] = [str(l)[:170] for l in (lane_progress.today_lines(lane, task) or [])][:4]
    except Exception as e:
        out["model"] = ["unavailable: %s" % type(e).__name__]
    try:
        import digest
        out["family"] = [str(l)[:140] for l in (digest.family_matches(task.get("questions") or []) or [])][:3]
    except Exception:
        out["family"] = []
    _flush(sd, out)
    contracts = {}
    for mode in MODES:
        if live and gm is not None:
            c = gm.contract(task["id"] + "/" + mode)
            if c and (c.get("questions") or c.get("answer_ids")):
                json.dump(c, open(os.path.join(sd, "contract_%s.json" % mode), "w", encoding="ascii"), indent=1, ensure_ascii=True)
        c = CP.load_contract(sd, mode)
        contracts[mode] = c
        if not c:
            out["modes"][mode] = {"verdict": "UNKNOWN", "reasons": ["no contract saved (run with --live)"], "residue": []}
            continue
        cdiff = {}
        try:
            if day is not None:
                pd, pc = prev_contract(lane, mode, day)
                if pc:
                    cdiff = contract_diff(pc, c)
                    cdiff["prev_day"] = pd
        except Exception:
            cdiff = {}
        mblobs, basis = timed_blobs(sd, mode)
        if not mblobs:
            mblobs, basis = blobs, STAND_IN_BASIS
        e = CP.evaluate(task, c, mblobs)
        ex = _extra(lane, CP.make_task(task, c), mblobs, mode)
        for t in ex.get("missing_tokens") or []:                  # a bytes-free token gap from the lane itself: a definite hole, whatever the stand-in said
            e["unresolved"].setdefault(t, [])
            e["needs_bytes"].pop(t, None)
        # 2026-10-21 (Day 11 Mobile prebrief fix): recognise_extra.facts.known_ids are ids the LANE has an extractor for; if the stand-in just lacked the real bytes, those ids are not holes - the LANE guarantees satisfaction on the real variant. Move them to `resolved_by_lane` and clear the matching format_problem; coverage then counts them as covered and the verdict is READY (the gate opens either way, but READY matches the agent's expectation when every contract id is lane-known).
        _facts = ex.get("facts") or {}
        _known = set(_facts.get("known_ids") or [])
        _is_lane_known = lambda t: (t in _known) or any(_k == "set<N>.answer" and str(t).startswith("set") and str(t).endswith(".answer") for _k in _known)
        _promoted = []
        if _known and basis == STAND_IN_BASIS:
            for _t in list(e["unresolved"].keys()):
                if _is_lane_known(_t):
                    e["unresolved"].pop(_t)
                    e["resolved"] = int(e.get("resolved") or 0) + 1
                    _promoted.append(_t)
            if _promoted:
                # If the format_problem was only "no answers computed" from the empty stand-in, drop it; the lane will produce a real answer at start.
                e["format_problems"] = [p for p in (e.get("format_problems") or []) if "no answers computed" not in str(p).lower()]
        v, why = verdict(e["ids"], e["resolved"], e["unresolved"], e["needs_bytes"], e["format_problems"], e["window_s"])
        # coverage_pct is RECORDED, not just used: the predictive model, lane_progress and any agent
        # reading prebrief.json can then see which mode is short and by how much (standing rule: 100%
        # expected, under MIN_COVERAGE_PCT is an OPTIMISE target to retry until closed).
        out["modes"][mode] = {"verdict": v, "ids": e["ids"], "resolved": e["resolved"], "residue": sorted(map(str, e["unresolved"]))[:50], "needs_real_bytes": len(e["needs_bytes"]),
                              "coverage_pct": round(coverage_pct(e["ids"], e["resolved"]), 2),
                              "coverage_min": MIN_COVERAGE_PCT,
                              "optimise": coverage_pct(e["ids"], e["resolved"]) < MIN_COVERAGE_PCT,
                              "window_s": e["window_s"], "reasons": why, "basis": basis, "contract_diff": cdiff, "error": e["error"], "facts": ex.get("facts") or {}, "expected_next": ex.get("expected_next") or []}
        _flush(sd, out)
    try:
        if contracts.get("time_trial") and contracts.get("mastery"):
            out["mode_diff"] = cross_mode_diff(contracts["time_trial"], contracts["mastery"])
    except Exception:
        pass
    if with_single:
        r = release_scan.run(task, blobs)                      # informational: autosolve solves the Single itself, so the live gate path skips this
        un = {k: v2 for k, v2 in (r.get("unresolved") or {}).items()}
        res_d = dict(r.get("resolved") or {})
        # 2026-10-22 (T3, Day 11 Local Secrets Single): the SAME lane-known promotion the timed modes get (see the block above). The Single's only id
        # 'answer' is the mobile codec's declared known id, so it is covered; an id outside the lane's known set stays a hole (fail closed).
        _sx = _extra(lane, task, blobs, "single_solve")
        _sk = set((_sx.get("facts") or {}).get("known_ids") or [])
        _sknown = lambda t: (t in _sk) or (any(k == "set<N>.answer" for k in _sk) and str(t).startswith("set") and str(t).endswith(".answer"))
        _sprom = []
        for _t in list(un.keys()):
            if _sk and _sknown(_t):
                un.pop(_t)
                res_d[_t] = True
                _sprom.append(_t)
        v, why = verdict(len(res_d) + len(un), res_d, un, {}, [], 0.0)
        out["modes"]["single_solve"] = {"verdict": v, "ids": len(res_d) + len(un), "resolved": len(res_d), "residue": sorted(map(str, un))[:50], "reasons": why, "secs": r.get("secs"), "error": r.get("error"), "lane_known": sorted(_sprom)}
    # 2026-10-22 (T6): ADVISORY learned-method retrieval. Only APPROVED methods (the approval gate lives in method_records: candidates never
    # reach here); a reference for the agent, never an input to any verdict or gate. Any failure is recorded and ignored.
    try:
        _lx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_accel_hs", "learn")
        if _lx not in sys.path:
            sys.path.insert(0, _lx)
        import method_records as _MR, method_retrieve as _RET
        _db = _MR.load()
        _res = _RET.retrieve(_db, {"lane": lane, "structure": {}})
        out["methods"] = {"approved_in_store": len(_MR.approved(_db)), "reason": _res.get("reason"),
                          "hits": [{"method_id": m.get("method_id"), "why": m.get("why"), "procedure_reference": m.get("procedure_reference")}
                                   for m in (_res.get("methods") or [])][:3]}
    except Exception as _e:
        out["methods"] = {"error": type(_e).__name__}
    geo = CP.geometry(task, contracts)
    out["geometry"] = geo
    out["geometry_flags"] = history_flags(lane, day or 0, geo, hist or {})
    _flush(sd, out)
    return out


def line(pb):
    """the ONE coord line for a challenge"""
    ms = pb["modes"]
    def short(m):
        x = ms.get(m, {})
        tag = "" if m == "single_solve" else (" [timed bytes]" if str(x.get("basis", "")).startswith("REHEARSED") else " [stand-in]")
        nc = (x.get("contract_diff") or {}).get("n_changed")
        return "%s%s%s%s" % (x.get("verdict", "?"), tag, (" residue=[%s]" % ",".join(x.get("residue", [])[:4])) if x.get("verdict") == "RESIDUE" else "", (" FORMAT-CHANGED=%d vs Day %s" % (nc, x["contract_diff"].get("prev_day"))) if nc else "")
    return "PREBRIEF %s (%s): single %s | TT %s | MM %s%s" % (str(pb.get("name"))[:28], str(pb.get("lane"))[:10], short("single_solve"), short("time_trial"), short("mastery"),
                                                             (" | CHANGED: " + "; ".join(pb.get("geometry_flags") or [])) if pb.get("geometry_flags") else "") +         ((" | TT-vs-MM FORMAT DIFFERS for %d ids (e.g. %s)" % (pb["mode_diff"]["n_changed"], ",".join(pb["mode_diff"]["changed"][:3]))) if (pb.get("mode_diff") or {}).get("n_changed") else "")


def main(argv):
    if argv and argv[0] == "--gate":
        go, why, res = gate(argv[1] if len(argv) > 1 else "")
        print("%s: %s%s" % ("GO" if go else "HELD", why, (" | residue: " + ", ".join(res[:8])) if res else ""))
        return 0 if go else 1
    if argv and argv[0] == "--one":
        sd, day = argv[1], int(argv[argv.index("--day") + 1]) if "--day" in argv else 0
        gm = None
        if "--live" in argv:
            from ctf_gm import GM
            gm = GM()
        hp0 = os.path.join(HERE, "kb", "mode_geometry.json")
        try:
            hist0 = json.load(open(hp0, encoding="utf-8")) if os.path.isfile(hp0) else {}
        except Exception:
            hist0 = {}
        brief_one(sd, "--live" in argv, gm, hist0, day, with_single=False)
        return 0
    if not argv or not argv[0].isdigit():
        print(__doc__)
        return 2
    day, live = int(argv[0]), "--live" in argv
    import contract_preflight as CP
    gm = None
    if live:
        from ctf_gm import GM
        gm = GM()
    hp = os.path.join(HERE, "kb", "mode_geometry.json")
    hist = json.load(open(hp, encoding="utf-8")) if os.path.isfile(hp) else {}
    sds = CP.stage_dirs(day)
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=max(1, len(sds))) as ex:
        res = list(ex.map(lambda sd: brief_one(sd, live, gm, hist, day), sds))
    if "--json" in argv:
        print(json.dumps(res))
        return 0
    print("PREBRIEF Day %d: %d challenges in %.1fs (%s contracts; coverage/format/window on stand-in bytes, NOT values)" % (day, len(res), time.time() - t0, "LIVE free-read" if live else "saved"))
    for pb in res:
        print(line(pb))
        rec = pb.get("recognise") or {}
        if rec:
            print("    recognise: %s %s | %d bytes sha256 %s | route %s" % (rec.get("type"), rec.get("detail") or "", rec.get("bytes", 0), rec.get("sha256"), rec.get("route")))
            for l in rec.get("members", [])[:2]:
                print("      " + l)
        for l in (pb.get("model") or [])[:2]:
            print("    model: " + l)
    held = [(pb["name"], m) for pb in res for m, x in pb["modes"].items() if x.get("verdict") == "RESIDUE"]
    print("HELD windows (RESIDUE): %s" % (", ".join("%s/%s" % h for h in held) or "none"))

    # The standing coverage rule, surfaced every run so nobody has to go looking for it. 100% is the
    # expectation; anything under MIN_COVERAGE_PCT is named here as a RETRY-UNTIL-OPTIMISED target, worst
    # first, because the point is to speed up TT and MM, not merely to explain why a window stayed shut.
    cov = [(x.get("coverage_pct"), pb["name"], m, x.get("residue") or [])
           for pb in res for m, x in pb["modes"].items() if x.get("coverage_pct") is not None]
    short = sorted([c for c in cov if c[0] < MIN_COVERAGE_PCT])
    full = [c for c in cov if c[0] >= 100.0]
    print("COVERAGE: %d of %d modes at 100%%; minimum is %.1f%%" % (len(full), len(cov), MIN_COVERAGE_PCT))
    if short:
        print("OPTIMISE (retry until these reach 100%%): %d mode(s)" % len(short))
        for pct, name, m, residue in short:
            print("   %-38s %-11s %5.1f%%  missing: %s"
                  % (name[:38], m, pct, ", ".join(map(str, residue[:4])) or "(count only)"))
    else:
        print("OPTIMISE: nothing below the minimum - every staged mode is fully covered")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
