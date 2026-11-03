#!/usr/bin/env python3
"""AUTOSOLVE: run the banked lane solver as soon as a challenge is claimed.

usage: python3 challenges/_lib/autosolve.py <day> <challenge_id> <lane> [budget_seconds]
Called by claim_next.py right after a claim (only when HUNTRESS_AUTOSOLVE=1, which Go.ps1 sets for live runs only, so
tests and rehearsals never submit). Workstation's Claude agent analyzes concurrently; before timed starts the runner
waits for its per-challenge TT/MM coverage prediction. Order: Single Solve first; timed modes only after Single Solve is
CORRECT in this run or already solved. Every CORRECT is marked on the board. Prints one line per mode:
  AUTOSOLVE <mode>: CORRECT | incorrect (<n> accepted, <m> remaining) | ERROR <reason> | SKIPPED <why>
and never raises. Per-lane adapters: challenges/_lib/autosolve_<lane>.py with run(gm, challenge_id) or compute(start, blobs).
"""
import hashlib, importlib, json, os, re, sys, threading, time, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import lane_registry
    ADAPTER = {lane: row["adapter"] for lane, row in lane_registry.LANES.items()}
except Exception:
    ADAPTER = {"warmups": "autosolve_warmups", "metadata-forensics": "autosolve_metadata", "script-analysis": "autosolve_script",
               "binary-reverse-engineering": "autosolve_binary", "mobile-android": "autosolve_mobile", "web": "autosolve_web",
               "web-exploitation": "autosolve_web"}
SUFFIX = {"single_solve": "", "time_trial": "/time_trial", "mastery": "/mastery"}


def say(line):
    print("AUTOSOLVE " + line, flush=True)


def _assignment_snapshot(day, cid, lane):
    """Load this claimed CID's exact release snapshot without contacting the GM."""
    path = os.environ.get("HUNTRESS_ASSIGNMENT_FILE")
    candidates = [path] if path else []
    pool_dir = os.environ.get("HUNTRESS_POOL_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(HERE)), "challenges", "_pool")
    safe_cid = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(cid))
    candidates.append(os.path.join(pool_dir, safe_cid + ".json"))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            with open(candidate, encoding="utf-8") as f:
                doc = json.load(f)
            challenge = doc.get("challenge") or {}
            if str(challenge.get("id")) != str(cid):
                continue
            if int(doc.get("day", -1)) != int(day):
                continue
            # D31 HS (2026-10-31): canonicalise BOTH sides. autosolve main() canonicalises lane via lane_registry
            # ('web' -> 'web-exploitation') before calling here, while the dispatcher writes challenge.lane with the
            # raw dispatcher name ('web'), so a strict compare rejected the right assignment. Fall back to strict
            # compare on any lane_registry failure so a broken registry stays fail-closed.
            _ch_lane = challenge.get("lane")
            if _ch_lane:
                try:
                    import lane_registry as _lr
                    if _lr.canonical_lane(_ch_lane) != _lr.canonical_lane(lane):
                        continue
                except Exception:
                    if _ch_lane != lane:
                        continue
            entries = doc.get("mode_entries")
            if isinstance(entries, list) and entries:
                return doc, entries
            return doc, None
        except Exception:
            continue
    return None, None


def _install_artifact_archive(assignment, day, cid, lane):
    """Archive the exact bytes returned to the lane adapter, with no extra GM request."""
    if not assignment:
        return False
    try:
        import ctf_gm
        from mode_prediction import artifact_path, base_id, workspace
        challenge = assignment.get("challenge") or {}
        root = os.path.abspath(os.path.join(HERE, "..", ".."))
        folder = os.path.join(workspace(root, day, challenge), "artifacts")
        os.makedirs(folder, exist_ok=True)
        cls = ctf_gm.GM
        if getattr(cls.download, "_huntress_archive", False):
            return False
        original = cls.download

        def download(self, challenge_id, entry, i=0):
            data = original(self, challenge_id, entry, i)
            challenge_text = str(challenge_id or "")
            assigned_id = str((assignment.get("challenge") or {}).get("id") or cid)
            if base_id(challenge_text) == assigned_id:
                mode = "single"
                if challenge_text.endswith("/time_trial"):
                    mode = "time_trial"
                elif challenge_text.endswith("/mastery"):
                    mode = "mastery"
                suffix = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(i))
                target = os.path.join(folder, "%s_%s.bin" % (mode, suffix))
                temp = target + ".tmp.%d" % os.getpid()
                with open(temp, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp, target)
                digest = hashlib.sha256(data).hexdigest()
                say("ARTIFACT %s %s bytes=%d sha256=%s" %
                    (mode, target, len(data), digest))
                # D30-E (2026-10-29): dispatcher may have prefetched TT/MM bytes via a free pre-start
                # artifact field. Compare sha; log diagnostic only — never alters returned data.
                if mode in ("time_trial", "mastery"):
                    try:
                        import _dispatch_prefetch
                        day_dir = os.path.join(root, "challenges", "Day %02d" % int(day))
                        cached = _dispatch_prefetch.load_prefetched_if_match(day_dir, assigned_id, mode, digest)
                        if cached is not None and len(cached) == len(data):
                            say("ARTIFACT-PREFETCH %s MATCHED (dispatcher prefetched bytes agree with GM download)" % mode)
                        else:
                            summary = _dispatch_prefetch.summary_from_stage(day_dir, assigned_id)
                            if summary.get(mode):
                                say("ARTIFACT-PREFETCH %s MISMATCH cached_sha=%s actual_sha=%s" %
                                    (mode, summary[mode]["sha256"], digest))
                    except Exception:
                        pass
            return data

        download._huntress_archive = True
        download.__wrapped__ = original
        cls.download = download
        return True
    except Exception as exc:
        say("ARTIFACT ARCHIVE unavailable (%s)" % type(exc).__name__)
        return False


def _load_adapter(lane, name, override):
    """Load a challenge-local solver from source bytes so same-size edits cannot reuse stale bytecode."""
    if override and os.path.isfile(override):
        import types
        with open(override, "rb") as f:
            source = f.read()
        mod = types.ModuleType("solver_copy_" + lane.replace("-", "_"))
        mod.__file__ = override
        exec(compile(source, override, "exec"), mod.__dict__)
        say("adapter OVERRIDE loaded from %s (no __pycache__)" % override)
        return mod
    if name == HANDLERS_ONLY:                                        # D32 auto item D: rebuilt (re-reading the challenge's handlers.py), never imported
        mod = _handlers_only_adapter(_HO_CTX.get("day"), _HO_CTX.get("cid"), _HO_CTX.get("lane"))
        if mod is None:
            raise ImportError("handlers-only adapter: no handler file applies any more")
        return mod
    return importlib.import_module(name)


_RUN_SUMMARY = {}                     # set at the end of main(): which open modes are still owed (D31 audit item 6)


def _owed_modes(results, open_modes, prior_path):
    """Open modes not CORRECT in this run nor in an earlier run's saved results (a Time-Trial-only rerun must not flag the Single)."""
    merged = {m: str((r or {}).get("result") or "") for m, r in (results or {}).items()}
    try:
        for m, v in (json.load(open(prior_path)) or {}).items():
            if str((v or {}).get("result", "")).upper() == "CORRECT":
                merged[m] = "CORRECT"
    except Exception:
        pass
    return [m for m in ("single_solve", "time_trial", "mastery")
            if m in (open_modes or {}) and merged.get(m, "").upper() != "CORRECT"]


def _final_status(status):
    """FINISHED with an open mode still owed -> INCOMPLETE + the owed modes and their existing repair capsules."""
    if status != "FINISHED" or not _RUN_SUMMARY.get("unresolved_modes"):
        return status, None
    caps = []
    for m in _RUN_SUMMARY["unresolved_modes"]:
        e = _RUN_SUMMARY["cid"] if m == "single_solve" else _RUN_SUMMARY["cid"] + "/" + m
        c = os.path.join(_RUN_SUMMARY["board"], e.replace("/", "_") + ".repair_capsule.json")
        if os.path.exists(c):
            caps.append(c)
    return "INCOMPLETE", {"unresolved_modes": list(_RUN_SUMMARY["unresolved_modes"]), "repair_capsules": caps}


def _update_runner_state(status, error=None, extra=None):
    path = os.environ.get("HUNTRESS_AUTOSOLVE_STATE")
    if not path:
        return
    try:
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:
            doc = {}
        doc["status"] = status
        for k in ("unresolved_modes", "repair_capsules"):     # never let a stale INCOMPLETE detail outlive a later run
            doc.pop(k, None)
        doc.update(extra or {})
        doc["pid"] = os.getpid()
        if status in ("RUNNING", "STARTING"):
            doc.pop("finished_epoch", None)
        else:
            doc["finished_epoch"] = time.time()
        if error:
            doc["error"] = str(error)[:200]
        tmp = path + ".tmp." + str(os.getpid())
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, ensure_ascii=True, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        pass
    if status not in ("RUNNING", "STARTING"):
        lock_path = os.environ.get("HUNTRESS_AUTOSOLVE_LOCK")
        if lock_path:
            try:
                os.unlink(lock_path)
            except OSError:
                pass


MEANINGS = (   # what each timed 409 REALLY means (docs/gm-facts.md "THE 409 FAMILY ON TIMED ROUTES"); none of them means "this mode is unavailable"
    ("timed_intent_not_available", "MEANING: the ONE ranked attempt on this route is already spent (or it is a legacy single-pool route that rejects run_for_time); a plain start only RESUMES it. Not 'mode unavailable'."),
    ("retry_variants_unavailable", "MEANING: the UNTIMED pool is empty (unique_attempts_remaining=0), so retry/practice have no variant to hand out; no GM call fixes it. Not 'mode unavailable'."),
    ("prerequisite_required", "MEANING: an earlier mode is not CORRECT yet (Single Solve first, then Time Trial, then Mastery)."),
    ("invalid_run_for_time", "MEANING: op=practice never takes run_for_time (it is a plain continuation op)."),
)


GM_EXHAUSTED = ("retry_variants_unavailable", "rotation_exhausted")


def _gm_side_dead(err):
    """True when a timed mode failed because the GM HAS NO VARIANT LEFT for it, not because our solver was not ready.

    The two are opposite situations and must not be treated alike (Day 12, Pascal's Wager): a Time Trial whose window
    was lost to the release 429 storm reads result=expired with unique_attempts_remaining=0, and both documented heal
    ops answer 409 retry_variants_unavailable - that mode can NEVER become CORRECT, by any call. Blocking Mastery on
    "the Time Trial is not CORRECT" then forfeits a mode we are measurably ready for. Mastery keeps its OWN readiness
    gate, and if the GM really does gate it the start is refused with 409 prerequisite_required, which hands out no
    variant and costs nothing - so attempting it is strictly better than skipping it."""
    s = str(err).lower()
    return any(k in s for k in GM_EXHAUSTED)


def explain(err):
    """append the real meaning of a known GM error to an autosolve ERROR line, so an agent reads the cause where it reads the failure (0 prompt bytes)"""
    s = str(err)
    for key, text in MEANINGS:
        if key in s:
            return s + " | " + text
    return s


_sleep = time.sleep
PREWARM_TRIES, PREWARM_GAP_S = 6, 5.0          # at most ~30 s of waiting, all BEFORE any timed window exists (no clock runs yet)


LAST_STATUS = {}          # entry -> the dict the pre-start op=status answered (only a real answer; a 409 start_required leaves nothing)


def first_op_from_status(st):
    """ONE RULE FOR EVERY LANE (2026-10-12, user: 'a clear route so the agents are not confused'): the GM's OWN free status names the one write that makes sense, and we do exactly that.
      fresh route (status 409 start_required) or a live attempt  -> 'start'    (the timed attempt itself / reconnect to it)
      finished (expired / rotation_exhausted) and fresh variants left (unique_attempts_remaining >= 1) -> 'retry'     (the next timed variant)
      finished, none left, next_op == 'practice'                 -> 'practice' (the UNTIMED continuation; a CORRECT practice submission still completes the mode; official README rule 5)
      anything else (unknown, malformed, no next_op)             -> 'start'    (never guess: start on a dead attempt only resumes it, and the GM answers what it means)
    A start on an expired attempt only RESUMES the corpse and spends the one authorised timed write, which is why this decision is made BEFORE the first write.
    The binary adapter has the same rule inside its own run() (autosolve_binary._first_op, test-pinned); every other lane gets it from route_first_write() below."""
    import gm_next_op
    return gm_next_op.first_write(st)


def route_first_write(gm, entry, st, say=print):
    """Make the FIRST gm.start() of this attempt be the op the GM named (see first_op_from_status). Done as a ONE-SHOT override on this GM object, so every adapter (generic solve_mode,
    script, metadata, mobile, warmups) follows the rule without being edited: its first start() call becomes practice() / retry(), then the real start() is restored. The same bookkeeping
    start() does (timed-window budget, per-route context) is repeated for the routed op. Returns the op chosen."""
    op = first_op_from_status(st)
    if op == "start":
        return op
    had_own = "start" in gm.__dict__                  # a test double may carry its own start(); the real client uses the class method
    own_start = gm.__dict__.get("start")

    def routed(challenge, *a, **k):
        if had_own:                                   # ONE-SHOT: put the original start() back before doing anything else
            gm.start = own_start
        else:
            gm.__dict__.pop("start", None)
        out = getattr(gm, op)(challenge)
        try:
            import ctf_gm as _cg
            if isinstance(out, dict) and out.get("deadline") and str(out.get("result", "")).lower() != "expired":
                _cg.open_window(out.get("deadline"))
            if hasattr(gm, "_ctx") and isinstance(out, dict):
                gm._ctx()[challenge] = {"start": out, "blobs": {}}
        except Exception:
            pass
        return out
    gm.start = routed
    say("%s: the GM's status says finished (%s) -> the first write is op=%s, not start (a start would only resume the dead attempt)" % (
        entry.rsplit("/", 1)[-1], "next_op=%s, %s fresh variant(s) left" % (st.get("next_op"), st.get("unique_attempts_remaining")), op))
    return op


def _continuation_operation(st):
    """Return only a continuation explicitly offered by a terminal GM status.

    A submit result alone is not proof that an attempt ended. In particular, do
    not synthesize expired/rotation counters to force practice after a failed
    ranked attempt. The server must report both terminal state and next_op.
    """
    import gm_next_op
    return gm_next_op.continuation(st, strict=True)


def _deadline_epoch(d):
    """GM deadline (epoch number or ISO-8601 string) -> epoch seconds, or None. Never raises."""
    try:
        if isinstance(d, (int, float)) and not isinstance(d, bool):
            return float(d)
        if isinstance(d, str) and d.strip():
            import datetime as _dt
            t = _dt.datetime.fromisoformat(d.strip().replace("Z", "+00:00"))
            if t.tzinfo is None:
                t = t.replace(tzinfo=_dt.timezone.utc)
            return t.timestamp()
    except Exception:
        return None
    return None


def _await_ranked_expiry(gm, entry, status, launch, say, sleep=time.sleep, now=time.time):
    """-> (status, op). Waits ONLY when the fresh status is the SAME ranked attempt (attempt_id == the ranked start's),
    still live (no result) with a deadline in the future that ends within the run budget and the cap; then re-reads the
    status once (and once more 5 s later if the GM has not flipped it yet). Any other shape returns (status, None)
    immediately, so it is still HELD exactly as before. Never sends a write itself."""
    try:
        if not isinstance(status, dict) or status.get("result"):
            return status, None
        cur_id, old_id = status.get("attempt_id"), launch.get("attempt_id")
        if not cur_id or (old_id and cur_id != old_id):
            return status, None
        dl = _deadline_epoch(status.get("deadline"))
        if dl is None:
            return status, None
        wait = dl - now() + 2.0
        cap = float(os.environ.get("HUNTRESS_RANKED_EXPIRE_WAIT_S", "900") or 900)
        if wait <= 0 or wait > cap or (_RUN_DEADLINE[0] and now() + wait > _RUN_DEADLINE[0]):
            return status, None
        say("%s: ranked attempt still live until its deadline; waiting %.0f s for the GM to end it, then continuing (no agent hand-off)"
            % (entry.rsplit("/", 1)[-1], wait))
        sleep(wait)
        for i in range(2):
            status = gm.status(entry)
            op = first_op_from_status(status)
            if op in ("retry", "practice"):
                return status, op
            if i == 0:
                sleep(5.0)
        return status, None
    except Exception:
        return status, None


def _fallback_with_live_status(gm, entry, run, say):
    """Re-authorize one status-backed continuation after ranked failure.

    Readiness is rechecked, then a fresh status is read immediately before the
    write. The existing GM guard is given a new one-write scope only after both
    checks pass. No fallback operation is inferred from the failed submit.
    """
    try:
        import prebrief
        go, why, residue = prebrief.gate(entry, wait_s=GATE_WAIT_S)
    except Exception as e:
        raise Held("HELD: continuation readiness unavailable (%s); no retry/practice sent" % type(e).__name__, [])
    if not go and os.environ.get("HUNTRESS_STRICT_PREBRIEF_GATE") == "1":
        raise Held("HELD: continuation readiness: %s; no retry/practice sent" % str(why)[:200], residue)
    try:
        status = gm.status(entry)
    except Exception as e:
        raise Held("HELD: current GM status unavailable (%s); no retry/practice sent" % type(e).__name__, [])
    # Same ONE rule as route_first_write (first_op_from_status), read from this fresh GM status: a finished attempt with variants left is retry
    # even when next_op is absent (the Day 21 warmups mastery case, 2026-10-21). Anything else is still held, never guessed.
    op = first_op_from_status(status)
    if op not in ("retry", "practice"):
        op = None
    launch = getattr(gm, "last_launch", None) or {}
    if not op:
        # D31 WS (all-done analysis: warmups MM, mobile MM, metadata TT all HELD here): after a ranked failure the SAME
        # ranked attempt is usually still LIVE (a wrong timed answer does not end it), so no continuation exists YET. The
        # GM itself names the next write once that attempt's own deadline passes (expired -> retry). Wait for exactly that,
        # bounded by the run budget and HUNTRESS_RANKED_EXPIRE_WAIT_S, then re-read the status and apply the SAME rule.
        status, op = _await_ranked_expiry(gm, entry, status, launch, say)
    if not op:
        raise Held("HELD: current GM status does not report an ended attempt with an available continuation; no write sent", [])
    old_id = launch.get("attempt_id")
    current_id = status.get("attempt_id") if isinstance(status, dict) else None
    if old_id and current_id and old_id != current_id:
        raise Held("HELD: GM attempt changed since the ranked start; refusing stale continuation", [])
    old_deadline = launch.get("deadline")
    current_deadline = status.get("deadline") if isinstance(status, dict) else None
    if old_deadline and current_deadline and old_deadline != current_deadline:
        raise Held("HELD: GM deadline changed since the ranked start; refusing stale continuation", [])
    if op == "retry":
        try:
            import timed_slot
            slot, detail = timed_slot.wait_for_slot(entry, say, hard_deadline_t=_RUN_DEADLINE[0])
        except Exception as e:
            raise Held("HELD: retry slot unavailable (%s); no retry sent" % type(e).__name__, [])
        if slot != "go":
            raise Held("HELD: retry slot did not open (%s); no retry sent" % str(detail)[:160], [])
    route_first_write(gm, entry, status, say)
    say("%s: continuation authorized from fresh GM status (op=%s, remaining=%s)" % (entry.rsplit("/", 1)[-1], op, status.get("unique_attempts_remaining")))
    import ctf_gm as _cg
    with _cg.timed_start_authorised():
        return run()


def next_step(day, cid, lane, open_modes, results, held_modes, errored, agent="<agent>"):
    """THE ONE LINE an agent reads after an autosolve run (2026-10-13, user: 'they think too much, they should have everything they need in their instructions'). The agent prompt is at its size
    cap, so the instruction for each outcome is printed HERE, in the output every agent reads at the claim and after every rerun. Pure. -> one line.
    Day 12 evidence: the agents whose run ended CORRECT made 6-9 tool calls; the one whose timed mode did not (108 calls) spent them reading adapter code to work out what to do next."""
    cmd = "python3 challenges/_lib/autosolve.py %s %s %s" % (day, cid, lane)
    left = [m for m in ("single_solve", "time_trial", "mastery") if m in (open_modes or {}) and str((results.get(m) or {}).get("result", "")).upper() != "CORRECT"]
    if "time_trial" in left and "mastery" in left:
        left = [m for m in left if m != "mastery"]           # Mastery opens only after the Time Trial is CORRECT: it is not the mode that needs work now
    if not left:
        return "NEXT: every mode of this challenge is CORRECT. Write the %s_Writeup.md (flags stay in it), run lessons.py add, then board.py finish. Nothing else: no re-solving, no extra GM calls." % cid
    if "single_solve" in left and "single_solve" not in held_modes:
        return "NEXT: the Single Solve did NOT pass. Read the ERROR / result line above, write ONE handler for exactly what it names in this challenge's handlers.py (`python3 challenges/_lib/fix.py %s %s` prints its path, the held ids and where an earlier day already solved them; autosolve_%s.py is FROZEN during the race), then run the same command: %s . The timed modes stay untouched until the Single is CORRECT. Do not call the GM by hand to look at values: the contract and the line above carry the GM's own words." % (day, cid, lane.split("-")[0], cmd)
    held = [m for m in left if m in held_modes]
    if held:
        return ("NEXT: %s HELD. Open %s*.residue.json (the GM's own words per id, plus tool_reading: resolve_field ALREADY ran on the artifact - start from its source key, do not rerun it by hand). TOOL-FIRST, do NOT think or hand-parse: for a header/metadata-shaped field run the GENERAL installed tool on the artifact FIRST - `python3 challenges/_lib/recognize.py <artifact>` then resolve_field, or exiftool / pefile / readelf / nm / strings / binwalk - a value the tool already knows needs no extractor (this is the class that cost us 10 min). ONLY if no general tool has it: `python3 challenges/_lib/fix.py %s %s` (held ids, SOLVED-BEFORE file:line, family matches, the handlers.py path), write a handler for exactly those ids in that handlers.py (autosolve_%s.py stays FROZEN), and rerun once: %s . Never guess, never submit by hand, never call the GM by hand." % (
            "/".join(held), cid, day, cid, lane.split("-")[0], cmd))
    # WRONG ANSWER (2026-10-14, Day 14 warmups MM): an 'incorrect' result or a SubmitRefused (identical resubmit) is NOT a window/slot problem - the extractor produced the wrong value, so rerunning as-is resubmits the same and is refused.
    # This is the agent-3 stall: it treated a wrong submit as "wait for the Commander". You OWN and must MASTER this lane: fix the extractor, verify offline, rerun. Never stall, never resubmit identical.
    wrong = [m for m in left if str((results.get(m) or {}).get("result", "")).lower() in ("incorrect", "wrong")
             or any(s in str(errored.get(m, "")).lower() for s in ("submitrefused", "already came back", "not correct"))]
    if wrong:
        return ("NEXT: %s got a WRONG answer (not a window/slot problem): the extractor for THIS lane produced the wrong value, so rerunning unchanged resubmits the same and is refused. FIX the value with a handler for exactly this "
                "mode in this challenge's handlers.py (`python3 challenges/_lib/fix.py %s %s`; mark it override=True if the adapter value is the wrong one; autosolve_%s.py stays FROZEN; check it on the real bytes with fix.py --dry), THEN rerun: %s . You OWN this lane and must master it - never resubmit an identical answer, never stall or wait for a human." % ("/".join(wrong), day, cid, lane.split("-")[0], cmd))
    return ("NEXT: %s ended without CORRECT (the line above says why). Run the SAME command once more: it reads the GM's own status, picks start / retry / practice itself, and waits for the quiet slot. "
            "If that run says no variant is left and no practice is offered, write that one line into %s.needuser and keep waiting for the Commander. Do NOT read ctf_gm.py or the adapter, do NOT start / retry / practice by hand, do NOT poll the GM: %s") % ("/".join(left), agent, cmd)


def _route_unmapped(cid, lane):
    """A released challenge whose lane has NO banked autosolver (web / blockchain / crypto / cloud / dfir, or any brand-new lane the
    GM peppers in from here on): do NOT go silent (the old bare 'SKIPPED no adapter' left the agent starting cold). These lanes are
    agent-solved, not auto-submitted (a live web target / a novel lane has no single deterministic transform), so instead DEPICT the
    staged artifact deterministically (recognize.depict: type + lane + predicted candidate + PREPARED? + the exact next action) so the
    agent runs the right tool and specialist in seconds. Submit ONLY a fully-validated value - never a guess. Never raises."""
    say("ALL: no banked autosolver for lane %r - routing (web/blockchain/crypto/cloud/new lanes are agent-solved, not auto-submitted)" % lane)
    try:
        import prebrief, recognize
        sd = prebrief.stage_dir_for(cid)
        task = {"id": cid, "lane": lane}
        arts = []
        if sd and os.path.isdir(sd):
            try:
                task = json.load(open(os.path.join(sd, "task.json"), encoding="utf-8")) or task
            except Exception:
                pass
            for f in sorted(os.listdir(sd)):
                if f == "task.json" or f.startswith(("contract_", "prebrief")) or f.endswith((".running", ".residue.json")):
                    continue
                p = os.path.join(sd, f)
                if os.path.isfile(p):
                    arts.append(p)
        for line in recognize.depict(task, arts):
            say("  " + line)
    except Exception as e:
        say("  ROUTE: recognize.depict unavailable (%s) - run `python3 challenges/_lib/recognize.py <artifact>` then the named tool by hand" % str(e)[:80])
    # WIRE the exact banked fast-win solver per unmapped lane (2026-10-14: a tool that exists but is not handed to the agent
    # = the 10-minute miss we had today). recognize.depict named it generically above; this gives the EXACT command to run now.
    L = "challenges/_lib/"
    RUN = {
        "web": "python3 %sautosolve_web.py <saved-response-or-url>  (flags/comments/secrets/AWS-key + JWT weak-HMAC crack & alg=none forge + SSTI/SQLi; live: probe(url) quick paths)" % L,
        "crypto-stego": "python3 %scrypto_id.py <file> FIRST (classifies + auto-attacks: encoding->decode_chain, classical->crypto_kit keyless vigenere/railfence/xor/affine/atbash/a1z26/baconian, n/e/c->rsa_tool; confident-only, never gibberish) | else rsa_tool.py / crypto_kit.py / decode_chain.py --slug directly" % L,
        "crypto": "python3 %scrypto_id.py <file>  (classify + auto-attack; confident-only)" % L,
        "osint-cti": "python3 %sosint_kit.py <file>  (extract+REFANG emails/domains/urls/ips/md5-sha/btc/eth/onion/cve/handles + names the pivot tool per entity: amass enum / crt.sh / dig / whois / chain-explorer) then run that lookup" % L,
        "condef": "python3 %scondef_kit.py  (draft a COMPILING YARA rule from strings/hashes + a valid Sigma rule from process/cmdline/network fields; pair with dfir_kit/osint_kit to EXTRACT the IOCs first)" % L,
        "constructing-defense": "python3 %scondef_kit.py  (YARA from strings/hashes + Sigma from log fields; extract IOCs with dfir_kit/osint_kit)" % L,
        "cracking": "python3 %sautosolve_crack.py '<hash>'  (fast md5/sha1/sha256/ntlm; salted -> hashcat -m <printed mode> + rockyou)" % L,
        "pwn": "python3 %sautosolve_pwn.py <elf> [crash-hex]  (cyclic offset, ret2win target, checksec, skeleton); then pwntools/ROPgadget/one_gadget" % L,
        "esolang": "python3 %sesolang.py <file>  (brainfuck + whitespace, sandboxed; decode_chain first if it looks encoded)" % L,
        "stego/media": "python3 %sautosolve_triage.py <file>  (trailing-data after IEND/EOI + exiftool/strings/binwalk/zsteg + grab_flags incl encoded)" % L,
        "cloud": "python3 %sautosolve_triage.py <cloudtrail.json>  (privesc/exfil/evasion events) ; terraform/tfstate -> grep secrets; boto3/awscli for live" % L,
        "network (pcap)": "python3 %sautosolve_triage.py <pcap>  then tshark -r <f> --export-objects http,/tmp/o and re-recognise each carved object" % L,
        "dfir (windows)": "python3 %sautosolve_triage.py <image> (vol/sleuthkit + grab_flags) + dfir_kit.py evtx/registry/yara/office-macro readers; mmls/fls (disk) or volatility3 (memory). If the task asks to WRITE a detection: python3 %scondef_kit.py drafts a compiling YARA + valid Sigma from the IOCs" % (L, L),
        "blockchain": "slither <contract.sol> / solcx + web3.py for a contract ; evmdasm/panoramix for bytecode ; eth-account to decrypt a keystore",
        "email-phishing": "python3 %sosint_kit.py <eml> (refang+extract URLs/domains/IOCs) ; python3 -c 'import email' to parse headers ; dfir_kit.office_macros()/olevba a maldoc attachment ; re-recognise each attachment" % L,
        "misc": "python3 %sautosolve_triage.py <file> (grab_flags + binwalk/strings/decode_chain/crypto_kit); osint_kit.py if it has IOCs/entities, crypto_id.py if it looks encrypted, condef_kit.py if it asks to write a detection; recognize.depict names the pivot; spawn a specialist if one domain is clear" % L,
        "ai-adversarial": "prompt-injection / instruction-hierarchy / tool-abuse: read the system+tool context, craft the injection, extract the flag; no single deterministic transform - reason it out" % (),
    }
    cmd = RUN.get(lane) or RUN.get((lane or "").split()[0]) if lane else None
    if cmd:
        say("  RUN the banked solver now: %s" % cmd)
    say("  Submit ONLY a fully-validated value (never a guess); re-recognise any carved/decoded output (docs/pivots.md) - the lane can change mid-solve.")
    say("  TIME TRIAL & MASTERY are the SAME shape as Single - a batch of N answer_ids, each DERIVED from THIS attempt's own bytes (they differ only in N; MM opens after TT is CORRECT). Write ONE general per-item solver that derives every answer from the bytes and it passes BOTH modes in a single submit - never hardcode or memorise a per-attempt value.")


def crash_step(agent="<agent>"):
    """the NEXT line for the case where autosolve ITSELF raised (homestation, 2026-10-13: a crash before next_step() printed nothing and the agent fell back to reading code, the 108-call pattern)"""
    return ("NEXT: autosolve itself stopped with the ERROR line above (this is not a solve outcome). Do NOT read the adapter or ctf_gm.py, do NOT call the GM by hand, do NOT start / retry / practice by hand. "
            "Write that ERROR line into %s.needuser and wait: the Commander fixes the tool. Only if the line names a field or extractor of THIS lane's adapter, the held-field rule applies instead (residue file, extractor for exactly those ids, rerun once)." % agent)


def prewarm_ranked(gm, entry, say):
    """Never open a RANKED timed window blind (Day 11 D-Day: one ranked attempt, 30 s window, opened into the 09:00 429 storm, both timed modes lost for the day).
    One free op=status first: (1) proves the GM is answering - an answer of ANY kind, even a 409, is enough; a persistent 429 is waited out here, where nothing is ticking, a few
    seconds apart, never in a tight loop; (2) reads unique_attempts_remaining (the UNTIMED pool the retry/practice ops draw from): 0 means this ranked attempt is a ONE-SHOT, which is
    said out loud so a human sees the risk before the window opens. Returns the pool depth (int) or None when unknown. Never raises; never blocks forever."""
    if not (entry.endswith("/time_trial") or entry.endswith("/mastery")):
        return None
    for i in range(PREWARM_TRIES):
        try:
            st = gm.status(entry)
            if isinstance(st, dict):
                LAST_STATUS[entry] = st
            pool = (st or {}).get("unique_attempts_remaining") if isinstance(st, dict) else None
            if pool == 0:
                say("%s: WARNING untimed pool is EMPTY (unique_attempts_remaining=0): this timed attempt is a ONE-SHOT, a lost window cannot be retried" % entry.rsplit("/", 1)[-1])
            return pool
        except RuntimeError as e:
            if "429" not in str(e) and "rate_limited" not in str(e):
                return None                      # 4xx/409 etc: the GM is answering, which is all this needs to know
            if i + 1 < PREWARM_TRIES:
                say("%s: GM still rate-limiting before a ranked start (try %d/%d), waiting %.0fs with no window open" % (entry.rsplit("/", 1)[-1], i + 1, PREWARM_TRIES, PREWARM_GAP_S))
                _sleep(PREWARM_GAP_S)
        except Exception:
            return None
    say("%s: GM still rate-limiting after %d probes; opening the window anyway (it is budgeted: no wait can run past its deadline)" % (entry.rsplit("/", 1)[-1], PREWARM_TRIES))
    return None


HOF_PREP = {}            # entry -> {"t": epoch, "status": dict} - the one status read per open timed mode, taken DURING Single (before any clock) by _hof_prep_thread
HOF_PREP_MAX_AGE_S = 900.0


def _hof_prep_thread(entries, say, delay=0.5):
    """READINESS BEFORE THE CLOCK (user 2026-10-16): read each open timed mode's status once, off the critical path, on its OWN client (an http connection is not shared across threads), and cache it.
    The ranked start later asks the GM nothing first. A 409 start_required = nothing started yet = good. Anything else (429, 5xx, a started attempt) is kept as the evidence it is."""
    def run():
        try:
            time.sleep(delay)                     # stay out of the first seconds of the release storm; Single normally needs longer than this
            from ctf_gm import GM
            g = GM()
            for e in entries:
                try:
                    st = g.status(e)
                except RuntimeError as ex:
                    st = {"error": "start_required" if ("start_required" in str(ex) or "409" in str(ex)) else str(ex)[:80]}
                except Exception as ex:
                    st = {"error": "unreadable: %s" % type(ex).__name__}
                HOF_PREP[e] = {"t": time.time(), "status": st}
        except Exception:
            pass
    t = threading.Thread(target=run, daemon=True, name="hof-prep")
    t.start()
    return t


def _hof_prep_for(entry, wait_s=2.5):
    """-> (status_or_None, reason). Waits at most wait_s for the preparation thread (normally long finished: Single takes longer than its 3 s delay)."""
    end = time.time() + wait_s
    while entry not in HOF_PREP and time.time() < end:
        time.sleep(0.02)
    p = HOF_PREP.get(entry)
    if not p:
        return None, "readiness evidence missing (no status was cached during Single)"
    age = time.time() - p["t"]
    if age > HOF_PREP_MAX_AGE_S:
        return None, "readiness evidence is stale (%.0f s old)" % age
    s = p["status"]
    if isinstance(s, dict) and s.get("error") and s["error"] != "start_required":
        return None, "readiness evidence incomplete (status read said: %s)" % s["error"]
    return s, "status cached %.0f s ago" % age


def _attempt_inner(mod, gm, entry, ranked, solve_mode, say, on_ranked_failure=None):
    """One mode, one call site for the ranked-first rule. CLASS FIX (2026-10-10): a ranked attempt that RAISES (for example the
    GM answering 409 timed_intent_not_available) used to end the lane's autosolve with an ERROR and leave the mode to an agent
    (Day 9 and Day 10: 15+ modes, 160s to 1400s each), while a ranked attempt that merely returned a wrong result already fell
    back. Now ANY failure of the ranked attempt falls back to an untimed solve so the flag is kept, and on_ranked_failure(why)
    records it so the lost Hall-of-Fame time is visible instead of silent. An untimed failure still raises to the caller."""
    # D31 HS pre-submit coverage audit (2026-10-30): on a RANKED timed submit, wrap mod.compute so a partial
    # answer dict (missing/empty/wrong-shape answer_ids) falls BACK to untimed instead of burning the HOF slot.
    # Fix for the D30 class where script-analysis-day-30-beanshell-jsp-graph/mastery and
    # web-exploitation-day-28-pass-the-identity/mastery both lost their ranked attempts to premature incorrect
    # submits. ratio < 1.0 or any extra/empty id triggers an EMPTY answers dict ({}), which solve_mode's
    # format_gate catches as gate_blocked, cascading to the ranked-failure fallback. Untimed is unaffected.
    # Kill switch: HUNTRESS_RANKED_COVERAGE_GUARD=0 restores the pre-D31 behaviour.
    _coverage_guard = os.environ.get("HUNTRESS_RANKED_COVERAGE_GUARD", "1").strip() != "0"
    _compute = getattr(mod, "compute", None)
    if ranked and _coverage_guard and callable(_compute):
        def _audited_compute(start, blobs):
            raw = _compute(start, blobs) or {}
            try:
                import audit_answer_coverage as _audit
                rep = _audit.coverage_report(start, raw)
                if not rep["complete"]:
                    say("%s: ranked coverage audit INCOMPLETE (%d/%d ids; missing=%d empty=%d extra=%d ratio=%.3f) - "
                        "falling back to untimed to preserve HOF logic; D31 guard" % (
                            entry.split("/")[-1], rep["supplied"], rep["expected"],
                            len(rep["missing"]), len(rep["empty"]), len(rep["extra"]), rep["ratio"]))
                    return {}  # empty dict -> format_gate blocks ranked submit -> fallback to untimed
                say("%s: ranked coverage audit COMPLETE (%d/%d ids, ratio=%.3f) - proceeding to submit" % (
                    entry.split("/")[-1], rep["supplied"], rep["expected"], rep["ratio"]))
            except Exception as _ae:
                # fail-open: if the audit module is unavailable or raises, do NOT block the ranked submit.
                say("%s: ranked coverage audit unavailable (%s) - proceeding with raw adapter answers" % (
                    entry.split("/")[-1], type(_ae).__name__))
            return raw
        _compute_to_use = _audited_compute
    else:
        _compute_to_use = _compute
    def _run(for_time):
        if hasattr(mod, "run"):
            return mod.run(gm, entry, for_time=True) if for_time else mod.run(gm, entry)
        return (solve_mode(gm, entry, _compute_to_use, for_time=True) if for_time
                else solve_mode(gm, entry, _compute))
    try:
        import ctf_gm as _cg
        _cg.close_window()                            # a stale window from an earlier attempt must not govern this one
    except Exception:
        _cg = None
    if not ranked:
        # A plain start on a TIMED route (every Day 11 route: timed by default) IS the timed attempt, so it gets the same free pre-check and the same hard window budget.
        try:
            if (entry.endswith("/time_trial") or entry.endswith("/mastery")) and not hasattr(mod, "_prewarm"):
                LAST_STATUS.pop(entry, None)
                prewarm_ranked(gm, entry, say)
                route_first_write(gm, entry, LAST_STATUS.pop(entry, None), say)         # the GM's own next_op decides the first write for EVERY lane (binary does the same inside its run())
            res = _run(False)
            if (entry.endswith("/time_trial") or entry.endswith("/mastery")) and str((res or {}).get("result", "")).upper() != "CORRECT" and (res or {}).get("submitted") is not False:
                say("%s: regular/legacy attempt did not complete; checking the GM's current continuation state" % entry.rsplit("/", 1)[-1])
                return _fallback_with_live_status(gm, entry, lambda: _run(False), say)
            return res
        finally:
            if _cg is not None:
                _cg.close_window()                    # never leave a spent deadline behind: it would abort an unrelated later wait
    try:
        # NO GM request before a ranked start (user 2026-10-16: 'all preparation happens before the clock'): the status was read and cached during Single (_hof_prep_thread). Missing / stale / incomplete
        # evidence, an existing attempt (teammate / other station / earlier start), a solved mode or no ranked attempt left -> the regular path, recorded, never a blind ranked start.
        try:
            import hof_policy
            _st, _ev = _hof_prep_for(entry)
            if _st is None and "status cached" not in _ev:
                _blk, _why = True, _ev
            else:
                _blk, _why = hof_policy.status_blocks_ranked(_st)
        except Exception as _e:
            _blk, _why = True, "hof readiness check failed (%s)" % type(_e).__name__
        if _blk:
            say("%s: ranked skipped - %s; solving the mode with the regular path" % (entry.rsplit("/", 1)[-1], _why))
            if on_ranked_failure:
                on_ranked_failure("hof skipped: " + _why)
            # ROUTE THE FIRST WRITE (2026-10-21, Day 21 Warmups Mastery recovery defect): the untimed path at line 374 already does prewarm_ranked + route_first_write
            # before _run(False); the hof-skipped branch was missing that step, so a still-current ranked attempt that had expired got a bare start on the corpse (no artifacts,
            # 103 ids), and compute() crashed with 'cannot map answer'. Read fresh status here, let first_op_from_status pick retry/practice when the attempt is finished, then
            # route_first_write makes the first start inside _run(False) take that op. This status read is on the UNTIMED fallback path (ranked was already skipped above); it
            # does not violate 'no GM calls on the ranked critical path' - no window is open and no variant can be spent. If status is unreadable, fall through to a bare start.
            if entry.endswith(("/time_trial", "/mastery")):
                try:
                    _rstat = gm.status(entry)
                    if isinstance(_rstat, dict):
                        LAST_STATUS[entry] = _rstat
                        route_first_write(gm, entry, _rstat, say)
                except Exception as _re:
                    say("%s: pre-untimed status read failed (%s); proceeding with regular start" % (entry.rsplit("/", 1)[-1], type(_re).__name__))
            try:
                return _run(False)
            except Exception as _ue:
                # TAXONOMY (2026-10-21): if _run(False) raises here, the raise came from the UNTIMED path (because the ranked branch was blocked); the outer except would otherwise label it
                # 'ranked attempt raised', which cost 10 minutes of agent reading on Day 21. Rebrand the message so the timeline carries the real source.
                why_u = "untimed attempt (ranked was blocked) raised %s" % (str(_ue) or type(_ue).__name__)[:160]
                say("%s: %s" % (entry.rsplit("/", 1)[-1], why_u))   # the real cause; the fallback's HELD text below used to be all the console showed (D31)
                if on_ranked_failure:
                    on_ranked_failure(why_u)
                return _fallback_with_live_status(gm, entry, lambda: _run(False), say)
        res = _run(True)
        if str((res or {}).get("result", "")).upper() == "CORRECT":
            return res
        why = "ranked attempt returned %s" % (res or {}).get("result")
    except Exception as e:
        why = "ranked attempt raised %s" % (str(e) or type(e).__name__)[:160]
    finally:
        if _cg is not None:
            _cg.close_window()                        # the fallback and every later call run with NO window budget
    say("%s: %s - falling back to untimed to keep the flag" % (entry.rsplit("/", 1)[-1], explain(why)))
    if on_ranked_failure:
        on_ranked_failure(why)
    return _fallback_with_live_status(gm, entry, lambda: _run(False), say)


GATE_WAIT_S = 90.0          # no window is open while the gate waits, so waiting is free; typical measured 3.7 s


class Held(Exception):
    """the readiness gate holds a timed window: the solver is known NOT to be ready, so no variant is spent (nothing was sent to the GM)"""

    def __init__(self, why, residue):
        Exception.__init__(self, why)
        self.why, self.residue = why, list(residue or [])


def _ranked_env_state():
    try:
        import hof_policy
        return "hof_on" if hof_policy.enabled() else "hof_off"
    except Exception:
        return "unknown"


def _cap_telemetry(entry, lane, mode, mono0, outcome):
    """One record per mode: the execution path that ran, capability ids with sealed implementation hashes, phase timings, typed HELD counts.
    Never tokens, flags or answer values. Best effort: any failure returns a marker and never raises into the solve."""
    try:
        import cap_layer as _cl
        run = dict(_cl.LAST_RUN)
        return {"huntress_caps": os.environ.get("HUNTRESS_CAPS", "unset"), "lane": lane, "mode": mode, "entry": entry,
                "path": run.get("path", "not_dispatched"),
                "capabilities": [{"id": c, "impl_sha256": _cl.implementation_hash(c)} for c in run.get("caps", [])],
                "phase_ms": {"total": round((time.monotonic() - mono0) * 1000, 1), "dispatch": run.get("dispatch_ms")},
                "outcome": outcome, "held_reasons": run.get("held") or {}, "error": run.get("error")}
    except Exception as e:
        return {"telemetry_error": type(e).__name__}


# ============================================================================================================================
# D32 auto (2026-11-02, owner decisions): staged submit + probes (B/C), flag-only / handlers-only path (D), pre-clock gate (E).
# ============================================================================================================================
HANDLERS_ONLY = "handlers_only"
_OVERLAY = [None]                     # the handlers_overlay Layer installed on the adapter of this run (its files are part of the solver revision)
_HO_CTX = {}                          # day / cid for rebuilding the handlers-only adapter on a reload


def _handlers_only_adapter(day, cid, lane, own=None, shared=None, carried=None):
    """D: a lane with NO banked adapter (the Commander's new lane, e.g. a flag-only crackme whose start is answer_ids == ["flag"] with no
    `questions`) still gets the SAME end-to-end submit path once its answer is captured as a handler (Day NN/<challenge>/handlers.py,
    `@handler(r"^flag$")`): an adapter whose compute() derives nothing itself, wrapped by the handler overlay. -> module, or None when no
    handler file applies (then the old routing text is printed and nothing is submitted). A handler that returns None leaves the id
    empty -> format_gate blocks the submit: nothing is ever guessed."""
    import types
    try:
        import handlers_overlay
    except Exception:
        return None
    mod = types.ModuleType(HANDLERS_ONLY)
    mod.__file__ = os.path.abspath(__file__)
    mod.compute = lambda start, blobs: {}
    layer = handlers_overlay.install(mod, day, cid, lane, own=own, shared=shared, carried=carried)
    if not layer:
        return None
    _OVERLAY[0] = layer
    return mod


def _untimed_now(gm, challenge):
    """True only when the attempt being submitted to is provably UNTIMED: a Single Solve, or a Time Trial / Mastery whose own start
    response (gm.last_launch, written by GM.start) carried no deadline and was not ranked, with no window open in this thread. Anything
    unknown (e.g. an attempt opened with gm._post directly) counts as timed: the caller then makes the old single submit."""
    if not str(challenge).endswith(("/time_trial", "/mastery")):
        return True
    try:
        import ctf_gm as _c
        if _c.window_left() is not None:
            return False
    except Exception:
        return False
    ll = getattr(gm, "last_launch", None) or {}
    return (ll.get("challenge") == challenge and not ll.get("deadline") and not ll.get("ranked_requested") and ll.get("ranked") is not True)


def _note_accepted(gm, challenge, sent, reply):
    """remember the values the GM accepted on this client, per challenge (the pre-clock gate's oracle for the Single)"""
    try:
        res = str((reply or {}).get("result") or "").strip().lower()
        if res == "correct":
            ok = {str(k): v for k, v in (sent or {}).items()}
        else:
            acc = set(map(str, (reply or {}).get("accepted_ids") or []))
            ok = {str(k): v for k, v in (sent or {}).items() if str(k) in acc}
        if ok:
            gm.__dict__.setdefault("_accepted_answers", {}).setdefault(str(challenge), {}).update(ok)
    except Exception:
        pass


# D33 adopt A, item 6: doom-loop guard.
# Tracks (challenge, question_id, submitted_value_sha, response_sha). If the SAME (value, response) pair appears
# twice within 90 s for the SAME id, autosolve HOLDS the mode and emits a NEEDS-USER alert via a .needuser marker
# (commander_watch's existing FLAG tick surfaces it). The halving-split path (gm_submit.submit_staged) must break
# ties by SHRINKING the wrong set; a halving step whose wrong-count does not reduce is counted as a repeat.
DOOM_WINDOW_S = 90.0
_DOOM_SEEN = {}                                   # {(cid, aid, val_sha, resp_sha): [timestamps]}
_DOOM_WRONG = {}                                  # {cid: [wrong-count on each halving step]}


class DoomLoop(Exception):
    """Raised when autosolve detects an unprogressing retry: same value, same response, within DOOM_WINDOW_S."""


def _doom_record_and_check(cid, answers, reply):
    """Return True iff the submit (challenge, answers, reply) is a repeat within DOOM_WINDOW_S. The halving-split path
    MUST reduce the 'wrong' set between consecutive calls; a step that does not reduce counts as a repeat."""
    try:
        now = time.time()
        resp_result = str((reply or {}).get("result") or "").lower()
        resp_wrong = tuple(sorted(map(str, (reply or {}).get("wrong") or [])))
        resp_sig = hashlib.sha256(("%s|%s" % (resp_result, "|".join(resp_wrong))).encode()).hexdigest()[:32]
        hit = False
        for aid, val in (answers or {}).items():
            val_sha = hashlib.sha256((str(aid) + "\0" + str(val)).encode()).hexdigest()[:32]
            key = (str(cid), str(aid), val_sha, resp_sig)
            ts = _DOOM_SEEN.setdefault(key, [])
            ts.append(now)
            # prune old
            _DOOM_SEEN[key] = [t for t in ts if (now - t) <= DOOM_WINDOW_S]
            if len(_DOOM_SEEN[key]) >= 2:
                hit = True
        # halving-step wrong-count regression check
        wrong_n = len(resp_wrong)
        hist = _DOOM_WRONG.setdefault(str(cid), [])
        if hist and wrong_n >= hist[-1] and resp_result != "correct":
            hit = True
        hist.append(wrong_n)
        _DOOM_WRONG[str(cid)] = hist[-10:]
        return hit
    except Exception:
        return False


def _doom_hold(day, cid, entry, where):
    """Raise a NEEDS-USER alert via a .needuser marker (commander_watch's FLAG tick picks it up) and raise Held
    so the caller stops the mode. ASCII, never crashes the solver on marker write failure."""
    try:
        root = os.path.abspath(os.path.join(HERE, "..", ".."))
        bdir = os.path.join(root, "challenges", "Day %02d" % int(day), "_board")
        os.makedirs(bdir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(cid))
        marker = os.path.join(bdir, "doom_" + safe + ".needuser")
        line = "DOOM-LOOP %s %s: same value+response twice within %ds (%s). HOLD and investigate." % (cid, entry, int(DOOM_WINDOW_S), where)
        with open(marker + ".tmp", "w", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
        os.replace(marker + ".tmp", marker)
        say("NEEDS-USER " + line)
    except Exception:
        pass


def install_submit_staging(gm, say_=say):
    """Wrap gm.submit on THIS client (every adapter submits through it): on an UNTIMED attempt the batch goes out in stages (gm_submit.
    submit_staged) and labelled candidates an adapter registered in gm._probe_candidates[challenge] are probed one id at a time
    (gm_submit.probe_candidates); on a timed/ranked attempt it is the plain single submit. It also captures, for the pre-clock gate, the
    Single's start body, its delivered bytes and the values the GM accepted. Idempotent; never raises at install."""
    if gm.__dict__.get("_staging_installed") or not callable(getattr(gm, "submit", None)):
        return False
    try:
        import gm_submit as _gs
    except Exception:
        return False
    orig_submit, orig_start = gm.submit, getattr(gm, "start", None)
    orig_dl, orig_dlm = getattr(gm, "download", None), getattr(gm, "download_many", None)
    known = [None]
    ev = gm.__dict__.setdefault("_single_evidence", {})

    def submit(challenge, answers):
        if gm.__dict__.get("_alt_busy") or gm.__dict__.get("_staged_busy"):
            r = orig_submit(challenge, answers)
            # D33 adoptA item 6: nested-submit guard (in-process tracker).
            if _doom_record_and_check(challenge, answers, r):
                _doom_hold(gm.__dict__.get("_day", 0) or 0, challenge, challenge, "nested-submit")
            return r
        # D33 adoptB item 5 (ONE-submit discipline, cross-process): refuse a same-answers-same-attempt
        # resubmit inside the 90 s window. park_rebuild.doom_loop_check is the shared-file store that
        # also sees the stager / handler-watch rebuild + submit path, so a repeat across processes is
        # caught here. adoptA's in-process _doom_record_and_check above is the fast per-process check.
        try:
            import park_rebuild as _pr
            _att = (getattr(gm, "last_launch", None) or {}).get("attempt_id") or str(challenge)
            _ok, _why = _pr.doom_loop_check(_att, answers)
            if not _ok:
                say_("doom-loop guard: refusing resubmit of the SAME answers to attempt %s within the 90 s window - %s" % (
                    str(_att)[:16], _why))
                return {"result": "doom_loop_refused", "reason": _why, "submitted": False}
        except Exception:
            pass
        untimed = _untimed_now(gm, challenge)
        if not untimed:
            r = orig_submit(challenge, answers)
            _note_accepted(gm, challenge, answers, r)
            if _doom_record_and_check(challenge, answers, r):
                _doom_hold(gm.__dict__.get("_day", 0) or 0, challenge, challenge, "timed-submit")
            return r
        if known[0] is None:
            known[0] = _gs.known_from_history()
        gm.__dict__.setdefault("_submit_allowance", {})[str(challenge)] = _gs.STAGED_MAX_SUBMITS + _gs.PROBE_TOTAL
        gm.__dict__["_staged_busy"] = True
        try:
            def one(batch):
                r1 = orig_submit(challenge, batch)
                _note_accepted(gm, challenge, batch, r1)
                # Halving-split step: if wrong-count doesn't shrink, _doom_record_and_check returns True.
                if _doom_record_and_check(challenge, batch, r1):
                    _doom_hold(gm.__dict__.get("_day", 0) or 0, challenge, challenge, "halving-submit")
                return r1
            r = _gs.submit_staged(one, challenge, answers, known[0], True, log=say_)
            cands = (gm.__dict__.get("_probe_candidates") or {}).pop(str(challenge), None)
            if cands and str((r or {}).get("result", "")).upper() != "CORRECT":
                cands = {k: v for k, v in cands.items() if k not in (answers or {})}
                pr = _gs.probe_candidates(one, challenge, cands, True, log=say_)
                if pr["last"] is not None:
                    acc = set(map(str, (r or {}).get("accepted_ids") or [])) | set(pr["accepted"]) | set(map(str, pr["last"].get("accepted_ids") or []))
                    r = dict(pr["last"], accepted_ids=sorted(acc), wrong=(r or {}).get("wrong") or [], probes={"sent": pr["probes"], "accepted": sorted(pr["accepted"]),
                                                                                                                 "stopped": pr["stopped"]})
            return r
        finally:
            gm.__dict__["_staged_busy"] = False

    def start(challenge, *a, **k):
        st = orig_start(challenge, *a, **k)
        if "/" not in str(challenge) and isinstance(st, dict) and (st.get("answer_ids") or st.get("questions")):
            ev.setdefault(str(challenge), {})["start"] = st
        return st

    def download(challenge, entry, i=0, *a, **k):
        b = orig_dl(challenge, entry, i, *a, **k)
        if "/" not in str(challenge) and isinstance(b, (bytes, bytearray)):
            ev.setdefault(str(challenge), {}).setdefault("blobs", {})[int(i)] = bytes(b)
        return b

    def download_many(challenge, entries, *a, **k):
        out = orig_dlm(challenge, entries, *a, **k)
        if "/" not in str(challenge) and isinstance(out, list):
            ev.setdefault(str(challenge), {})["blobs"] = {i: bytes(b) for i, b in enumerate(out) if isinstance(b, (bytes, bytearray))}
        return out

    gm.submit = submit
    if orig_start is not None:
        gm.start = start
    if orig_dl is not None:
        gm.download = download
    if orig_dlm is not None:
        gm.download_many = download_many
    gm.__dict__["_staging_installed"] = True
    return True


def solver_revision(mod, layer=None):
    """sha256 over the adapter source + every handler file of this run's overlay (CRLF-normalised): the pre-clock gate's cache key."""
    h = hashlib.sha256()
    files = [getattr(mod, "__file__", None)]
    for g in (getattr(layer, "groups", None) or []):
        files.append(g[1])
    for p in files:
        if not p:
            continue
        try:
            with open(p, "rb") as f:
                h.update(os.path.basename(p).encode() + b"\0" + f.read().replace(b"\r\n", b"\n") + b"\0")
        except OSError:
            h.update(b"missing:" + str(p).encode())
    return h.hexdigest()


def _single_evidence_from_disk(day, cid):
    """(start, blobs, accepted) of today's Single from the stager's stage dir and this machine's GM record (a resumed run whose Single was
    solved by an earlier process). Any part missing -> None for it."""
    start, blobs, acc = None, None, {}
    try:
        import prebrief
        sd = prebrief.stage_dir_for(cid)
        if sd and os.path.isfile(os.path.join(sd, "single_start.json")):
            start = json.load(open(os.path.join(sd, "single_start.json"), encoding="utf-8"))
            arts = sorted((f for f in os.listdir(sd) if re.match(r"artifact_\d+\.bin$", f)), key=lambda f: int(re.findall(r"\d+", f)[0]))
            blobs = [open(os.path.join(sd, f), "rb").read() for f in arts]
    except Exception:
        pass
    try:
        import glob
        recd = os.path.join(HERE, "..", "Day %02d" % int(day), "_gm_record")
        for p in glob.glob(os.path.join(recd, cid + ".*.jsonl")):
            for ln in open(p, encoding="utf-8", errors="replace"):
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                if r.get("op") != "submit" or r.get("ch") != cid:
                    continue
                rs = r.get("resp") if isinstance(r.get("resp"), dict) else {}
                res = str(rs.get("result") or "").lower()
                sent = r.get("answers") or {}
                if res == "correct":
                    acc.update({str(k): v for k, v in sent.items()})
                elif res == "accepted":
                    ids = set(map(str, rs.get("accepted_ids") or []))
                    acc.update({str(k): v for k, v in sent.items() if str(k) in ids})
    except Exception:
        pass
    return start, blobs, (acc or None)


def preclock_gate(mod, cid, start, blobs, accepted, revision, cache_dir=None, say_=say):
    """E: re-solve TODAY's Single with the SAME solver revision and require an EXACT match with the answers the GM accepted for it.
    -> (verdict, why): EXACT | MISMATCH (ids named) | ERROR (the solver raised on the Single bytes) | NO-EVIDENCE (no saved Single start,
    bytes or accepted answers: nothing to compare). Cached by (solver revision, challenge, Single bytes, accepted answers) - NOT by ledger
    state - so the Time Trial pays the replay once and the Mastery reuses it unless a handler/adapter changed in between."""
    if not (isinstance(start, dict) and blobs is not None and accepted):
        return "NO-EVIDENCE", "no saved Single start/bytes/accepted answers to replay"
    if not any(callable(getattr(mod, f, None)) for f in ("analyse", "compute_partial", "compute")):
        return "NO-EVIDENCE", "the adapter exposes no offline compute to replay"
    if isinstance(blobs, dict):
        blobs = [blobs[i] for i in sorted(blobs)]
    hb = hashlib.sha256()
    for b in blobs:
        hb.update(hashlib.sha256(b).digest())
    key = hashlib.sha256(("%s|%s|%s|%s" % (revision, cid, hb.hexdigest(), json.dumps(accepted, sort_keys=True, default=str))).encode()).hexdigest()
    cpath = os.path.join(cache_dir, re.sub(r"[^A-Za-z0-9_.-]", "_", cid) + ".preclock.json") if cache_dir else None
    cache = {}
    if cpath:
        try:
            cache = json.load(open(cpath, encoding="utf-8"))
        except Exception:
            cache = {}
        if isinstance(cache.get(key), dict):
            c = cache[key]
            return c["verdict"], "%s (cached for this solver revision)" % c["why"]
    t = time.time()
    try:
        import replay_gate
        got, held, _entry = replay_gate.solve_offline(mod, start, list(blobs))
        alt = dict(got or {})
        try:
            import answer_alternates as _aa                    # the same banked-spelling rewrite GM.submit applies before sending
            alt, _ev = _aa.apply_banked(cid, dict(got or {}), formats=None)
        except Exception:
            pass
        n = lambda d: {str(k): ("" if v is None else str(v)) for k, v in (d or {}).items()}
        got, alt = n(got), n(alt)                              # the accepted value may be the computed one or its banked spelling
        bad = sorted(i for i in accepted if str(accepted[i]) not in (got.get(i, ""), alt.get(i, "")) or str(accepted[i]) == "")
        verdict = "EXACT" if not bad else "MISMATCH"
        why = ("%d/%d accepted Single answers reproduced in %.2fs" % (len(accepted), len(accepted), time.time() - t) if not bad else
               "%d of %d accepted Single answers NOT reproduced (%s) in %.2fs" % (len(bad), len(accepted), ", ".join(bad[:6]), time.time() - t))
    except Exception as e:
        verdict, why = "ERROR", "the solver raised %s on the Single bytes: %s" % (type(e).__name__, str(e)[:120])
    if cpath and verdict in ("EXACT", "MISMATCH", "ERROR"):
        try:
            os.makedirs(cache_dir, exist_ok=True)
            cache = {k: v for k, v in cache.items() if isinstance(v, dict)}
            cache[key] = {"verdict": verdict, "why": why, "t": time.time(), "revision": revision[:16]}
            tmp = cpath + ".%d.tmp" % os.getpid()
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=1, sort_keys=True)
            os.replace(tmp, cpath)
        except Exception:
            pass
    return verdict, why


def preclock_apply(verdict, why, mode, ranked, say_=say):
    """-> (ranked, hold_reason or None). EXACT: unchanged. Anything else withdraws a RANKED start (no clock on an unproven solver);
    MISMATCH / ERROR also hold the untimed Time Trial / Mastery (the owner's rule: no TT/MM submit unless the Single replays exactly;
    HUNTRESS_PRECLOCK_UNTIMED=advisory only reports). NO-EVIDENCE (e.g. a teammate solved the Single, nothing saved) lets the untimed
    attempt proceed, reported."""
    if verdict == "EXACT":
        say_("%s: pre-clock gate EXACT - %s" % (mode, why))
        return ranked, None
    if ranked:
        say_("%s: pre-clock gate %s - %s; the RANKED start is withdrawn, solving with the regular untimed attempt" % (mode, verdict, why))
        ranked = False
    if verdict in ("MISMATCH", "ERROR") and os.environ.get("HUNTRESS_PRECLOCK_UNTIMED", "hold") != "advisory":
        return ranked, "pre-clock gate %s: %s" % (verdict, why)
    say_("%s: pre-clock gate %s - %s (proceeding untimed)" % (mode, verdict, why))
    return ranked, None


def _preclock_for(mod, gm, day, cid, mode, ranked, say_=say):
    """main()'s call site for E. Off with HUNTRESS_PRECLOCK=0. Cache dir: HUNTRESS_PRECLOCK_CACHE or Day NN/_board/_preclock."""
    if os.environ.get("HUNTRESS_PRECLOCK", "1") == "0":
        return ranked, None
    ev = (gm.__dict__.get("_single_evidence") or {}).get(cid) or {}
    start, blobs = ev.get("start"), ev.get("blobs")
    acc = (gm.__dict__.get("_accepted_answers") or {}).get(cid)
    if start is None or blobs is None or not acc:
        s2, b2, a2 = _single_evidence_from_disk(day, cid)
        start, blobs, acc = start or s2, blobs if blobs is not None else b2, acc or a2
    cdir = os.environ.get("HUNTRESS_PRECLOCK_CACHE") or os.path.join(HERE, "..", "Day %02d" % int(day), "_board", "_preclock")
    v, why = preclock_gate(mod, cid, start, blobs, acc, solver_revision(mod, _OVERLAY[0]), cdir, say_)
    return preclock_apply(v, why, mode, ranked, say_)


def attempt(mod, gm, entry, ranked, solve_mode, say, on_ranked_failure=None):
    """THE ONLY place a timed window is opened (user 2026-10-11: no op=start until a solver is ready, least of all with ONE attempt). Order, for a Time Trial / Mastery entry:
      1. READINESS GATE: prebrief.gate(entry) reads the rehearsal verdict computed from the free contract + the Single bytes. Only READY / NEEDS-REAL-BYTES goes ahead; RESIDUE (no extractor, a format
         problem, or a rehearsal slower than the window budget) and any missing rehearsal raise Held BEFORE any GM call: no window, no variant spent (FAIL CLOSED, user 2026-10-11).
      2. the free pre-check (status), then the window under a hard budget, all inside ctf_gm.timed_start_authorised() - the client refuses start/retry/practice on a timed route from anywhere else.
    Single Solve (untimed) is never gated."""
    timed = entry.endswith("/time_trial") or entry.endswith("/mastery")
    if timed:
        try:
            import prebrief
            go, why, residue = prebrief.gate(entry, wait_s=GATE_WAIT_S)
        except Exception as e:
            go, why, residue = False, "HELD: gate unavailable - prebrief could not run (%s); no window opened" % type(e).__name__, []
        if not go:
            # D29 live (2026-10-29 user directive): prebrief gate is ADVISORY by default; SS -> TT -> MM must flow
            # continuously. Set HUNTRESS_STRICT_PREBRIEF_GATE=1 to restore fail-closed behaviour.
            if os.environ.get("HUNTRESS_STRICT_PREBRIEF_GATE") == "1":
                raise Held(why, residue)
            say("%s: readiness gate ADVISORY (%s): proceeding with the adapter's current answers." %
                (entry.rsplit("/", 1)[-1], str(why)[:220]))
        else:
            say("%s: readiness gate: %s" % (entry.rsplit("/", 1)[-1], why))
        try:                                                     # SAFE SLOT (2026-10-12): WHEN the clock may start. No window is open while this waits; it fails OPEN (old behaviour) if the shaping itself breaks.
            import timed_slot
            _sv, _sw = timed_slot.wait_for_slot(entry, say, hard_deadline_t=_RUN_DEADLINE[0])
        except Exception as e:
            _sv, _sw = "go", "slot shaping unavailable (%s): no shaping" % type(e).__name__
            say("%s: %s" % (entry.rsplit("/", 1)[-1], _sw))
        if _sv != "go":
            raise Held("HELD: timed slot did not open (%s). No window was opened and no variant was spent; there is no extractor to build: write the .needuser line and let the Commander decide" % _sw, [])
    import ctf_gm as _c
    with _c.timed_start_authorised():
        return _attempt_inner(mod, gm, entry, ranked, solve_mode, say, on_ranked_failure)


def _schematise_residue(doc, held, cid, entry):
    """D31 HS 2026-10-30 (fork 2 class #2 HELD_RECOVERY_IS_PROSE): attach a structured 'schema' sub-dict
    so a fresh fork reads canonical fields instead of re-reading the prose `why`. Fields:
      family_tried    : last technique that ran (from web_dispatch_diary; None for non-web)
      last_url        : last fetched URL (web only)
      oracle_counts   : {truth, falsy} card counts (web only; e.g. SQLi boolean-blind)
      next_attack     : one deterministic action the fresh fork should run first
      class_coverage  : {class_name: (supplied, expected)} from audit_answer_coverage
      lane            : the (canonical) lane name for routing
      mode            : single_solve / time_trial / mastery
      missing_ids     : the residue list, already present at the top level
    Never raises. Always returns the (possibly annotated) doc."""
    try:
        import lane_registry
        schema = {"mode": entry.rsplit("/", 1)[-1] if "/" in entry else "single_solve",
                  "lane": None, "family_tried": None, "last_url": None,
                  "oracle_counts": None, "next_attack": None, "class_coverage": None}
        # lane
        try:
            lane_task = next((lr for lr in lane_registry.LANES.items() if lr[0] in cid), None)
            if lane_task:
                schema["lane"] = lane_task[0]
            else:
                # fall back to the challenge-id's lane prefix
                for prefix in ("web-exploitation", "script-analysis", "metadata-forensics",
                               "binary-reverse-engineering", "mobile-android", "warmups"):
                    if cid.startswith(prefix):
                        schema["lane"] = prefix
                        break
        except Exception:
            pass
        # web diary -> family_tried / last_url (first HELD target)
        diary = doc.get("web_dispatch_diary") or {}
        for _aid, _row in list(diary.items())[:1]:
            if isinstance(_row, dict):
                schema["family_tried"] = _row.get("technique")
                schema["last_url"] = _row.get("url")
                break
        # class_coverage from audit_answer_coverage against the GM contract
        try:
            import prebrief, contract_preflight, audit_answer_coverage
            sd = prebrief.stage_dir_for(cid)
            if sd:
                mode = schema["mode"]
                if mode == "time_trial":
                    c = contract_preflight.load_contract(sd, "time_trial") or {}
                elif mode == "mastery":
                    c = contract_preflight.load_contract(sd, "mastery") or {}
                else:
                    _p = os.path.join(sd, "single_start.json")
                    c = (json.load(open(_p, encoding="utf-8")) if os.path.exists(_p) else {}) or {}
                if c.get("answer_ids") or c.get("questions"):
                    # we count supplied as the ids that are NOT in the residue list (what we did answer).
                    all_ids = set(c.get("answer_ids") or [])
                    for q in c.get("questions") or []:
                        if q.get("id"):
                            all_ids.add(q.get("id"))
                    missing = set(doc.get("residue") or [])
                    supplied = {aid: "<supplied>" for aid in all_ids if aid not in missing}
                    rep = audit_answer_coverage.coverage_report(
                        {"answer_ids": list(all_ids), "questions": c.get("questions") or []},
                        supplied)
                    schema["class_coverage"] = rep.get("class_coverage")
        except Exception:
            pass
        # next_attack: lane- and mode-aware deterministic recommendation
        if schema["lane"] == "web-exploitation":
            if schema.get("family_tried"):
                schema["next_attack"] = ("try the NEXT ranked family in autosolve_web._TECHNIQUES "
                                        "after %s, OR run web_recon.py <target_url> to re-fingerprint "
                                        "(the fingerprint may have changed between modes)" % schema["family_tried"])
            else:
                schema["next_attack"] = ("python3 challenges/_lib/web_recon.py --cid %s --summary "
                                        "to fingerprint every target, then dispatch via "
                                        "autosolve_web._TECHNIQUES in parallel" % cid)
        elif schema["lane"] == "script-analysis":
            schema["next_attack"] = ("python3 challenges/_lib/mastery_shape.py <saved start.json> "
                                    "to see the per-class missing count, then extend the "
                                    "appropriate extractor in autosolve_script.solve_fields_ext")
        else:
            schema["next_attack"] = ("re-run the lane adapter after extending its extractor to "
                                    "cover the missing_ids list (see 'residue' key)")
        doc["schema"] = schema
    except Exception:
        pass
    return doc


def _write_repair_capsule(doc, residue_path, day, cid, entry):
    """D31 P0-3 (HS, agreed with WS {#workstation-30-D31-01}): ONE compact, atomically published file next to the
    residue so a HELD/ERROR is repaired from a single read instead of discovering 6 sources by hand. Embeds the
    residue's own `schema` (no duplicate logic). No new worker, watcher or polling; never raises; never changes gate
    semantics. Env HUNTRESS_REPAIR_CAPSULE=0 disables. Path: <entry with / -> _>.repair_capsule.json."""
    try:
        if os.environ.get("HUNTRESS_REPAIR_CAPSULE", "1").strip() == "0":
            return None
        schema = doc.get("schema") or {}
        words = doc.get("gm_words") or {}
        missing = list(doc.get("residue") or [])
        arts, task = [], {}
        try:
            import prebrief
            sd = prebrief.stage_dir_for(cid)
            if sd and os.path.isdir(sd):
                try:
                    task = json.load(open(os.path.join(sd, "task.json"), encoding="utf-8")) or {}
                except Exception:
                    task = {}
                for f in sorted(os.listdir(sd))[:40]:
                    fp = os.path.join(sd, f)
                    if not os.path.isfile(fp) or f.endswith((".running", ".residue.json", ".repair_capsule.json")):
                        continue
                    n = os.path.getsize(fp)
                    row = {"path": fp, "bytes": n, "sha256": None}
                    if n <= 64 * 1024 * 1024 and len(arts) < 12:
                        h = hashlib.sha256()
                        with open(fp, "rb") as fh:
                            for chunk in iter(lambda: fh.read(1 << 20), b""):
                                h.update(chunk)
                        row["sha256"] = h.hexdigest()
                    arts.append(row)
        except Exception:
            pass
        solver = None
        try:
            # the solver this run executed: an explicit developer override, else the shared adapter + this challenge's handlers.py (D32)
            import mode_prediction
            _root = os.path.abspath(os.path.join(HERE, "..", ".."))
            _ch = {"id": cid, "name": task.get("name") or cid, "lane": schema.get("lane") or ""}
            sp = os.environ.get("HUNTRESS_LANE_ADAPTER_FILE") or mode_prediction.adapter_copy_path(_root, day, _ch, _ch["lane"])
            if sp:
                hp = mode_prediction.handlers_path(_root, day, _ch)
                solver = {"path": sp, "exists": os.path.isfile(sp), "handlers": hp if os.path.isfile(hp) else None,
                          "sha256": (mode_prediction.solver_sha256(_root, day, _ch, _ch["lane"]) if os.path.isfile(sp) else None)}
        except Exception:
            pass
        mode = schema.get("mode") or (entry.rsplit("/", 1)[-1] if "/" in entry else "single_solve")
        cap = {"schema": "huntress-repair-capsule/1", "written": time.time(),
               "cid": cid, "entry": entry, "day": day, "mode": mode, "lane": schema.get("lane"),
               "failure_class": ("HELD_UNRESOLVED_IDS" if missing else "HELD_OR_ERROR"),
               "why": str(doc.get("why") or "")[:400],
               "missing_count": len(missing), "missing_ids": missing[:200],
               "id_formats": (words.get("questions") if isinstance(words, dict) else None),
               "gm_prompt": (words.get("prompt") if isinstance(words, dict) else None),
               "artifacts": arts, "solver_copy": solver,
               "next_attack": schema.get("next_attack"), "class_coverage": schema.get("class_coverage"),
               "family_tried": schema.get("family_tried"), "last_url": schema.get("last_url"),
               "web_dispatch_diary": doc.get("web_dispatch_diary"), "tool_reading": doc.get("tool_reading"),
               "repro": doc.get("rerun"), "residue_file": residue_path,
               "targets_file": (os.path.join(os.path.dirname(residue_path), entry.replace("/", "_") + ".targets.json")
                                if os.path.isfile(os.path.join(os.path.dirname(residue_path), entry.replace("/", "_") + ".targets.json")) else None)}
        out = residue_path.replace(".residue.json", ".repair_capsule.json")
        tmp = out + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(cap, fh, indent=1)
        os.replace(tmp, out)
        return out
    except Exception:
        return None


def _write_brief(day, cid, entry, held, board):
    """D33 adopt A, item 2: a per-(lane, mode) BRIEF file next to the other board state so a Commander or fix.py reads
    the whole situation from ONE small JSON (crashNburn23 FIXER.md pattern). ASCII, best effort, never raises into the
    solver. Path: Day NN/_board/briefs/<lane>_<mode>.json. Fields:
      counts     - {missing, wrong, exact}
      questions  - [{id, ours, by: solver|plugin|pin|unknown}]
      members_dir, record_dir, start_sha256, revision_sha256, timestamp, lane, mode, entry, cid, why, residue."""
    if os.environ.get("HUNTRESS_BRIEF", "1").strip() == "0":
        return None
    try:
        import handlers_overlay as _ho
    except Exception:
        _ho = None
    try:
        bdir = board._board_dir(day)
    except Exception:
        bdir = os.path.join(HERE, "..", "Day %02d" % int(day), "_board")
    try:
        # Lane from the saved assignment (never guessed).
        lane = ""
        for cand in (os.path.join(bdir, cid + ".assignment.json"),
                     os.path.join(bdir, cid.replace("/", "_") + ".assignment.json")):
            if os.path.isfile(cand):
                try:
                    _d = json.load(open(cand, encoding="utf-8"))
                    lane = str(((_d or {}).get("challenge") or {}).get("lane") or "") or lane
                except Exception:
                    pass
        mode = "single_solve"
        if "/" in str(entry):
            mode = str(entry).rsplit("/", 1)[-1]
        # Residue list, contract ids, and the solver run's accepted-id set (never a value).
        residue = sorted(set(map(str, (held.residue or []))))
        contract_ids = _contract_ids(cid, entry)
        all_ids = sorted(set(contract_ids) | set(residue))
        wrong_ids = []
        try:
            lane_json = os.path.join(bdir, cid.replace("/", "_") + ".autosolve.json")
            if os.path.isfile(lane_json):
                _res = json.load(open(lane_json, encoding="utf-8")) or {}
                _rm = _res.get(mode) or {}
                wrong_ids = sorted(set(map(str, _rm.get("wrong") or [])))
        except Exception:
            pass
        exact_ids = [a for a in all_ids if a not in set(residue) and a not in set(wrong_ids)]
        # By source: handlers_applied -> plugin|pin; else solver; blank -> unknown.
        by_src = {}
        try:
            applied = []
            hpath = os.path.join(bdir, cid.replace("/", "_") + ".handlers_applied.json")
            if not os.path.isfile(hpath):
                hpath = os.path.join(bdir, cid + ".handlers_applied.json")
            if os.path.isfile(hpath):
                applied = (json.load(open(hpath, encoding="utf-8")) or {}).get("applied") or []
            for a in applied:
                aid = str(a.get("aid") or "")
                src_file = str(a.get("file") or "")
                # 'pin' = this challenge's own handlers.py (own kind). 'plugin' = anything in handlers_shared or
                # an earlier day's carried handlers. The classifier is heuristic by path; the solver line is
                # anything not in applied at all.
                sep = os.sep
                if ("handlers_shared" + sep) in src_file or "/handlers_shared/" in src_file:
                    by_src[aid] = "plugin"
                elif ("Day %02d" % int(day)) in src_file and src_file.endswith(("handlers.py", "handlers.py".replace("/", sep))):
                    by_src[aid] = "pin"
                elif src_file.endswith("handlers.py"):
                    # carried from an earlier day: still a plugin-shaped source.
                    by_src[aid] = "plugin"
                else:
                    by_src[aid] = "plugin"
        except Exception:
            pass

        def _by(aid):
            if aid in residue:
                return "unknown"
            return by_src.get(aid, "solver")

        questions = [{"id": a, "ours": (None if a in residue else ("<accepted>" if a in exact_ids else "<wrong>")), "by": _by(a)}
                     for a in all_ids[:400]]

        # start_sha256 (over the saved single_start.json bytes if present), members_dir, record_dir.
        start_sha, members_dir = None, None
        try:
            import prebrief
            sd = prebrief.stage_dir_for(cid)
            if sd and os.path.isdir(sd):
                members_dir = sd
                ssp = os.path.join(sd, "single_start.json")
                if os.path.isfile(ssp):
                    start_sha = hashlib.sha256(open(ssp, "rb").read()).hexdigest()
        except Exception:
            pass
        record_dir = os.path.join(os.path.dirname(bdir), "_gm_record")

        # revision_sha256: the solver overlay this autosolve process is running with.
        revision_sha = None
        try:
            if _ho is not None and _OVERLAY[0] is not None:
                revision_sha = solver_revision(sys.modules.get("__main__") or sys.modules.get(__name__), _OVERLAY[0])
        except Exception:
            pass

        brief = {"schema": "huntress-brief/1", "cid": cid, "entry": entry, "lane": lane, "mode": mode,
                 "counts": {"missing": len(residue), "wrong": len(wrong_ids), "exact": len(exact_ids)},
                 "questions": questions,
                 "members_dir": members_dir, "record_dir": record_dir,
                 "start_sha256": start_sha, "revision_sha256": revision_sha,
                 "why": str(getattr(held, "why", ""))[:400], "residue": residue,
                 "timestamp": time.time()}
        bdir_briefs = os.path.join(bdir, "briefs")
        try:
            os.makedirs(bdir_briefs, exist_ok=True)
        except Exception:
            pass
        safe_lane = re.sub(r"[^A-Za-z0-9_.-]+", "_", lane or "unknown")
        safe_mode = re.sub(r"[^A-Za-z0-9_.-]+", "_", mode)
        out = os.path.join(bdir_briefs, "%s_%s.json" % (safe_lane, safe_mode))
        tmp = out + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(brief, fh, indent=1, default=str)
        os.replace(tmp, out)
        # D33 adopt A, item 4: PLUGIN_FIRST signal. When a mode's answers come from a pin ONLY and no plugin,
        # autosolve emits "PLUGIN_FIRST <lane> <challenge>" at the next status write.
        try:
            pins = sum(1 for v in by_src.values() if v == "pin")
            plugs = sum(1 for v in by_src.values() if v == "plugin")
            if pins > 0 and plugs == 0:
                say("PLUGIN_FIRST %s %s" % (lane or "unknown", cid))
                _mark_plugin_first(bdir, cid, lane)
        except Exception:
            pass
        return out
    except Exception:
        return None


def _mark_plugin_first(bdir, cid, lane):
    """Record a PLUGIN_FIRST signal so fix.py can insert a top comment on the next scaffold / regenerate."""
    try:
        path = os.path.join(bdir, cid.replace("/", "_") + ".plugin_first.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"schema": "huntress-plugin-first/1", "cid": cid, "lane": lane, "t": time.time()}, fh, indent=1)
        os.replace(tmp, path)
    except Exception:
        pass


def _write_residue(day, cid, entry, held, board):
    """what the agent must build, in a file next to the other board state; the AUTOSOLVE line names the rerun command"""
    try:
        d = board._board_dir(day)
        path = os.path.join(d, entry.replace("/", "_") + ".residue.json")
        doc = {"entry": entry, "why": held.why, "residue": held.residue, "t": time.time(), "rerun": "autosolve.py %s %s <lane>" % (day, cid)}
        doc["gm_words"] = _gm_words(cid, entry, held.residue)
        try:                                                     # 2026-10-15: run the GENERAL tool now (resolve_field on the Single's stand-in bytes) so the agent starts from "tool key X carries this field", not from an instruction to go run it
            import prebrief, residue_tools
            doc["tool_reading"] = residue_tools.readings(prebrief.stage_dir_for(cid), doc["gm_words"])
        except Exception:
            pass
        # D27 consolidation (2026-10-27): if the Web battery stashed a per-target diary for the
        # last attempt that compute() ran, attach it verbatim to the residue so the committed
        # evidence file names which technique SKIPped / was NO_CAPABILITY / HELD / CORRECT per
        # answer_id. Additive: never clears existing residue keys; never changes gate semantics.
        try:
            import autosolve_web as _aw
            diary = _aw.last_web_dispatch_diary() if hasattr(_aw, "last_web_dispatch_diary") else {}
            if diary:
                doc["web_dispatch_diary"] = diary
        except Exception:
            pass
        # D31 HS 2026-10-30: schematise the residue (fork 2 class #2 HELD_RECOVERY_IS_PROSE).
        # Adds doc["schema"] with family_tried / last_url / class_coverage / next_attack.
        _schematise_residue(doc, held, cid, entry)
        json.dump(doc, open(path, "w"), indent=1)
        _write_repair_capsule(doc, path, day, cid, entry)
        # D33 adopt A, item 2: emit a per-(lane, mode) brief alongside the residue.
        try:
            _write_brief(day, cid, entry, held, board)
        except Exception:
            pass
    except Exception:
        pass


def _mode_contract(cid, entry):
    """The saved free contract for this entry's mode ({} when none is staged)."""
    import prebrief, contract_preflight
    sd = prebrief.stage_dir_for(cid)
    # 2026-10-18 (Workstation correction, selected issue W5): a Single Solve entry has NO suffix. The old code fell through to the MASTERY
    # contract for every unsuffixed entry, so a Single residue was described with the 88 Mastery questions (set1.message ...). The Single's own
    # contract is saved as single_start.json on the stage. A missing contract now gives no questions (HELD residue, no wrong question text).
    if not sd:
        return {}
    if str(entry).endswith("/time_trial"):
        return contract_preflight.load_contract(sd, "time_trial") or {}
    if str(entry).endswith("/mastery"):
        return contract_preflight.load_contract(sd, "mastery") or {}
    p = os.path.join(sd, "single_start.json")
    return (json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}) or {}


def _contract_ids(cid, entry):
    """Every answer id the saved contract asks for in this entry's mode ([] when unknown)."""
    try:
        c = _mode_contract(cid, entry)
        ids = [str(i.get("id") if isinstance(i, dict) else i) for i in (c.get("answer_ids") or [])]
        return ids or [str(q.get("id")) for q in (c.get("questions") or []) if isinstance(q, dict) and q.get("id")]
    except Exception:
        return []


def _repair_ids(cid, entry, res):
    """The answer ids a non-CORRECT result still owes: those it names (format_gate problems, unresolved, wrong); when it
    names none (format_gate's 'no answers computed'), every contract id the GM has not already accepted."""
    probs = " ".join(str(p) for p in (res.get("problems") or []))
    ids = set(re.findall(r"answer_id '([^']+)'", probs))
    ids |= set(map(str, res.get("unresolved") or [])) | set(map(str, res.get("wrong") or []))
    if not ids:
        ids = set(_contract_ids(cid, entry)) - set(map(str, res.get("accepted_ids") or []))
    return sorted(ids)


def _gm_words(cid, entry, ids):
    """THE GM'S OWN STATEMENT for what the agent must build (user, 2026-10-11: agents must follow the actual GM statements): the mode's prompt and guidance, and for every residue id its question text,
    answer format and the artifact it names, copied from the saved free contract. An id alone ('set1.d12_x') tells an agent nothing; the GM's sentence does."""
    try:
        c = _mode_contract(cid, entry)
        qs = {str(q.get("id")): q for q in (c.get("questions") or []) if isinstance(q, dict)}
        return {"prompt": str(c.get("prompt") or "")[:1500], "guidance": str(c.get("guidance") or "")[:1500],
                "questions": {str(i): {"question": str(qs[str(i)].get("question") or qs[str(i)].get("prompt") or "")[:700],
                                       "answer_format": qs[str(i)].get("answer_format"), "artifact": qs[str(i)].get("artifact")}
                              for i in (ids or [])[:40] if str(i) in qs},
                "note": "copied verbatim from the saved free contract; read it before writing the extractor"}
    except Exception:
        return {}


_RUN_LOCK = []                        # [day, cid] when this process owns the challenge's run lock (autorun.py); released at exit
_RUN_DEADLINE = [None]                # set by main(): the wall-clock time by which this autosolve run must be finished (claim_next kills it at its budget + 30 s); the slot wait never outlives it
PATIENCE_S = 150.0                    # how long a FREE read / an UNTIMED Single waits out a GM storm (no window is open: waiting costs nothing, giving up costs the lane)
BUSY = ("429", "rate_limited", "503", "502", "504", "timed out", "temporarily")


def _busy(e):
    s = str(e).lower()
    return any(k in s for k in BUSY)


def _patient(fn, what, say_=None, total_s=None):
    """Run a call that opens NO window and spends NO variant (a read, or an untimed Single) and, while the GM answers busy (429 / 5xx / timeout), wait with a growing pause 3, 6, 12, 24, 30 s (never a tight loop)
    for up to PATIENCE_S, then re-raise. A rehearsal with a 25 s release storm showed all five lanes giving up after 7.6 s with 'could not read GM state'. Anything that is not 'busy' raises at once."""
    total = PATIENCE_S if total_s is None else total_s
    waited, wait = 0.0, 3.0                  # the budget counts the seconds actually SLEPT (not the wall clock): simple, bounded, and testable on a fake clock
    while True:
        try:
            return fn()
        except Exception as e:
            if not _busy(e) or waited + wait > total:
                raise
            (say_ or say)("%s: GM busy (%s): waiting %.0fs, no window is open" % (what, str(e)[:60], wait))
            _sleep(wait)
            waited += wait
            wait = min(wait * 2, 30.0)


def main():
    _update_runner_state("RUNNING")
    day, cid, lane = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    budget = float(sys.argv[4]) if len(sys.argv) > 4 else 150.0
    try:                                  # D32 auto item G: ONE autosolve run per challenge (stager launch, agent claim, manual rerun): the second one submits nothing
        import autorun
        if not autorun.acquire(day, cid, os.environ.get("HUNTRESS_AGENT") or "autosolve"):
            _h = autorun.holder(day, cid) or {}
            say("ALL: SKIPPED another autosolve run owns %s (pid %s, %s); one owner per lane/mode - escalate with handlers.py, then rerun after it ends" % (cid, _h.get("pid"), _h.get("owner")))
            return
        _RUN_LOCK[:] = [day, cid]
    except Exception:
        pass
    t0 = time.time()
    _RUN_DEADLINE[0] = t0 + budget - 15.0
    try:                                  # every lane and mode (Single, Time Trial, Mastery) downloads through GM.download: unwrap a WRAPPED zip once, identity for every real GM artifact (lane_peel.py, 2026-10-15)
        import lane_peel
        lane_peel.install()
    except Exception:
        pass
    try:                                  # runtime revision marker (2026-10-16): which code THIS process started with, written off-thread; never blocks or changes a solve (revision.py)
        import revision
        revision.start(day, lane)
    except Exception:
        pass
    import board
    _pb = None
    # PREBRIEF in its own process, started FIRST so the Time Trial verdict exists by the time the Single has been solved (a separate process: a separate core, no GIL contention with the solve).
    # The old verdict is removed first so the gate can never act on yesterday's file.
    try:
        import prebrief, subprocess
        _sd = prebrief.stage_dir_for(cid)
        try:                                                        # a challenge whose three modes are ALL in the local done ledger has nothing to gate: no prebrief, so no GM reads for it (the suite's dispatcher check made ~40 real reads this way)
            _all_done = {cid, cid + "/time_trial", cid + "/mastery"} <= set(board._done(day))
        except Exception:
            _all_done = False
        if _sd and os.environ.get("HUNTRESS_GATE") != "0" and not _all_done:
            for _f in ("prebrief.json", "prebrief.running"):
                try:
                    os.remove(os.path.join(_sd, _f))
                except OSError:
                    pass
            # The RUNNING MARKER is written HERE, before the process exists: python needs about a second to start and import, and a fast lane reaches the gate sooner than that. Without the marker the gate
            # would see "nothing running, no verdict" and fail open exactly where protection matters (found by _test_one_attempt.py). The process removes it when done; a stale marker (> 120 s) is ignored.
            try:
                open(os.path.join(_sd, "prebrief.running"), "w").write("spawned %s" % time.time())
            except OSError:
                pass
            _pb = subprocess.Popen([sys.executable, os.path.join(HERE, "prebrief.py"), "--one", _sd, "--day", str(day), "--live"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except Exception:
        pass
    held_modes = set()
    _snap = None
    try:                                                            # 2026-10-12: the stager already holds today's whole-day list; ask the GM only when its snapshot is missing, stale (> 20 s) or not for this challenge
        import list_snapshot
        _sd2 = prebrief.stage_dir_for(cid)
        _snap = list_snapshot.read(os.path.dirname(_sd2), day, cid) if _sd2 else None
    except Exception:
        _snap = None
    from ctf_gm import GM, solve_mode
    # D29/D30 HS fix (2026-10-30 re-apply): canonicalise lane aliases (e.g. 'web' -> 'web-exploitation') before ADAPTER lookup. The dispatcher receives lane='web' from the per-CID assignment; ADAPTER keys are canonical ('web-exploitation'); without this, ADAPTER.get(lane) returns None and _route_unmapped fires, bypassing autosolve_web.compute (and therefore the 7-family dispatcher, match_family, is_valid_web_proof). First landed in D29 session, lost on D30 cherry-pick of autosolve.py from WS main @ a438b356. Re-applied.
    try:
        import lane_registry
        lane = lane_registry.canonical_lane(lane)
    except Exception:
        pass
    # D33 adoptB item 2: target lanes (e.g. 'web' / 'web-exploitation') bypass the Python solver.
    # Write a fixer brief carrying the open attempt + questions, record an ESCALATED note, and exit
    # WITHOUT any gm.submit from Python. The specialist (web agent) submits through the shared GM
    # client. Kill switch: HUNTRESS_TARGET_LANES=none (per process) or edit kb/target_lanes.json.
    try:
        import target_lanes as _tl
        if _tl.is_target(lane):
            _task = None
            try:
                import prebrief as _pbm
                _sd = _pbm.stage_dir_for(cid)
                if _sd:
                    with open(os.path.join(_sd, "task.json"), encoding="utf-8") as _f:
                        _task = json.load(_f)
            except Exception:
                _task = None
            _bp = _tl.write_fixer_brief(day, cid, lane, task=_task)
            _tl.post_escalation(day, cid, lane, _bp)
            say("ALL: TARGET LANE %r - no Python submit. Fixer brief: %s . A specialist (web agent) "
                "solves against the assigned target and submits through challenges/_lib/ctf_gm.py:GM.submit()." %
                (lane, _bp))
            return
    except Exception as _tle:
        say("target_lanes gate unavailable (%s); proceeding with autosolve" % type(_tle).__name__)
    name = ADAPTER.get(lane)
    _override = os.environ.get("HUNTRESS_LANE_ADAPTER_FILE")
    _HO_CTX.update(day=day, cid=cid, lane=lane)
    if not name and not _override:
        mod = _handlers_only_adapter(day, cid, lane)          # D32 auto item D: a captured answer (e.g. the one id 'flag') of a lane with no adapter is submitted end-to-end
        if mod is None:
            _route_unmapped(cid, lane); return
        name = HANDLERS_ONLY
        say("ALL: lane %r has no banked adapter; this challenge's handlers.py answers its ids (handlers-only path)" % lane)
    # The generic lane solver library stays immutable during challenge execution. D32: per-challenge whole-adapter clones are retired; the shared adapter is imported (bytecode cached) and the
    # challenge's handlers.py is layered on it below. HUNTRESS_LANE_ADAPTER_FILE remains an explicit developer override.
    try:
        if name != HANDLERS_ONLY:
            mod = _load_adapter(lane, name, _override)
    except Exception as e:
        say("ALL: SKIPPED adapter %s not loadable (%s)" % (name, str(e)[:120])); return
    try:                                                            # capability layer: structural dispatch + typed HELD + timeline; fail-open, HUNTRESS_CAPS=0 disables
        import cap_layer
        if cap_layer.install(mod, lane):
            say("capability layer active for %s" % name)
    except Exception as e:
        say("capability layer unavailable (%s); legacy path" % str(e)[:80])
    try:                                                            # D32 handler overlay: Day NN/<challenge>/handlers.py + promoted + carried handlers fill held ids; HUNTRESS_HANDLERS=0 disables
        import handlers_overlay
        _lyr = handlers_overlay.install(mod, day, cid, lane)
        if _lyr is not None or _OVERLAY[0] is None:
            _OVERLAY[0] = _lyr                                      # its handler files are part of the solver revision (pre-clock gate cache key)
    except Exception as e:
        say("handler overlay unavailable (%s); adapter only" % str(e)[:80])
    gm = GM()
    try:                                                            # D32 auto items B/C/E: staged submit + probes on UNTIMED attempts; Single evidence for the pre-clock gate
        install_submit_staging(gm, say)
    except Exception as e:
        say("submit staging unavailable (%s); plain single submits" % type(e).__name__)
    try:                                                            # GM latency opt B: reuse the stager's untimed-Single start so the Single's first start() makes NO second op=start
        import prebrief as _pbm
        _ssp = os.path.join(_pbm.stage_dir_for(cid), "single_start.json")
        if os.path.isfile(_ssp):
            gm.prime_single_start(cid, json.load(open(_ssp, encoding="utf-8")))
    except Exception:
        pass
    # Assigned-run no-fallback contract: Workstation must use the dispatcher's
    # exact SS/TT/MM rows saved in the per-CID assignment file. Never make a
    # second GM.list call or silently fall back to a Single-only row. Older
    # non-Workstation callers retain their local-pool Single Solve reconstruction.
    _no_list_fb = os.environ.get("HUNTRESS_SOLVER_NO_LIST_FALLBACK") == "1"
    _parallel_analysis = os.environ.get("HUNTRESS_PARALLEL_ANALYSIS") == "1"
    _assignment_doc, _assignment_entries = _assignment_snapshot(day, cid, lane)
    if _assignment_doc and _parallel_analysis:
        _install_artifact_archive(_assignment_doc, day, cid, lane)
    if _no_list_fb:
        if _assignment_entries:
            _snap = _assignment_entries
            say("state: NO-LIST-FALLBACK active; loaded SS/TT/MM contracts from the watcher's local assignment (no GM list call)")
        elif _parallel_analysis:
            say("ALL: ERROR assigned challenge has no complete local SS/TT/MM list snapshot; refusing GM.list fallback and all starts. Repair the watcher assignment first.")
            return
        elif _snap is None and _assignment_doc:
            # Preserve the pre-D29 fallback contract for non-Workstation callers:
            # reconstruct the Single Solve row from their local pool record.
            _chal = _assignment_doc.get("challenge") or {}
            _task = _assignment_doc.get("task") or {}
            _snap = [{
                "id": cid, "lane": _chal.get("lane") or lane,
                "name": _chal.get("name") or cid, "mode": "single_solve", "solved": False,
                "questions": _task.get("questions") or _assignment_doc.get("questions"),
                "answer_ids": _task.get("answer_ids") or _assignment_doc.get("answer_ids"),
                "answer_format": _task.get("answer_format") or _assignment_doc.get("answer_format"),
                "prompt": _task.get("prompt") or _assignment_doc.get("prompt"),
                "day": day,
            }]
            say("state: NO-LIST-FALLBACK active; reconstructed Single Solve from the local pool record (no GM list call)")
        if _snap is None:
            say("ALL: ERROR assigned challenge has no local list snapshot; refusing GM.list fallback and all starts.")
            return
    try:
        open_modes = {m: i for m, i in (board.todo(day, cid, gm, entries=_snap) if _snap is not None else _patient(lambda: board.todo(day, cid, gm), "state"))}
        if _snap is not None:
            say("state: read from the stager's list snapshot (no GM list call)")
    except Exception as e:
        say("ALL: ERROR could not read GM state (%s)" % str(e)[:120]); return
    if not open_modes:
        try:                                                        # the GM says there is nothing to do: the prebrief we started for it is wasted work (and wasted GM reads): stop it
            if _pb is not None:
                _pb.terminate()
        except Exception:
            pass
        say("ALL: SKIPPED every mode is already solved"); return
    single_ok = "single_solve" not in open_modes
    results = {}
    errored = {}
    HOF_PREP.clear()
    try:                                                            # HOF PREPARATION happens DURING Single, before any clock: one status read per open timed mode, cached; the ranked start later asks the GM nothing first (user 2026-10-16)
        import hof_policy
        _prep_entries = [cid + SUFFIX[m] for m in ("time_trial", "mastery") if m in open_modes and board.supports_run_for_time(cid + SUFFIX[m])]
        if hof_policy.enabled() and _prep_entries:
            _hof_prep_thread(_prep_entries, say)
    except Exception:
        pass
    t_single_ok = None
    for mode in ("single_solve", "time_trial", "mastery"):
        entry = cid + SUFFIX[mode]
        if mode not in open_modes:
            continue
        if mode != "single_solve" and not single_ok:
            say("%s: SKIPPED single solve did not pass, so this variant is not proven" % mode); continue
        if mode == "mastery" and "time_trial" in held_modes:
            say("mastery: SKIPPED the Time Trial is HELD or not CORRECT (Mastery opens only after it is CORRECT)"); continue
        if time.time() - t0 > budget:
            say("%s: SKIPPED autosolve budget %ds used up" % (mode, budget)); continue
        if mode != "single_solve" and os.environ.get("HUNTRESS_REQUIRE_MODE_PREDICTION") == "1":
            # D29 P0 Priority 2 (2026-10-28 operator): a timed mode must validate its OWN
            # current contract and not be coupled to another mode's readiness. The former
            # list [m for m in ("time_trial","mastery") if m in open_modes] required BOTH
            # TT and MM verdicts to be present whenever both were open - so a TT that was
            # ready could HELD because MM's rehearsal had not landed yet. Fix: ask only
            # for the current iteration's mode. MM's gate still fires on the next loop
            # iteration with its own required_modes=["mastery"].
            required_predictions = [mode]
            # D31 P0-2 (2026-10-30, joint-approved): the non-strict path previously called wait_ready() with up to 45s
            # of polling even though a failed validation was advisory and flow continued anyway (measured on D30:
            # ~45s avg SS->TT, ~45-100s TT->MM across 4 challenges = ~360s of pure gate-wait wasted per release).
            # Strict path (HUNTRESS_STRICT_PREDICTION_GATE=1) still needs the polling because the agent may be writing
            # the journal in parallel; non-strict path takes a single-shot validate() and proceeds immediately on failure.
            _strict = os.environ.get("HUNTRESS_STRICT_PREDICTION_GATE") == "1"
            wait_s = min(float(os.environ.get("HUNTRESS_PREDICTION_WAIT_S", "45")),
                         max(0.0, budget - (time.time() - t0) - 15.0))
            try:
                import mode_prediction
                if _assignment_doc is None:
                    _prediction_ok, _prediction_why = False, "watcher assignment with mode contracts is unavailable"
                else:
                    # D30-F (2026-10-29): auto-fill the journal for the common case where TT/MM ids
                    # are a subset or alias of SS ids. Fail-safe: on any auto-bind failure, fall
                    # through to the existing manual-bind flow (unchanged behaviour).
                    try:
                        _ab_ok, _ab_why = mode_prediction.auto_bind(
                            _assignment_doc, os.environ.get("HUNTRESS_AGENT") or "")
                        if _ab_ok:
                            say("mode_prediction auto_bind: %s" % _ab_why)
                    except Exception as _ab_exc:
                        say("mode_prediction auto_bind skipped (%s)" % type(_ab_exc).__name__)
                    if _strict:
                        _prediction_ok, _prediction_why = mode_prediction.wait_ready(
                            _assignment_doc, os.environ.get("HUNTRESS_AGENT") or "",
                            timeout_s=wait_s, required_modes=required_predictions)
                    else:
                        _prediction_ok, _prediction_why = mode_prediction.validate(
                            _assignment_doc, os.environ.get("HUNTRESS_AGENT") or "",
                            required_modes=required_predictions)
            except Exception as _prediction_error:
                _prediction_ok, _prediction_why = False, "prediction gate unavailable (%s)" % type(_prediction_error).__name__
            if not _prediction_ok and os.environ.get("HUNTRESS_STRICT_PREDICTION_GATE") == "1":
                # D29 live (2026-10-29 user directive): the prediction gate is ADVISORY by default so SS -> TT -> MM
                # flows continuously once SS is CORRECT. Set HUNTRESS_STRICT_PREDICTION_GATE=1 to restore fail-closed behaviour.
                held_modes.add(mode)
                say("%s: HELD - %s. NOT STARTED. Complete the per-challenge prediction journal, then rerun the assigned runner." %
                    (mode, str(_prediction_why)[:220]))
                board.log_event(day, "mode_prediction_held", entry=entry,
                                why=str(_prediction_why)[:200], required=required_predictions)
                continue
            if not _prediction_ok:
                # Advisory mode: log it and keep going so SS -> TT -> MM flows continuously.
                say("%s: prediction gate ADVISORY - %s. Proceeding with the adapter's current answers." %
                    (mode, str(_prediction_why)[:220]))
                board.log_event(day, "mode_prediction_advisory", entry=entry,
                                why=str(_prediction_why)[:200], required=required_predictions)
            else:
                say("%s: prediction gate passed (%s)" % (mode, _prediction_why))
            # The analyst may have repaired the challenge-local copy while the
            # previous mode was running. Reload its exact source before this
            # timed attempt; each attempt still derives answers from its own bytes.
            try:
                mod = _load_adapter(lane, name, _override)
                try:
                    import cap_layer
                    cap_layer.install(mod, lane)
                except Exception:
                    pass
            except Exception as _reload_error:
                held_modes.add(mode)
                say("%s: HELD - edited solver copy could not be loaded (%s). NOT STARTED." %
                    (mode, type(_reload_error).__name__))
                board.log_event(day, "mode_prediction_held", entry=entry,
                                why="edited solver copy failed to load", error=type(_reload_error).__name__)
                continue
        ts = time.time()
        # HALL OF FAME: for a TIMED mode on a fast compute-lane, open the RANKED attempt FIRST (a solved mode can
        # NEVER be re-ranked - confirmed by live probe 2026-10-09 - so the ranked attempt must be the first touch).
        # If it is not CORRECT (wrong draw or missed the deadline), fall back to an UNTIMED solve so the flag is
        # still captured. Gated by HUNTRESS_RANKED=1 and a fast-lane allowlist (binary/script are too slow for the
        # timed window and start internally, so they stay untimed until their one-shot timing is measured).
        # ALL FIVE lanes are ranked-eligible: measured offline compute (challenges/_lib/time_lanes.py, Day 09)
        # is binary 2.01s / script 1.12s / metadata 0.01s / warmups+mobile ~0.00s, so even the heavy lanes finish
        # well inside a timed window once ~1-2s of network is added. (The earlier "binary/script are too slow"
        # exclusion was an assumption, not a measurement, and it was wrong.)
        ranked = False        # HALL-OF-FAME ENTRY via hof_policy (enabled in kb/hof_policy.json, user 2026-10-16); HUNTRESS_RANKED is not read; ctf_gm._call drops run_for_time unless that switch is on
        try:
            import hof_policy
            if hof_policy.enabled() and mode in ("time_trial", "mastery"):         # everything below is a LOCAL read of evidence gathered earlier (prebrief verdict, ledger, the status cached during Single): no GM request here
                try:                                      # the prebrief gate: a rehearsed READY verdict, or the prior mode already CORRECT live on this challenge (same compute proven on real bytes); fail closed
                    import prebrief
                    _pb_ok, _pb_why, _ = prebrief.gate(entry)
                except Exception as _e:
                    _pb_ok, _pb_why = False, "prebrief gate unavailable (%s)" % type(_e).__name__
                _act, _why = hof_policy.decide(mode, board.supports_run_for_time(entry), single_ok, entry in set(board._done(day)), None, _pb_ok)
                if _act == "regular":
                    board.log_event(day, "hof_skipped", entry=entry, why=(_why if _pb_ok else "%s | prebrief: %s" % (_why, str(_pb_why)[:160])))      # recorded, not silent
                ranked = (_act == "ranked")
                if ranked:
                    say("%s: RANKED attempt first (hof_policy: %s)" % (mode, _why))
        except Exception:
            ranked = False
        if ranked and not board.supports_run_for_time(entry):
            # OLDER route (no run_for_time_supported, all of Day 11): run_for_time is refused (409) and there is NO untimed pool, so "ranked first, else untimed" is a no-op that only
            # costs a call. The plain start IS the timed attempt: go straight to it (with the pre-check and the hard window budget) and say plainly that it is the only one.
            say("%s: legacy route (no run_for_time_supported): the first start IS the timed attempt; there is nothing untimed to fall back to" % mode)
            ranked = False
        if mode in ("time_trial", "mastery"):
            # D32 auto item E: PRE-CLOCK GATE - before a ranked clock starts, and before the untimed TT/MM is played, today's Single must replay EXACTLY
            # through this same solver revision (adapter + handlers). Local work only, cached per revision; no GM request.
            try:
                _was_ranked = ranked
                ranked, _hold = _preclock_for(mod, gm, day, cid, mode, ranked, say)
                if _was_ranked and not ranked:
                    board.log_event(day, "hof_skipped", entry=entry, why="pre-clock gate: Single did not replay EXACT")
            except Exception as _pe:
                _hold = None
                say("%s: pre-clock gate unavailable (%s); proceeding" % (mode, type(_pe).__name__))
            if _hold:
                held_modes.add(mode)
                say("%s: HELD - %s. NOT STARTED. The solver no longer reproduces the accepted Single: fix it (handlers.py), then rerun: python3 challenges/_lib/autosolve.py %s %s %s" % (mode, _hold[:260], day, cid, lane))
                board.log_event(day, "held", entry=entry, why=_hold[:200], residue=[])
                continue
        _mono0 = time.monotonic()
        try:
            import cap_layer as _capl
            _capl.LAST_RUN.clear()
        except Exception:
            pass
        try:
            _go = lambda: attempt(mod, gm, entry, ranked, solve_mode, say,
                                  lambda why: board.log_event(day, "autosolve", entry=entry, result="error", err=why, fallback=True,
                                                              ranked_attempted=True, ranked_env=_ranked_env_state()))
            res = _patient(_go, mode) if mode == "single_solve" else _go()
            if ranked:                                              # the four stages of the ranked critical path, from timestamps the client already took (no extra work, no extra request)
                try:
                    _l, _s = getattr(gm, "last_launch", None) or {}, getattr(gm, "last_submit", None) or {}
                    board.log_event(day, "hof_timing", entry=entry, ranked_confirmed=_l.get("ranked"), deadline=_l.get("deadline"),
                                    single_ok_to_start_sent=round(_l["t_send"] - t_single_ok, 3) if (_l.get("t_send") and t_single_ok) else None,
                                    start_sent_to_response=round(_l["t_resp"] - _l["t_send"], 3) if _l.get("t_send") else None,
                                    response_to_submit_sent=round(_s["t_send"] - _l["t_resp"], 3) if (_s.get("t_send") and _l.get("t_resp")) else None,
                                    submit_sent_to_result=round(_s["t_resp"] - _s["t_send"], 3) if _s.get("t_send") else None)
                except Exception:
                    pass
        except Held as h:
            held_modes.add(mode)
            say("%s: HELD - %s. NOT STARTED. Build the extractor for the residue, then rerun: python3 challenges/_lib/autosolve.py %s %s %s" % (mode, h.why[:260], day, cid, lane))
            board.log_event(day, "held", entry=entry, why=h.why[:200], residue=h.residue[:20])
            _write_residue(day, cid, entry, h, board)
            # D33 adoptB item 1: PARK the mode. handler_watch picks it up on the next handlers.py /
            # pin-file change and does an offline rebuild + ONE live submit to the SAME attempt.
            try:
                import park_rebuild as _pr
                _att = (getattr(gm, "last_launch", None) or {}).get("attempt_id")
                _pr.park(day, cid, mode, lane, _att, (getattr(gm, "last_launch", None) or {}),
                         h.residue, h.why, residue=h.residue)
            except Exception as _pxe:
                say("park_rebuild unavailable (%s); the mode is not parked for watcher rebuild" % type(_pxe).__name__)
            continue
        except Exception as e:
            errored[mode] = str(e)[:200]
            say("%s: ERROR %s" % (mode, explain(str(e) or type(e).__name__)[:520]))
            board.log_event(day, "autosolve", entry=entry, result="error", err=traceback.format_exc()[-400:])
            if mode == "single_solve":
                break
            if mode == "time_trial":
                # D31 P0-1 (2026-10-30, joint-approved): strict prereq. ANY TT non-CORRECT exit must block MM.
                # Previous behavior bypassed held_modes on _gm_side_dead(e) (rotation_exhausted / retry_variants_unavailable)
                # and relied on the GM to 409 at MM start. The directive requires MM only after an observed TT CORRECT
                # (or an authoritative GM.status already_solved recovery). One GM.status probe is permitted to recover
                # a teammate's TT CORRECT; a single call, no retry loop.
                held_modes.add("time_trial")
                if _gm_side_dead(e):
                    try:
                        _st = gm.status(entry)
                        if _st and str(_st.get("result", "")).lower() == "correct":
                            held_modes.discard("time_trial")  # authoritative already_solved, MM may proceed
                            say("time_trial: ERROR but GM.status reports already-CORRECT (teammate/prior) - MM authorised")
                        else:
                            say("time_trial: GM has no variant left and status is not CORRECT - MM blocked")
                    except Exception:
                        say("time_trial: GM has no variant left; GM.status check failed - MM blocked (fail-closed)")
            continue
        # D29 Fix H (2026-10-28 TT/MM analysis): already_solved loses the flag because
        # GM.submit doesn't return it on this path (6 historical cases). GM.status DOES
        # return the flag + solved_by on this path. Recover once + canonicalize to CORRECT
        # so the normal CORRECT branch below (L829+) logs the flag + marks the mode done.
        _res_now = res or {}
        if str(_res_now.get("result", "")).lower() == "already_solved" and not _res_now.get("flag"):
            try:
                _st = gm.status(entry)
                _flag = (_st or {}).get("flag") or (_st or {}).get("solved_flag")
                if _flag:
                    _res_now["flag"] = _flag
                    _res_now["solved_by"] = (_st or {}).get("solved_by") or _res_now.get("solved_by")
                    _res_now["result"] = "CORRECT"   # canonical so downstream treats as a win
                    say("%s: already_solved -> recovered flag via op=status (teammate solved first or prior attempt)" % mode)
                    res = _res_now
            except Exception as _asx:
                say("%s: already_solved + status-flag recovery FAILED (%s); will treat as CORRECT without flag" % (mode, str(_asx)[:120]))
                _res_now["result"] = "CORRECT"  # still treat as CORRECT so SS->TT->MM chain proceeds
                res = _res_now
        ok = str((res or {}).get("result", "")).upper() == "CORRECT"
        results[mode] = res
        if not ok and str((res or {}).get("result", "")).upper() == "HELD":
            # D30 (2026-10-29): BEFORE surfacing HELD to the agent, try cross-lane fallback. If byte-level
            # probe says another adapter owns the shape (e.g. GM mis-routed a mobile APK to binary; a web
            # challenge embedded a base64 the warmups chain already decodes), that adapter's compute() may
            # answer. Fail-open: nothing is submitted here (that is still the runner's job on a NEXT call);
            # we only enrich the HELD line with "try lane=X" so the agent AUTO-LOOP has a lead.
            try:
                import cross_lane as _cl
                _artifact_blobs = (res or {}).get("blobs") or []
                _probes = _cl.probe_lane(_artifact_blobs[0]) if _artifact_blobs else []
                _alts = [l for l, c in _probes if l != lane and c >= 0.5]
                if _alts:
                    say("%s: cross-lane hint - this shape also matches %s; consider porting the extractor "
                        "into this challenge's handlers.py (call that lane's reader) before --rerun" % (mode, ", ".join(_alts[:3])))
                    board.log_event(day, "cross_lane_hint", entry=entry, primary=lane, alternates=_alts[:3])
            except Exception:
                pass
            h = Held(str((res or {}).get("why") or "adapter held the mode"), (res or {}).get("unresolved") or [])
            say("%s: HELD - %s. NOTHING SUBMITTED. Build the extractor for the residue, then rerun: python3 challenges/_lib/autosolve.py %s %s %s" % (mode, h.why[:260], day, cid, lane))
            board.log_event(day, "held", entry=entry, why=h.why[:200], residue=h.residue[:20])
            _write_residue(day, cid, entry, h, board)
        if res is not None and not ok and str(res.get("result", "")).upper() not in ("CORRECT", "ALREADY_SOLVED", "HELD"):
            # D31 audit P0-3: a mode that ended non-CORRECT without a Held (gate_blocked, incorrect, expired ...) needs the
            # same repair hand-off as HELD: residue + repair capsule naming the exact ids. Submission behaviour is unchanged.
            try:
                _probs = [str(p) for p in (res.get("problems") or [])]
                _detail = "; ".join(_probs) or str(res.get("prompt") or res.get("why") or "")
                h = Held(("%s: %s" % (res.get("result") or "not CORRECT", _detail))[:300], _repair_ids(cid, entry, res))
                say("%s: %s - %d id(s) unresolved. Repair capsule written next to the residue." % (mode, h.why[:200], len(h.residue)))
                _write_residue(day, cid, entry, h, board)
            except Exception:
                pass
        if not ok and mode == "time_trial":
            held_modes.add("time_trial")          # Mastery opens only after the Time Trial is CORRECT: starting it now is a refused write (409 prerequisite_required)
        # ranked_attempted (2026-10-10): makes "did HUNTRESS_RANKED actually reach THIS process" directly checkable
        # from the timeline instead of inferred - verified the env var propagates WSL-wide in isolation the same
        # day this was added, but had no way to prove it reached an actual spawned agent's autosolve.py call.
        _r = res or {}
        board.log_event(day, "autosolve", entry=entry, result=_r.get("result"), secs=round(time.time() - ts, 1),
                        ranked_attempted=ranked, ranked_env=_ranked_env_state(), cap=_cap_telemetry(entry, lane, mode, _mono0, str(_r.get("result"))),
                        accepted_n=len(_r.get("accepted_ids") or []), remaining=_r.get("remaining"),
                        unresolved=sorted(map(str, (_r.get("unresolved") or [])))[:30], wrong=sorted(map(str, (_r.get("wrong") or [])))[:30])
        if ok:
            board.mark(day, entry)
            single_ok = single_ok or mode == "single_solve"
            if mode == "single_solve":
                t_single_ok = time.time()                          # the clock for 'Single CORRECT -> ranked start sent'
            # ATTRIBUTION (2026-10-09): the GM returns solved_by {name, at} on a submit, so each flag is
            # attributable. Print it and log it so the stats window / watcher shows WHO solved it and WHEN,
            # which also distinguishes our own solve from a teammate's on a shared attempt.
            sb = (res or {}).get("solved_by") or {}
            who = sb.get("name") or ""
            ranked = bool((res or {}).get("run_for_time"))
            say("%s: CORRECT in %.1fs%s%s" % (mode, time.time() - ts,
                                              (" by " + who) if who else "",
                                              " [RANKED]" if ranked else ""))
            flag = (res or {}).get("flag") or (res or {}).get("solved_flag")
            if flag:
                say("%s: FLAG %s" % (mode, flag))
            board.log_event(day, "solved", entry=entry, by=who, at=sb.get("at"),
                            ranked=ranked, hof_eligible=(res or {}).get("hall_of_fame_eligible"), secs=round(time.time() - ts, 1))      # the GM's own word, logged next to what we asked for
            # D30-#1 (2026-10-29): bank each accepted token's lane so a repeat token tomorrow can short-circuit the FIELDS
            # table lookup via accepted_cache.cached_extractor(). Form-level banking (dec/hex/pattern) stays with
            # answer_alternates; this records the lane that answered the token, so autosolve_<lane>.FIELDS can trust the
            # extractor-registered-here cache before probing. Fail-open; a cache miss is still handled by the full dispatch.
            try:
                import accepted_cache as _ac
                accepted_ids = (res or {}).get("accepted_ids") or (res or {}).get("answer_ids") or list((res or {}).get("answers") or {}).keys()
                for _tok in accepted_ids or []:
                    try: _ac.record_extractor(int(day), lane, str(_tok), "autosolve_%s" % lane)
                    except Exception: pass
            except Exception:
                pass
        else:
            r = res or {}
            say("%s: %s (%s accepted, %s remaining) in %.1fs" % (mode, r.get("result"), len(r.get("accepted_ids") or []),
                                                                r.get("remaining"), time.time() - ts))
            if mode == "single_solve":
                break
    try:                                              # keep every flag for the writeup (flags are never redacted)
        _p = os.path.join(board._board_dir(day), cid.replace("/", "_") + ".autosolve.json")
        try:
            _old = json.load(open(_p))                 # MERGE: a rerun (e.g. only the Time Trial) must never erase an earlier mode's CORRECT result and flag
            _old = _old if isinstance(_old, dict) else {}
        except Exception:
            _old = {}
        _new = {m: {"result": (r or {}).get("result"), "flag": (r or {}).get("flag"),
                    "solved_by": ((r or {}).get("solved_by") or {}).get("name") if isinstance((r or {}).get("solved_by"), dict) else (r or {}).get("solved_by"),
                    "ranked": bool((r or {}).get("run_for_time"))} for m, r in results.items()}
        for m, v in _new.items():
            o = _old.get(m) or {}
            if str(o.get("result", "")).upper() == "CORRECT" and str(v.get("result", "")).upper() != "CORRECT":
                continue                              # never replace a CORRECT with something worse
            _old[m] = v
        with open(_p, "w") as f:
            json.dump(_old, f, indent=1)
    except Exception:
        pass
    try:                                              # D31 audit item 6: the runner must not report FINISHED while an open mode is still owed
        _RUN_SUMMARY.update(cid=cid, board=board._board_dir(day),
                            unresolved_modes=_owed_modes(results, open_modes,
                                                         os.path.join(board._board_dir(day), cid.replace("/", "_") + ".autosolve.json")))
    except Exception:
        pass
    try:                                              # D32: what the handler overlay filled / which handler raised (file:line) - read by fix.py and the nightly fold
        import handlers_overlay
        handlers_overlay.record(day, cid)
    except Exception:
        pass
    try:                                              # print-only: the one instruction for this outcome; it can never change what the run did
        say(next_step(day, cid, lane, open_modes, results, held_modes, errored, os.environ.get("HUNTRESS_AGENT") or "<agent>"))
    except Exception:
        pass


if __name__ == "__main__":
    _status, _error = "FINISHED", None
    try:
        main()
    except Exception as e:
        _status, _error = "ERROR", type(e).__name__
        say("ALL: ERROR %s" % str(e)[:200])
        try:
            say(crash_step(os.environ.get("HUNTRESS_AGENT") or "<agent>"))
        except Exception:
            pass
    finally:
        _status, _extra = _final_status(_status)
        _update_runner_state(_status, _error, _extra)
        try:
            if _RUN_LOCK:
                import autorun
                autorun.release(*_RUN_LOCK)
        except Exception:
            pass
