#!/usr/bin/env python3
"""Reusable Huntress CTF 2026 Game Master client + solve helpers.

OFFICIAL PATH (2026-10-03): pair ONCE (challenges/_lib/pair_once.sh), then GM() talks to
https://2026.huntress.ctf.games with the bearer token read from [credential store] No VM, VPN or SSH.
If the token file is absent the client falls back to the in-VM path (http://[ip]/huntress-ctf-proxy,
reachable only from the Homebase / over SSH); GM_MODE=vm forces that fallback. Never print the token.

Writing a new solver becomes ~15 lines:

    from ctf_gm import GM, unzip, file_type, solve_mode
    gm = GM()
    for c in gm.list(day=2):                       # enumerate the day's challenges
        print(c["id"], c.get("mode"), c.get("name"))
    def compute(start, blobs):                      # your per-challenge logic
        members = unzip(blobs[0])                   # AES zip, default pw 'infected'
        ...                                         # derive each answer from the REAL bytes
        return {aid: value for aid in start["answer_ids"]}
    print(solve_mode(gm, "<challenge-id>", compute))   # start(+retry)->download->submit

Run from anywhere once paired:
    python3 your_solver.py
Dynamic reality (John Hammond): the GM API is how you get challenge details AND retrieve flags. Single-solve
artifacts are fixed; Time Trial / Mastery are mutated per attempt, so derive every answer from the attempt's OWN bytes.
"""
import concurrent.futures as cf
import contextlib
import atexit, hashlib, queue
import http.client, io, json, os, re, subprocess, tempfile, threading, time, urllib.parse
import gzip, email.utils, weakref

GM_HOST = os.environ.get("GM_HOST", "[ip]")
GM_PATH = "/huntress-ctf-proxy"   # NO trailing slash (a trailing / 404s)


def _hof_switch_on():
    """True only when the user has switched ranked (Hall-of-Fame) timed starts on (hof_policy.enabled(): env HUNTRESS_HOF=1 or kb/hof_policy.json). Any problem reading it = False = the old, safe behaviour."""
    try:
        import hof_policy
        return bool(hof_policy.enabled())
    except Exception:
        return False
ZIP_PW  = b"infected"

# --- Direct public path (official since 2026-10-03): bearer token, no VM / VPN / SSH ---
# Pair ONCE on the inside (POST http://[ip]/huntress-ctf-proxy?op=pair); the token is stored in
# [credential store] (600) and read here at runtime - never inline, never printed. If the token file is
# absent (or GM_MODE=vm) the client falls back to the in-VM path above.
PUB_HOST = os.environ.get("GM_PUBLIC_HOST", "2026.huntress.ctf.games")
TOKEN_FILE = os.environ.get("HUNTRESS_TOKEN_FILE", os.path.expanduser("[credential store]"))

def _token_file_safe(p):
    """D32 gmnet (audit G2): on POSIX a token file readable or writable by group/other is REFUSED (the bearer is the team's
    identity). Windows ACLs are not mode bits, so the check is POSIX-only. HUNTRESS_TOKEN_PERM_CHECK=0 skips it."""
    if os.name != "posix" or os.environ.get("HUNTRESS_TOKEN_PERM_CHECK") == "0":
        return True
    try:
        return (os.stat(p).st_mode & 0o077) == 0
    except OSError:
        return True                              # a missing file is handled by the open() below


def _load_token():
    try:
        if not _token_file_safe(TOKEN_FILE):
            import sys as _sys
            print("REFUSED: the GM token file is readable by group/other (chmod 600 it); not used. The value was not read.", file=_sys.stderr, flush=True)
            return None
        with open(TOKEN_FILE) as f:
            return f.read().strip() or None
    except OSError:
        return None


# ---- NO BLIND TIMED START (user, 2026-10-11: "we were not supposed to op=start until we had a solver ready ... without spending our one attempt only if given only one attempt") ------------------------------
# start / retry / practice on a TIMED route (.../time_trial, .../mastery) each SPEND a variant when they succeed (agent-2's measured call budget) and, on a route with one variant left, that is the one attempt.
# The only sanctioned way to open a timed window is autosolve.attempt(), AFTER its readiness gate (prebrief verdict) passed: it wraps the work in timed_start_authorised(). Any other caller of this client
# (an agent's own script, a hand-typed GM().start(...)) is REFUSED here, before a byte goes on the wire, with the reason. Commander override: HUNTRESS_TIMED_START=commander-override (deliberate, named).
# Raw HTTP that bypasses this client is outside what code can stop; the agent instructions and the Bash guard cover that.
_TIMED_AUTH = [0]           # timed writes the CURRENT gate pass may still make: ONE (audit A-F6). It is consumed when that write SUCCEEDS, so a 429 retry of the same start is allowed, but a heal retry/practice/second start after it is refused
_TIMED_LOCK = threading.Lock()   # D32 gmnet (audit G6): the slot is consumed under a lock
TIMED_WRITE_OPS = ("start", "retry", "practice")

# ---- CLIENT BOUNDARY (D32 gmnet, post-mortem): an op allowlist and a strict challenge-id shape, checked before anything is sent ----
GET_OPS = ("openapi", "list", "status", "artifact", "download")
POST_OPS = ("start", "submit", "retry", "practice")
CHALLENGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:/(?:time_trial|mastery))?")


class BadRequest(ValueError):
    """refused at the client boundary: unknown op or a malformed challenge id. Nothing was sent."""


def valid_challenge(cid):
    s = str(cid or "")
    return len(s) <= 128 and ".." not in s and CHALLENGE_RE.fullmatch(s) is not None


def _check_boundary(method, op, challenge):
    if os.environ.get("HUNTRESS_GM_BOUNDARY") == "0":
        return
    ok_ops = GET_OPS if method == "GET" else POST_OPS
    if op not in ok_ops:
        raise BadRequest("REFUSED: op=%r is not a %s op of the GM API; nothing was sent" % (str(op)[:40], method))
    if challenge is not None and not valid_challenge(challenge):
        raise BadRequest("REFUSED: malformed challenge id %r (allowed: [A-Za-z0-9_.-], max 128, no '..', optional /time_trial|/mastery); nothing was sent" % str(challenge)[:80])


class TimedStartRefused(RuntimeError):
    """a timed window may only be opened by autosolve after its readiness gate"""


@contextlib.contextmanager
def timed_start_authorised(n=1):
    prev = _TIMED_AUTH[0]
    _TIMED_AUTH[0] = n
    try:
        yield
    finally:
        _TIMED_AUTH[0] = prev


def _check_timed_start(payload):
    """-> True when the write is authorised by a gate-pass slot (the caller consumes the slot once the write SUCCEEDS), False when it is not a timed write or the Commander override is set. Raises TimedStartRefused otherwise."""
    if not (isinstance(payload, dict) and payload.get("op") in TIMED_WRITE_OPS and str(payload.get("challenge", "")).endswith(("/time_trial", "/mastery"))):
        return False
    if os.environ.get("HUNTRESS_TIMED_START") == "commander-override":
        return False
    if _TIMED_AUTH[0] > 0:
        return True
    raise TimedStartRefused("REFUSED: op=%s on %s would spend a variant (on a one-variant route, THE attempt). Timed windows are opened only by autosolve.py after its readiness gate, and each gate pass makes ONE timed write: "
                            "a retry / practice / second start after a lost or stale window is a NEW decision, so rerun autosolve and let the gate run again "
                            "(python3 challenges/_lib/prebrief.py --gate <entry> shows GO or HELD and the residue to build first). Nothing was sent." % (payload.get("op"), payload.get("challenge")))


# ---- TIMED WINDOW BUDGET (2026-10-11, Day 11 D-Day) -----------------------------------------------------------------------------------------------------------
# A ranked Time Trial opens ONE attempt with a short server deadline (D-Day: 30 s). The release-time 429 storm made the retry/backoff below sleep through the whole window, the attempt
# expired, and with the untimed pool empty both timed modes were lost for the day. While a window is open, a wait that would run past the deadline (minus a reserve for download +
# analyse + submit) now RAISES WindowExpired immediately so the caller can fall back, instead of sleeping. Process-wide: one timed attempt per process.
# D32 gmnet (audit G6): the window is now kept PER THREAD (run_parallel jobs no longer overwrite each other's deadline). A thread that opened no window of
# its own (a download worker of download_many) is protected by the EARLIEST window any thread has open. _WIN["deadline"] keeps its old read/write shape.
_WIN_LOCK = threading.Lock()


class _ThreadWin(dict):
    def __init__(self):
        super().__init__()
        self._by_thread = {}

    def __setitem__(self, k, v):
        if k != "deadline":
            return super().__setitem__(k, v)
        with _WIN_LOCK:
            if v is None:
                self._by_thread.pop(threading.get_ident(), None)
            else:
                self._by_thread[threading.get_ident()] = v

    def __getitem__(self, k):
        if k != "deadline":
            return super().__getitem__(k)
        with _WIN_LOCK:
            own = self._by_thread.get(threading.get_ident())
            if own is not None:
                return own
            live = [d for d in self._by_thread.values() if d is not None]
            return min(live) if live else None

    def get(self, k, default=None):
        if k == "deadline":
            v = self.__getitem__(k)
            return default if v is None else v
        return super().get(k, default)


_WIN = _ThreadWin()
WINDOW_RESERVE_S = 3.0


class WindowExpired(RuntimeError):
    """the open timed window cannot survive the wait the client was about to make"""


def open_window(deadline):
    """deadline = ISO-8601 string from the GM ('2026-10-11T13:00:40.047Z') or an epoch float; None/garbage closes the window."""
    try:
        if isinstance(deadline, (int, float)):
            _WIN["deadline"] = float(deadline)
        elif deadline:
            import datetime as _dt
            _WIN["deadline"] = _dt.datetime.fromisoformat(str(deadline).replace("Z", "+00:00")).timestamp()
        else:
            _WIN["deadline"] = None
    except (ValueError, TypeError):
        _WIN["deadline"] = None
    _budget_clock_sync()
    return _WIN["deadline"]


def close_window():
    _WIN["deadline"] = None
    _budget_clock_sync()


def _budget_clock_sync():
    """D32 auto (item A): tell the machine-wide request budget whether THIS process has a clock running (any thread's open window), so
    untimed traffic of the other processes yields to it. A no-op unless the budget is in live/test use. Never raises."""
    try:
        import gm_budget
        with _WIN_LOCK:
            live = [d for d in _WIN._by_thread.values() if d is not None]
        if live:
            gm_budget.clock_on(max(live))
        else:
            gm_budget.clock_off()
    except Exception:
        pass


def _budget_mod(conn, host):
    """-> the gm_budget module when the per-minute request budget applies to this client (real GM, or a test that named
    HUNTRESS_GM_BUDGET_FILE), else None. HUNTRESS_GM_BUDGET=0 turns it off."""
    try:
        import gm_budget
        real = _real_remote(conn, host)
        if real:
            gm_budget.mark_real()
        return gm_budget if gm_budget.enabled(real) else None
    except Exception:
        return None


def window_left():
    """seconds left in the open window, or None when no window is open"""
    return None if _WIN["deadline"] is None else _WIN["deadline"] - time.time()


def _check_window(wait):
    dl = _WIN["deadline"]
    if dl is not None and time.time() + wait + WINDOW_RESERVE_S > dl:
        raise WindowExpired("timed window: %.1fs left, a %.1fs backoff would not leave %.0fs for download+solve+submit" % (dl - time.time(), wait, WINDOW_RESERVE_S))


# ---- NO HAMMERING (user directive 2026-10-11, binding): "solve locally, submit to the GM only when truly positive; no brute force, no endless guessing" ------------------------------
# (1) REPEAT-FAILURE GUARD: an IDENTICAL call (method + path + body) that the GM refused with a client-side 4xx (409 timed_intent_not_available, retry_variants_unavailable,
#     prerequisite_required, 400, 404 ...) is NOT sent again for GUARD_S seconds: it raises RepeatFailure at once with the earlier error, so a loop cannot hammer the GM and a Commander/agent
#     must change something (the body, the route, or wait). 429/5xx keep their own backoff. HUNTRESS_GM_REPEAT_GUARD_S=0 disables it.
# (2) CALL LEDGER: every call appends one line to [home path] (t, pid, method, op, challenge, status, secs, waited, err) so the next incident can be root-caused from data
#     (on Day 11 nobody could say where 46 of the 50 s of the D-Day window went).
# (refused calls are remembered per client instance, see GM._call)
GUARD_S = float(os.environ.get("HUNTRESS_GM_REPEAT_GUARD_S", "60"))
LEDGER = os.environ.get("HUNTRESS_GM_LEDGER", os.path.join(os.path.expanduser("~"), "gm_calls.jsonl"))


class RepeatFailure(RuntimeError):
    """an identical call was refused by the GM moments ago; change something before asking again"""


# ---- LIVE GM RECORD (user, 2026-10-11: "we should have had the agents recording what the game master stated ... how are we to know the write ups are even correct and in context?"; audit C) -------------
# One JSON line per GM response: Day NN/_gm_record/<challenge>.<machine>.jsonl (per machine: no merge conflicts; NOT in _board, which sync drops). It holds what we SUBMITTED, what the GM ANSWERED (accepted_ids,
# remaining, flag, solved_by, error, message), and the prompt / guidance / questions the FIRST time each attempt is seen. Never the bearer token, never artifact bytes (size + sha only). Only the REAL GM is
# recorded (HUNTRESS_GM_RECORD_ALWAYS=1 for tests, HUNTRESS_GM_RECORD=0 turns it off). The write happens on a background thread AFTER the response is returned: nothing is added to a timed window.
_RECQ = queue.Queue()
_REC_THREAD = [None]
_REC_SEEN = set()
_REC_KEEP = ("result", "accepted_ids", "remaining", "flag", "solved_by", "error", "message", "attempt_id", "deadline", "unique_attempts_remaining", "next_op", "mode", "hall_of_fame_eligible",
             "answer_ids", "wrong", "rejected_ids", "missing_ids", "name", "status")


def _rec_machine():
    try:
        import machine
        return machine.name() or "unknown"
    except Exception:
        return "unknown"


def _rec_writer():
    while True:
        item = _RECQ.get()
        try:
            if item is None:
                return
            path, line = item
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line)                                        # ONE write of the whole line: atomic enough for an O_APPEND file
            finally:
                os.close(fd)
        except Exception:
            pass
        finally:
            _RECQ.task_done()


def _rec_flush():
    try:
        t = _REC_THREAD[0]
        if t is not None:
            end = time.time() + 3.0
            while _RECQ.unfinished_tasks and time.time() < end:
                time.sleep(0.02)
    except Exception:
        pass


atexit.register(_rec_flush)


def _record(gm, method, path, body, status, d, timing=None):
    """enqueue ONE record of a GM exchange. Never raises, never blocks, never touches the request."""
    try:
        if os.environ.get("HUNTRESS_GM_RECORD") == "0":
            return
        if not (_real_remote(gm._c, gm.host) or os.environ.get("HUNTRESS_GM_RECORD_ALWAYS") == "1"):
            return
        q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        req = {}
        try:
            req = json.loads(body) if body else {}
        except Exception:
            req = {}
        op = str(req.get("op") or (q.get("op") or [""])[0])
        ch = str(req.get("challenge") or (q.get("challenge") or [""])[0])
        if op in ("list", "openapi") or not ch:
            return
        entry = {"t": round(time.time(), 3), "machine": _rec_machine(), "pid": os.getpid(), "agent": os.environ.get("HUNTRESS_AGENT"), "op": op, "ch": ch, "http": status}
        if isinstance(timing, dict):
            entry["request_send_epoch"] = timing.get("request_send_epoch")
            entry["response_first_byte_epoch"] = timing.get("response_first_byte_epoch")
            entry["response_complete_epoch"] = timing.get("response_complete_epoch")
            entry["response_first_byte_ms"] = timing.get("response_first_byte_ms")
            entry["response_complete_ms"] = timing.get("response_complete_ms")
        if op == "submit":
            entry["answers"] = req.get("answers")
        if op in ("artifact", "download"):
            entry["resp"] = {"bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()[:16]}
        else:
            j = json.loads(d.decode("utf-8", "replace"))
            resp = {}
            if isinstance(j, dict):
                resp = {k: j[k] for k in _REC_KEEP if k in j}
                if "message" in resp:
                    resp["message"] = str(resp["message"])[:500]
                if "error" in resp:
                    resp["error"] = str(resp["error"])[:500]
                full = {k: j[k] for k in ("prompt", "guidance", "questions") if k in j}
                if full:
                    sig = hashlib.sha1(json.dumps(full, sort_keys=True, default=str).encode()).hexdigest()
                    resp["statement_sha1"] = sig
                    if (ch, sig) not in _REC_SEEN:
                        _REC_SEEN.add((ch, sig))
                        txt = json.dumps(full, default=str)
                        resp["statement"] = full if len(txt) <= 1000000 else {"truncated": True, "prompt": full.get("prompt"), "guidance": full.get("guidance")}
            entry["resp"] = resp
        m = re.search(r"-day-(\d+)", ch)
        day = int(m.group(1)) if m else 0
        base = ch.split("/")[0]
        root = os.environ.get("HUNTRESS_GM_RECORD_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))        # the env override is for tests
        fn = os.path.join(root, "Day %02d" % day, "_gm_record", "%s.%s.jsonl" % (base, _rec_machine()))
        line = (json.dumps(entry, ensure_ascii=True, default=str) + "\n").encode("ascii")
        if _REC_THREAD[0] is None:
            _REC_THREAD[0] = threading.Thread(target=_rec_writer, name="gm-record", daemon=True)
            _REC_THREAD[0].start()
        _RECQ.put((fn, line))
    except Exception:
        pass


def _throttle_rec(gm, method, path, body, r, status, ra, wait):
    """enqueue ONE throttle record (429/5xx) with the server's Retry-After + rate-limit headers, the
    computed wait, and the timed-window remaining, so the backoff can be CALIBRATED from real server
    guidance (homestation, 2026-10-12; was requested but never recorded). Background write: never raises,
    never blocks a timed window. Lands in Day NN/_gm_record/_throttle.<machine>.jsonl (per machine)."""
    try:
        if os.environ.get("HUNTRESS_GM_RECORD") == "0":
            return
        if not (_real_remote(gm._c, gm.host) or os.environ.get("HUNTRESS_GM_RECORD_ALWAYS") == "1"):
            return
        q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        try:
            req = json.loads(body) if body else {}
        except Exception:
            req = {}
        op = str(req.get("op") or (q.get("op") or [""])[0])
        ch = str(req.get("challenge") or (q.get("challenge") or [""])[0])
        hdrs = {h: r.getheader(h) for h in ("Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining",
                                            "X-RateLimit-Reset", "RateLimit-Reset", "RateLimit-Remaining", "Date") if r.getheader(h)}
        wl = (_WIN["deadline"] - time.time()) if _WIN.get("deadline") else None
        entry = {"t": round(time.time(), 3), "machine": _rec_machine(), "pid": os.getpid(), "agent": os.environ.get("HUNTRESS_AGENT"),
                 "event": "throttle", "op": op, "ch": ch, "http": status, "retry_after": ra, "computed_wait": round(wait, 2),
                 "window_left_s": round(wl, 2) if wl is not None else None, "headers": hdrs}
        m = re.search(r"-day-(\d+)", ch)
        day = int(m.group(1)) if m else 0
        root = os.environ.get("HUNTRESS_GM_RECORD_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fn = os.path.join(root, "Day %02d" % day, "_gm_record", "_throttle.%s.jsonl" % _rec_machine())
        line = (json.dumps(entry, ensure_ascii=True, default=str) + "\n").encode("ascii")
        if _REC_THREAD[0] is None:
            _REC_THREAD[0] = threading.Thread(target=_rec_writer, name="gm-record", daemon=True)
            _REC_THREAD[0].start()
        _RECQ.put((fn, line))
    except Exception:
        pass


def _state_body(d):
    """a >= 400 reply that is really a mode STATE (an expired attempt, flag unavailable) and not an error, judged on the JSON result / status / error FIELDS only (audit A-F5: the old test searched the whole
    body for 'expired', so a prompt, a question or an auth error that merely contained the word passed for a state)."""
    try:
        j = json.loads(d.decode("utf-8", "replace"))
    except Exception:
        return False
    if not isinstance(j, dict):
        return False
    for k in ("result", "status", "error"):
        v = str(j.get(k, "")).lower()
        if any(w in v for w in ("token", "auth", "unauthor", "forbidden")):
            return False
        if v.startswith(("expired", "attempt_expired", "flag_unavailable")):
            return True
    return False


def _state_text(st):
    """the words of a start/submit reply that describe its STATE (result, status, error, message): never the prompt or the questions"""
    if not isinstance(st, dict):
        return str(st).lower()
    return " ".join(str(st.get(k, "")) for k in ("result", "status", "error", "message")).lower()


def _no_real_gm(conn, host):
    """HUNTRESS_NO_REAL_GM=1 (the regression suite sets it): a call that would go to the REAL Game Master is refused. The suite made 67 real GM reads in 30 minutes on the homestation and about 50 per run on the workstation
    (measured in [home path]): an offline test must use a local fake or gm_sim.py, never the live service."""
    return os.environ.get("HUNTRESS_NO_REAL_GM") == "1" and _real_remote(conn, host)


def _real_remote(conn, host):
    """the ledger is a record of REAL traffic to the Game Master: a fake connection object (tests) or a loopback server never counts (2026-10-11: test runs filled it with 700 fake calls)"""
    try:
        return isinstance(conn, http.client.HTTPConnection) and not str(host or "").startswith(("127.", "localhost", "::1", "[::1]"))
    except Exception:
        return False


_Q_KEEP = ("op", "day", "lane", "all", "search", "delivery", "challenge")     # query parameters worth recording; 'capability' (a download secret) and anything else is NEVER written
_H_KEEP = ("content-encoding", "cache-control", "etag", "age", "content-type", "content-length", "server", "via", "x-cache", "cf-cache-status",
           "server-timing", "cf-ray")      # response headers that explain latency/caching/tracing (server-timing = the edge/origin/worker milliseconds, cf-ray = a per-request id for a support ticket); never Set-Cookie / Report-To / Authorization


def _sanitize_query(path):
    """-> {param: value} for the whitelisted query parameters of a request path (values cut to 60 chars). Never raises."""
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(str(path or "")).query)
        return {k: str(v[0])[:60] for k, v in q.items() if k in _Q_KEEP and v}
    except Exception:
        return {}


def _ledger(method, body, status, secs, waited, err="", real=True, path=None, size=None, ttfb=None, hdrs=None):
    """one JSON line per REAL GM call: when, pid, method, op, challenge, status, seconds, backoff wait, and (2026-10-16, instrumentation) the sanitized query, the response size in bytes, the time to
    first byte and a few latency/caching response headers. Never credentials, answers, request bodies or the capability token."""
    if not real:
        return
    try:
        op = ch = ""
        if body:
            j = json.loads(body)
            op, ch = str(j.get("op", "")), str(j.get("challenge", ""))
        row = {"t": round(time.time(), 3), "pid": os.getpid(), "m": method, "op": op, "ch": ch[-60:], "status": status, "secs": round(secs, 3),
               "waited": round(waited, 2), "err": err[:120]}
        q = _sanitize_query(path) if path else {}
        if q:
            row["q"] = q
            if not op:
                row["op"] = str(q.get("op", ""))
            if not ch and q.get("challenge"):
                row["ch"] = str(q["challenge"])[-60:]
        if size is not None:
            row["bytes"] = int(size)
        if ttfb is not None:
            row["ttfb"] = round(ttfb, 3)
        if hdrs:
            h = {k: str(v)[:60] for k, v in hdrs.items() if k in _H_KEEP}
            if h:
                row["h"] = h
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        pass                                           # a ledger problem must never touch a solve


def _hdr_dict(r):
    """lower-cased response headers of a response object (a test double without getheaders gives {}). Never raises."""
    try:
        return {str(k).lower(): v for k, v in r.getheaders()}
    except Exception:
        return {}


SUBMIT_CAP = int(os.environ.get("HUNTRESS_SUBMIT_CAP", "8"))
WRONG_VERDICTS = ("incorrect", "wrong", "rejected")      # D32 gmnet (audit G3): the only submit results that prove a batch wrong

# WRONG-SUBMIT MEMORY that survives a process restart (user 2026-10-13; workstation finding on Day 13 warmups).
# _guard_submit's "wrong" set lives in ONE process, so an agent that RE-RUNS autosolve (a new process) starts empty
# and the identical wrong batch goes out again (cost that day: ~39 s + a wasted attempt). Persist the keys to a small
# per-day file in the WSL home. Day-scoped (from the challenge id) so a new day starts clean; keys are a sha1 of the
# challenge + the sorted answers. HUNTRESS_SUBMIT_WRONG_STORE=0 disables it. Every read/write is best-effort: a
# missing or corrupt file is ignored and can NEVER raise or slow a submit.
WRONG_STORE = os.environ.get("HUNTRESS_WRONG_STORE_FILE", os.path.expanduser("[credential store]"))
def _wrong_enabled():
    # OFF by default (fail-safe): tests never touch the shared store, so no parallel race. The LIVE launcher
    # (go.sh / Go.ps1) sets HUNTRESS_SUBMIT_WRONG_STORE=1 so the real agents get cross-restart protection.
    return os.environ.get("HUNTRESS_SUBMIT_WRONG_STORE") == "1"
def _wrong_day(challenge):
    m = re.search(r"-day-(\d+)", str(challenge))
    return int(m.group(1)) if m else -1
def _wrong_key(challenge, answers):
    return hashlib.sha1((str(challenge) + "|" + json.dumps(answers, sort_keys=True, default=str)).encode("utf-8")).hexdigest()
def _wrong_load(day):
    """the sha1 keys persisted for `day` (an empty set on any problem). Best-effort."""
    try:
        with open(WRONG_STORE, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and d.get("day") == day and isinstance(d.get("keys"), list):
            return set(str(k) for k in d["keys"])
    except Exception:
        pass
    return set()
def _wrong_save(day, keys):
    """persist the wrong-key set for `day` atomically. Best-effort; never raises."""
    try:
        os.makedirs(os.path.dirname(WRONG_STORE), exist_ok=True)
        tmp = WRONG_STORE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"day": day, "keys": sorted(keys)}, f)
        os.replace(tmp, WRONG_STORE)
    except Exception:
        pass


class SubmitRefused(RuntimeError):
    """a submit that is guaranteed to waste a GM call: empty, an identical repeat of one the GM did not accept, or past the per-challenge cap"""


def _guard_submit(gm, challenge, answers):
    """LOCAL FIRST at the client (user, 2026-10-11: "nothing should attempt to even submit until they locally solve"; audit A-F4/F10). Refuses, before anything is sent: an empty submit, an empty/None value,
    an IDENTICAL resubmit of a batch the GM already answered with anything but CORRECT (a wrong submit returns 200 'incorrect', so the 4xx repeat guard never saw it), and more than SUBMIT_CAP (8) submits for one
    challenge on this client (the GM is not a probe; HUNTRESS_SUBMIT_CAP=0 disables the cap). -> the key to remember if the GM does not accept the batch."""
    if not isinstance(answers, dict) or not answers:
        raise SubmitRefused("REFUSED: an empty submit for %s was not sent" % challenge)
    empty = [k for k, v in answers.items() if v is None or (isinstance(v, (str, list, dict, tuple)) and len(v) == 0)]
    if empty:
        raise SubmitRefused("REFUSED: empty value for %s in the submit for %s was not sent (solve it locally first)" % (empty[:4], challenge))
    st = gm.__dict__.setdefault("_sub", {"n": {}, "wrong": set(), "wrong_day": None})
    day = _wrong_day(challenge)
    if _wrong_enabled() and getattr(gm, "host", None) == PUB_HOST and st.get("wrong_day") != day:
        st["wrong"] = _wrong_load(day); st["wrong_day"] = day     # seed this process from the persisted store for THIS day (a new day starts clean). REAL GM only (PUB_HOST): a fake/offline-test GM must never load or pollute the store.
    key = _wrong_key(challenge, answers)
    if key in st["wrong"]:
        raise SubmitRefused("REFUSED: this exact submit for %s already came back NOT correct; change the answers (an identical resubmit cannot succeed)" % challenge)
    _cap = SUBMIT_CAP + int((gm.__dict__.get("_submit_allowance") or {}).get(str(challenge), 0))   # D32 auto: a bounded extra allowance granted ONLY by autosolve's staged/probe submit on an UNTIMED attempt
    if SUBMIT_CAP > 0 and st["n"].get(str(challenge), 0) >= _cap:
        raise SubmitRefused("REFUSED: %d submits already made for %s on this client: the GM is not a probe, solve locally first (HUNTRESS_SUBMIT_CAP=0 lifts the cap)" % (_cap, challenge))
    st["n"][str(challenge)] = st["n"].get(str(challenge), 0) + 1
    return key


# ---- ALTERNATE SPELLINGS (2026-10-28, user: "in any type of contradiction, include both ways ... with the single solve") -------------------------------------------------
# All logic lives in answer_alternates.py; these two shims only add the re-entrancy guard (probe submits go back through GM.submit so the guard, the wrong-batch store, the call
# record and accepted_values banking all see them) and make sure nothing here can ever fail a solve. Timed modes only APPLY a banked spelling; they never probe.
def _alt_capture_formats(gm, challenge, st):
    """remember each question's answer_format from the start response (needed to know a field is a free `pattern`, never an enum); never raises"""
    try:
        qs = st.get("questions") if isinstance(st, dict) else None
        if isinstance(qs, list):
            gm.__dict__.setdefault("_alt_formats", {})[str(challenge)] = {str(q.get("id")): q.get("answer_format") for q in qs if isinstance(q, dict) and q.get("id") is not None}
    except Exception:
        pass


def _alt_formats(gm, challenge):
    try:
        return (gm.__dict__.get("_alt_formats") or {}).get(str(challenge))
    except Exception:
        return None


def _alt_pre(gm, challenge, answers):
    try:
        if gm.__dict__.get("_alt_busy"):
            return answers
        import answer_alternates as _aa
        out, ev = _aa.apply_banked(challenge, answers, formats=_alt_formats(gm, challenge))
        if ev:
            gm.__dict__.setdefault("_alt_events", []).append({"challenge": str(challenge), "phase": "pre", "events": ev})
        return out
    except Exception:
        return answers


def _alt_post(gm, challenge, answers, res):
    try:
        if gm.__dict__.get("_alt_busy"):
            return res
        import answer_alternates as _aa
        if not _aa.enabled() or _is_timed(challenge):
            return res
        _fmts = _alt_formats(gm, challenge)
        _aa.bank_if_correct(challenge, answers, res, formats=_fmts)
        gm.__dict__["_alt_busy"] = True
        try:
            out, ev = _aa.resolve_single_solve(lambda batch: gm.submit(challenge, batch), challenge, answers, res, formats=_fmts)
        finally:
            gm.__dict__["_alt_busy"] = False
        if ev:
            gm.__dict__.setdefault("_alt_events", []).append({"challenge": str(challenge), "phase": "post", "events": ev})
        return out
    except Exception:
        return res


# ---- 429 BACKOFF (2026-10-16, P1): honour the SERVER's Retry-After, otherwise bounded exponential backoff with JITTER, and share "not before" across the processes of this machine -------------------------
# A real 429 is the only thing that makes a request wait here. Retry-After is honoured up to RETRY_AFTER_CAP_S (it used to be cut to 10 s, so a longer server instruction was retried early and refused again);
# inside a timed window _check_window() still raises WindowExpired instead of sleeping past the deadline. Jitter is ADDITIVE (never shorter than the server or base wait) so five agents hit by the same 429
# do not retry in the same instant. The shared "not before" file (real GM traffic only, or HUNTRESS_GM_BACKOFF for tests) makes the other processes wait out a 429 they have not seen themselves instead of
# sending a request that would be refused. Identical-call, duplicate-submit and attempt-identity guards are untouched.
RETRY_AFTER_CAP_S = 60.0
BACKOFF_FILE = os.environ.get("HUNTRESS_GM_BACKOFF") or os.path.join(os.path.expanduser("~"), "gm_backoff.json")


def backoff_wait(retry_after, attempt, rnd=None):
    """-> seconds to wait after a 429/502/503/504. Retry-After (numeric) wins: capped at RETRY_AFTER_CAP_S, plus 0-10% jitter; none: 0.5 * 2**attempt plus 0-25% jitter."""
    import random
    r = (rnd or random.random)()
    s = retry_after_seconds(retry_after)
    if s is not None:
        w = min(s, RETRY_AFTER_CAP_S)
        return w * (1.0 + 0.10 * r)
    w = 0.5 * 2 ** attempt
    return w * (1.0 + 0.25 * r)


def retry_after_seconds(retry_after, now=None):
    """-> seconds from a Retry-After header: delta-seconds, or (D32 gmnet, audit G8) an HTTP-date in the FUTURE; None otherwise
    (absent, garbage, or a date already past, which says nothing about how long to wait)."""
    ra = str(retry_after).strip() if retry_after is not None else ""
    if not ra:
        return None
    if ra.replace(".", "", 1).isdigit():
        return float(ra)
    try:
        t = email.utils.parsedate_to_datetime(ra).timestamp()
    except Exception:
        return None
    d = t - (time.time() if now is None else now)
    return d if d > 0 else None


# ---- 429 MINUTE HOLD (D32 gmnet, compare item 16): the GM Worker answers 429 'rate_limited' with NO Retry-After, and the window clears at the next
# clock minute (:00) - every call in between is refused (mylaptop, 47 race-window 429s). So a 429 without Retry-After holds THIS process and, through the
# shared not-before file, every other process of the machine until the next :00 of GM time (+50 ms) and then resends once. Applies to real GM traffic;
# HUNTRESS_GM_429_MINUTE=1 forces it on (tests), =0 keeps the old exponential backoff.
CLOCK = {"offset": 0.0}


def set_clock_offset(off):
    try:
        CLOCK["offset"] = float(off)
    except (TypeError, ValueError):
        pass


def until_next_minute(now=None):
    t = (time.time() if now is None else now) + CLOCK["offset"]
    return (60.0 - (t % 60.0)) + 0.05


def _minute_hold_on(conn, host):
    v = os.environ.get("HUNTRESS_GM_429_MINUTE", "")
    if v in ("0", "1"):
        return v == "1"
    return _real_remote(conn, host)


def _shared_enabled(conn, host):
    return bool(os.environ.get("HUNTRESS_GM_BACKOFF")) or _real_remote(conn, host)


SHARED_MAX_S = 125.0      # D32 gmnet (audit G8): a shared not-before up to this far ahead is honoured (was 72 s); beyond it the file is treated as corrupt


def _shared_until():
    try:
        with open(BACKOFF_FILE, encoding="ascii") as f:
            return float(json.load(f).get("until", 0))
    except Exception:
        return 0.0


def _shared_note(until, reason=""):
    """keep the LATEST 'not before' (atomic replace); never raises"""
    try:
        if until <= _shared_until():
            return
        tmp = "%s.%d.%d.tmp" % (BACKOFF_FILE, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="ascii") as f:
            json.dump({"until": round(until, 3), "pid": os.getpid(), "reason": str(reason)[:40]}, f)
        os.replace(tmp, BACKOFF_FILE)
    except Exception:
        pass


def _shared_wait_s(now=None):
    """seconds this process must still wait for a not-before another process (or this one) recorded; 0 when none"""
    rem = _shared_until() - (time.time() if now is None else now)
    return rem if 0.05 < rem <= SHARED_MAX_S else 0.0


# --- Static-contract cache (GM latency opt A, 2026-10-17; isolated worktree, NOT on the live branch) ---
# The FREE op=status / op=contract 409 start_required body (questions / answer_ids / answer_format) of an
# UN-STARTED mode is immutable until THIS process starts/retries/practices that mode, so the several readers
# that each re-read it (prebrief.gate, contract_preflight, HOF readiness) can share ONE GM round trip.
# Keyed by the exact challenge id; invalidated the moment this process issues a start/retry/practice for it.
# NEVER caches a started/live/solved body (deadline/result are mutable). Disable with HUNTRESS_NO_CONTRACT_CACHE=1.
_CONTRACT_CACHE = {}
_CONTRACT_LOCK = threading.Lock()
_CONTRACT_HITS = [0]            # test/telemetry: how many reads the cache served without a GM call
_STATUS_CACHE = {}              # GM.status short-TTL cache (HUNTRESS_GM_STATUS_TTL); D32 gmnet audit G6: created once here with its lock
_STATUS_LOCK = threading.Lock()


def _contract_cache_on():
    return os.environ.get("HUNTRESS_NO_CONTRACT_CACHE", "") not in ("1", "true", "yes", "on")


def _contract_cache_get(challenge):
    if not _contract_cache_on():
        return None
    with _CONTRACT_LOCK:
        d = _CONTRACT_CACHE.get(challenge)
        if isinstance(d, dict):
            _CONTRACT_HITS[0] += 1
            return dict(d)
    return None


def _contract_cache_put(challenge, body):
    """Store ONLY a static pre-start contract (a 409 start_required body carrying the fields). Refuse any
    body that shows a live/started/solved attempt so mutable state can never be served from the cache."""
    if not _contract_cache_on() or not isinstance(body, dict):
        return
    if not (body.get("questions") or body.get("answer_ids")):
        return
    if body.get("deadline") or str(body.get("result", "")).lower() in ("correct", "accepted", "expired"):
        return
    with _CONTRACT_LOCK:
        _CONTRACT_CACHE[challenge] = dict(body)


def _contract_cache_clear(challenge=None):
    with _CONTRACT_LOCK:
        if challenge is None:
            _CONTRACT_CACHE.clear()
        else:
            _CONTRACT_CACHE.pop(challenge, None)


# COMPETITION CUTOFF (owner, 2026-10-18, confirmed): the event ends 2026-11-01T00:00:00-04:00 (= 04:00:00Z, before the
# Nov-1 02:00 DST change). No NEW competition GM activity - any mutating op (start/retry/practice/submit) is REFUSED at
# or after that instant. Free reads (list/status/contract/openapi) stay allowed for post-event audit. (Some docs said
# 09:00 ET; the owner's 00:00:00 EDT governs. This is a protective guard, not an enablement of any new behavior.)
EVENT_CUTOFF_EPOCH = 1793505600          # 2026-11-01T04:00:00Z = 2026-11-01T00:00:00 America/New_York (EDT, UTC-4)


class EventEnded(RuntimeError):
    """Raised when a mutating GM op is attempted at/after the competition cutoff. Nothing is sent."""


def _now_epoch():
    o = os.environ.get("HUNTRESS_NOW_EPOCH")     # TEST-ONLY override (simulate a time); production uses the real clock
    try:
        return float(o) if o else time.time()
    except ValueError:
        return time.time()


def event_over():
    return _now_epoch() >= EVENT_CUTOFF_EPOCH


_GMS = weakref.WeakSet()          # every GM built by __init__ (D32 gmnet: the exit hook saves their unsubmitted timed attempts)


_STALE_EXC = (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, ConnectionAbortedError)
NO_RETRY_CODES = ("release_unavailable",)       # a coded 5xx that is an ANSWER for a GET too (a list before 09:00): retrying it only delays the poller
IDLE_UNUSED_S = float(os.environ.get("HUNTRESS_GM_IDLE_UNUSED_S", "12"))     # the GM closes a connected-but-unused socket ~15 s after connect
IDLE_USED_S = float(os.environ.get("HUNTRESS_GM_IDLE_USED_S", "150"))        # an answered socket stayed open > 180 s (mylaptop day-11 test)
_NOSOCK = object()


class PostOutcomeUnknown(RuntimeError):
    """D32 gmnet (external audit item 1): a start/submit/retry/practice POST got no usable answer after it may have reached the GM (read timeout, a reply cut off,
    an uncoded 5xx). It is NOT resent; GM._post reads op=status once and returns that state when it proves the write happened, otherwise this is raised."""


class IncidentHold(RuntimeError):
    """a GM incident (a 5xx on a timed write) is open on this machine: no timed write is sent until it is resolved (gm_incident.py)"""


class ArtifactUnavailable(RuntimeError):
    """D32 gmnet (audit G1): the download answered an error/state body, or bytes that do not match the GM-published sha256. Never cached."""


class RerollRefused(RuntimeError):
    """the re-roll cap or the crashed-run hold of gm_timed.py refused an op=retry on a timed tier. Nothing was sent."""


def _post_legacy():
    return os.environ.get("HUNTRESS_GM_POST_RESEND", "").lower() == "legacy"


def _https(conn):
    return isinstance(conn, http.client.HTTPSConnection)


def _gzip_on():
    return os.environ.get("HUNTRESS_GM_GZIP", "1") != "0"


def _err_code(d):
    try:
        j = json.loads(d.decode("utf-8", "replace") if isinstance(d, (bytes, bytearray)) else d)
        if isinstance(j, dict):
            return str(j.get("error") or j.get("code") or "")
    except Exception:
        pass
    return ""


def _incident_mod(conn, host):
    try:
        import gm_incident as _gi
        return _gi if _gi.enabled(_real_remote(conn, host)) else None
    except Exception:
        return None


class GM:
    def __init__(self, host=None, timeout=5.0):
        tok = None if os.environ.get("GM_MODE") == "vm" else _load_token()
        self._tok = tok
        if tok and host is None:                      # public HTTPS + bearer
            self.host, self.timeout = PUB_HOST, timeout
            self.path = "/"
            self._c = http.client.HTTPSConnection(PUB_HOST, timeout=timeout)
        else:                                         # in-VM fallback
            self.host, self.timeout = (host or GM_HOST), timeout
            self.path = GM_PATH
            self._c = http.client.HTTPConnection(self.host, timeout=timeout)
        _GMS.add(self)
        # Warm the accepted-values cache NOW, in the background. format_gate reads it between compute and a (possibly ranked) submit;
        # parsing a populated store costs ~29 ms on the FIRST call in a process (2.8 ms when empty), which would land on the ranked
        # attempt. start -> download -> compute takes at least one network round trip, so the parse overlaps time spent waiting anyway.
        def _warm():
            try:
                import accepted_values
                accepted_values.load_cached()
            except Exception:
                pass
        threading.Thread(target=_warm, name="av-warm", daemon=True).start()

    # ---- D32 gmnet socket bookkeeping: when the socket was connected, how many answers it carried, when the last one arrived ----
    def _net(self):
        n = self.__dict__.get("_netst")
        if n is None:
            n = self.__dict__["_netst"] = {"t0": None, "n": 0, "last": None}
        return n

    def _net_prepare(self):
        """Before a send: replace a socket the GM is about to close (connected but unused > IDLE_UNUSED_S, or idle > IDLE_USED_S since its last
        answer), then connect EXPLICITLY, so a connect failure is known to be PRE-SEND (nothing reached the GM). A test double without a
        socket attribute is left alone. HUNTRESS_GM_IDLE_REFRESH=0 turns the refresh off."""
        c = getattr(self, "_c", None)
        sock = getattr(c, "sock", _NOSOCK)
        if sock is _NOSOCK:
            return
        n = self._net()
        if sock is not None and n["t0"] is not None and os.environ.get("HUNTRESS_GM_IDLE_REFRESH", "1") != "0":
            now = time.time()
            if (n["n"] == 0 and now - n["t0"] > IDLE_UNUSED_S) or (n["last"] is not None and now - n["last"] > IDLE_USED_S):
                self._reconnect()
                c, n = self._c, self._net()
                sock = getattr(c, "sock", None)
        if sock is None and hasattr(c, "connect"):
            c.connect()
            n["t0"], n["n"], n["last"] = time.time(), 0, None

    def _net_answered(self):
        n = self._net()
        now = time.time()
        if n["t0"] is None:
            n["t0"] = now
        n["n"] += 1
        n["last"] = now

    def _call(self, method, path, payload=None, _raw=False):
        path = path.replace(GM_PATH, self.path, 1) if path.startswith(GM_PATH) else path
        if _no_real_gm(self._c, self.host):
            raise RuntimeError("REFUSED: HUNTRESS_NO_REAL_GM=1 and %s %s would go to the REAL Game Master. Tests use a local fake or gm_sim.py." % (method, path[:60]))
        # HALL-OF-FAME ENTRY is allowed only through hof_policy (user 2026-10-19: try the ranked timed entry, op=practice as the fallback). Outside that path run_for_time is still dropped.
        # ONE choke point for every writer in the framework (the adapters' for_time, GM.start's heal branches, autosolve_script's heal branches, a hand-typed gm._post): the run_for_time key
        # is dropped from any outgoing body, True or False. A plain request is the pre-Hall-of-Fame behaviour; on legacy routes even False is refused (409).
        _hof = ""
        if isinstance(payload, dict) and "run_for_time" in payload and not (_hof_switch_on() and getattr(self, "_hof_ok", False)):       # 2026-10-16: the ONLY exception = the user's switch is ON (hof_policy.py; OFF = byte-for-byte the old behaviour) AND this call is inside GM.start(for_time=True), i.e. autosolve's policy decision; a hand-typed or heal-branch run_for_time is still dropped
            payload = {k: v for k, v in payload.items() if k != "run_for_time"}
            _hof = "run_for_time dropped by policy"
        _consume = _check_timed_start(payload)                # no blind timed start: refused before anything is sent; True = a gate-pass slot to consume when the write SUCCEEDS
        _inc = _incident_mod(self._c, self.host)
        _timed_write = _inc is not None and _inc.is_timed_write(payload)
        if _timed_write:                                      # D32 gmnet: an open GM incident holds every timed write of this machine (nothing is sent)
            _a = _inc.active()
            if _a:
                raise IncidentHold("HELD: GM incident open since %s (HTTP %s %s on %s); no timed write is sent until it is resolved (python3 challenges/_lib/gm_incident.py resolve). Nothing was sent."
                                   % (time.strftime("%H:%M:%S", time.localtime(float(_a.get("opened", 0)))), _a.get("status"), _a.get("error"), _a.get("challenge")))
        body = None if payload is None else json.dumps(payload, separators=(",", ":"))
        hdr = {"Content-Type": "application/json"} if body is not None else {}
        if self._tok and _https(self._c):                      # D32 gmnet (audit G2): the bearer only ever travels over TLS
            hdr["Authorization"] = "Bearer " + self._tok
        _is_dl = ("op=download" in path) or ("op=artifact" in path)
        if not _is_dl and _gzip_on():
            hdr["Accept-Encoding"] = "gzip"                  # JSON only: a 523 kB mastery start crossed in 29 kB (mylaptop); downloads are ZIP and never compressed
        _key = (method, path, body)
        _failed = self.__dict__.setdefault("_failed", {})   # per client instance: a poller keeps ONE client, so it is guarded; separate clients/tests do not leak into each other
        _chal = ""
        try:
            _chal = str((json.loads(body) if body else {}).get("challenge", ""))
        except Exception:
            pass
        if GUARD_S > 0:                                   # NO HAMMERING: an identical call the GM refused moments ago is not sent again until something changes (or GUARD_S passes)
            _f = _failed.get(_key)
            if _f and time.time() - _f[0] < GUARD_S:
                raise RepeatFailure("identical call refused %.0fs ago (%s); NOT sent again for %.0fs - change the request, the route or wait (no polling loops)" % (time.time() - _f[0], _f[1], GUARD_S - (time.time() - _f[0])))
        _t0, _waited = time.time(), 0.0
        # Rate limits / gateway hiccups / dropped keep-alive: back off and retry (honour Retry-After). At the 09:00 release
        # every agent's autosolve hits the GM at once, and a 429 used to surface as a plain error = a false "wrong answer".
        # D32 gmnet (external audit item 1): a POST (start/submit/retry/practice) is resent ONLY after a 429 (refused before any work) or when a
        # kept-alive socket died BEFORE any reply (the request never reached the GM), once, on a fresh socket. A read timeout, a cut-off reply or a
        # 5xx is NOT resent (it may already have been applied: a double submit or a second variant); GM._post then reads op=status once.
        # HUNTRESS_GM_POST_RESEND=legacy restores the old resend-everything loop.
        _shared = _shared_enabled(self._c, self.host)
        _strict_post = method == "POST" and not _post_legacy()
        _one = bool(self.__dict__.get("_one_shot"))           # gm_net.hedged_list: one send, no backoff sleep inside a release hedge
        _resent = False
        _bud = _budget_mod(self._c, self.host)                # D32 auto (item A): one request budget per calendar minute for the whole machine
        _clock_req = _WIN["deadline"] is not None or (isinstance(payload, dict) and payload.get("run_for_time") is True)
        for attempt in range(5):
            if _shared:                                       # another process of this machine was told to back off: wait that out instead of sending a request that would be refused
                _rem = _shared_wait_s()
                if _rem:
                    if _one:
                        raise RuntimeError("GM HTTP 429 hold: a shared not-before is in force for %.1fs; not sent" % _rem)
                    _check_window(_rem)
                    _waited += _rem
                    time.sleep(_rem)
            if _bud is not None:                              # take a slot of this minute BEFORE sending; untimed traffic yields to a running clock
                try:
                    _waited += _bud.acquire(clock=_clock_req, offset=CLOCK["offset"], one_shot=_one, check=_check_window,
                                            low=bool(self.__dict__.get("_budget_low")))
                except _bud.BudgetExceeded as _be:
                    raise RuntimeError(str(_be))
            _pre, _reused = True, False
            try:
                self._net_prepare()
                _pre = False
                _reused = self._net()["n"] > 0 if getattr(self._c, "sock", _NOSOCK) is not _NOSOCK else True
                _tq = time.time()
                _tm = time.perf_counter()
                self._c.request(method, path, body=body, headers=hdr)
                r = self._c.getresponse(); _ttfb = time.time() - _tq
                _first_byte_epoch = time.time()
                d = r.read()
                _complete_epoch = time.time()
                self._net_answered()
                self._last_request_timing = {
                    "request_send_epoch": _tq,
                    "response_first_byte_epoch": _first_byte_epoch,
                    "response_complete_epoch": _complete_epoch,
                    "response_first_byte_ms": round(_ttfb * 1000, 3),
                    "response_complete_ms": round((time.perf_counter() - _tm) * 1000, 3),
                    "status": r.status,
                }
            except (http.client.HTTPException, OSError) as _ex:
                if _strict_post and not _pre:
                    if isinstance(_ex, _STALE_EXC) and _reused and not _resent:
                        _resent = True                        # the kept-alive socket was dead before any reply: the GM never saw it; one resend on a fresh socket
                        self._reconnect()
                        continue
                    self._reconnect()
                    _ledger(method, body, 0, time.time() - _t0, _waited, "POST outcome unknown: %s" % type(_ex).__name__, real=_real_remote(self._c, self.host), path=path)
                    _e = PostOutcomeUnknown("GM %s %s: no usable reply (%s); NOT resent (it may have been applied)" % (method, (payload or {}).get("op"), type(_ex).__name__))
                    _e.status_code, _e.op, _e.challenge = 0, (payload or {}).get("op"), _chal
                    raise _e from _ex
                if attempt == 4 or _one:
                    raise
                _check_window(0.5 * 2 ** attempt)
                _waited += 0.5 * 2 ** attempt
                self._reconnect(); time.sleep(0.5 * 2 ** attempt); continue
            try:
                if "gzip" in str(r.getheader("Content-Encoding") or "").lower():
                    d = gzip.decompress(d)
            except Exception:
                pass
            if r.status in (429, 502, 503, 504) and attempt < 4:
                if _strict_post and r.status != 429:
                    break                                     # a POST is never resent on a 5xx (coded = an answer, uncoded = outcome unknown)
                if r.status != 429 and _err_code(d) in NO_RETRY_CODES:
                    break                                     # e.g. release_unavailable: the GM's answer, not a hiccup
                ra = r.getheader("Retry-After")
                wait = backoff_wait(ra, attempt)
                if r.status == 429 and retry_after_seconds(ra) is None and _minute_hold_on(self._c, self.host):
                    import random as _rnd
                    wait = until_next_minute() + 0.15 * _rnd.random()      # the GM's 429 window clears at the next :00 of its clock
                _throttle_rec(self, method, path, body, r, r.status, ra, wait)   # record Retry-After + rate headers for Day-13 backoff calibration (before _check_window, which may raise)
                if _shared and r.status == 429:
                    _shared_note(time.time() + wait, "429")  # tell this machine's other processes (they read it before their next request)
                if _one:
                    break
                _check_window(wait)          # inside a timed window a long wait is fatal: raise WindowExpired instead of sleeping past the deadline
                _waited += wait
                time.sleep(wait)
                continue
            break
        if _timed_write and r.status >= 500:
            _inc.open_incident(r.status, _err_code(d), _chal)  # the first 5xx on a timed write opens the machine-wide incident
        if r.status >= 400 and not _state_body(d):
            if GUARD_S > 0 and 400 <= r.status < 500 and r.status != 429 and not (_raw and r.status == 409):
                _failed[_key] = (time.time(), "HTTP %s %s" % (r.status, d[:70].decode("utf-8", "replace")))
            _ledger(method, body, r.status, time.time() - _t0, _waited, d[:120].decode("utf-8", "replace"), real=_real_remote(self._c, self.host), path=path, size=len(d), ttfb=_ttfb, hdrs=_hdr_dict(r))
            _record(self, method, path, body, r.status, d)
            if _raw:
                return r.status, d
            if _strict_post and r.status >= 500 and not _err_code(d):
                _e = PostOutcomeUnknown("GM HTTP %s (uncoded) on %s: NOT resent (it may have been applied)" % (r.status, (payload or {}).get("op")))
                _e.status_code, _e.op, _e.challenge = r.status, (payload or {}).get("op"), _chal
                raise _e
            _err = RuntimeError(f"GM HTTP {r.status}: {d[:200]!r}")
            _err.status_code = r.status
            try:
                _err.retry_after = retry_after_seconds(r.getheader("Retry-After"))
            except (TypeError, ValueError):
                _err.retry_after = None
            raise _err
        if _chal:                                          # a SUCCESS for this challenge means its state changed: earlier refusals no longer describe it
            for _k in [k for k in _failed if _chal in (k[2] or "")]:
                _failed.pop(_k, None)
        _failed.pop(_key, None)
        _ledger(method, body, r.status, time.time() - _t0, _waited, _hof, real=_real_remote(self._c, self.host), path=path, size=len(d), ttfb=_ttfb, hdrs=_hdr_dict(r))
        if _consume:
            with _TIMED_LOCK:
                _TIMED_AUTH[0] = max(0, _TIMED_AUTH[0] - 1)   # the gate pass's ONE timed write has succeeded
        _record(self, method, path, body, r.status, d, timing=getattr(self, "_last_request_timing", None))
        if _raw:
            return r.status, d
        return d

    def _clone(self):
        """A second GM with its OWN socket, same identity. http.client connections are NOT safe to share between
        threads (interleaved request/getresponse on one socket corrupts both), so every parallel worker gets one."""
        g = GM.__new__(GM)
        g._tok, g.host, g.timeout, g.path = self._tok, self.host, self.timeout, self.path
        g._timed_ctx = self._ctx()                     # parallel downloads land in the SAME timed-corpus record as the parent's start
        cls = http.client.HTTPSConnection if self.path == "/" else http.client.HTTPConnection
        g._c = cls(self.host, timeout=self.timeout)
        return g

    def download_many(self, challenge, entries, workers=None, straggler=None):
        """Fetch several assigned artifacts CONCURRENTLY, returned in the SAME ORDER as `entries`.

        Why (measured from the homestation 2026-10-10): one GM round trip is ~400 ms, and the binary lane now
        carries one artifact per day block (d01..dNN), so the old sequential loop cost ~400 ms x N and grew by
        400 ms EVERY DAY of the event. Parallel fetch makes that a flat ~one round trip.
        D32 gmnet (compare item 19): 6 workers by default (HUNTRESS_GM_DL_WORKERS), and a STRAGGLER HEDGE: a download
        still running when it is at least 1.5 s old AND 4x the median of the finished ones gets ONE duplicate on another
        socket; the first copy to arrive wins (downloads ignore Range, so a slow file cannot be split, only re-raced).
        No duplicate is sent while a 429 hold is in force. HUNTRESS_GM_STRAGGLER=0 turns the hedge off.

        Index `i` is preserved because adapters address blobs positionally. Any failure falls back to a plain
        sequential fetch on the main connection, so this can never turn a working solve into a failed one."""
        entries = list(entries)
        if len(entries) < 2:
            return [self.download(challenge, e, i) for i, e in enumerate(entries)]
        if workers is None:
            try:
                workers = int(os.environ.get("HUNTRESS_GM_DL_WORKERS", "6"))
            except ValueError:
                workers = 6
        if straggler is None:
            straggler = os.environ.get("HUNTRESS_GM_STRAGGLER", "1") != "0"
        out = [None] * len(entries)
        self.__dict__["_dl_dups"] = 0
        try:
            local = threading.local()

            def fetch(i, e, dup):
                g = getattr(local, "gm", None)
                if g is None:
                    g = local.gm = self._clone()
                if not dup:
                    return g.download(challenge, e, i)
                try:
                    return g.download(challenge, e, i, _dup=True)
                except TypeError:                          # a download() double without the _dup keyword
                    return g.download(challenge, e, i)

            ex = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(entries))) + (2 if straggler else 0))
            try:
                futs = {}
                for i, e in enumerate(entries):
                    futs[ex.submit(fetch, i, e, False)] = (i, time.time())
                durs, dups, pending = [], set(), set(futs)
                while pending:
                    done, pending = cf.wait(pending, timeout=0.1, return_when=cf.FIRST_COMPLETED)
                    for f in done:
                        i, t0 = futs[f]
                        if out[i] is not None:
                            continue
                        try:
                            out[i] = f.result()
                            durs.append(time.time() - t0)
                        except Exception:
                            if not any(futs[p][0] == i for p in pending):
                                raise                                  # no twin left for this file: fall back below
                    pending = {p for p in pending if out[futs[p][0]] is None}
                    if straggler and durs and pending and not _shared_wait_s():
                        med = sorted(durs)[len(durs) // 2]
                        now = time.time()
                        for p in list(pending):
                            i, t0 = futs[p]
                            age = now - t0
                            if i not in dups and age >= 1.5 and age >= 4.0 * med:
                                dups.add(i)
                                nf = ex.submit(fetch, i, entries[i], True)
                                futs[nf] = (i, now)
                                pending.add(nf)
                                self.__dict__["_dl_dups"] += 1
            finally:
                ex.shutdown(wait=False)
            if all(b is not None for b in out):
                return out
        except Exception:
            pass
        return [out[i] if out[i] is not None else self.download(challenge, e, i) for i, e in enumerate(entries)]

    def _reconnect(self):
        try:
            self._c.close()
        except Exception:
            pass
        cls = http.client.HTTPSConnection if self.path == "/" else http.client.HTTPConnection
        self._c = cls(self.host, timeout=self.timeout)
        self.__dict__["_netst"] = None

    def _ctx(self):
        """{challenge: {'start': dict, 'blobs': {i: bytes}}} for the timed corpus; created lazily (GM.__new__ in tests and clones skips __init__)"""
        if getattr(self, "_timed_ctx", None) is None:
            self._timed_ctx = {}
        return self._timed_ctx

    def _exchange(self, method, path, payload=None):
        """-> (http_status, body) through the one transport (_call with _raw=True). A test double that replaced _call on this INSTANCE
        (older signature, no _raw) is honoured: its body is taken as a 200."""
        own = self.__dict__.get("_call")
        if own is not None:
            return 200, (own(method, path, payload) if payload is not None else own(method, path))
        return self._call(method, path, payload, _raw=True)

    def _get(self, **q):
        _check_boundary("GET", q.get("op"), q.get("challenge"))
        return json.loads(self._call("GET", GM_PATH + "?" + urllib.parse.urlencode(q)))

    def _recover_from_status(self, pl, err):
        """D32 gmnet (external audit item 1): a write whose outcome is unknown is NOT resent. Read op=status ONCE (this is the failure path only,
        never in front of a healthy start or submit) and return it when it proves the write happened; otherwise re-raise the original error."""
        op, ch = pl.get("op"), pl.get("challenge")
        try:
            st = self._get(op="status", challenge=ch)
        except Exception:
            raise err
        if not isinstance(st, dict):
            raise err
        res = str(st.get("result") or "").strip().upper()
        if op == "submit":
            if res == "CORRECT" or st.get("solved") is True:
                return {"result": "CORRECT", "flag": st.get("flag"), "solved_by": st.get("solved_by"), "_recovered_from_status": True}
            raise err
        try:
            import gm_next_op as _gno
            finished = _gno.terminal(st)
        except Exception:
            finished = res in ("EXPIRED",)
        prev = (getattr(self, "last_launch", None) or {}).get("attempt_id") if op == "retry" else None
        if (st.get("attempt_id") or st.get("deadline")) and not finished and not (prev and st.get("attempt_id") == prev):
            return dict(st, _recovered_from_status=True)
        raise err

    def _post(self, **pl):
        if event_over():                                    # owner cutoff: no new GM activity after 2026-11-01T00:00:00-04:00
            raise EventEnded("REFUSED op=%s on %s: the competition ended 2026-11-01T00:00:00-04:00; no new GM activity. Nothing was sent."
                             % (pl.get("op"), pl.get("challenge", "")))
        op = pl.get("op")
        _check_boundary("POST", op, pl.get("challenge"))
        if op in ("start", "retry", "practice", "submit") and pl.get("challenge"):
            _contract_cache_clear(pl["challenge"])          # our own mutating op changes the attempt: drop any cached pre-start contract
            # D31 HS 2026-10-30: drop any cached status for this challenge too; a start/retry/submit
            # changes attempt state and a stale cached status after it would mislead downstream.
            try:
                _STATUS_LOCK.acquire()
                try:
                    _STATUS_CACHE.pop(pl["challenge"], None)
                finally:
                    _STATUS_LOCK.release()
            except Exception:
                pass
        try:
            d = json.loads(self._call("POST", GM_PATH, pl))
        except PostOutcomeUnknown as e:
            if op not in ("start", "retry", "practice", "submit") or not pl.get("challenge"):
                raise
            d = self._recover_from_status(pl, e)
        try:                                            # D32 gmnet: the timed-corpus record is opened by ANY timed write that returns an attempt (autosolve_script opens attempts
            ch = str(pl.get("challenge") or "")        # with gm._post directly, so GM.start alone never saw them and its bytes were never saved)
            if op in TIMED_WRITE_OPS and _is_timed(ch) and isinstance(d, dict) and (d.get("answer_ids") or d.get("questions") or d.get("attempt_id")):
                self._ctx()[ch] = {"start": d, "blobs": {}}
        except Exception:
            pass
        return d

    def list(self, **q):          return self._get(op="list", **q).get("challenges", [])
    def openapi(self):            return self._get(op="openapi")
    def status(self, challenge):
        """D31 HS 2026-10-30 (fork 1 finding: 94 status calls on D30 summed 182 s; many are repeat
        reads from mode_prediction + prebrief + autosolve re-entry on the same (challenge) within
        2 s of each other). Short-TTL (2 s) in-process cache dedupes those; clears on any
        start/submit/retry (those mutate attempt state and run through _call where the contract
        cache is already cleared). Opt-in via HUNTRESS_GM_STATUS_TTL env (seconds, default 0 = off
        for safety on D31 last day). ZERO behavioural change when the env is unset or 0.
        Shared via module-level dict guarded by a short-lived lock; thread-safe for CPython."""
        try:
            ttl = float(os.environ.get("HUNTRESS_GM_STATUS_TTL", "0") or "0")
        except Exception:
            ttl = 0.0
        if ttl <= 0:
            return self._get(op="status", challenge=challenge)
        now = time.monotonic()                     # D32 gmnet (audit G6): cache + lock are created once at import, never lazily
        with _STATUS_LOCK:
            hit = _STATUS_CACHE.get(challenge)
            if hit is not None and (now - hit[0]) < ttl:
                return hit[1]
        val = self._get(op="status", challenge=challenge)
        with _STATUS_LOCK:
            _STATUS_CACHE[challenge] = (now, val)
        return val

    def contract(self, challenge):
        """FREE READ of a mode's public questions contract (agent-2, 2026-10-11): op=status on a mode that is NOT started answers 409 start_required WITH the full contract (every answer id,
        answer_format, syntax, normalization, artifact reference). _call raises on a 409 and truncates the body to 200 bytes, so this reads the response itself, on its own connection.
        -> the parsed dict (200 or 409), or None for anything else / any failure. Never raises, never starts or retries anything, one call."""
        cached = _contract_cache_get(challenge)       # GM latency opt A: a prior reader already fetched this un-started contract
        if cached is not None:
            return cached
        g = None
        try:
            if _no_real_gm(getattr(self, "_c", None), getattr(self, "host", None)):      # getattr: the free read must work on a partially built client (tests build one with __new__)
                return None
            if not valid_challenge(challenge):
                return None
            # D32 gmnet (audit G7): through the ONE transport (_call with _raw=True): shared 429 not-before, repeat guard, ledger, record, gzip and
            # the TLS-only bearer all apply; the clone's socket is closed afterwards instead of leaking one per call.
            g = self._clone()
            path = GM_PATH + "?" + urllib.parse.urlencode({"op": "status", "challenge": challenge})
            if isinstance(g, GM):
                g.__dict__["_failed"] = self.__dict__.setdefault("_failed", {})
                status, d = g._exchange("GET", path)
            else:                                         # a test double clone that only carries a connection: read it directly, as before
                hdr = {"Authorization": "Bearer " + self._tok} if self._tok and _https(g._c) else {}
                p2 = path.replace(GM_PATH, self.path, 1) if path.startswith(GM_PATH) else path
                g._c.request("GET", p2, headers=hdr)
                r = g._c.getresponse()
                status, d = r.status, r.read()
            if status in (200, 409):
                j = json.loads(d.decode("utf-8", "replace"))
                if isinstance(j, dict):
                    if status == 409:                     # 409 start_required = the static pre-start contract; safe to cache
                        _contract_cache_put(challenge, j)
                    return j
        except Exception:
            pass
        finally:
            try:
                if g is not None:
                    g._c.close()
            except Exception:
                pass
        return None

    def _tiers(self):
        """gm_timed when it applies to this client (real GM, or a test that named HUNTRESS_GM_TIER_FILE), else None"""
        try:
            import gm_timed as _gt
            return _gt if _gt.enabled(_real_remote(getattr(self, "_c", None), getattr(self, "host", None))) else None
        except Exception:
            return None

    def retry(self, challenge):
        """op=retry. D32 gmnet (compare item 15): on a timed tier at most HUNTRESS_GM_REROLL_CAP (2) re-rolls per day, and none while the
        tier's last run crashed (gm_timed.may_reroll). Refused before anything is sent."""
        gt = self._tiers() if _is_timed(challenge) else None
        if gt is not None:
            ok, why = gt.may_reroll(challenge)
            if not ok:
                raise RerollRefused("REFUSED op=retry on %s: %s. Nothing was sent." % (challenge, why))
        d = self._post(op="retry", challenge=challenge)
        if gt is not None:
            gt.note_reroll(challenge)
        return d

    def attempt_state(self, cid, mode="single_solve"):
        """FREE READ of the current attempt state for a (cid, mode) pair.

        D27 next-phase Item B (operator directive 3 section 2): the single
        authoritative helper autosolvers call BEFORE any start/retry/practice
        on a rerun. Combines GM.status (for a started mode) with the
        GM.contract 409 free-read (for a NOT-STARTED mode). Returns the
        structured dict defined in _classify_attempt_state. Never raises;
        falls back to UNKNOWN when the GM is offline or unreachable.
        """
        # D27 review fix (B3): reject unknown mode values rather than silently
        # mapping to single_solve. A typo like "timed_trial" or "MASTERY" would
        # have mis-routed as a Single query; the caller must fail-closed and
        # pick a known mode. Returns the UNKNOWN classification skeleton so
        # the "never raises" contract is preserved.
        _modes = {"single_solve": "", "time_trial": "/time_trial",
                  "mastery": "/mastery"}
        if mode not in _modes:
            return _classify_attempt_state({"challenge": cid})
        entry = cid + _modes[mode]
        st = None
        try:
            st = self.status(entry)
        except Exception:
            st = None
        if not isinstance(st, dict) or not st:
            # NOT-STARTED mode -> read the free contract (409 start_required).
            try:
                st = self.contract(entry)
            except Exception:
                st = None
        return _classify_attempt_state(st or {"challenge": entry})

    def practice(self, challenge):
        """op=practice: the UNTIMED continuation the GM itself names in status.next_op once a timed route's rotation is
        spent (official README rule 5: after the final variant, retry answers rotation_exhausted and a CORRECT practice
        submission can STILL complete the mode and unlock the next one; the GM marks "practice":true).
        It is a TIMED_WRITE op, so the gate guard above governs it exactly like start/retry. Never takes run_for_time
        (op=practice is a plain continuation; invalid_run_for_time otherwise)."""
        return self._post(op="practice", challenge=challenge)

    def submit(self, challenge, answers):
        """Submit, then bank every field the GM ACCEPTED (2026-10-10, homestation).

        Hooked HERE rather than in solve_mode() because the lane adapters (autosolve_script, autosolve_binary)
        call gm.submit directly, so this is the one place every accepted answer passes through. accepted_values
        records only on CORRECT/accepted, keeps enum vocabularies, and deliberately DISCARDS the values of
        per-attempt fields so none of this can ever be mistaken for a reusable answer. It never raises."""
        answers = _alt_pre(self, challenge, answers)          # a spelling a Single Solve already banked for this challenge (no-op when none / when probing)
        _key = _guard_submit(self, challenge, answers)
        _t_send = time.time()
        res = self._post(op="submit", challenge=challenge, answers=answers)
        self.last_submit = {"challenge": challenge, "t_send": _t_send, "t_resp": time.time()}     # stage timing for the ranked critical path (autosolve logs it as hof_timing); two floats, no I/O
        # 'accepted' is the GM's answer to a PARTIAL batch it banked in full: those answers were right, so the batch is
        # not wrong and must not be blocked from being sent again (Day 15: a banked single-field probe poisoned the store
        # and the next run refused its own correct submit).
        _rs = str((res or {}).get("result", "")).strip().lower()
        try:                                                  # D32 gmnet: the run reached a GM verdict -> it is no longer an unsubmitted/crashed run
            rec0 = self._ctx().get(challenge) if _is_timed(challenge) else None
            if rec0 is not None:
                rec0["submitted"] = True
            gt = self._tiers() if _is_timed(challenge) else None
            if gt is not None and _rs:
                gt.note_run(challenge, _rs)
        except Exception:
            pass
        # D32 gmnet (audit G3): only a real INCORRECT verdict marks the batch wrong. 'expired', 'already_solved', an error or an empty reply say
        # nothing about the answers; remembering them as wrong refused correct answers locally on the next run.
        if _rs in WRONG_VERDICTS:
            sub = self.__dict__["_sub"]; sub["wrong"].add(_key)  # an identical resubmit of a batch the GM did not fully accept cannot succeed
            if _wrong_enabled() and self.host == PUB_HOST:       # ...and remember it ACROSS process restarts so a re-run never re-sends the same wrong batch. REAL GM only: a fake/offline-test GM must not write [credential store]
                _wrong_save(sub.get("wrong_day", _wrong_day(challenge)), sub["wrong"])
            try:                                                 # D31 HS (WS review): a Web proof the GM refused must never be reused by the per-attempt proof cache
                import web_proof_cache as _wpc
                _wpc.retire_matching(answers)
            except Exception:
                pass
        # Bank ONLY what the REAL Game Master accepted. A fake/local GM (the offline tests spin one up over real
        # HTTP) accepts by construction, so its "accepted" values are meaningless and would poison the store -
        # caught when _test_gm_http.py wrote a literal 'x' into kb/accepted_values.json on the first suite run.
        if self.host == PUB_HOST:
            try:
                import accepted_values
                m = re.search(r"-day-(\d+)", str(challenge))
                accepted_values.record_async(answers, res, day=int(m.group(1)) if m else None)   # off the solve path
            except Exception:
                pass      # banking is bookkeeping: it must never be able to fail a solve
            try:          # TIMED CORPUS: a timed attempt's real bytes + the answers we sent, written off the solve path.
                # Day 15 (homestation): this used to save only a CORRECT attempt, so an INCORRECT timed attempt threw its
                # bytes away and there was nothing left to diagnose offline - the one case where the corpus is needed most.
                # Saved for every result now; the folder name is the attempt_id, so a later CORRECT attempt cannot be hidden.
                rec = self._ctx().get(challenge) if _is_timed(challenge) else None
                if rec:
                    threading.Thread(target=save_timed_corpus, args=(challenge, rec.get("start"), dict(rec.get("blobs") or {}), dict(answers or {}), dict(res or {})),
                                     daemon=False).start()
            except Exception:
                pass
        return _alt_post(self, challenge, answers, res)      # Single Solve only: settle a contested spelling with SUBSET probes (answer_alternates.py); otherwise returns res untouched

    def start(self, challenge, for_time=False):
        """see _start_inner. Also OPENS the timed-window budget when a timed route answers with a live deadline, so every later call of this attempt is protected."""
        self._hof_ok = bool(for_time) and _hof_switch_on()          # a ranked request is allowed to reach the wire ONLY from here (autosolve asked for it after hof_policy.decide)
        _t_send = time.time()
        try:
            st = self._start_inner(challenge, for_time)
        finally:
            self._hof_ok = False
        _t_resp = time.time()
        _alt_capture_formats(self, challenge, st)
        if isinstance(st, dict):
            self.last_launch = {"challenge": challenge, "ranked": None, "ranked_requested": bool(for_time),
                                "attempt_id": st.get("attempt_id"), "deadline": st.get("deadline"),
                                "unique_attempts_remaining": st.get("unique_attempts_remaining"),
                                "t_send": _t_send, "t_resp": _t_resp}
        try:
            timed = challenge.endswith("/time_trial") or challenge.endswith("/mastery")
            if timed and isinstance(st, dict) and st.get("deadline") and str(st.get("result", "")).lower() != "expired":
                open_window(st.get("deadline"))
            if timed and isinstance(st, dict):
                self._ctx()[challenge] = {"start": st, "blobs": {}}      # a fresh attempt replaces any older record for this route
        except Exception:
            pass                                  # the budget is a safety net; it must never break a start
        if for_time and _hof_switch_on():         # ranked was REQUESTED: judge the GM's own response, not our request. Never restarts or retries anything; it only says (and records) what the GM actually opened.
            try:
                import hof_policy
                v = hof_policy.verify_launch(st)
                self.last_launch = {"challenge": challenge, "ranked": v["ranked"], "why": v["why"], "t_send": _t_send, "t_resp": _t_resp,
                                    "attempt_id": (st or {}).get("attempt_id"), "deadline": (st or {}).get("deadline"),
                                    "unique_attempts_remaining": (st or {}).get("unique_attempts_remaining")}      # preserve the server state from THIS response; no extra GM request
                print("HOF %s: %s (%s)" % (challenge.rsplit("/", 1)[-1], "RANKED attempt confirmed by the GM" if v["ranked"] else "NOT ranked per the GM - continuing with the attempt as it is, no restart", v["why"]), flush=True)
            except Exception:
                pass
        return st

    def prime_single_start(self, challenge, st):
        """GM latency opt B (2026-10-17, worktree): hand this GM the full op=start body the STAGER already
        fetched for an UNTIMED Single, so the Single's first start() reuses it instead of POSTing op=start a
        second time (on an untimed Single a second start only RESUMES the same attempt - evidenced for untimed
        routes). Timed routes are never primed. Disable with HUNTRESS_NO_START_REUSE=1."""
        if os.environ.get("HUNTRESS_NO_START_REUSE", "") in ("1", "true", "yes", "on"):
            return
        if challenge.endswith(("/time_trial", "/mastery")):
            return
        if not isinstance(st, dict) or not (st.get("answer_ids") or st.get("questions")):
            return
        low = _state_text(st)
        if "expired" in low or "flag_unavailable" in low:          # a stale/dead staged start must not be reused
            return
        if getattr(self, "_single_start", None) is None:
            self._single_start = {}
        self._single_start[challenge] = st

    def _start_inner(self, challenge, for_time=False):
        """Start or resume exactly the server operation requested by the caller.

        Dual-pool fix (Day 08): a timed route (<id>/time_trial, <id>/mastery) defaults to the
        UNtimed 'training' pool, which can be exhausted/invalid -> GM 503 training_rotation_invalid.
        Opt into the ranked timed pool with run_for_time:true, which provisions a fresh variant.
        Single Solve and non-timed routes do not accept run_for_time, so only timed routes retry.

        HALL OF FAME (for_time=True, 2026-10-09): on a timed route, open a FRESH RANKED (Hall-of-Fame)
        attempt from the first call. Confirmed by live probe: a mode already solved UNTIMED cannot be
        re-ranked (run_for_time on a solved mode just returns the solved state), so the ranked attempt
        must be the FIRST touch of that timed mode. The caller must be ready to submit a verified solver
        immediately (the deadline clock starts here) and to fall back to an untimed start to still
        capture the flag if the ranked attempt does not come back CORRECT.
        """
        timed = challenge.endswith("/time_trial") or challenge.endswith("/mastery")
        if not timed and not for_time:
            primed = (getattr(self, "_single_start", None) or {}).pop(challenge, None)   # opt B: reuse the stager's start for an untimed Single, consume once
            if isinstance(primed, dict):
                return primed
        if for_time and timed:
            # for_time=True is an explicit ranked request. Legacy routes must be
            # selected as plain/timed-by-default by the caller's route contract;
            # do not reinterpret a rejected ranked request as a different mode.
            return self._post(op="start", challenge=challenge, run_for_time=True)
        # NOTE (Day 10): a timed route may return GM 409 timed_intent_not_available for the
        # RANKED (run_for_time:true) Hall-of-Fame pool while the regular UNTIMED attempt on that
        # same route is available. So only training_rotation_invalid justifies reprovisioning
        # ranked here; a plain start failure is NOT auto-escalated to run_for_time.
        # A plain start means regular pool on routes advertising
        # run_for_time_supported:true and timed-by-default on legacy routes.
        # Return expired/stale state unchanged. A retry is a distinct write and
        # requires a fresh GM status that explicitly permits it.
        return self._post(op="start", challenge=challenge)

    @staticmethod
    def artifacts(start):
        """Normalize the start response's artifact list to [{'download':...}, ...]. D32 gmnet (audit G1): when the start carries ONE artifact and a
        top-level sha256 (the GM publishes the artifact hash there; checked against 30 archived single-artifact attempts), the entry carries it too,
        so download() can verify the bytes."""
        sha = start.get("sha256") if isinstance(start.get("sha256"), str) and re.fullmatch(r"[0-9a-fA-F]{64}", start.get("sha256") or "") else None
        if start.get("artifacts"):
            arts = start["artifacts"]
            if sha and isinstance(arts, list) and len(arts) == 1 and isinstance(arts[0], dict) and "sha256" not in arts[0]:
                return [dict(arts[0], sha256=sha)]
            return arts
        dls = start.get("downloads") or ([start["download"]] if start.get("download") else [])
        if sha and len(dls) == 1:
            return [{"download": dls[0], "sha256": sha}]
        return [{"download": d} for d in dls]

    def download(self, challenge, entry, i=0, _dup=False):
        """Fetch an assigned artifact (ROOT-RELATIVE, THROUGH the proxy). A Single Solve artifact is cached
        on disk (challenge+i+capability) so a second download of the same bytes reads the local copy instead
        of re-pulling it; timed artifacts are per-attempt and not cached. HUNTRESS_NO_DL_CACHE=1 disables.
        D32 gmnet (audit G1): an error/state reply (HTTP >= 400, e.g. an 'expired' body) is never returned or cached as the artifact,
        and when the entry carries the GM-published sha256 the bytes (fetched or cached) must match it. _dup = a straggler duplicate
        (download_many): it skips the cache wait so it really races the slow copy."""
        link = entry.get("download", "") if isinstance(entry, dict) else entry
        want = entry.get("sha256") if isinstance(entry, dict) and isinstance(entry.get("sha256"), str) else None
        want = want.lower() if want and re.fullmatch(r"[0-9a-fA-F]{64}", want) else None
        cap = link.rstrip("/").rsplit("/", 1)[-1] if link else ""
        cache = None
        if not _is_timed(challenge) and not os.environ.get("HUNTRESS_NO_DL_CACHE"):
            cache = _dl_cache_path(challenge, i, cap)
            hit = None if _dup else _dl_cache_read(cache)
            if hit is not None:
                if want is None or hashlib.sha256(hit).hexdigest() == want:
                    return hit
                try:
                    os.replace(cache, cache + ".badhash")         # a cached copy that does not match the published hash is set aside, then refetched
                except OSError:
                    pass
            if not _dup:
                try:
                    os.makedirs(_DL_DIR, exist_ok=True)
                    open(cache + ".part", "w").close()   # tell a concurrent caller we are fetching these exact bytes
                except OSError:
                    pass
        try:
            if re.fullmatch(r"[0-9a-f]{64}", cap):
                status, data = self._exchange("GET", GM_PATH + "?" + urllib.parse.urlencode({"op": "download", "capability": cap}))
            else:
                if not valid_challenge(challenge):
                    raise BadRequest("REFUSED: malformed challenge id %r; nothing was sent" % str(challenge)[:80])
                status, data = self._exchange("GET", GM_PATH + "?" + urllib.parse.urlencode({"op": "artifact", "challenge": challenge, "delivery": i}))
        finally:
            if cache and not _dup:
                try:
                    os.remove(cache + ".part")
                except OSError:
                    pass
        if status >= 400:
            e = ArtifactUnavailable("GM HTTP %s instead of the artifact (%s): %r" % (status, _err_code(data) or "state reply", data[:120]))
            e.status_code = status
            raise e
        if want is not None and hashlib.sha256(data).hexdigest() != want:
            e = ArtifactUnavailable("artifact %d of %s does not match the GM-published sha256 (got %s..., %d bytes); not cached, not used" % (i, challenge, hashlib.sha256(data).hexdigest()[:12], len(data)))
            e.status_code = 0
            raise e
        if cache:
            _dl_cache_write(cache, data)
        try:
            rec = self._ctx().get(challenge) if _is_timed(challenge) else None
            if rec is not None:
                rec["blobs"][i] = data
        except Exception:
            pass
        return data


# ---- Single-Solve download cache (homestation, 2026-10-12): the stager and the solver fetched the SAME
# 31.9 MB Single artifact twice on the binary lane (~2.5 s on the critical path + double bytes through the
# shared rate limit). Cache a Single artifact once per (challenge, delivery index, capability); a later
# download of the same thing reads the local copy. Timed artifacts (per attempt) are NOT cached. An in-flight
# fetch by another process is waited for (max 10 s) instead of duplicated. HUNTRESS_NO_DL_CACHE=1 disables. ----
_DL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_pool", "_dl")
_DL_MAX = 200 * 1024 * 1024


def _dl_cache_path(challenge, i, cap):
    k = hashlib.sha256(("%s|%s|%s" % (challenge, i, cap)).encode("utf-8")).hexdigest()[:32]
    return os.path.join(_DL_DIR, k + ".bin")


def _dl_cache_read(path):
    part, t0 = path + ".part", time.time()
    while os.path.exists(part) and not os.path.exists(path) and time.time() - t0 < 10.0:
        time.sleep(0.1)                              # another process is fetching these exact bytes: wait for it instead of downloading twice
    try:
        return open(path, "rb").read()
    except OSError:
        return None


def _dl_cache_write(path, data):
    if not data or len(data) > _DL_MAX:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp.%d" % os.getpid()
        open(tmp, "wb").write(data)
        os.replace(tmp, path)
    except OSError:
        pass


# ---- bytes/analysis helpers (format-agnostic; work on the REAL downloaded bytes) ----
def unzip(blob, password=[redacted]):
    import pyzipper  # AES-256 zips (method 99); `pip install --user pyzipper` if missing
    with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
        z.setpassword(password)
        return [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]

def sh(*a):
    try: return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL)
    except Exception: return ""

def tmpf(data, suffix=""):
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix); f.write(data); f.close(); return f.name

def file_type(data):
    """libmagic (`file -b`) on bytes. Grader-faithful for object-format fields (ELF->'elf', PE->...)."""
    p = tmpf(data); t = sh("file", "-b", p).strip(); os.unlink(p); return t


def format_gate(start, answers):
    """Refuse a submit that is ALREADY guaranteed to fail, before it is spent (2026-10-09).

    The GM gives no per-field feedback and rejects a batch wholesale if ANY field is wrong, so an empty or
    missing answer value is a certain reject - and on a ranked run_for_time attempt that wastes the one shot at
    a Hall-of-Fame time. This is a cheap pre-submit check in MILLISECONDS; it does NOT prove an answer is right
    (only the GM can), it only catches the unambiguously broken cases.

    Deliberately narrow: it blocks on an empty answers dict or a None/blank VALUE. A MISSING answer_id is only
    warned about, never blocked, because partial/accumulating per-field batches are a legitimate pattern.
    Returns a list of blocking problems (empty list = go ahead).
    """
    problems = []
    if not answers:
        return ["no answers computed"]
    for k, v in answers.items():
        if v is None or (isinstance(v, str) and not v.strip()):
            problems.append("empty value for answer_id %r" % k)
    missing = [a for a in (start.get("answer_ids") or []) if a not in answers]
    if missing and not problems:
        print("GATE warn: %d answer_id(s) not in this submit (ok for a partial batch): %s"
              % (len(missing), missing[:5]), flush=True)
    if not problems:
        try:   # ADVISORY ONLY (2026-10-10): a value the GM has never accepted for a field it has accepted 3+ times. Never blocks.
            import accepted_values
            keys = accepted_values.load_cached().get("keys", {})
            odd = [k for k, v in answers.items() if isinstance(v, str) and accepted_values.unseen_value(k, v, keys)]
            if odd:
                print("GATE note: %d value(s) never accepted before for a known-enum field (advisory, NOT a block - a new legal "
                      "value can appear): %s" % (len(odd), odd[:5]), flush=True)
        except Exception:
            pass
    return problems


# ---- TIMED CORPUS (2026-10-11, user: "the single solve is never timed! it is the TT and the MM"): the real timed bytes + the answers the GM ACCEPTED for them,
# kept so the next day's prebrief can rehearse on timed-shaped bytes instead of the Single stand-in. OUTSIDE the framework folder (binary bundles are ~31 MB each
# and must never ride a git sync): <parent of the framework root>/_timed_corpus/<entry>/<attempt>/. Local to the machine that solved the lane. Never raises.
CORPUS_DIR = os.environ.get("HUNTRESS_TIMED_CORPUS") or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "_timed_corpus")   # <root>/challenges/_lib/ctf_gm.py -> 4 levels up = BESIDE the framework root


def _is_timed(challenge):
    return str(challenge).endswith("/time_trial") or str(challenge).endswith("/mastery")


def _safe_name(s):
    """one path component: [A-Za-z0-9._-] only, and (D32 gmnet, audit G9) never '.', '..' or a leading dot, so an attempt_id cannot climb out"""
    n = re.sub(r"^\.+", "_", re.sub(r"[^A-Za-z0-9._-]", "_", str(s)))
    return n or "_"


def save_failed_run(gm, challenge, reason="crashed", outcome="crashed"):
    """D32 gmnet (compare item 15): save a timed attempt that never reached a GM verdict (solver crash, deadline, process exit) with its real
    bytes, into the timed corpus (result.json = {'result': outcome, 'reason': ...}), and record it in gm_timed so the chained tier is held.
    -> the folder or None. Real GM only, unless HUNTRESS_GM_SAVE_FAILED_ALWAYS=1 (tests). Never raises."""
    try:
        if not (getattr(gm, "host", None) == PUB_HOST or os.environ.get("HUNTRESS_GM_SAVE_FAILED_ALWAYS") == "1"):
            return None
        rec = gm._ctx().get(challenge)
        if not rec or rec.get("submitted") or rec.get("saved_failed"):
            return None
        rec["saved_failed"] = True
        d = save_timed_corpus(challenge, rec.get("start"), dict(rec.get("blobs") or {}), {}, {"result": outcome, "reason": str(reason)[:300]})
        try:
            gt = gm._tiers()
            if gt is not None:
                gt.note_run(challenge, outcome, saved=d)
        except Exception:
            pass
        return d
    except Exception:
        return None


def _save_unsubmitted_at_exit():
    """atexit: every timed attempt this process opened but never submitted is saved as 'unsubmitted' (covers every lane, including a crash
    that skipped the adapter's own save)."""
    try:
        for g in list(_GMS):
            for ch in list((getattr(g, "_timed_ctx", None) or {}).keys()):
                if _is_timed(ch):
                    save_failed_run(g, ch, reason="process ended before any submit", outcome="unsubmitted")
    except Exception:
        pass


atexit.register(_save_unsubmitted_at_exit)


def save_timed_corpus(challenge, start, blobs, answers, result, base=None):
    """write one CORRECT timed attempt: start.json (the contract), blob_<i>.bin, answers.json, result.json (flag removed). -> the folder, or None."""
    try:
        aid = str((start or {}).get("attempt_id") or int(time.time()))
        d = os.path.join(base or CORPUS_DIR, _safe_name(challenge), _safe_name(aid))
        os.makedirs(d, exist_ok=True)
        json.dump(start, open(os.path.join(d, "start.json"), "w", encoding="utf-8"), indent=1, default=str)
        for i in sorted(blobs or {}):
            b = blobs[i]
            if isinstance(b, (bytes, bytearray)):
                open(os.path.join(d, "blob_%d.bin" % i), "wb").write(b)
        json.dump(answers, open(os.path.join(d, "answers.json"), "w", encoding="utf-8"), indent=1, default=str)
        json.dump({k: v for k, v in (result or {}).items() if k != "flag"}, open(os.path.join(d, "result.json"), "w", encoding="utf-8"), indent=1, default=str)
        return d
    except Exception:
        return None


def _classify_attempt_state(status):
    """Pure classifier for a GM op=status response + the free-contract hint.

    status: the GM status dict (as returned by GM.status(cid+SUFFIX) or by
    GM.contract(cid+SUFFIX) for a NOT-STARTED mode). May be None.

    Returns a structured dict with the keys the operator directive 3 §2
    helper names. Never raises. Never calls the GM. Used by
    GM.attempt_state() below and directly by the regression tests.

    Field semantics (observed across Days 8-27):
      attempt_id             : str or None
      mode                   : "single_solve" | "time_trial" | "mastery" | "unknown"
      active                 : True iff the GM has an open attempt with a deadline
                               that has not elapsed and the result is not CORRECT
      deadline_remaining_s   : float or None (negative when past)
      prev_accepted_ids      : list[str] (last recorded accepted set, if any)
      prev_rejected_ids      : list[str] (last recorded rejected set, if any)
      unchanged_rejected_submission:
                               True iff the GM says the submission would be
                               rejected (e.g. identical to the last wrong one)
      retry_permitted        : True iff op=retry would provision a fresh variant
      practice_permitted     : True iff op=practice is the UNTIMED continuation
      ranked_consumed_on_variant_open :
                               True iff on this timed route a plain op=start
                               (no run_for_time) would spend the FINAL ranked
                               attempt; always False for untimed routes.
      state                  : one of ACTIVE, CORRECT, HELD, INCORRECT, EXPIRED,
                               UNKNOWN. ACTIVE means a submit is still possible
                               NOW on the live attempt. CORRECT means already
                               solved. HELD = GM reports the mode cannot be
                               started (prerequisite_required / absent variant).
                               INCORRECT = last submit was wrong, but a retry
                               may be permitted. EXPIRED = window elapsed.
                               UNKNOWN = anything the status does not
                               unambiguously classify (fail-closed caller).
    """
    out = {
        "attempt_id": None, "mode": "unknown", "active": False,
        "deadline_remaining_s": None, "prev_accepted_ids": [],
        "prev_rejected_ids": [], "unchanged_rejected_submission": False,
        "retry_permitted": False, "practice_permitted": False,
        "ranked_consumed_on_variant_open": False, "state": "UNKNOWN",
    }
    if not isinstance(status, dict):
        return out
    sid = status.get("challenge") or status.get("id") or ""
    s = str(sid)
    if s.endswith("/time_trial"):
        out["mode"] = "time_trial"
    elif s.endswith("/mastery"):
        out["mode"] = "mastery"
    elif s:
        out["mode"] = "single_solve"
    out["attempt_id"] = status.get("attempt_id") or status.get("current_attempt_id")
    # Accepted / rejected lists observed in GM responses + saved contracts.
    acc = status.get("accepted_ids") or status.get("prev_accepted_ids") or []
    rej = status.get("rejected_ids") or status.get("prev_rejected_ids") or []
    if isinstance(acc, list):
        out["prev_accepted_ids"] = [str(x) for x in acc]
    if isinstance(rej, list):
        out["prev_rejected_ids"] = [str(x) for x in rej]
    # Deadline math. D27 review fix (B4): accept int, float, numeric str
    # (epoch seconds as "17..." string), or ISO-8601 "YYYY-MM-DDThh:mm:ss[Z]"
    # (some GM responses observed as strings). Any unparseable value falls
    # through to deadline_remaining_s=None (handled by the ACTIVE/EXPIRED
    # branches below as "deadline unknown").
    dl = status.get("deadline")
    _dl_epoch = None
    if isinstance(dl, (int, float)):
        _dl_epoch = float(dl)
    elif isinstance(dl, str) and dl:
        try:
            _dl_epoch = float(dl)
        except (TypeError, ValueError):
            try:
                import datetime as _dt
                _iso = dl.replace("Z", "+00:00")
                _dl_epoch = _dt.datetime.fromisoformat(_iso).timestamp()
            except Exception:
                _dl_epoch = None
    if _dl_epoch is not None:
        out["deadline_remaining_s"] = _dl_epoch - time.time()
    # retry / practice gates (official README rule 5 + 409 taxonomy)
    uar = status.get("unique_attempts_remaining")
    if isinstance(uar, (int, float)) and uar >= 1:
        out["retry_permitted"] = True
    nxt = str(status.get("next_op") or "").lower()
    if nxt == "practice":
        out["practice_permitted"] = True
    if nxt == "retry":
        out["retry_permitted"] = True
    # unchanged rejected submission signal
    tv = (status.get("terminal_value") or status.get("result") or "")
    tv_lo = str(tv).lower()
    if "unchanged" in tv_lo or status.get("unchanged_rejected_submission") is True:
        out["unchanged_rejected_submission"] = True
    # ranked_consumed_on_variant_open: on a timed route a plain start spends
    # the ONE ranked attempt if hall_of_fame_eligible is true AND no run_for_time
    # has been issued yet. Signalled via the openapi hall_of_fame_eligible or
    # via explicit ranked_consumed_on_variant_open the server may surface.
    if out["mode"] in ("time_trial", "mastery"):
        hof = status.get("hall_of_fame_eligible")
        if hof is True and status.get("ranked_attempt_consumed") is not True:
            out["ranked_consumed_on_variant_open"] = True
    # state resolution
    res = str(status.get("result") or "").upper()
    if res == "CORRECT" or status.get("solved") is True:
        out["state"] = "CORRECT"
    elif "expired" in tv_lo or res == "EXPIRED":
        out["state"] = "EXPIRED"
    elif res == "HELD" or "prerequisite_required" in tv_lo:
        out["state"] = "HELD"
    elif res == "INCORRECT":
        out["state"] = "INCORRECT"
    elif out["deadline_remaining_s"] is not None and out["deadline_remaining_s"] > 0:
        out["state"] = "ACTIVE"
    elif out["deadline_remaining_s"] is not None and out["deadline_remaining_s"] <= 0:
        out["state"] = "EXPIRED"
    elif out["attempt_id"]:
        # D27 review fix (B8): a Single (untimed) attempt in flight has an
        # attempt_id but no deadline. Classify as ACTIVE so callers can resume
        # rather than fall through to UNKNOWN (which fails closed and would
        # start a fresh attempt).
        out["state"] = "ACTIVE"
    # D27 review fix (A7): derive `active` independently from the state branch
    # so an INCORRECT attempt with a still-live deadline is reported as the
    # docstring promises: "active True iff deadline not elapsed and result not
    # CORRECT". The ACTIVE branch above sets state only; this derivation sets
    # the flag according to the invariant whether or not state=="ACTIVE".
    _dl_live = (out["deadline_remaining_s"] is None
                or out["deadline_remaining_s"] > 0)
    if out["state"] in ("CORRECT", "HELD", "EXPIRED"):
        out["active"] = False
    elif _dl_live and (out["attempt_id"] or out["state"] in ("ACTIVE", "INCORRECT")):
        out["active"] = True
    return out


def solve_mode(gm, challenge, compute, retries=1, for_time=False):
    """start(+retry) -> download assigned bytes -> compute(start, blobs)->answers -> submit.
    `compute` MUST derive every answer from the attempt's OWN bytes (dynamic per attempt).
    for_time=True opens a ranked Hall-of-Fame attempt (timed route only); the caller should fall back to an
    untimed solve_mode() if the ranked one is not CORRECT so the flag is still captured.
    Returns the GM submit result (check result=='CORRECT'; result holds 'flag'/'remaining')."""
    res = None
    st = gm.start(challenge, for_time=for_time)
    for attempt in range(retries + 1):
        if str((st or {}).get("result", "")).upper() == "CORRECT":
            return {"result": "CORRECT", "flag": (st or {}).get("flag"), "solved_by": (st or {}).get("solved_by"), "submitted": False}
        blobs = gm.download_many(challenge, gm.artifacts(st))   # concurrent; order preserved (2026-10-10)
        answers = compute(st, blobs)
        blocked = format_gate(st, answers)
        if blocked:
            return {"result": "gate_blocked", "problems": blocked}
        res = gm.submit(challenge, answers)
        if str(res.get("result", "")).upper() == "CORRECT":
            return res
        # D32 gmnet (audit G4): 'expired' is judged on whole field values (gm_next_op.terminal), not a substring ('not expired' is not expired),
        # and the retry's OWN reply is the new attempt: no second start() after it (that was two timed writes for one re-roll).
        try:
            import gm_next_op as _gno
            _exp = _gno.terminal(res) or str(res.get("error") or "").strip().lower().startswith(("expired", "attempt_expired"))
        except Exception:
            _exp = False
        if _exp and attempt < retries:
            st = gm.retry(challenge)
            if not (isinstance(st, dict) and (st.get("answer_ids") or st.get("questions"))):
                return res                       # the retry did not hand out a usable attempt: stop here, never a second write
            continue
        return res
    return res


def run_parallel(jobs, workers=6):
    """jobs: list of (label, callable). Runs concurrently (distinct challenges never race). Prints results."""
    out = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn): lbl for lbl, fn in jobs}
        for fut in cf.as_completed(futs):
            lbl = futs[fut]
            try: out[lbl] = fut.result()
            except Exception as e: out[lbl] = f"ERR {e}"
            print("[DONE]", lbl, "->", json.dumps(out[lbl]) if isinstance(out[lbl], dict) else out[lbl], flush=True)
    return out


if __name__ == "__main__":
    import sys
    gm = GM()
    day = int(sys.argv[1]) if len(sys.argv) > 1 else None
    chals = gm.list(day=day) if day else gm.list()
    for c in chals:
        print(c.get("id"), "|", c.get("mode"), "|", c.get("lane"), "|", c.get("name"), flush=True)
