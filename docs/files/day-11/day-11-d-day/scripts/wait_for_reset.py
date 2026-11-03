#!/usr/bin/env python3
"""Sleep until the rotation reset, then fire the pre-verified solve with the FEWEST possible GM calls.

The rotations reset at 00:00:00 EDT (user). Polling for the ~13 hours until then would be pure waste, so this
makes ZERO GM calls while waiting - it just sleeps - and only starts calling just after midnight.

Cadence after the reset, deliberately frugal:
  * 00:00:20 local, then every 60s for 20 minutes   (catches a slightly late reset quickly)
  * then every 10 minutes for up to 3 more hours    (catches a lazy/batched reset without hammering)
Each cycle is 2 calls at most (op=start, then one renewal op), and it stops the instant a mode is CORRECT.

On a fresh attempt it runs the proven path: download -> analyse -> ONE submit, then chains into Mastery.
Everything is pre-verified: TT 110 fields in 2.2s, Mastery 330 fields in 6.7s, 20.4 MB/s download, ~11.4s of
a 30s window worst case, format_gate clean, zero unknowns. See handoff/FIRE_PLAN.md.

usage: wait_for_reset.py [route] [--now]      --now skips the wait (for a manual immediate run)
"""
import datetime
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVER = os.path.join(HERE, "solve_timed.py")
ROUTE = next((a for a in sys.argv[1:] if not a.startswith("--")),
             "binary-reverse-engineering-day-11-d-collection-planner/time_trial")
NOW = "--now" in sys.argv


def log(m):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), m), flush=True)


def seconds_to_midnight():
    now = datetime.datetime.now()
    target = (now + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=20, microsecond=0)
    return (target - now).total_seconds(), target


if not NOW:
    secs, target = seconds_to_midnight()
    log("armed: sleeping %.1f hours until %s local (00:00:20), making ZERO GM calls until then"
        % (secs / 3600.0, target.strftime("%Y-%m-%d %H:%M:%S")))
    # sleep in chunks so the log shows it is alive and a stop is responsive
    end = time.time() + secs
    while time.time() < end:
        time.sleep(min(1800.0, max(1.0, end - time.time())))
        left = (end - time.time()) / 3600.0
        if left > 0:
            log("still waiting, %.1f h to the reset (no GM calls made)" % left)
    log("reset window reached")

# FREE PRE-CHECK before any write op. challenges/_lib/route_watch.py polls this same route with free
# op=status reads from 12:17 until 23:50 and fires catchup_timed --go the moment the rotation refills, so
# by the time this waiter wakes the mode may ALREADY be CORRECT. op=status costs no variant (see
# docs/gm-facts.md, THE GM CALL BUDGET), whereas start/retry/practice each spend one, and re-submitting a
# solved mode is pure waste. So: read first, and only open a window if there is still something to win.
def already_correct(route):
    """One FREE op=status. True only on an explicit CORRECT; any error or unknown shape means 'keep going'."""
    try:
        sys.path.insert(0, "challenges/_lib")
        from ctf_gm import GM
        st = GM().status(route)
    except Exception as e:
        log("free pre-check on %s could not read status (%s) - proceeding" % (route, str(e)[:120]))
        return False
    res = str((st or {}).get("result", "")).lower()
    log("free pre-check %s -> result=%r uniq_rem=%r" % (route, (st or {}).get("result"),
                                                        (st or {}).get("unique_attempts_remaining")))
    return res == "correct"


base = ROUTE.rsplit("/", 1)[0] if ROUTE.endswith(("/time_trial", "/mastery")) else ROUTE
if all(already_correct(base + "/" + m) for m in ("time_trial", "mastery")):
    log("both timed modes are ALREADY CORRECT (route_watch got there first) - nothing to spend, exiting")
    sys.exit(0)

# PHASE 1: tight, 60s for 20 minutes - a reset that lands on time is caught within a minute
log("phase 1: every 60s for 20 min")
r = subprocess.call([sys.executable, SOLVER, ROUTE, "20", "60"])
log("phase 1 exit %s" % r)
if r == 0:
    log("SOLVED in phase 1 - done")
    sys.exit(0)

# PHASE 2: frugal, 10 min for 3 hours - catches a late or batched reset without hammering
log("phase 2: every 10 min for 3 h")
r = subprocess.call([sys.executable, SOLVER, ROUTE, "180", "600"])
log("phase 2 exit %s" % r)
sys.exit(0 if r == 0 else 2)
