#!/usr/bin/env python3
"""ROUTE WATCH: ONE poller for a timed route that lost its window, FREE READS ONLY (user, 2026-10-11, relayed by the homestation: keep checking TODAY until it can be solved; an organiser may fix it before any
automatic reset; one poller, no hammering).

usage: python3 challenges/_lib/route_watch.py <day> <challenge-base-id> <lane> [--interval 120] [--until HH:MM]

Every INTERVAL seconds (floor 60) it makes ONE `op=status` read of <base>/time_trial (it costs no variant, unlike start / retry / practice) and decides with catchup_timed.decide:
GO only when the attempt is expired AND unique_attempts_remaining >= 1. On GO it runs the proven single autosolve exactly once (catchup_timed --go: Time Trial with the free pre-check and the hard window
budget, then Mastery in the same pass) and exits. It does NOT fire while another runner is active (agent-2's wait_for_reset.py / solve_timed.py after their wait ends), so two runners never touch one attempt.
One poller per machine (lock file with the pid). Log: [home path] (one line per change and every 10th check). Stops at --until (default 23:50 local). No write call is ever made by the polling itself.
Read-only toward the GM until GO; ASCII only."""
import datetime, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
LOCK = os.path.join(os.path.expanduser("~"), ".route_watch.lock")
LOG = os.path.join(os.path.expanduser("~"), "route_watch.log")
FLOOR_S = 60.0
RUNNER_WORDS = ("wait_for_reset.py", "solve_timed.py")


def other_runner_active(ps_text, own_pid=None):
    """pure: True when the process listing shows a python process running one of the recovery solvers. wait_for_reset.py is ASLEEP until its reset time making no GM calls; it counts as active only
    once it has started firing, which shows as a solve_timed.py child, so only solve_timed.py counts; a sleeping waiter alone does not block a daytime fire."""
    for line in (ps_text or "").splitlines():
        low = line.lower()
        if "python" in low and "solve_timed.py" in low and "route_watch.py" not in low:
            if own_pid is None or (" %s " % own_pid) not in (" " + line + " "):
                return True
    return False


def clamp_interval(v):
    try:
        return max(FLOOR_S, float(v))
    except (TypeError, ValueError):
        return 120.0


def run_watch(status_fn, decide_fn, fire_fn, other_active_fn, sleep_fn, now_fn, until_ts, interval, log_fn):
    """the loop with every side effect injected (tests drive it with fakes). -> 'fired' | 'deadline' | 'blocked-then-deadline'"""
    interval = clamp_interval(interval)
    n, last, errs, blocked = 0, None, 0, False
    while now_fn() < until_ts:
        n += 1
        try:
            st = status_fn()
            errs = 0
        except Exception as e:
            st, errs = "error: %s" % str(e)[:80], errs + 1
        go, why = decide_fn(st)
        sig = (go, why)
        if sig != last or n % 10 == 0:
            log_fn("check %d: %s -> %s" % (n, why, "GO" if go else "no-go"))
            last = sig
        if go:
            if other_active_fn():
                blocked = True
                log_fn("GO seen but another runner is active; not firing (one runner per attempt)")
            else:
                log_fn("FIRING the single autosolve now")
                fire_fn()
                return "fired"
        sleep_fn(min(interval * (2 if errs >= 3 else 1), 600.0))
    return "blocked-then-deadline" if blocked else "deadline"


def _log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        open(LOG, "a", encoding="ascii", errors="replace").write(line + "\n")
    except OSError:
        pass


def _lock_acquire():
    try:
        old = int(open(LOCK).read().strip())
        os.kill(old, 0)                                      # alive?
        return old
    except (OSError, ValueError):
        pass
    open(LOCK, "w").write(str(os.getpid()))
    return None


def main(argv):
    if len(argv) < 3 or not argv[0].isdigit():
        print(__doc__)
        return 2
    day, base, lane = argv[0], argv[1], argv[2]
    interval = clamp_interval(argv[argv.index("--interval") + 1]) if "--interval" in argv else 120.0
    hh, mm = (argv[argv.index("--until") + 1] if "--until" in argv else "23:50").split(":")
    until = datetime.datetime.now().replace(hour=int(hh), minute=int(mm), second=0, microsecond=0).timestamp()
    holder = _lock_acquire()
    if holder:
        print("route_watch is already running (pid %s): one poller per machine." % holder)
        return 3
    import catchup_timed
    from ctf_gm import GM
    gm = GM()
    route = base + "/time_trial"

    def fire():
        rc = catchup_timed.main(["catchup_timed.py", day, base, lane, "--go"])
        _log("catchup_timed --go returned %s" % rc)

    def others():
        try:
            out = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True, timeout=20).stdout
        except Exception:
            out = ""
        return other_runner_active(out, os.getpid())

    _log("route_watch start: %s every %.0fs until %s (free op=status reads; GO needs expired AND unique_attempts_remaining >= 1)" % (route, interval, "%s:%s" % (hh, mm)))
    try:
        res = run_watch(lambda: gm.status(route), catchup_timed.decide, fire, others, time.sleep, time.time, until, interval, _log)
    finally:
        try:
            os.remove(LOCK)
        except OSError:
            pass
    _log("route_watch end: %s" % res)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
