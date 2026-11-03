# FIRE PLAN - D-Day Time Trial + Mastery, pre-built and pre-verified (agent-2, 2026-10-11)

Both modes get **one shot** each inside a ~30 second window, and Mastery's shot only exists for as long as
Time Trial stays CORRECT-and-fresh. So everything that can be decided in advance is decided here. Nothing in
this plan needs thinking at fire time.

## One command

```
wsl --cd [local path] python3 \
  "challenges/Day 11/D-Day/scripts/solve_timed.py" \
  binary-reverse-engineering-day-11-d-collection-planner/time_trial <minutes> <poll_seconds>
```

It polls, solves Time Trial the instant an attempt exists, marks the board, then **chains into Mastery by
itself** and does the same. It never marks a mode done without an accepted GM result.

## What is already proven (zero GM calls needed at fire time)

| Fact | Value | How it was proven |
|---|---|---|
| Time Trial fields | 110, all resolved, 0 unknown, 0 probe | `lab_time.py` on the attempt's own saved bytes |
| Time Trial compute | **2.2s** | same |
| Mastery fields | **330** = 110 core x 3 sets (`set1`/`set2`/`set3`) | real contract captured off its own `409 start_required` |
| Mastery compute | **6.7s** | `preflight_mastery.py` against that real contract |
| Mastery deliveries | **3** (one artifact each) | the contract's `artifact` fields + set prefixes |
| Download throughput | **20.4 MB/s** measured | `measure_download.py` against the live endpoint |
| Mastery download | ~96 MB -> **4.7s serial**, less in parallel | measured, not assumed |
| **Mastery window total** | **~11.4s of ~30s, serial worst case** | 4.7s download + 6.7s compute |
| Format safety | `ctf_gm.format_gate` raises nothing; all 330 values match their declared kind/syntax | `preflight_mastery.py` checks 3 and 4 |
| Submits needed | **ONE** - no unknowns, so no GM feedback loop | 0 probe / 0 unknown above |

`preflight_mastery.py` prints `RESULT: PASS` on all five checks. Re-run it any time; it touches the GM not
at all.

Field-kind census of the 330 (so nothing is a surprise):
`exact_text 210, pattern 60, integer 33, json 15, enum 12`.

## Op selection - the part that is easy to get wrong

The two modes need **different** ops, and this cost a bug worth recording:

| Route | State | Correct op |
|---|---|---|
| `/time_trial` | an attempt EXISTS and is expired | `retry` / `practice` - the documented renewal ops. `start` only RESUMES the dead attempt. |
| `/mastery` | **never started** (`status` = `start_required`) | **`start`** - and only once Time Trial is CORRECT. `practice`/`retry` answer `retry_variants_unavailable` because there is no attempt to renew. |

A "gentle" edit had reduced the watcher to `practice`/`retry` only, which is correct for Time Trial but would
have left the **Mastery leg polling forever without ever issuing `start`**. Fixed: `op=start` is tried first
every cycle (harmless on Time Trial - `fresh()` rejects the resumed corpse), then the alternating renewal op.
Two GM calls per cycle, still gentle at a 5-minute cadence.

## Window discipline at fire time

- The lane adapter now treats the deadline as a hard budget (`_window`/`_left`/`_GUARD_SECS = 3.0`) and
  refuses to let 429 backoff sleep past it, and `_prewarm` proves the GM is answering before the clock starts.
  `_test_binary_timed_budget.py` 16/16 PASS.
- `solve_timed.py` submits **once**, with sure + first-probe values, and only falls back to the adapter's
  isolate-by-halving path if something is unexpectedly unresolved. With 0 unknowns that path is never taken.
- Deliveries are fetched in parallel, one connection each.

## Residual risks, and what to do about each

1. **Mastery's variant draw differs from today's material.** Values are always derived from the attempt's own
   bytes, so this is handled by construction. The *shape* could still differ - a 4th set, or a new slot. The
   adapter reports unresolved ids rather than guessing, and `preflight_mastery.py` can be re-run against a
   freshly captured contract (`op=status` on `/mastery` returns it off the 409) in under a minute to re-prove
   coverage before firing.
2. **Mastery's window might be shorter than 30s.** At 11.4s worst case there is ~2.6x headroom, and the
   window guard aborts cleanly rather than dying silently if it is tighter than expected.
3. **Time Trial must be CORRECT before Mastery is reachable.** The chaining already enforces the order; do
   not try to open Mastery first (`409 prerequisite_required`).
4. **The rotation must be refilled.** Nothing in this plan can create server material. Per the user, rotations
   reset at **00:00 EDT**.

## Re-verify in one minute before firing

```
python3 "challenges/Day 11/D-Day/scripts/preflight_mastery.py"     # 5 checks, no GM calls
python3 "challenges/Day 11/D-Day/scripts/gm_talk.py"               # read-only: is there an attempt yet?
```

If `preflight` says `RESULT: PASS` and `gm_talk` shows a non-zero `unique_attempts_remaining` (or Time Trial
no longer `expired`), fire the one command at the top.

## ARMED (2026-10-11 10:26 EDT)

A retry is already scheduled: `scripts/wait_for_reset.py` is running in agent-2's session. It makes **zero
GM calls** while waiting, wakes at **2026-10-12 00:00:20 local (00:00 EDT)**, then fires phase 1 (every 60s
for 20 min) and, if needed, phase 2 (every 10 min for 3 h) - at most **2 GM calls per cycle**, stopping the
instant a mode is CORRECT and chaining Time Trial into Mastery by itself.

**Dependency:** it lives in that session, so it only fires if the window stays open. If the window is closed,
reproduce it with one command:

```
wsl --cd [local path] python3   "challenges/Day 11/D-Day/scripts/wait_for_reset.py"   binary-reverse-engineering-day-11-d-collection-planner/time_trial
```

Add `--now` to skip the wait and try immediately.
