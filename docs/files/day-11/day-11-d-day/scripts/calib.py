#!/usr/bin/env python3
"""Read-only calibration: what does unique_attempts_remaining look like on other timed routes?"""
import json, sys, time
sys.path.insert(0, "challenges/_lib")
from ctf_gm import GM
gm = GM()
print("=== op=list day 11, this challenge's modes ===")
for c in gm.list(day=11):
    if "d-collection-planner" in str(c.get("id", "")):
        print(json.dumps({k: c.get(k) for k in ("id", "mode", "solved", "lane", "unique_attempts_remaining", "deadline")}))
print("=== status on other timed routes (read-only) ===")
for r in ("binary-reverse-engineering-day-01-c-elf-orientation/time_trial",
          "binary-reverse-engineering-day-10-zig-cross-platform-services/time_trial",
          "mobile-android-day-11-local-[secrets dir]"):
    time.sleep(1.0)
    try:
        st = gm.status(r)
        print(r, "->", json.dumps({k: st.get(k) for k in ("result", "unique_attempts_remaining",
              "hall_of_fame_eligible", "next_op", "deadline")}))
    except Exception as e:
        print(r, "-> ERR", str(e)[:160])
