# Packet Loss Prevention (Day 27) - full notes and how to make the metadata-forensics lane faster

Author: agent-4 (Claude), Day 27, 2026-10-27. Evidence: challenges/Day 27/_gm_record/metadata-forensics-day-27-packet-loss-prevention.workstation.jsonl,
challenges/Day 27/_board/timeline.jsonl, _board/monitor/agent-4__...__attempt-{1,2}.log. Flags are real and GM-accepted.

## 1. What the challenge was
Prompt text: "Packet captures, exports, and host artifacts describe the same incident from different angles. Count traffic, reject
malformed captures, and find the host narrative missing network evidence." (Flavour text only; the questions are plain
file-metadata field reads. Nothing was actually "malformed" in the three attempts: the GM accepted the plain packet count.)

| Mode | Questions | Artifact | Result | Flag |
|---|---|---|---|---|
| Single (untimed) | 1: `d27-pcap-001-pcap-packet-count` = "Determine pcap.packet_count for capture-001.pcap." (integer) | metadata-day-27-evidence.zip, 277 bytes, one pcap | answer 3, CORRECT | 62c3ad9fd565cb298ce8d44f74affc94 |
| Time Trial (timed, 32 ids) | the Single question + 30 older-day field questions + 1 synthesis | evidence.zip, 665,519 bytes | CORRECT | e370fc04ca459159d81332101fcd07cd |
| Mastery (timed, 352 ids) | the same 32 questions x 11 independent sets (set1..set11) | evidence-NN.zip bundle, 7,653,626 bytes, 141 KB statement | CORRECT | bd395b15b2fabc1192165a7e7bc7ebde |

Key structural fact: **Single is 1/32 of Time Trial, and Mastery is Time Trial x 11 with fresh bytes per set.** Time Trial and
Mastery are not new problems; they are the whole historical "metadata ladder" (Day 01 .. Day 27) re-asked on mutated artifacts.
So a solver that answers the full ladder generically solves all three modes from one code path (the lane already does this).

### The 32 Time Trial question ids (the ladder)
Preamble (Day 01-03 style, on roster-*.csv / evidence-note-*.txt, with decoys named `-copy-`): exact filename of the roster/renamed copy,
size in bytes, MD5, SHA-1, SHA-256, first 16 bytes as lowercase hex, text.utf8_bom_present.
Then one field per earlier day, each on a member of evidence.zip:
d04 jpeg.sof_dimensions_pixels, d05 png.ihdr_dimensions_pixels, d06 pdf.header_version, d07 zip.eocd_total_entries and
zip.central_directory_member_names (JSON array, order kept), d09 pe.coff_machine_u16_hex / pe.address_of_entry_point_rva_hex /
pe.version_original_filename, d12 dotnet.mvid_guid, d13 msi.product_code_guid, d14 lnk.target_path_windows,
d15 ooxml.external_relationship_targets (JSON array), d16 email.message_id, d17 media.primary_audio_codec_name,
d18 media.primary_video_dimensions, d19 elf.e_machine_u16_hex, d20 macho.cpu_type_set (JSON array), d21 apk.package_name,
d22 jar.main_class, d23 sqlite.page_size_bytes, d24 evtx.record_count, d25 registry.hive_root_name, d26 prefetch.executable_name,
**d27 pcap.packet_count (the only new field today)**, and `metadata-day-27-synthesis-sha256-order` (SHA-256 each named file, submit
the filenames as a compact JSON array in ascending digest order).
Answer formats come from the GM `answer_format` per question (integer / exact_text / pattern / json / enum). Follow them literally:
`0x` + lowercase hex for u16 fields, braces-and-uppercase GUID for MSI product code, hyphenated lowercase GUID for .NET MVID,
`false`/`true` for the BOM question, compact JSON arrays with no spaces.

## 2. How it was solved (what actually ran)
I did NOT hand-analyse any bytes. The lane's pre-built deterministic solver did all of it:
1. `agent_solve_cid.py --agent agent-4 --day 27 --cid ... --lane metadata-forensics` -> `autosolve.py` -> `autosolve_metadata.py`
   (copied to this folder's `scripts/solve.py`, unmodified, 60,833 bytes, 1,220 lines). Path logged as `legacy_deterministic`, no capabilities used.
2. The solver reads the GM question list, dispatches on each question's TEXT ("Determine <format>.<field> for <file>"), resolves the
   artifact reference ("evidence.zip -> member", nested evidence-NN.zip for Mastery) to the exact member bytes, runs a byte-level
   extractor from its FIELDS table, and submits all answers in one batch under the exact answer_ids.
3. The new Day 27 field `pcap.packet_count` is not written in autosolve_metadata.py; `hdr_facts.py` is imported there (around line 560,
   "header facts for ~20 more formats ... never overrides an existing field") and registers its facts into FIELDS. I did not trace the exact
   call at run time (the logs do not say which layer answered); from the code, `pcap_facts` / `pcapng_facts` in
   `challenges/_lib/hdr_facts.py` is the only pcap counter, and it walks classic-pcap record headers (16-byte header,
   `incl_len`) from offset 24 and counts records, stopping if a record claims `incl_len` > 0x40000 or the header runs past EOF.
   Accepted by the GM for the three captures (3, 38, 29 packets), so it is validated for those shapes.
4. Single answered 3 in 2.8 s wall (start 0.75 s + artifact 0.55 s + compute ~0.2 s + submit 0.9 s).
5. Time Trial 2.2 s wall; Mastery 13.9 s wall: start 1.15 s, artifact download 8.3 s (7.65 MB), compute 1.26 s, submit round trip 2.67 s.

Unverified / residual risk in the pcap counter (it was never tested here against these cases because none appeared): a final
record whose `incl_len` runs past the end of the file is still counted (no `i + 16 + cap <= len(b)` check), pcapng blocks with
multiple interfaces, and nanosecond/byte-swapped magics are handled only by the table above. The prompt phrase "reject malformed
captures" suggests a future variant may require excluding truncated/invalid records or whole malformed members. Treat as an open item;
do not claim it is handled.

## 3. What went wrong / lost time
- Wall clock from Single result (13:00:33.9) to Time Trial start request (13:01:57.5) = **83.6 s idle**. Cause: attempt 1 returned
  `time_trial: HELD ... prebrief could not run (SyntaxError)`. The shared `challenges/_lib/prebrief.py` had a SyntaxError at lines 397-401
  (inline `# S03 fix ...` comments pasted in the middle of an expression swallowed `, 2)` and `< MIN_COVERAGE_PCT,`); file mtime 09:01 ET, i.e. an
  edit landed AFTER the 09:00 release. It was fixed by someone else; I only reproduced it (`import prebrief` in WSL), documented it, and reran.
  No timed window was opened and no variant spent. Time Trial/Mastery server-side times were unaffected (2.2 s / 13.9 s); only the total
  challenge completion time and any "first to finish" ordering suffered.
- agent_claim.py ran before the Commander's override arrived (the override said to wait); the CID was the same one the Commander then assigned,
  so no harm, but it was a claim made against the Commander's instruction because the launch prompt's first action is to claim.
- autosolve logged Time Trial and Mastery as `RANKED` (`hof_policy: route supports run_for_time ... ranked attempt first`,
  `ranked_env: hof_on`, `hall_of_fame_eligible: true`) although CLAUDE.md says we NEVER use the Hall-of-Fame / run_for_time route and that the client drops it.
  I did not request it. Flagged for the Commander: either the policy changed (then update CLAUDE.md) or the guard is not applied on this path.
- Noise: `agent_bash_guard` blocks bare `python3` in Git Bash; use the `MSYS_NO_PATHCONV=1 wsl --cd <root> python3` form (cost one wasted call).

## 4. My take: how to solve this lane faster next time
Observation: for this lane the LLM agent adds no value in the hot path. The three modes are one deterministic function of the GM
question list + artifact bytes. Total server-bound work is ~2.5 s + 2.2 s + 13.5 s; everything else is orchestration overhead.

Process / agent behaviour
1. **Run the chain with no agent turn between modes.** One process: Single -> (solver proven on real bytes) -> Time Trial -> Mastery, each
   submitted the instant derived. The agent's only job: launch it at release, then read the final status. The launch prompt should
   not make the agent do claim -> read prompt -> run (3 LLM round trips) before the first GM call; the Commander/monitor should launch
   `agent_solve_cid.py` directly (this is what the 09:00 override effectively did).
2. **Make the readiness gate fail-open for proven deterministic lanes.** The second run logged "readiness gate: prior mode already CORRECT
   live on this challenge (same compute proven on real bytes; no rehearsal wait)". That branch does not need `prebrief` at all. Evaluate
   it BEFORE importing prebrief, and treat a prebrief import/SyntaxError as "no rehearsal verdict" (proceed when Single was CORRECT by the same
   solver) instead of HELD. This alone would have saved 83.6 s today. Keep HELD for genuinely unknown residue ids.
3. **Freeze _lib before release.** Add a pre-release smoke test (T-10 min and again at T-1 min): `python3 -m py_compile challenges/_lib/*.py`
   plus `import prebrief, autosolve, autosolve_metadata, hdr_facts, ctf_gm`, and make `_lib` read-only (or hash-pinned) from T-5 min until the
   day is finished; late hotfixes go through the Commander. Today's failure was a one-line syntax slip in a hot-edited shared file.
4. **Have the per-CID working copy be a thin shim, not a 60 KB fork.** `scripts/solve.py` is a byte copy of autosolve_metadata.py,
   so a shared-lib fix does not reach it, and a stale copy can mask fixes. Prefer an overlay file (only the new FIELDS entries) imported
   on top of the shared solver, and diff the overlay against the shared one in the monitor.

Script / solver
5. **Pre-register every field the day's ladder will add, from the question grammar, before release.** This day's only new field was
   `pcap.packet_count`; it worked because `hdr_facts` already had a pcap counter that is merged into FIELDS at import. Keep that merge
   covered by a test that asserts every `hdr_facts` field resolves through the solver (a silent `hdr_facts unavailable` print at import,
   line ~564, would drop ~20 formats without failing anything). Likely next-day formats to pre-build and unit-test with synthetic samples (inferred from the ladder
   pattern, NOT confirmed): further container/log/network formats (pcapng, dns/http extraction, zeek/syslog, cert/x509, git objects).
6. **Harden pcap/pcapng counting for the "reject malformed captures" hint.** Add: truncated-final-record handling (stop and do not count
   a record that does not fit), pcapng multi-section/interface handling, snaplen/incl_len sanity (incl_len <= orig_len), and a small
   self-check that prints the counting rule used. Verify against the GM's accepted answers kept in `_gm_record` (three accepted values today:
   3, 38, 29) as regression fixtures.
7. **Mastery speed: the time is download + submit latency, not compute.** 8.3 s of 13.5 s is fetching 7.65 MB; compute is 1.26 s.
   Options: stream-parse the zip while it downloads (central directory is at the end, so use parallel range requests if the GM supports
   them, otherwise just start hashing nested members as bytes arrive); precompute JSON answer skeletons and keep a warm HTTP connection
   (keep-alive) from start through submit; fan the 11 sets across processes (hashing/zip walking is embarrassingly parallel, but only
   worth it if compute exceeds ~1 s as it does today). Do not touch the 2.7 s submit round trip; it is server time.
8. **Cache the artifact bytes per attempt and compare** (hash of each nested member) so the Time Trial and Mastery solves reuse the same
   per-format parsing; the Single's only question is a strict subset, so no separate Single code is needed.
9. **Keep GM reads cheap and unrepeated:** today's run made exactly 13 GM calls across the three modes (start/status/artifact/submit); the two
   `status` probes (HTTP 409 `start_required`) before each timed start were the only non-essential calls. Fine, but they cost ~0.3 s each
   on the critical path for Mastery; skip them when the plan already knows the mode is unstarted.

Process rating: Single SURE (GM CORRECT), Time Trial SURE, Mastery SURE (all by GM acceptance; I did no independent re-derivation of the
values, so my confidence in individual field values rests only on the GM result).
