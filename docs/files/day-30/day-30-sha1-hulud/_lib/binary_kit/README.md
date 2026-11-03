# binary_kit

Companion to `autosolve_binary.py`. Where the adapter answers STRUCTURED FIELD
challenges (format / arch / crc32 / xor-key - Day 03-07+), this kit covers the
other thing a binary lane can serve: a STANDALONE RE binary whose only answer_id
is `flag` (Day 30 SHA1-Hulud shape). The adapter will never solve those; the kit
tells us so in milliseconds and names the next step.

## FIRST: the general crackme ladder (any "what input does this accept?" binary)

    wsl python3 challenges/_lib/binary_kit/crackme.py <binary> [--budget 600]

Runs the cheap general methods first, time-boxed, and stops at the first VERIFIED answer; never runs the binary
natively (Qiling / Speakeasy emulators, angr). Measured on author-made fixtures (`_test_crackme_ladder.py`):

| rung | what it does | fixture | time |
|---|---|---|---|
| R0 triage | signals below; keyed anti-analysis -> HARD ROUTE, skip R2/R3 | SHA1-Hulud | 2.6 s |
| R1 strings | FLOSS decoded/stack strings, flag regex, success/failure messages | all | < 3 s |
| R2 gate | hook strcmp/memcmp/lstrcmp*/CompareString*/RtlCompareMemory..., read both operands; learn a per-byte xor/add/sub from two probes and invert | runtime-decoded strcmp; xor-then-memcmp | 1-3 s |
| R3 angr | input reaching the success message, avoiding the failure one | per-char arithmetic | 5-7 s |

The bespoke workflow below is only for what R0 sends to the HARD ROUTE (anti-analysis folded into the key).

## When to use it

Fire triage as the first thing on any binary challenge whose start-response's
`answer_ids` is just `["flag"]` or `["answer"]`. Also fire it when the normal
adapter says `unknown field` on more than one id and the file looks oversized
for a Day 03-07 variant.

    from binary_kit import recognize
    r = recognize("/path/to/the.exe")
    print(r.summary())
    for a in r.plan: print("  -", a)

Example output (SHA1-Hulud, verified 2026-10-30):

    sha1-hulud.exe  pe64/x86_64  runtime=rust  secs=9 obf=['.xsobf']  veh=True
    tls_cb=True  tf_traps=3  sha1_cores=7  big_loops=0  api_hash_pairs=23  full_re=True

      * obfuscator sections present (.xsobf): dump each section and verify no
        code refs them from .text (orphan sections = XOR-string stash)
      * VEH / TLS / trap-flag obfuscation: debugging is unsafe; use
        binary_kit.snapshot + binary_kit.emu
      * Rust binary: expect embre or obfstr XOR string tables ...
      * 7 inlined SHA1-shaped cores: likely input-derived key schedule; log
        calls through Unicorn and REPLAY the decrypted trace (not emulate the
        self-modifying code)
      * 23 hashed-API resolver call sites: let the live process do the
        resolution, then snapshot ...
      * FULL-RE: this is NOT a fields challenge; do not hand to
        autosolve_binary - open under binary_kit workflow

## The workflow when full_re is true

The order is deliberate. Earlier runs on SHA1-Hulud wasted hours trying each
step out of order; the signals above all exist to short-circuit guessing.

1. **Triage** (this module). ~5 ms. Reads the file, nothing else. Tells us this
   is NOT a fields challenge and lists the protections.

2. **Run the real exe once** on known-bad input. Record output length and exit
   code (SHA1-Hulud: 18 bytes exactly, exit 0 on any wrong input).

3. **Snapshot** (`binary_kit.snapshot` - lives in the Day 30 solver copy for now
   because the exact RVA window differs per binary). CreateProcess the exe,
   wait for the anti-tamper loops to pass, SuspendThread, dump every committed
   region + full CONTEXT + TEB + module list. ~2-3 s one-off.

   The reason: debugging is defeated by `ThreadHideFromDebugger`,
   `NtGetContextThread` (debug registers), and PEB/NtGlobalFlag checks; those
   results feed the key schedule, so attached debuggers silently corrupt it.
   Snapshot-and-emulate skips all of that.

4. **Emulate** (`binary_kit.emu`). Unicorn resumes from the snapshot. Three
   things that must be reimplemented in the emulator because the real exe
   relied on CPU/OS behaviour Unicorn does not provide:

   - **VEH semantics.** The exe installs its own handler at
     `AddVectoredExceptionHandler(1, <addr>)`. INT3/#UD/single-step/AV must be
     replayed to that handler with the same effect the Windows kernel would
     have had (RIP redirect, DRx read, EFLAGS tweaks). Read the handler out of
     the exe and port its branches - do NOT guess.
   - **Syscalls.** Match stubs by SSN (parse ntdll exports in the snapshot).
     The anti-debug ones (NtQIP class 0x1e/0x1f, NtQuerySystemInformation 0x23,
     NtGetContextThread) need "not a debugger" answers; everything else can
     return 0 unless it writes an output buffer.
   - **AVX ntdll helpers.** Unicorn has no AVX, so hook ntdll!memset / memcpy /
     memmove / memcmp / wcslen / strlen / RtlCopyMemory at their entry points
     with Python stand-ins. These are called via indirect pointers so a single
     entry-point hook catches every path.

5. **Replay self-decrypting routines**. If an inner function patches its own
   bytes as it runs (SHA1-Hulud: 4 copies of a 77-byte SHA1 stub, each slot
   decrypted just before executing), Unicorn's translation cache misbehaves
   even with ctl_remove_cache. Instead: single-step the FIRST call to each
   copy, record every executed instruction's bytes AS THEY WERE, and replay the
   data-path of that trace in Python on subsequent calls. The 2b840 trace was
   verified 6/6 against real calls.

6. **Model the top-level transform** in plain Python once the inner primitives
   are known. For SHA1-Hulud that was two ARX passes (forward CBC, reverse CBC)
   over 16-byte blocks with a Klimov-Shamir T-function `x -> x + (x^2|5)` as
   the per-round nonlinear op. The T-function is a permutation on u64 and
   invertible bit-by-bit, which is what makes the final check solvable rather
   than brute-forced.

7. **Invert**. Pull `target_bytes = ks1 ^ sil ^ dl` out of the comparison
   (`xor bl,sil; xor bl,dl; or [acc],bl`). Where keys depend on earlier blocks,
   iterate: recover block i, feed it back as the input prefix, re-run emulator,
   read block i+1's key, repeat.

8. **Verify on the real binary** before submitting. The emulator can be wrong
   in subtle ways (one XMM lane, one wrong EFLAG), but the exe is the oracle.

9. **Submit via `GM.submit(cid, {"flag": "flag{...}"})`**. Save `flag.txt` and
   the solver next to the challenge; append a lesson entry; coord-note.

## Fingerprints collected so far

| exe                | runtime | obfuscator  | protections                                   | solve path            |
|--------------------|---------|-------------|-----------------------------------------------|-----------------------|
| sha1-hulud.exe     | rust    | embre+xsobf | VEH + TF trap + inlined SHA1 + API-hash + SMC | snapshot+emu+replay   |

Add rows as new patterns are seen so the next recognition is a lookup, not
re-discovery.

## Non-goals

- This kit does not touch `autosolve_binary.py` or any lane adapter. If an
  integration is needed later (e.g. auto-fire triage on claim and hand to
  Commander), that goes through the HS owner of the binary adapter.
- No GM calls here. The kit is static + local-emulation only. Submit is still
  the Commander/agent's call through `ctf_gm.GM.submit`.
