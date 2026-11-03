# Full-RE binary playbook (VEH / self-modifying Rust)

Written 2026-10-30 after SHA1-Hulud (Day 30 special). The target class is: a
protected console binary where the GM only wants `flag` (no fields), the exe
reads one line of stdin, computes for ~3.5 s regardless of input, and prints
nothing on wrong input. The playbook is a 10-step process; most are seconds.

## The ten steps, in order

1. **Triage with `binary_kit.recognize`** (`python -m challenges._lib.binary_kit.triage <exe>`).
   Costs 5 ms. Reads the real signals: runtime, obfuscator sections, VEH
   import, TLS callback, TF trap sites, inlined SHA1 cores, hashed-API resolver
   count, big-loop immediates. If `probable_full_re=True` -> this playbook; if
   False -> hand to `autosolve_binary.run`.

2. **Grep for well-known crate paths** in the raw bytes once: `embre`, `obfstr`,
   `litcrypt`, `rust_code_obfuscator`, `encrust`, `obfustring`. If any match,
   that pins the string-obfuscation layer and tells us how BYTES/KEY are
   stored. SHA1-Hulud had `[local path]`.

3. **Run the real exe ONCE** with distinctive input (`"ABCDEFGHIJKLMNOP"` or
   similar). Record `len(stdout)`, exit code, wall time. These three numbers
   are the oracle for every later step.

4. **Decode visible XOR-string pairs** before anything heavy. Rust XOR
   obfuscators store (BYTES[N], KEY[N]) as two consts in `.rdata` separated by
   a short distance. For success/prompt messages the N is usually under 64.
   For SHA1-Hulud, `.rdata[0x8838e] ^ .rdata[0x883a3]` = `correct, the flag is `.
   This step alone sometimes shortcuts the whole challenge if the comparison
   is `strcmp(input, decoded_string)`.

5. **Snapshot after the anti-tamper loops.** `snapshot.py` creates the
   process, waits until RIP leaves the loop window, SuspendThread, dumps
   regions + CONTEXT + TEB + modules. Reusable across every emulation run.

   The sentinel for "loops done": once the triage prints a big-loop immediate
   (e.g. ~45M), find its site in main (`cmp r9, 0x2aea540`) and anchor on the
   first RIP that leaves that function block after the compare has fired.

6. **Build the Unicorn emulator** from the snapshot (`emu.py`). What has to be
   right:

   a. **GS base**. `msr_write(0xC0000101, teb)`. Without this, every TEB-based
      anti-debug check reads zeroes and the whole program branches wrong.
   b. **Syscall table.** Parse ntdll exports from the snapshot, map SSNs to
      names, hook UC_HOOK_INSN on SYSCALL. Answer debug-related ones ("no
      debugger"), return 0 for the rest.
   c. **VEH.** Read the exe's own VEH out of `AddVectoredExceptionHandler`
      arg2, decode its branches, call it on INT3/#UD/single-step/AV in the
      emulator with the fields it expects (`ExceptionCode`, `ExceptionAddress`,
      ExceptionInformation).
   d. **ntdll AVX routines**. Hook `memset`, `memcpy`, `memmove`, `memcmp`,
      `wcslen`, `wcsnlen`, `strlen`, `strnlen`, `RtlCopyMemory`, `RtlMoveMemory`
      at their export addresses with Python stand-ins. Unicorn has no AVX.
   e. **SMC.** Hook MEM_WRITE on `.text`. Call `ctl_remove_cache(addr, addr+size)`
      for each write so Unicorn re-decodes.

7. **Replay self-decrypting routines.** When a function patches its own
   instruction bytes immediately before executing them (SHA1-Hulud: 4 copies
   of a 77-byte stub, each slot decrypted inline), Unicorn's cache cannot keep
   up even with per-write invalidation. The reliable fix:

   - Single-step the FIRST call to each copy and record every executed byte
     block AS THE CPU SAW IT (not as it sits in the file).
   - Lift the data-path operations into Python (`parse_trace` + `make_runner`
     from `hulud_compress.py`). ~2000 ops reduce to a plain register-and-memory
     loop. Validate 6/6 against subsequent real calls.
   - On every later call, call the Python runner instead of letting Unicorn
     retrace the SMC.

8. **Model the top-level transform in Python.** Once the inner primitive is a
   pure function, read the surrounding assembly as if it were any other block
   cipher. For SHA1-Hulud: two ARX passes of 16 rounds, each with a
   Klimov-Shamir T-function `x -> x + (x^2 | 5)`. The T-function is a bijection
   on u64 and invertible one bit at a time; that is what makes the check
   solvable instead of brute-forced.

9. **Pull the compare target from the trace.** The comparison instruction is
   almost always three XORs and an OR into an accumulator byte
   (`xor bl,sil; xor bl,dl; or [acc],bl`). Log `(bl, sil, dl)` per byte for one
   emulated run, compute `target = ks1 ^ sil ^ dl`, feed through the inverse
   transform. Iterate block-by-block if later block keys depend on earlier
   recovered bytes.

10. **Verify on the real binary before GM submit.** Pipe the recovered flag to
    the exe and confirm `len(stdout) != baseline`. Only then
    `GM.submit(cid, {"flag": flag})`.

## Fingerprints that must trigger this playbook instantly

- `AddVectoredExceptionHandler` import + any custom-named section not
  referenced by `lea reg, [rip+disp]` from `.text`.
- Three or more TF trap sites (`9c 48 81 0c 24 00 01 00 00 9d`).
- Two or more inlined SHA1 IV sequences (`01 23 45 67 ... 89 ab cd ef` within
  32 bytes).
- `_ZN` or `/rustc/<hash>/` strings + a section like `.xsobf` / `.obf` /
  `.litcrypt`.
- Hashed-API resolver pattern (`mov ecx,imm32; mov edx,imm32; call <same>`)
  seen more than ~20 times.

`binary_kit.recognize` already checks all five.

## What NOT to do

- Do not attach a debugger. The anti-debug readings feed the key schedule;
  attached = silent wrong answer.
- Do not patch out branches to force the success path. The success message
  is derived from input + state, not stored verbatim; patching produces
  garbage.
- Do not brute-force the input. Even 2^80 of a 20-byte compare target is
  infeasible, and inversion is tractable once the T-function is modelled.
- Do not ignore the `.text` SMC-write hook. Without `ctl_remove_cache`,
  Unicorn silently runs stale code and the SHA1 variants return the same hash
  for every input.
- Do not call `autosolve_binary.run` on this shape. The adapter expects
  `answer_ids` with structured fields; a `flag`-only start wastes attempts.

## Time budget

With this playbook end-to-end on a familiar protection stack: triage 5 ms,
grep + visible-string decode 1 min, snapshot 10 s, emulator smoke 2 min
(iterate until it reaches the comparison), trace+replay the inner routines 5
min, Python model 10 min, inversion 2 min, verify + submit 30 s. Target total:
under 25 minutes.

First time on a new stack (SHA1-Hulud was first) was ~4 hours; next similar
binary should be under 30 min.

## Related files in this repo

- `challenges/_lib/binary_kit/triage.py` - the fingerprint.
- `challenges/_lib/binary_kit/README.md` - mirror of this doc, kept short.
- `challenges/Day 30/\u2699\ufe0f SHA1-Hulud/solver/` - the concrete, working
  reference pipeline (snapshot.py, emu.py, hulud_compress.py, hulud_cipher.py,
  hulud_model.py, solve_hulud.py, step_solve2.py, probes).
- `challenges/Day 30/\u2699\ufe0f SHA1-Hulud/SHA1-Hulud_Writeup.md` - the full
  writeup including the "what methods / what to recognize / faster next time"
  section.
