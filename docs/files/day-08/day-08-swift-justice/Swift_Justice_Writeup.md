# Swift Justice

## Challenge

- Category/lane: Binary Reverse Engineering (Huntress CTF 2026, Day 08)
- GM id: `binary-reverse-engineering-day-08-swift-network-configuration`
- Prompt: "Swift binaries speak in protocols and hide their networking in plain sight. Follow
  the symbols to the URL configuration and see where this one phones home."
- Modes: Single Solve, Time Trial, Mastery. 80 per-field questions in the staged task.
- Answers are submitted as per-field `answer_ids` through the Game Master; flags are
  returned by the GM on a correct submission.

This challenge is the `dual_format_re` family's Day 08 entry, and continues the progression
documented across the whole month: the delivered evidence zip (password `infected`) bundles
Day 01-08 variants together (`d01_*` through `d08_*` field prefixes), with Day 08 adding a
64 MB static Swift ELF on top of every earlier day's ELF/PE/.NET/Go/Rust/Java/Kotlin layer.

## Artifacts

- Evidence zip (password `infected`), containing `d01`-`d08` binary variants; the `d08`
  artifact is a large statically-linked Swift ELF.

## Triage

- Fingerprinted against the `dual_format_re` family in `challenges/_lib/kb/families.json`
  (known-hard; `challenges/_lib/autosolve_binary.py` is the banked day-generic adapter).
- The new, Day-08-specific layer: an HCFG-style config stored **base64-encoded in `.rodata`**
  (symbols `HuntressDay08.encodedConfig` / `decodeConfig`), decoded by the existing single-byte-XOR
  + CRC32-validated `_b64_hcfg` scanner already in `autosolve_binary.py`.

## Investigation

`autosolve_binary.py` was extended with the field handlers this day's variant needed:
- `entry_point` - the ELF `e_entry` value, reported as hex.
- `has_symtab`, `has_cpp_typeinfo`, `has_vtable` - Itanium-mangled C++ typeinfo/vtable symbol
  presence, checked the same way on both ELF and PE.
- `compression_methods` - the sorted set of zip `compress_type` integers across the archive
  (e.g. `[0, 8]` for stored + deflated members).
- Day-08-specific integer-kind fields: `elf_class` (64) and `machine` (62, EM_X86_64).

All 80 fields across the `d01`-`d08` prefixes were resolved by the extended adapter and
submitted per-field; the GM's partial-credit grading banked each one independently.

## Flag Recovery

Derived entirely from static analysis of the delivered binaries (readelf/nm/objdump-equivalent
parsing inside `autosolve_binary.py`) - no dynamic execution, no network access beyond the GM
submit calls. Verified against the GM's own authoritative record (`op=status` /
`op=list`), not just the local autosolve log.

## Flag

```
single_solve 89a532aa7e8f96fd34e807f259699588
mastery      084841b2ccc4be53084f9d98d2027087
```

Time Trial also graded CORRECT (confirmed in the done-ledger and the live autosolve run); its
completion flag is no longer retrievable from `op=status` because that attempt's timed window
has since expired/rotated past the solve itself - that is the server dropping the finished
attempt object, not evidence the mode was unsolved.

## Minimal Reproduction

1. Fingerprint the artifact against the `dual_format_re` family (`challenges/_lib/kb/families.json`).
2. Run `challenges/_lib/autosolve_binary.py` against the challenge id; it unzips with password
   `infected`, parses each `d01`-`d08` variant, decodes the base64/XOR/CRC32 HCFG config, and
   submits every resolved field.
3. Reuse the accepted Single Solve field formats verbatim for Time Trial and Mastery; derive
   every value from that attempt's own bytes (never a memorized/replayed value - see the
   TT/Mastery rotation-patch doctrine).

## Lessons Learned

- The bundled `d01`-`d08` artifact is itself evidence of the "each day extends the previous
  day's lane" progression rule holding across the whole month, not just day-to-day: one
  attempt's zip can carry every earlier day's binary alongside the new one.
- `op=status` on a timed mode can report `expired` for an attempt that was already solved -
  check the done-ledger / `op=list`'s persistent `solved` flag before concluding a mode needs
  rework.
- Writeup filename-contract discipline matters even under time pressure: a solving agent's
  working notes (`writeup.md`) are useful but must be promoted to the contract name
  (`Swift_Justice_Writeup.md`) before the challenge is considered documented.
