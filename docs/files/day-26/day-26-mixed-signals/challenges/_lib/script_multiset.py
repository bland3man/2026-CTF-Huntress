#!/usr/bin/env python3
"""Deterministic solver for the SCRIPT-ANALYSIS "multi-set polyglot" family.

First seen Day 26 "Mixed Signals" (script-analysis-day-26-beam-message-flow):
Mastery = 10 sets x 1677 answer ids = 16770, delivered as ONE outer zip of
per-set evidence archives (evidence-01.zip .. evidence-NN.zip), setK <-> evidence-0K.
Each evidence archive holds ~170 script fixtures across 25+ carriers (PowerShell,
Python, JScript, VBScript, batch, bash, node, plus the polyglot carriers: PHP, Lua,
Perl, Ruby, TypeScript, AppleScript, AutoIt, AutoHotkey, C# script, Google Apps
Script, Groovy, GitHub Actions YAML, MSBuild XML, NSIS, WMI MOF, JSP, GDScript,
Erlang escript, Elixir). Every fixture embeds a layered-encoded key=value descriptor.

This module exists because the STOCK path (autosolve_script.solve_fields_ext called on
the whole outer blob) has three defects that cost the Day-26 Mastery window:

  BUG 1 - SET/BLOB MISALIGNMENT at >=10 sets.  solve_fields_ext aligns sets to inner
          blobs by INDEX after sorted({set-prefix strings}).  Lexicographically that is
          [set1, set10, set2, ... set9] while the inner archives sort numerically
          [evidence-01 .. evidence-10], so 9 of 10 sets read the WRONG evidence archive.
          Because every set reuses the same file names with different bytes ("collision"
          decoys), the mis-read yields confident-but-wrong answers, not a crash.
          Day 11 had only 2 sets (lexical == numeric) so the bug was dormant.
  BUG 2 - SEQUENTIAL SOLVE.  The 10 sets are analysed one after another (~15-18 s each
          => 150-180 s), which overruns a ~5 min Mastery window once download + submit
          are added, and is exactly the kind of thing a 32-core box should do in ~18 s.
  BUG 3 - DESCRIPTOR DECODE SPILL.  A small number of fixtures (Day 26: one csharp_script
          descriptor) decode with trailing non-printable bytes AFTER the real value, so a
          path/url field comes out as "/tmp/.../.<hex>.stage\x00<garbage>".  exact_text is
          graded literally, so that one field fails the whole all-or-nothing batch.

FIXES HERE: explicit setK -> evidence-0K mapping taken from each question's own
`artifact` field (never index order); parallel per-set extraction (fork pool); and a
field sanitiser that trims a path/url value at its real terminator and drops trailing
control/non-ASCII bytes.  Extraction itself is unchanged - we call the proven
autosolve_script.solve_fields_ext once PER SET with a single-set mini-start (so its
internal set sort is unambiguous).

Live use (Commander, after the readiness gate / with the sanctioned override):
    HUNTRESS_TIMED_START=commander-override python3 challenges/_lib/script_multiset.py \
        script-analysis-day-NN-... [--dry] [--save DIR]
Offline (replay a captured attempt dir holding start.json + artifact_0.bin):
    python3 challenges/_lib/script_multiset.py --offline DIR
"""
import json, os, re, sys, time, multiprocessing as mp

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import autosolve_script as A           # noqa: E402  (proven per-field extraction)
import ctf_gm as _cg                   # noqa: E402
from ctf_gm import unzip               # noqa: E402

SET_RE = re.compile(r"^set(\d+)\.")
# path/url fields whose exact_text value must be a single clean token-path and so must
# be trimmed of any decode spill.
_PATH_SUFFIXES = ("-file-path", "-path-leaf")
_STAGE_TERMINATORS = (".stage",)


# --------------------------------------------------------------------------- recognise
def recognize(start):
    """-> dict(is_multiset, n_sets, set_archive{setnum:archive}) or is_multiset False.

    A start is this family when its answer ids are namespaced set1. .. setN. with N>=2
    and each set names its own evidence archive in the question `artifact` field."""
    qs = start.get("questions") or []
    setnums, set_archive = set(), {}
    for q in qs:
        m = SET_RE.match(q.get("id", ""))
        if not m:
            continue
        sn = int(m.group(1))
        setnums.add(sn)
        arc = (q.get("artifact") or "").split("->")[0].strip()
        if arc and sn not in set_archive:
            set_archive[sn] = arc
    is_ms = len(setnums) >= 2 and len(set_archive) == len(setnums)
    return {"is_multiset": is_ms, "n_sets": len(setnums), "set_archive": set_archive}


# ------------------------------------------------------------------------- field fixes
def sanitize_field(qid, value):
    """BUG 3 fix: trim a path/url exact_text value at its real terminator and drop any
    trailing control / non-ASCII bytes a descriptor decode may have spilled."""
    if not isinstance(value, str):
        return value
    if re.fullmatch(r"[\x20-\x7e]*", value):
        # D32: a clean printable value is NOT a spill and is never trimmed. The old unconditional '.stage' cut turned the real
        # '/tmp/huntress-cache/.stage-3259bee150' into '/tmp/huntress-cache/.stage' (D15 Mastery replay: 20 of 5130 wrong).
        return value
    base = re.sub(r"^set\d+\.", "", qid)
    if base.endswith(_PATH_SUFFIXES):
        for term in _STAGE_TERMINATORS:
            i = value.find(term)
            if i != -1:
                return value[: i + len(term)]
        # no known terminator: cut at the first control / non-printable byte
        m = re.match(r"^[\x20-\x7e]+", value)
        if m:
            return m.group(0)
    return value


# ----------------------------------------------------------------------- per-set solve
def _solve_one_set(args):
    """Top-level worker (fork/pickle safe). args = (setnum, questions, evidence_bytes)."""
    setnum, questions, blob = args
    ids = [q["id"] for q in questions]
    mini = {"questions": questions, "answer_ids": ids}
    ans, un, bad, _cand = A.solve_fields_ext(mini, [blob])
    ans = {k: sanitize_field(k, v) for k, v in ans.items()}
    return setnum, ans, list(un), list(bad), dict(A.CONTRACT_REJECTED)


def solve(start, blobs, workers=None, log=lambda m: None):
    """Deterministically resolve every answer id. Returns (answers, unresolved, undecodable)."""
    info = recognize(start)
    qs = start.get("questions") or []
    ids = start.get("answer_ids") or [q["id"] for q in qs]
    if not info["is_multiset"]:
        # single-set / legacy shape: the stock path is already correct and unambiguous.
        ans, un, bad, _ = A.solve_fields_ext(start, blobs)
        ans = {k: sanitize_field(k, v) for k, v in ans.items()}
        return ans, [i for i in ids if i not in ans], bad

    # expand outer artifact(s) into {archive-basename: bytes}
    inner, full, dup = {}, {}, set()
    for b in blobs:
        try:
            for n, d in unzip(b):
                bn = os.path.basename(n)
                if bn in inner and inner[bn] != d:
                    dup.add(bn)               # D31 HS (e): same filename in two folders - never pick one silently
                inner[bn] = d
                full[n] = d
        except Exception:
            pass

    by_set = {}
    for q in qs:
        m = SET_RE.match(q["id"])
        if m:
            by_set.setdefault(int(m.group(1)), []).append(q)

    jobs = []
    for sn in sorted(by_set):                                   # BUG 1 fix: explicit mapping
        arc = info["set_archive"].get(sn)
        if arc in full:
            blob = full[arc]                  # exact path named by the question: unambiguous
        elif os.path.basename(arc or "") in dup:
            log("WARN set%d: evidence archive %r is ambiguous (that filename occurs in several folders) - set held, not guessed" % (sn, arc))
            continue                          # its ids stay unresolved -> HELD, never another set's bytes
        else:
            blob = inner.get(arc) or inner.get(os.path.basename(arc or ""))
        if blob is None and len(inner) == 0 and len(blobs) == 1:
            blob = blobs[0]                                     # single evidence archive == whole blob
        if blob is None:
            log("WARN set%d: no evidence archive %r" % (sn, arc))
            continue
        jobs.append((sn, by_set[sn], blob))

    if not jobs:                                                # D31 HS: every set held/missing -> HELD, never Pool(0) (which raises)
        log("no set could be mapped to its evidence archive - all ids held")
        return {}, list(ids), []
    workers = workers or min(len(jobs), os.cpu_count() or 4)
    try:
        ctx = mp.get_context("fork")                            # BUG 2 fix: parallel per set
    except ValueError:
        ctx = mp.get_context()
    t0 = time.time()
    with ctx.Pool(workers) as pool:
        results = pool.map(_solve_one_set, jobs)
    merged, un, bad = {}, [], []
    for sn, ans, u, b, rej in sorted(results):
        merged.update(ans)
        un += u
        bad += b
    log("solved %d set(s) in %.1fs, %d/%d ids" % (len(jobs), time.time() - t0, len(merged), len(ids)))
    return merged, [i for i in ids if i not in merged], sorted(set(bad))


# -------------------------------------------------------------------------------- CLI
def _main(argv):
    dry = "--dry" in argv
    save = None
    offline = None
    for i, a in enumerate(argv):
        if a == "--save":
            save = argv[i + 1]
        if a == "--offline":
            offline = argv[i + 1]
    log = lambda m: print("[%.3f] %s" % (time.time(), m), flush=True)

    if offline:
        start = json.load(open(os.path.join(offline, "start.json"), encoding="utf-8"))
        blobs = [open(os.path.join(offline, "artifact_0.bin"), "rb").read()]
        ans, un, bad = solve(start, blobs, log=log)
        log("offline: %d answered, %d unresolved, %d undecodable" % (len(ans), len(un), len(bad)))
        return ans

    cid = [a for a in argv[1:] if not a.startswith("--") and a != save and a != offline][0]
    mm = cid if cid.endswith(("/mastery", "/time_trial")) else cid + "/mastery"
    from ctf_gm import GM
    gm = GM()
    st = A.start(gm, mm, for_time=True)
    if st is None:
        print(json.dumps({"result": "CORRECT", "already_solved": True})); return
    ids = st.get("answer_ids") or [q["id"] for q in st.get("questions", [])]
    log("attempt %s deadline=%s ids=%d" % (str(st.get("attempt_id"))[:12], st.get("deadline"), len(ids)))
    blobs = [gm.download(mm, e, i) for i, e in enumerate(gm.artifacts(st))]
    if save:
        os.makedirs(save, exist_ok=True)
        json.dump(st, open(os.path.join(save, "start.json"), "w"))
        for i, b in enumerate(blobs):
            open(os.path.join(save, "artifact_%d.bin" % i), "wb").write(b)
    ans, un, bad = solve(st, blobs, log=log)
    if un:
        print(json.dumps({"result": "HELD", "unresolved": len(un), "sample": un[:10]})); return
    if dry:
        print(json.dumps({"result": "DRY", "answered": len(ans), "ids": len(ids)})); return
    res = gm.submit(mm, {i: ans[i] for i in ids})
    print(json.dumps({"result": res.get("result"), "flag": res.get("flag"),
                      "solved_by": res.get("solved_by")}))


if __name__ == "__main__":
    _main(sys.argv)
