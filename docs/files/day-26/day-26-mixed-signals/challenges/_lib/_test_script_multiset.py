#!/usr/bin/env python3
"""Offline, synthetic tests for script_multiset (the multi-set polyglot solver).

Proves the two fixes that cost the Day-26 Mastery window, with NO live bytes:
  - BUG 1: setK is solved from evidence-0K (explicit name mapping), NOT index order,
    so set10 does not read evidence-02's bytes.
  - BUG 3: a path field with a decode spill after '.stage' is trimmed.

Run: python3 challenges/_lib/_test_script_multiset.py
"""
import io, os, sys, json
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import pyzipper
import ctf_gm
import script_multiset as M
import multiprocessing as _mp

if "fork" not in _mp.get_all_start_methods():
    # D31 (HS 2026-10-30): Windows python has no 'fork', so solve()'s pool would SPAWN fresh workers that re-import
    # script_multiset and never see this test's monkeypatched extractor (production runs under WSL = fork). Run the
    # per-set jobs in-process here instead; the set -> evidence-archive mapping under test is unchanged.
    class _InProcPool:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def map(self, fn, jobs):
            return [fn(j) for j in jobs]

    class _InProcCtx:
        Pool = _InProcPool

    M.mp = type("_mp_shim", (), {"get_context": staticmethod(lambda *_a, **_k: _InProcCtx())})


def _aeszip(members):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(ctf_gm.ZIP_PW)
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_recognize_and_mapping():
    # three sets chosen to break lexical sort: 1, 2, 10
    setnums = [1, 2, 10]
    questions, inner = [], {}
    for sn in setnums:
        qid = "set%d.polyglot-php-aaaaaa-file-path" % sn
        questions.append({"id": qid, "artifact": "evidence-%02d.zip -> x.php" % sn})
        # inner evidence archive carries a marker naming its OWN set number
        inner["evidence-%02d.zip" % sn] = _aeszip({"marker.txt": ("SET=%d" % sn).encode()})
    outer = _aeszip(inner)
    start = {"questions": questions, "answer_ids": [q["id"] for q in questions]}

    info = M.recognize(start)
    assert info["is_multiset"] and info["n_sets"] == 3, info
    assert info["set_archive"] == {1: "evidence-01.zip", 2: "evidence-02.zip", 10: "evidence-10.zip"}, info["set_archive"]

    # monkeypatch the heavy extractor: return, for each id, the marker found in the blob
    # it was handed. If BUG 1 regressed, set10 would receive evidence-02's bytes.
    def fake_solve_fields_ext(mini, blobs):
        marker = None
        for n, d in ctf_gm.unzip(blobs[0]):
            if n.endswith("marker.txt"):
                marker = d.decode()
        ans = {q["id"]: marker for q in mini["questions"]}
        return ans, [], [], {}

    orig = M.A.solve_fields_ext
    M.A.solve_fields_ext = fake_solve_fields_ext
    try:
        ans, un, bad = M.solve(start, [outer], workers=3)
    finally:
        M.A.solve_fields_ext = orig
    assert not un, un
    for sn in setnums:
        qid = "set%d.polyglot-php-aaaaaa-file-path" % sn
        assert ans[qid] == "SET=%d" % sn, "set%d read the wrong evidence archive: %r" % (sn, ans[qid])
    print("OK test_recognize_and_mapping (set10 read evidence-10, not evidence-02)")


def test_sanitize_path_spill():
    qid = "set8.polyglot-csharp_script-bdaec5-file-path"
    spilled = "/tmp/huntress-csharp_script/.7e2d2dd8d2ed7742.stage\x00\x9f{garbage\xffbytes"
    assert M.sanitize_field(qid, spilled) == "/tmp/huntress-csharp_script/.7e2d2dd8d2ed7742.stage"
    leaf = "set1.polyglot-php-f4f1e8-path-leaf"
    assert M.sanitize_field(leaf, ".b7fbd3863d45aea9.stage\x00junk") == ".b7fbd3863d45aea9.stage"
    # a clean value is unchanged; a non-path field is never touched
    assert M.sanitize_field(qid, "/tmp/huntress-php/.deadbeefdeadbeef.stage") == "/tmp/huntress-php/.deadbeefdeadbeef.stage"
    assert M.sanitize_field("set1.x-url", "https://h/stage\x00x") == "https://h/stage\x00x"
    print("OK test_sanitize_path_spill")


def test_legacy_single_set_passthrough():
    start = {"questions": [{"id": "powershell-aa-url"}], "answer_ids": ["powershell-aa-url"]}
    assert M.recognize(start)["is_multiset"] is False
    print("OK test_legacy_single_set_passthrough")


if __name__ == "__main__":
    test_recognize_and_mapping()
    test_sanitize_path_spill()
    test_legacy_single_set_passthrough()
    print("ALL PASS")
