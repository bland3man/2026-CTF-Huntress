#!/usr/bin/env python3
"""Day 13 'Crystal Clear' (binary-reverse-engineering) local reproduction.

The live solve ran entirely through the banked lane adapter
(challenges/_lib/autosolve_binary.py -> binary_facts.facts_for), which needed NO
extension today: the d13 block reuses slot shapes already covered (format,
machine, architecture, sha256, hcfg_offset, config_{campaign,domain,url,mutex},
config_crc32_hex). This script reproduces the d13 answer values offline so the
writeup numbers can be re-derived without touching the Game Master.

Usage:
  wsl python3 "challenges/Day 13/Crystal Clear/scripts/solve_crystal.py"
"""
import hashlib
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "challenges", "_lib"))

from ctf_gm import unzip          # noqa: E402  (AES zip, password 'infected')
import binary_facts as bf         # noqa: E402

ARTIFACT = os.path.join(ROOT, "challenges", "Day 13", "_stage", "Crystal_Clear", "artifact_0.bin")

# the ten d13 answer ids -> how each is rendered for the grader
SLOTS = (
    ("d13_artifact_sha256_1", lambda f: f["sha256"]),
    ("d13_analysis_format", lambda f: f["format"]),                     # short label: 'elf'
    ("d13_analysis_machine", lambda f: f["machine_name"]),              # 'x86-64' (62 / 0x3e also accepted)
    ("d13_analysis_architecture", lambda f: f["machine_name"]),
    ("d13_analysis_hcfg_offset", lambda f: f["hcfg_offset"]),           # base-10 integer
    ("d13_analysis_config_campaign", lambda f: f["config_campaign"]),
    ("d13_analysis_config_domain", lambda f: f["config_domain"]),
    ("d13_analysis_config_url", lambda f: f["config_url"]),
    ("d13_analysis_config_mutex", lambda f: f["config_mutex"]),
    ("d13_analysis_config_crc32_hex", lambda f: "0x%08x" % f["config_crc32"]),
)


def main():
    raw = open(ARTIFACT, "rb").read()
    members = unzip(raw)
    print("bundle: %d bytes, sha256 %s" % (len(raw), hashlib.sha256(raw).hexdigest()))
    print("members: %d (cumulative d01..d13)" % len(members))
    for name, blob in members:
        print("  %-38s %9d  %s" % (name, len(blob), blob[:4]))

    d13 = [b for n, b in members if n.startswith("d13")]
    assert len(d13) == 1, "expected exactly one d13 member"
    _, facts = bf.facts_for(d13[0])

    print("\nruntime fingerprint (Crystal):")
    print("  needed_libs      %s" % (facts["needed_libs"],))
    print("  symbol_count     %d (Crystal mangles as *Namespace::method)" % facts["symbol_count"])
    print("  has_gopclntab=%s has_cpp_typeinfo=%s is_stripped=%s"
          % (facts["has_go_buildid"], facts["has_cpp_typeinfo"], facts["is_stripped"]))

    print("\nHCFG record:")
    for k in ("hcfg_magic", "hcfg_version", "hcfg_offset", "hcfg_length",
              "hcfg_encoding", "hcfg_xor_key", "hcfg_keys"):
        print("  %-16s %s" % (k, facts[k]))

    print("\nd13 answers:")
    for aid, fn in SLOTS:
        print("  %-32s %s" % (aid, fn(facts)))


if __name__ == "__main__":
    main()
