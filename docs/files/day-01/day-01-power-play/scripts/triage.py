# Usage: python triage.py file1.ps1 [...]   (or paste script text on stdin)
import sys, re, base64, json
RULES = [("Aes", "synthetic_impact (ransomware)", "T1486"),
         ("ZipFile", "synthetic_collection (browser creds)", "T1555.003"),
         ("Diagnostics.Process", "resource_hijacking (miner)", "T1496")]
def triage(name, text):
    print("==", name)
    for b in re.findall(r"FromBase64String\('([^']+)'\)", text):
        print(json.dumps(json.loads(base64.b64decode(b)), indent=1))
    m = re.search(r"\$nativeTypes\s*=\s*@\(([^)]*)\)", text)
    types = m.group(1) if m else ""
    print("types:", types)
    for k, intent, tid in RULES:
        if k in types: print("=>", intent, tid)
args = sys.argv[1:]
if args:
    for a in args: triage(a, open(a, encoding="utf-8").read())
else:
    triage("stdin", sys.stdin.read())
