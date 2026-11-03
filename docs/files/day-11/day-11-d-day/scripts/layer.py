import json, re, collections
lab = json.load(open("challenges/Day 11/D-Day/scripts/lab_answers.json"))
sure = lab["sure"]
blocks = collections.defaultdict(list)
for k in sure:
    m = re.match(r"(d\d\d)_(.*)", k)
    blocks[m.group(1) if m else "other"].append(m.group(2) if m else k)
for b in sorted(blocks):
    print(b, "(%d):" % len(blocks[b]), sorted(blocks[b]))
print()
print("=== slot shapes across blocks ===")
slots = collections.Counter(s for v in blocks.values() for s in v)
for s, n in sorted(slots.items(), key=lambda x: (-x[1], x[0])):
    print("%2d x %s" % (n, s))
print()
print("=== d11 / highest block values (today's own layer) ===")
hi = sorted(blocks)[-1]
for k in sorted(sure):
    if k.startswith(hi + "_"):
        v = sure[k]
        print("  %-42s = %s" % (k, (v[:120] + "...") if isinstance(v, str) and len(v) > 120 else v))
