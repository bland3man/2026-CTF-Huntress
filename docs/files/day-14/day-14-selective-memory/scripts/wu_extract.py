import json

p = 'challenges/Day 14/_gm_record/binary-reverse-engineering-day-14-objective-c-persistence-descriptor.homestation.jsonl'
recs = []
for line in open(p, encoding='utf-8', errors='replace'):
    line = line.strip()
    if not line:
        continue
    try:
        recs.append(json.loads(line))
    except Exception:
        pass

for i, r in enumerate(recs):
    op = r.get('op')
    resp = r.get('resp') or {}
    if isinstance(resp, dict):
        brief = {k: resp.get(k) for k in ('status', 'result', 'mode', 'flag', 'accepted', 'remaining', 'message', 'error') if k in resp}
    else:
        brief = str(resp)[:120]
    print(i, op, r.get('http'), json.dumps(brief)[:300])

# the d14 answers from the single_solve submit (first submit with answers)
for i, r in enumerate(recs):
    a = r.get('answers')
    if not a:
        continue
    print('--- submit record', i, 'op', r.get('op'), 'n_answers', len(a))
    d14 = {k: v for k, v in a.items() if k.startswith('d14')}
    print(json.dumps(d14, indent=1)[:4000])
    break
