import json, sys
t = json.load(open('challenges/Day 14/_stage/Trust_the_Process/task.json'))
res = json.load(open('challenges/Day 14/_board/script-analysis-day-14-msbuild-trusted-project-abuse.residue.json'))['residue']
qs = t['questions']
by = {}
for e in qs:
    k = e.get('id') or e.get('answer_id') or e.get('key')
    by[k] = e
want = set(res)
for i in res:
    e = by.get(i)
    print("=== ", i)
    print(json.dumps(e, indent=1)[:2000])
