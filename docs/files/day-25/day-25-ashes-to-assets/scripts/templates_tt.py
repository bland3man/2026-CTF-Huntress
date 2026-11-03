import json, re, collections
s = json.load(open('/tmp/tt_status.json'))
A = json.load(open('/tmp/tt_answers_new.json'))
seen = collections.OrderedDict()
for q in s['questions']:
    w = re.sub(r'[0-9a-f]{6}\.\w+', 'FILE', q['question'])
    w = re.sub(r'\b[\w.-]+\.(ps1|js|vbs|py|sh|bat|cmd|php|exs|mjs|ts|lua|pl|rb|gs|csx|groovy|jsp|mof|au3|applescript|proj|ahk|yml|nsi|gd)\b', 'FILE', w)
    key = w[:160]
    seen.setdefault(key, []).append(q['id'])
for k, ids in seen.items():
    print('[%d] %s' % (len(ids), k))
    for i in ids[:2]:
        print('      %s = %r' % (i, A.get(i)))
