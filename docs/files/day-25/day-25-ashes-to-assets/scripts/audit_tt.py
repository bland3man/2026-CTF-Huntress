import json, re, collections
s = json.load(open('/tmp/tt_status.json'))
A = json.load(open('/tmp/tt_answers_new.json'))
qs = {q['id']: q for q in s['questions']}
bad = collections.defaultdict(list)
for i, q in qs.items():
    v = A.get(i)
    t = q['question']
    if 'joined by |' in t and (v is None or '|' not in str(v)):
        bad['pipe_missing'].append((i, v))
    if q['answer_format'].get('kind') == 'enum' and v not in q['answer_format'].get('accepted_values', []):
        bad['enum_bad'].append((i, v))
    if q['answer_format'].get('kind') == 'ordered_tokens' and v is not None and (' ' in str(v) or ',' in str(v)):
        bad['tokens_bad'].append((i, v))
for k, l in bad.items():
    print(k, len(l))
    for x in l[:40]:
        print('   ', x)
# question templates (distinct wording, id suffix)
tmpl = collections.Counter()
for i, q in qs.items():
    w = re.sub(r'[0-9a-f]{6}\.\w+', 'FILE', q['question'])[:110]
    tmpl[w] += 1
print('distinct question templates:', len(tmpl))
