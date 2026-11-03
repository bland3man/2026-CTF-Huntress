import sys, os, glob, importlib.util
root = "[local path]"
sys.path.insert(0, root + "/_lib")
spec = importlib.util.spec_from_file_location("wwip", root + "/Day 31/\U0001F476 One More Thing/scripts/warmups_wip.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
d = root + "/Day 31/\U0001F476 One More Thing/.tmp_mm"
files = sorted(glob.glob(d + "/blob-*.txt"))
ok = 0
bad = []
slugs = []
for f in files:
    data = open(f, "rb").read()
    out = m.decode_blob(data)
    ans = m.answer_from(out) if out else None
    if ans:
        ok += 1
        slugs.append(ans)
    else:
        bad.append(os.path.basename(f))
print("ok", ok, "of", len(files), "bad", bad[:10])
print(slugs[:3])
