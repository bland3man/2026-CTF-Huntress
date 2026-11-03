import pyzipper, os, sys
src = 'challenges/Day 14/_stage/Trust_the_Process/artifact_0.bin'
out = 'challenges/Day 14/Trust the Process/extracted'
os.makedirs(out, exist_ok=True)
with pyzipper.AESZipFile(src) as z:
    z.pwd = b'infected'
    names = z.namelist()
    for n in names:
        z.extract(n, out)
proj = [n for n in names if n.endswith('.proj')]
print("PROJ:", proj)
print("TOTAL:", len(names))
