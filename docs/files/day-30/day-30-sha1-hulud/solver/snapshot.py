"""
Snapshot sha1-hulud.exe right after both 45M-iteration anti-tamper loops finish.
Writes snap/regions.bin + snap/meta.json (regions, context, teb, modules, input addrs).
Usage: python snapshot.py "<input string>"
"""
import ctypes, ctypes.wintypes as wt, time, sys, json, os, struct

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
psapi = ctypes.WinDLL("psapi")
k32.OpenThread.restype = wt.HANDLE

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_ulonglong)]
class CONTEXT(ctypes.Structure):
    _pack_ = 16
    _fields_ = [("P1Home",ctypes.c_ulonglong),("P2Home",ctypes.c_ulonglong),("P3Home",ctypes.c_ulonglong),
        ("P4Home",ctypes.c_ulonglong),("P5Home",ctypes.c_ulonglong),("P6Home",ctypes.c_ulonglong),
        ("ContextFlags",wt.DWORD),("MxCsr",wt.DWORD),
        ("SegCs",wt.WORD),("SegDs",wt.WORD),("SegEs",wt.WORD),("SegFs",wt.WORD),("SegGs",wt.WORD),("SegSs",wt.WORD),
        ("EFlags",wt.DWORD),
        ("Dr0",ctypes.c_ulonglong),("Dr1",ctypes.c_ulonglong),("Dr2",ctypes.c_ulonglong),
        ("Dr3",ctypes.c_ulonglong),("Dr6",ctypes.c_ulonglong),("Dr7",ctypes.c_ulonglong),
        ("Rax",ctypes.c_ulonglong),("Rcx",ctypes.c_ulonglong),("Rdx",ctypes.c_ulonglong),
        ("Rbx",ctypes.c_ulonglong),("Rsp",ctypes.c_ulonglong),("Rbp",ctypes.c_ulonglong),
        ("Rsi",ctypes.c_ulonglong),("Rdi",ctypes.c_ulonglong),
        ("R8",ctypes.c_ulonglong),("R9",ctypes.c_ulonglong),("R10",ctypes.c_ulonglong),("R11",ctypes.c_ulonglong),
        ("R12",ctypes.c_ulonglong),("R13",ctypes.c_ulonglong),("R14",ctypes.c_ulonglong),("R15",ctypes.c_ulonglong),
        ("Rip",ctypes.c_ulonglong),("FltSave", ctypes.c_ubyte*512),
        ("VectorRegister", M128A*26),("VectorControl",ctypes.c_ulonglong),
        ("DebugControl",ctypes.c_ulonglong),("LastBranchToRip",ctypes.c_ulonglong),
        ("LastBranchFromRip",ctypes.c_ulonglong),("LastExceptionToRip",ctypes.c_ulonglong),
        ("LastExceptionFromRip",ctypes.c_ulonglong)]
CONTEXT_ALL = 0x10001F  # control|integer|segments|floating point|debug
class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD),("lpReserved", wt.LPWSTR),("lpDesktop", wt.LPWSTR),("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),("dwY", wt.DWORD),("dwXSize", wt.DWORD),("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),("dwYCountChars", wt.DWORD),("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),("wShowWindow", wt.WORD),("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.POINTER(wt.BYTE)),("hStdInput", wt.HANDLE),("hStdOutput", wt.HANDLE),("hStdError", wt.HANDLE)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE),("hThread", wt.HANDLE),("dwProcessId", wt.DWORD),("dwThreadId", wt.DWORD)]
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wt.DWORD),("lpSecurityDescriptor", ctypes.c_void_p),("bInheritHandle", wt.BOOL)]
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),("__alignment1", wt.DWORD),
                ("RegionSize", ctypes.c_size_t),("State", wt.DWORD),
                ("Protect", wt.DWORD),("Type", wt.DWORD),("__alignment2", wt.DWORD)]
class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_long), ("TebBaseAddress", ctypes.c_void_p),
                ("UniqueProcess", ctypes.c_void_p), ("UniqueThread", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_size_t), ("Priority", ctypes.c_long), ("BasePriority", ctypes.c_long)]

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "ext", "sha1-hulud.exe")
OUT = os.path.join(HERE, "snap")
os.makedirs(OUT, exist_ok=True)
INPUT = (sys.argv[1] if len(sys.argv) > 1 else "flag{0123456789abcdef0123456789abcdef}")
LOOP_LO, LOOP_HI = 0x481d0, 0x48280

def read(hp, a, n):
    b = (ctypes.c_char * n)(); br = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(hp, ctypes.c_void_p(a), b, n, ctypes.byref(br)): return bytes(b[:br.value])
    return None

hRi, hWi, hRo, hWo = wt.HANDLE(), wt.HANDLE(), wt.HANDLE(), wt.HANDLE()
sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
k32.CreatePipe(ctypes.byref(hRi), ctypes.byref(hWi), ctypes.byref(sa), 0)
k32.CreatePipe(ctypes.byref(hRo), ctypes.byref(hWo), ctypes.byref(sa), 1 << 16)
k32.SetHandleInformation(hWi, 1, 0); k32.SetHandleInformation(hRo, 1, 0)
si = STARTUPINFO(); si.cb = ctypes.sizeof(si); si.dwFlags = 0x100
si.hStdInput = hRi; si.hStdOutput = hWo; si.hStdError = hWo
pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(EXE, None, None, None, True, 0, None, None, ctypes.byref(si), ctypes.byref(pi))
time.sleep(0.3)
mods = (ctypes.c_void_p * 256)(); need = wt.DWORD()
psapi.EnumProcessModules(pi.hProcess, mods, ctypes.sizeof(mods), ctypes.byref(need))
img = mods[0]
hT = k32.OpenThread(0x1FFFFF, False, pi.dwThreadId)
data = INPUT.encode() + b"\n"
w = wt.DWORD(); k32.WriteFile(hWi, data, len(data), ctypes.byref(w), None)
t0 = time.time(); seen = False
ctx = CONTEXT()
while time.time() - t0 < 30:
    time.sleep(0.005)
    ec = wt.DWORD(); k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(ec))
    if ec.value != 259:
        print("process exited before snapshot"); sys.exit(1)
    k32.SuspendThread(hT)
    ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
    k32.GetThreadContext(hT, ctypes.byref(ctx))
    r = ctx.Rip - img
    if LOOP_LO <= r < LOOP_HI:
        seen = True
    elif seen and img <= ctx.Rip < img + 0x80000:
        break  # stay suspended: first sample in our image after loop 2
    k32.ResumeThread(hT)
else:
    print("never reached post-loop state"); k32.TerminateProcess(pi.hProcess, 0); sys.exit(1)
print(f"suspended at RVA {hex(ctx.Rip - img)} t={time.time()-t0:.2f}s")

tbi = THREAD_BASIC_INFORMATION(); rl = wt.ULONG()
ntdll.NtQueryInformationThread(hT, 0, ctypes.byref(tbi), ctypes.sizeof(tbi), ctypes.byref(rl))
teb = tbi.TebBaseAddress

# modules
modlist = []
n = need.value // 8
psapi.EnumProcessModules(pi.hProcess, mods, ctypes.sizeof(mods), ctypes.byref(need))
for i in range(need.value // 8):
    nm = ctypes.create_unicode_buffer(260)
    psapi.GetModuleBaseNameW(pi.hProcess, ctypes.c_void_p(mods[i]), nm, 260)
    modlist.append((nm.value, mods[i]))

# regions
regions = []; off = 0
with open(os.path.join(OUT, "regions.bin"), "wb") as fb:
    addr = 0; mbi = MEMORY_BASIC_INFORMATION()
    while k32.VirtualQueryEx(pi.hProcess, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base = mbi.BaseAddress or 0; size = mbi.RegionSize
        if mbi.State == 0x1000 and not (mbi.Protect & 0x100) and mbi.Protect not in (0, 1):
            d = read(pi.hProcess, base, size)
            if d is not None and len(d) == size:
                fb.write(d)
                regions.append({"base": base, "size": size, "prot": mbi.Protect, "off": off})
                off += size
        addr = base + size
        if size == 0 or addr >= 0x7FFFFFFFFFFF: break

# input locations
needle = INPUT.encode()
inp_addrs = []
with open(os.path.join(OUT, "regions.bin"), "rb") as fb:
    blob = fb.read()
for r in regions:
    seg = blob[r["off"]:r["off"] + r["size"]]
    i = seg.find(needle)
    while i >= 0:
        inp_addrs.append(r["base"] + i); i = seg.find(needle, i + 1)
    wneedle = INPUT.encode("utf-16-le")
    i = seg.find(wneedle)
    while i >= 0:
        inp_addrs.append(("w", r["base"] + i)); i = seg.find(wneedle, i + 1)

regs = {f: getattr(ctx, f) for f in ["Rax","Rcx","Rdx","Rbx","Rsp","Rbp","Rsi","Rdi","R8","R9","R10","R11","R12","R13","R14","R15","Rip","EFlags","MxCsr"]}
flt = bytes(ctx.FltSave)
xmm = [flt[160 + 16 * i: 176 + 16 * i].hex() for i in range(16)]
meta = {"regs": regs, "xmm": xmm, "fcw_fsw": flt[:4].hex(), "teb": teb, "img": img,
        "modules": modlist, "regions": regions, "input": INPUT, "input_addrs": inp_addrs,
        "segs": {"cs": ctx.SegCs, "ss": ctx.SegSs, "ds": ctx.SegDs, "es": ctx.SegEs, "fs": ctx.SegFs, "gs": ctx.SegGs}}
json.dump(meta, open(os.path.join(OUT, "meta.json"), "w"), indent=1)
print(f"dumped {len(regions)} regions, {off/1e6:.1f} MB; TEB={hex(teb)}; input at {inp_addrs[:6]}")
k32.TerminateProcess(pi.hProcess, 0)
