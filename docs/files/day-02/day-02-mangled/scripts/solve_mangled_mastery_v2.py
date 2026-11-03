#!/usr/bin/env python3
"""Mangled MASTERY one-shot solver (v2, grader-faithful, from live recon ground truth).
Per-delivery 17-field inventory; handles mixed PE/ELF C++ deliveries; byte-level + libmagic
(`file`) so it beats the <5s deadline. start(+retry)->download->compute->submit in one run.
"""
import hashlib, http.client, importlib, io, json, os, re, subprocess, sys, tempfile, time, urllib.parse
HOST="[ip]"; BASE="/huntress-ctf-proxy"; PW=b"infected"

def pz():
    v=os.path.join(tempfile.gettempdir(),"mm-deps")
    if os.path.isdir(v): sys.path.insert(0,v)
    try: return importlib.import_module("pyzipper")
    except ImportError:
        subprocess.run([sys.executable,"-m","pip","install","-q","--target",v,"pyzipper"],check=True,timeout=40)
        sys.path.insert(0,v); return importlib.import_module("pyzipper")
pyzipper=pz()
conn=http.client.HTTPConnection(HOST,timeout=4.0)

def call(m,path,pl=None):
    b=None if pl is None else json.dumps(pl,separators=(",",":"))
    h={"Content-Type":"application/json"} if b is not None else {}
    conn.request(m,path,body=b,headers=h); r=conn.getresponse(); d=r.read()
    if r.status>=400:
        if b"expired" in d.lower() or b"flag_unavailable" in d.lower(): return d
        raise RuntimeError(f"GM {r.status}: {d[:200]!r}")
    return d
def api(m,q=None,pl=None):
    path=BASE+(("?"+urllib.parse.urlencode(q)) if q else ""); return json.loads(call(m,path,pl))
def mastery_id():
    for it in api("GET",{"op":"list","all":"true"}).get("challenges",[]):
        cid=str(it.get("id","")); blob=(str(it.get("name",""))+" "+cid).lower()
        if ("mangled" in blob or "cpp-and-pe" in blob) and (it.get("mode")=="mastery" or cid.endswith("/mastery")): return cid
    raise RuntimeError("no mastery id")
def fresh_start(cid):
    st=api("POST",pl={"op":"start","challenge":cid})
    if "expired" in json.dumps(st).lower() or "flag_unavailable" in json.dumps(st).lower() or not st.get("answer_ids"):
        api("POST",pl={"op":"retry","challenge":cid}); st=api("POST",pl={"op":"start","challenge":cid})
    return st
def dl(cid,e,i):
    link=e.get("download",""); cap=link.rstrip("/").rsplit("/",1)[-1]
    if re.fullmatch(r"[0-9a-f]{64}",cap):
        return call("GET",BASE+"?"+urllib.parse.urlencode({"op":"download","capability":cap}))
    return call("GET",BASE+"?"+urllib.parse.urlencode({"op":"artifact","challenge":cid,"delivery":i}))
def run(*a): return subprocess.check_output(a,text=True,stderr=subprocess.DEVNULL)
def tmp(data,suf):
    f=tempfile.NamedTemporaryFile(delete=False,suffix=suf); f.write(data); f.close(); return f.name
def hcfg(d):
    m=d.find(b"HCFG"); key=d[m+5]; ln=int.from_bytes(d[m+6:m+8],"little"); crc=int.from_bytes(d[m+8:m+12],"little")
    dec=bytes(x^key for x in d[m+12:m+12+ln]); return json.loads(dec),key,crc
def fields(members):
    cpp=next(d for n,d in members if b"HCFG" in d)
    c=next(d for n,d in members if d is not cpp)
    o={}
    o["c_sha256"]=hashlib.sha256(c).hexdigest(); o["cpp_sha256"]=hashlib.sha256(cpp).hexdigest()
    mk=re.search(rb"BR\d{2}-[A-Z]+-\d+",c); o["c_marker"]=mk.group(0).decode() if mk else "none"
    cfg,key,crc=hcfg(cpp); o["cpp_xor_key"]="0x%02x"%key; o["cpp_config_crc32"]="0x%08x"%crc
    for k in ("campaign","domain","url","mutex"): o[k]=str(cfg.get(k,"none"))
    o["has_cpp_vtable"]="true" if re.search(rb"_ZTV\d+DiscoveryEngine",cpp) else "false"
    o["has_cpp_typeinfo"]="true" if re.search(rb"_ZTI\d+\w*Engine",cpp) else "false"
    sc=re.search(rb"_ZNK?\d+DiscoveryEngine5scoreEPKc",cpp); o["mangled_score_symbol"]=sc.group(0).decode() if sc else "none"
    vt=re.search(rb"_ZTV\d+DiscoveryEngine",cpp); o["vtable_symbol"]=vt.group(0).decode() if vt else "none"
    cp=tmp(cpp,".bin"); fo=run("file","-b",cp).strip().lower(); os.unlink(cp)
    o["cpp_format"]=("elf" if "elf" in fo else ("pe" if ("pe32" in fo or fo.startswith("pe")) else fo.split()[0]))
    cc=tmp(c,".elf")
    fb=run("file","-b",cc).strip().split(","); o["c_machine"]=fb[1].strip() if len(fb)>1 else "none"
    o["c_has_symtab"]="true" if ".symtab" in run("readelf","-S",cc) else "false"
    dis=run("objdump","-d",cc); mm=re.search(r"<recover_code>:\n((?:.*\n){1,6})",dis)
    im=re.search(r"\$(0x[0-9a-fA-F]+),%eax",mm.group(1)) if mm else None
    o["c_recover_code"]=str(int(im.group(1),16)) if im else "none"; os.unlink(cc)
    return o
def solve_once(cid):
    st=fresh_start(cid); ids=st["answer_ids"]
    entries=st.get("artifacts") or [{"download":d} for d in (st.get("downloads") or [])]
    blobs=[dl(cid,e,i) for i,e in enumerate(entries)]; per=[]
    for b in blobs:
        with pyzipper.AESZipFile(io.BytesIO(b)) as z:
            z.setpassword(PW); mem=[(n,z.read(n)) for n in z.namelist() if not n.endswith("/")]
        per.append(fields(mem))
    ans={}
    for aid in ids:
        mo=re.match(r"^set([12])\.(.+)$",aid); ans[aid]=per[int(mo.group(1))-1][mo.group(2)]
    return api("POST",pl={"op":"submit","challenge":cid,"answers":ans})
def main():
    cid=mastery_id(); print("CHALLENGE_ID",cid,flush=True)
    t0=time.time(); res=solve_once(cid); print("ELAPSED",round(time.time()-t0,2),flush=True)
    print("GAME_MASTER",json.dumps({k:res[k] for k in ("result","flag","completion_token","token","remaining") if k in res}),flush=True)
    if "expired" in json.dumps(res).lower():
        print("EXPIRED -> one clean retry",flush=True)
        api("POST",pl={"op":"retry","challenge":cid}); t0=time.time(); res=solve_once(cid); print("ELAPSED2",round(time.time()-t0,2),flush=True)
        print("GAME_MASTER",json.dumps({k:res[k] for k in ("result","flag","completion_token","token","remaining") if k in res}),flush=True)
    tok=res.get("flag") or res.get("completion_token") or res.get("token")
    if res.get("result","").upper()=="CORRECT" and tok: print("COMPLETION_TOKEN",tok,flush=True)
if __name__=="__main__": main()
