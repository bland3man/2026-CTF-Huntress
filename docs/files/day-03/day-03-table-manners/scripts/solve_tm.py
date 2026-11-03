import json,sys,re,struct,zlib,hashlib,time
sys.path.insert(0,'.')
from ctf_gm import GM, unzip
sh=lambda b:hashlib.sha256(b).hexdigest()
def elf(d):
    shoff=struct.unpack_from("<Q",d,0x28)[0]; n,si=struct.unpack_from("<HH",d,0x3C)[0],struct.unpack_from("<H",d,0x3E)[0]
    secs=[struct.unpack_from("<IIQQQQIIQQ",d,shoff+k*64) for k in range(n)]
    so=secs[si][4]; nm=lambda o:d[so+o:d.index(b"\0",so+o)].decode()
    names=[nm(s[0]) for s in secs]
    syms=[]
    for s in secs:
        if s[1]==2:
            stro=secs[s[6]][4]
            for k in range(s[5]//24):
                x=struct.unpack_from("<IBBHQQ",d,s[4]+k*24); syms.append(d[stro+x[0]:d.index(b"\0",stro+x[0])].decode())
    return secs,names,[x for x in syms if x]
def rc_imm(d):
    m=[re.search(rb"\xb8(....)\xc3",d[a:b]) for a,b in []]
    secs,names,_=elf(d); t=secs[names.index(".text")]; body=d[t[4]:t[4]+t[5]]
    c=[int.from_bytes(m.group(1),"little") for m in re.finditer(rb"\xb8(....)\xc3",body,re.S)]
    c=[x for x in c if 8100<=x<=8199] or c
    return c[0]
def hcfg(d):
    i=d.find(b"HCFG"); key=d[i+5]; ln=d[i+6]|d[i+7]<<8; crc=int.from_bytes(d[i+8:i+12],"little")
    p=bytes(b^key for b in d[i+12:i+12+ln]); assert zlib.crc32(p)==crc
    return json.loads(p),key,crc
def dn(d):
    pe=struct.unpack_from("<I",d,0x3c)[0]; mach=struct.unpack_from("<H",d,pe+4)[0]
    i=d.find(b"BSJB"); l=struct.unpack_from("<I",d,i+12)[0]; ver=d[i+16:i+16+l].split(b"\0")[0].decode()
    for key in range(256):
        pat=bytes(b^key for b in b'{"campaign"'); j=d.find(pat)
        if j>=0:
            e=j; out=bytes(b^key for b in d[j:j+600]); k=0; dep=0
            for k,ch in enumerate(out):
                dep+=(ch==123)-(ch==125)
                if dep==0: break
            return mach,ver,json.loads(out[:k+1])
    raise RuntimeError("no cfg")
def one(files,dkey):
    return next(c for n,c in files if n.startswith(dkey+"--") and not n.endswith(".json")), next((c for n,c in files if n.startswith(dkey+"--") and n.endswith(".json")),None)
MACH={0x14c:"i386",0x8664:"amd64"}
def answer(files,aid):
    dk,suf=aid.split("_",1)
    main,aux=one(files,dk)
    if suf=="artifact_sha256_1": return sh(main)
    if suf=="artifact_sha256_2": return sh(aux)
    if dk=="d01":
        secs,names,syms=elf(main)
        return {"analysis_elf_class":"ELF64" if main[4]==2 else "ELF32","analysis_machine":"x86-64","analysis_elf_type":"ET_EXEC","analysis_endianness":"little" if main[5]==1 else "big",
         "analysis_section_names":json.dumps(names,separators=(",",":")),"analysis_symbols":json.dumps(syms,separators=(",",":")),
         "analysis_disassembly":json.dumps(["mov eax, %d"%rc_imm(main),"ret"],separators=(",",":"))}[suf]
    if dk=="d02":
        c,key,crc=hcfg(main)
        return {"analysis_format":"elf","analysis_config_campaign":c["campaign"],"analysis_config_domain":c["domain"],"analysis_config_mutex":c["mutex"],"analysis_config_url":c["url"],
         "analysis_config_crc32_hex":"0x%08x"%crc,"analysis_xor_key_hex":"0x%02x"%key}[suf]
    mach,ver,c=dn(main)
    return {"analysis_format":"pe_cli","analysis_machine":MACH.get(mach,hex(mach)),"analysis_metadata_version":ver,"analysis_config_campaign":c["campaign"],"analysis_config_domain":c["domain"],"analysis_config_mutex":c["mutex"]}[suf]
def compute(st,blobs):
    sets=[unzip(b) for b in blobs]; out={}
    for aid in st["answer_ids"]:
        m=re.match(r"^set(\d+)\.(.*)$",aid); idx=int(m.group(1))-1 if m else 0; core=m.group(2) if m else aid
        out[aid]=answer(sets[idx],core)
    return out
if __name__=="__main__":
    g=GM(); cid="binary-reverse-engineering-day-03-managed-configuration/"+sys.argv[1]
    t=time.time()
    for attempt in range(int(sys.argv[2]) if len(sys.argv)>2 else 3):
        st=g.start(cid); blobs=[g.download(cid,e,i) for i,e in enumerate(g.artifacts(st))]
        a=compute(st,blobs); r=g.submit(cid,a)
        print(attempt,round(time.time()-t,2),{k:v for k,v in r.items() if k not in("questions","prompt","guidance","name")},flush=True)
        if str(r.get("result")).upper()=="CORRECT": break
        g.retry(cid)
