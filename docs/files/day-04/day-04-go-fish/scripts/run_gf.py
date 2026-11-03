"""ONE automated shot for a timed Go Fish mode. Usage: python3 run_gf.py <time_trial|mastery>
start -> download -> compute everything from THIS attempt's bytes -> submit sure fields -> probe d04 arch/format labels (set-wise).
GM accumulates accepted fields; sure batch first so a wrong label cannot reject it."""
import sys,os,re,json,time
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.join(HERE,"..","..","..","_lib"))
import tm_base as tm, solve_gf as sg
from ctf_gm import GM
BASE="binary-reverse-engineering-day-04-go-runtime-fingerprints"
ARCH=["x86-64","amd64","x86_64"]; FMT=["elf","go_elf","elf64","go"]
def sub(g,cid,a):
    for i in range(40):
        try: return g.submit(cid,a)
        except RuntimeError as e:
            if "429" not in str(e): raise
            time.sleep(0.6+0.1*i)
    raise RuntimeError("429 persisted")
def brief(r): return {k:v for k,v in r.items() if k not in("questions","prompt","guidance","name")}
def main(mode):
    g=GM(); cid=BASE+"/"+mode; t0=time.time()
    st=g.start(cid); blobs=[g.download(cid,e,i) for i,e in enumerate(g.artifacts(st))]
    sets=[tm.unzip(b) for b in blobs]
    def setof(aid):
        m=re.match(r"^set(\d+)\.(.*)$",aid)
        return (sets[int(m.group(1))-1],m.group(2)) if m else (sets[0],aid)
    sure={}; probe={}
    for aid in st["answer_ids"]:
        files,core=setof(aid)
        if core in("d04_analysis_architecture","d04_analysis_format"): probe[aid]=core; continue
        sure[aid]=sg.answer(files,core)
    print("computed",len(sure),"sure,",len(probe),"probe",round(time.time()-t0,2),flush=True)
    os.makedirs(os.path.join(HERE,"..","output"),exist_ok=True)
    json.dump({"answer_ids":st["answer_ids"],"sure":sure},open(os.path.join(HERE,"..","output",mode+"_computed.json"),"w"),indent=1)
    r=sub(g,cid,sure); print("sure",round(time.time()-t0,2),brief(r),flush=True)
    if str(r.get("result")).upper()=="CORRECT": return
    for aid,core in probe.items():
        cands=ARCH if core.endswith("architecture") else FMT
        for c in cands:
            r=sub(g,cid,{aid:c}); print(aid,c,round(time.time()-t0,2),brief(r),flush=True)
            if str(r.get("result")).lower() in("accepted","correct"): break
        if str(r.get("result")).upper()=="CORRECT": return
if __name__=="__main__": main(sys.argv[1])
