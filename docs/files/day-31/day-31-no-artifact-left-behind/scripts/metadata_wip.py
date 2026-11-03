#!/usr/bin/env python3
"""Metadata-forensics lane auto-solver: compute(start, blobs) -> answers (ctf_gm.solve_mode contract), generic across days.

Dispatches on each question's TEXT (never on day/id), resolves its artifact reference to the exact member bytes, and runs
a byte-level extractor. Seen 2026 Days 01-07:
  - "What is the exact filename of the <thing>?"   -> base name of the member its sibling questions point at
  - "What is its exact size in bytes?" / MD5 / SHA-1 / SHA-256 / SHA-512 digest   (Day 01)
  - "What are the first sixteen bytes as lowercase hexadecimal?" (any N spelled out or numeric)   (Day 02)
  - "Determine <format>.<field> for <file>."  structured fields (Day 03+):
      text.utf8_bom_present, jpeg.sof_dimensions_pixels, png.ihdr_dimensions_pixels, pdf.header_version,
      zip.eocd_total_entries
  PRE-BUILT for likely next days (same strict "Determine <format>.<field> for" form, exact field tokens; see FIELDS):
      gzip.* (original_filename, mtime_unix, mtime_utc, os), tar.* (member_count, member_names), pe.* (machine,
      machine_name, number_of_sections, timedatestamp[_utc], subsystem, entry_point), elf.* (class, machine, entry_point,
      type), pdf.* (page_count, info_producer/creator/title/author), exif.* (make, model, datetime_original, gps_present),
      id3.* (title, artist, album, year), png.* (chunk_count, chunk_types, ihdr_*), file.magic_type, ooxml.core_*.
      Test: _test_autosolve_metadata.py (offline). A field name not in FIELDS still raises - add one entry when a day uses it.
Artifact references handled: "X.zip", "X.zip -> member", "delivery N: X.zip -> member" (N-th download), and Mastery bundles
that nest X-01.zip / X-02.zip inside one download. Zips: plain or AES (password infected), any nesting depth.
Unknown question -> ValueError naming it (never a guessed answer). ASCII only.
"""
import hashlib, io, re, struct, sys, os, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctf_gm import ZIP_PW

# D30-#4 (2026-10-29): module-level per-content-sha ZIP members cache. ONE parse per unique blob across the
# whole compute() call's dispatch tree. Bounded size to avoid long-running leak (practical cap: ~64 entries,
# which covers a bundle MM with dozens of embedded zips). Not thread-safe but compute() is serial.
_ZIP_MEMBERS_CACHE = {}
_ZIP_MEMBERS_CACHE_MAX = 64


def _zip_cache_trim():
    while len(_ZIP_MEMBERS_CACHE) > _ZIP_MEMBERS_CACHE_MAX:
        try: _ZIP_MEMBERS_CACHE.pop(next(iter(_ZIP_MEMBERS_CACHE)))
        except StopIteration: break

NUMS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
        "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "twenty": 20,
        "thirty-two": 32, "sixty-four": 64}


# ----------------------------------------------------------------------------- archive tree
def _members(blob):
    """[(name, bytes)] for a zip blob (plain first, then AES/password), [] if not a zip."""
    if blob[:2] != b"PK":
        return []
    # D30-#4 (2026-10-29): cache the per-ZIP members list by content sha so a bundle that is read by N
    # extractors in one compute() call parses once instead of N times. Fail-open: a cache miss just re-parses.
    # Kill switch env HUNTRESS_METADATA_ZIP_CACHE=0 restores per-call re-parse.
    _cache_on = os.environ.get("HUNTRESS_METADATA_ZIP_CACHE", "1") != "0"
    if _cache_on:
        try:
            _h = hashlib.sha256(blob).digest()
            _hit = _ZIP_MEMBERS_CACHE.get(_h)
            if _hit is not None:
                return _hit
        except Exception:
            _h = None
    for pw in (None, ZIP_PW):
        try:
            if pw is None:
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    out = [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
                    if _cache_on and _h is not None:
                        _ZIP_MEMBERS_CACHE[_h] = out
                        _zip_cache_trim()
                    return out
            import pyzipper
            with pyzipper.AESZipFile(io.BytesIO(blob)) as z:
                z.setpassword(pw)
                out = [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
                if _cache_on and _h is not None:
                    _ZIP_MEMBERS_CACHE[_h] = out
                    _zip_cache_trim()
                return out
        except Exception:
            continue
    return []


class Node:
    def __init__(self, name, data):
        self.name, self.data, self._kids = name, data, None
        self._kid_index = None
        self._find_cache = {}

    @property
    def kids(self):
        if self._kids is None:
            self._kids = [Node(n, d) for n, d in _members(self.data)]
            index = {}
            for child in self._kids:
                index.setdefault(child.name, child)
                index.setdefault(os.path.basename(child.name), child)
            self._kid_index = index
        return self._kids

    def find(self, name, depth=6):
        """Breadth-first: the shallowest descendant whose base name (or path) equals name."""
        cache_key = (name, depth)
        if cache_key in self._find_cache:
            return self._find_cache[cache_key]
        if depth == 1:
            direct = (self._kid_index or {}).get(name)
            if direct is not None:
                self._find_cache[cache_key] = direct
                return direct
        level = [self]
        for _ in range(depth):
            nxt = []
            for n in level:
                for k in n.kids:
                    if k.name == name or os.path.basename(k.name) == name:
                        self._find_cache[cache_key] = k
                        return k
                    nxt.append(k)
            level = nxt
        self._find_cache[cache_key] = None
        return None


def _roots(start, blobs):
    arts = start.get("artifacts") or []
    names = [(a.get("filename") if isinstance(a, dict) else None) or "artifact_%d" % i for i, a in enumerate(arts)]
    names += ["artifact_%d" % i for i in range(len(names), len(blobs))]
    return [Node(names[i], b) for i, b in enumerate(blobs)]


def resolve(ref, roots):
    """'delivery N: A.zip -> B -> C' -> Node of C (or of A when there is no '->')."""
    ref = (ref or "").strip()
    m = re.match(r"delivery\s+(\d+)\s*:\s*(.*)$", ref, re.I)
    scope = roots
    if m:
        k = int(m.group(1)) - 1
        scope = [roots[k]] if 0 <= k < len(roots) else roots
        ref = m.group(2)
    chain = [p.strip() for p in ref.split("->") if p.strip()]
    if not chain:
        raise ValueError("empty artifact reference")
    cur = None
    head = chain[0]
    for r in scope:                                          # the head is a download itself...
        if r.name == head or os.path.basename(r.name) == head:
            cur = r; break
    if cur is None:                                          # ...or a container nested inside one (Mastery bundles)
        for r in scope:
            cur = r.find(head)
            if cur:
                break
    if cur is None and len(scope) == 1:                      # a single download whose served name differs from the label
        cur = scope[0]
    if cur is None:
        raise ValueError("artifact %r not found in %s" % (head, [r.name for r in scope]))
    for link in chain[1:]:
        nxt = cur.find(link)
        if nxt is None:
            raise ValueError("member %r not found under %r" % (link, cur.name))
        cur = nxt
    return cur


# ----------------------------------------------------------------------------- byte extractors
def jpeg_sof_dims(b):
    if b[:2] != b"\xff\xd8":
        return "none"
    i = 2
    while i + 4 <= len(b):
        if b[i] != 0xFF:
            i += 1; continue
        mk = b[i + 1]
        if mk == 0xFF:
            i += 1; continue
        if mk in (0xD8, 0x01) or 0xD0 <= mk <= 0xD7:
            i += 2; continue
        if mk in (0xD9, 0xDA):
            break
        ln = struct.unpack(">H", b[i + 2:i + 4])[0]
        if 0xC0 <= mk <= 0xCF and mk not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", b[i + 5:i + 9])
            return "%dx%d" % (w, h)
        i += 2 + ln
    return "none"


def png_ihdr_dims(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
        return "none"
    w, h = struct.unpack(">II", b[16:24])
    return "%dx%d" % (w, h)


def pdf_header_version(b):
    m = re.match(rb"%PDF-(\d+\.\d+)", b)
    return m.group(1).decode() if m else "none"


def zip_eocd_total_entries(b):
    k = b.rfind(b"PK\x05\x06")
    if k < 0 or k + 22 > len(b):
        return "none"
    return str(struct.unpack("<H", b[k + 10:k + 12])[0])


def zip_central_directory_member_names(b):
    """Central-directory member names as a lexicographically sorted JSON array.

    From Day 23 the delivered zips store their central directory in shuffled order, and the GM graded the sorted list CORRECT on D24-D27
    while the two D23 Time Trial attempts that sent the raw stored order came back incorrect. Through D22 the stored order was already
    sorted, so sorting is identical there."""
    k = b.rfind(b"PK\x05\x06")
    if k < 0 or k + 22 > len(b):
        return "none"
    n, _sz, off = struct.unpack("<HII", b[k + 10:k + 20])
    names, p = [], off
    for _ in range(n):
        if b[p:p + 4] != b"PK\x01\x02":
            break
        nl, el, cl = struct.unpack("<HHH", b[p + 28:p + 34])
        names.append(b[p + 46:p + 46 + nl].decode("utf-8", "replace"))
        p += 46 + nl + el + cl
    return _json.dumps(sorted(names), separators=(",", ":"))


def utf8_bom_present(b):
    return "true" if b[:3] == b"\xef\xbb\xbf" else "false"


# ----------------------------------------------------------------------------- likely-next extractors (pre-built 2026-10-07)
# Format choices (documented because the GM has not asked these yet; mirror conventions it HAS accepted):
#   counts / sizes / unix timestamps -> decimal string; addresses + codes -> lowercase "0x%x"; booleans -> "true"/"false";
#   lists -> compact JSON array in file order (same convention the binary lane's GM accepted); absent -> "none";
#   UTC times -> "YYYY-MM-DDTHH:MM:SSZ"; machine names follow the binary lane's GM-confirmed "x86-64" spelling.
import datetime, json as _json, tarfile, zlib


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _jarr(xs):
    return _json.dumps(list(xs), separators=(",", ":"))


def _gzip_hdr(b):
    if b[:2] != b"\x1f\x8b" or len(b) < 10:
        return None
    flg, mtime, os_b = b[3], struct.unpack("<I", b[4:8])[0], b[9]
    i, name = 10, None
    if flg & 4:
        i += 2 + struct.unpack("<H", b[i:i + 2])[0]
    if flg & 8:
        j = b.index(b"\x00", i)
        name = b[i:j].decode("latin-1"); i = j + 1
    return {"mtime": mtime, "os": os_b, "name": name}


def gzip_original_filename(b):
    h = _gzip_hdr(b)
    return (h["name"] or "none") if h else "none"


def gzip_mtime_unix(b):
    h = _gzip_hdr(b)
    return str(h["mtime"]) if h else "none"


def gzip_mtime_utc(b):
    h = _gzip_hdr(b)
    return _utc(h["mtime"]) if h and h["mtime"] else "none"


def gzip_os(b):
    h = _gzip_hdr(b)
    return str(h["os"]) if h else "none"


def _tar_members(b):
    try:
        with tarfile.open(fileobj=io.BytesIO(b), mode="r:*") as t:
            return t.getmembers()
    except Exception:
        return None


def tar_member_count(b):
    m = _tar_members(b)
    return str(len(m)) if m is not None else "none"


def tar_member_names(b):
    m = _tar_members(b)
    return _jarr(x.name for x in m) if m is not None else "none"


PE_MACHINES = {0x8664: "x86-64", 0x14c: "x86", 0xaa64: "arm64", 0x1c0: "arm", 0x1c4: "armnt"}


def _pe(b):
    if b[:2] != b"MZ" or len(b) < 0x40:
        return None
    off = struct.unpack("<I", b[0x3c:0x40])[0]
    if b[off:off + 4] != b"PE\x00\x00":
        return None
    mach, nsec, tds = struct.unpack("<HHI", b[off + 4:off + 12])
    opt = off + 24
    return {"machine": mach, "nsec": nsec, "tds": tds, "entry": struct.unpack("<I", b[opt + 16:opt + 20])[0],
            "subsystem": struct.unpack("<H", b[opt + 68:opt + 70])[0], "magic": struct.unpack("<H", b[opt:opt + 2])[0]}


def _pe_field(key, fmt):
    def f(b):
        p = _pe(b)
        return fmt(p[key]) if p else "none"
    return f


ELF_MACHINES = {62: "x86-64", 3: "x86", 183: "aarch64", 40: "arm", 243: "riscv", 8: "mips"}
ELF_TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}


def _elf(b):
    if b[:4] != b"\x7fELF" or len(b) < 0x34:
        return None
    is64, end = b[4] == 2, "<" if b[5] == 1 else ">"
    et, em = struct.unpack(end + "HH", b[16:20])
    entry = struct.unpack(end + ("Q" if is64 else "I"), b[24:32] if is64 else b[24:28])[0]
    return {"class": "64" if is64 else "32", "type": et, "machine": em, "entry": entry}


def _elf_field(fn):
    def f(b):
        e = _elf(b)
        return fn(e) if e else "none"
    return f


def _pdf_inflated(b):
    """Raw bytes plus every inflatable stream, so Info/page objects inside FlateDecode object streams are seen too."""
    parts = [b]
    for m in re.finditer(rb"stream\r?\n", b):
        s = m.end()
        e = b.find(b"endstream", s)
        if e < 0:
            continue
        try:
            parts.append(zlib.decompress(b[s:e]))
        except Exception:
            pass
    return b"\n".join(parts)


def pdf_page_count(b):
    if not b.startswith(b"%PDF"):
        return "none"
    return str(len(re.findall(rb"/Type\s*/Page(?![a-zA-Z])", _pdf_inflated(b))))


def _pdf_info(key):
    def f(b):
        if not b.startswith(b"%PDF"):
            return "none"
        m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", _pdf_inflated(b))
        if m:
            raw = re.sub(rb"\\(.)", rb"\1", m.group(1))
            if raw.startswith(b"\xfe\xff"):
                return raw[2:].decode("utf-16-be", "replace")
            return raw.decode("latin-1")
        m = re.search(rb"/" + key + rb"\s*<([0-9a-fA-F\s]+)>", _pdf_inflated(b))
        if m:
            raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())
            return raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1")
        return "none"
    return f


def _exif(b):
    """{tag: value} from IFD0 + the Exif sub-IFD (+ 'gps' if a GPS IFD pointer exists). JPEG APP1 only."""
    if b[:2] != b"\xff\xd8":
        return None
    k = b.find(b"Exif\x00\x00")
    if k < 0:
        return {}
    t = b[k + 6:]
    end = "<" if t[:2] == b"II" else ">"
    out = {}

    def ifd(off):
        n = struct.unpack(end + "H", t[off:off + 2])[0]
        for i in range(n):
            e = off + 2 + 12 * i
            tag, typ, cnt = struct.unpack(end + "HHI", t[e:e + 8])
            vo = t[e + 8:e + 12]
            if typ == 2:                                   # ASCII
                p = struct.unpack(end + "I", vo)[0] if cnt > 4 else None
                raw = t[p:p + cnt] if p is not None else vo[:cnt]
                out[tag] = raw.split(b"\x00")[0].decode("latin-1").strip()
            elif typ == 4:                                 # LONG (IFD pointers)
                out[tag] = struct.unpack(end + "I", vo)[0]
    ifd(struct.unpack(end + "I", t[4:8])[0])
    if 0x8769 in out:
        ifd(out[0x8769])
    return out


def _exif_tag(tag):
    def f(b):
        e = _exif(b)
        return e.get(tag) or "none" if e is not None else "none"
    return f


def exif_gps_present(b):
    e = _exif(b)
    return "true" if e and 0x8825 in e else "false"


def _id3(b):
    out = {}
    if b[:3] == b"ID3" and len(b) > 10:
        ver = b[3]
        size = (b[6] << 21) | (b[7] << 14) | (b[8] << 7) | b[9]
        i, end = 10, 10 + size
        while i + 10 <= end:
            fid = b[i:i + 4]
            if not fid.strip(b"\x00"):
                break
            fs = ((b[i + 4] << 21) | (b[i + 5] << 14) | (b[i + 6] << 7) | b[i + 7]) if ver == 4 else struct.unpack(">I", b[i + 4:i + 8])[0]
            body = b[i + 10:i + 10 + fs]
            if fid[:1] == b"T" and body:
                enc, txt = body[0], body[1:]
                s = txt.decode({0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin-1"), "replace")
                out[fid.decode("latin-1")] = s.split("\x00")[0].strip()
            i += 10 + fs
    if len(b) >= 128 and b[-128:-125] == b"TAG":     # ID3v1 fallback for anything v2 did not carry
        t = b[-128:]
        for key, sl in (("TIT2", t[3:33]), ("TPE1", t[33:63]), ("TALB", t[63:93]), ("TYER", t[93:97])):
            out.setdefault(key, sl.split(b"\x00")[0].decode("latin-1").strip())
    return out


def _id3_frame(*fids):
    def f(b):
        d = _id3(b)
        for fid in fids:
            if d.get(fid):
                return d[fid][:4] if fid == "TDRC" else d[fid]
        return "none"
    return f


def _png_chunks(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i, out = 8, []
    while i + 8 <= len(b):
        ln, typ = struct.unpack(">I4s", b[i:i + 8])
        out.append(typ.decode("latin-1"))
        i += 12 + ln
        if typ == b"IEND":
            break
    return out


def png_chunk_count(b):
    c = _png_chunks(b)
    return str(len(c)) if c is not None else "none"


def png_chunk_types(b):
    c = _png_chunks(b)
    return _jarr(c) if c is not None else "none"


def _png_ihdr(i, fmt=str):
    def f(b):
        if b[:8] != b"\x89PNG\r\n\x1a\n" or b[12:16] != b"IHDR":
            return "none"
        w, h, depth, ctype = struct.unpack(">IIBB", b[16:26])
        return fmt((w, h, depth, ctype)[i])
    return f


MAGIC = [(b"%PDF", "pdf"), (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"PK\x03\x04", "zip"),
         (b"PK\x05\x06", "zip"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"),
         (b"Rar!", "rar"), (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"ID3", "mp3"), (b"\xd0\xcf\x11\xe0", "ole"),
         (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"), (b"\xfe\xed\xfa\xcf", "macho"), (b"\xfe\xed\xfa\xce", "macho"),
         (b"dex\n", "dex"), (b"SQLite format 3\x00", "sqlite"), (b"RIFF", "riff"),
         (b"OggS", "ogg"), (b"fLaC", "flac"), (b"\x00asm", "wasm")]


def file_magic_type(b):
    if b[:3] == b"\xca\xfe\xba":                     # CAFEBABE = Java class OR fat Mach-O; CAFEBABF = fat64 Mach-O (found by the homestation audit 2026-10-10)
        try:
            import hdr_facts
            k = hdr_facts.classify_cafebabe(b)
            if k:
                return "java-class" if k == "java-class" else "macho"
        except Exception:
            pass
    for sig, name in MAGIC:
        if b.startswith(sig):
            return name
    if len(b) > 262 and b[257:262] == b"ustar":
        return "tar"
    if b[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    return "none"


def _ooxml_core(tag):
    def f(b):
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                x = z.read("docProps/core.xml").decode("utf-8", "replace")
        except Exception:
            return "none"
        m = re.search(r"<(?:\w+:)?%s\b[^>]*>(.*?)</(?:\w+:)?%s>" % (tag, tag), x, re.S)
        return m.group(1).strip() if m else "none"
    return f


def ooxml_external_relationship_targets(b):
    """Targets of every Relationship with TargetMode="External" across all .rels parts, in archive then document order."""
    import html as _html
    def scan(zf):
        out = []
        for info in zf.infolist():
            if not info.filename.lower().endswith(".rels"):
                continue
            x = zf.read(info.filename).decode("utf-8", "replace")
            for tag in re.findall(r"<(?:\w+:)?Relationship\b[^>]*?/?>", x, re.S):
                attrs = dict((k.lower(), v) for k, _q, v in re.findall(r"([\w:]+)\s*=\s*([\"'])(.*?)\2", tag, re.S))
                if attrs.get("targetmode", "").lower() == "external" and "target" in attrs:
                    out.append(_html.unescape(attrs["target"]))
        return out
    # Day 15: document order (rId9, rId10 as stored) was REJECTED by the GM; sorted order is the GM's convention.
    try:
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            if any(i.filename.lower().endswith(".rels") for i in z.infolist()):
                return _json.dumps(sorted(scan(z)), separators=(",", ":"))
            for i in z.infolist():                      # outer wrapper zip: look inside the Office member
                if i.filename.lower().endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
                    with zipfile.ZipFile(io.BytesIO(z.read(i.filename))) as z2:
                        return _json.dumps(sorted(scan(z2)), separators=(",", ":"))
    except Exception:
        pass
    return "none"


FIELDS = {
    "ooxml.external_relationship_targets": ooxml_external_relationship_targets,
    "text.utf8_bom_present": utf8_bom_present,
    "jpeg.sof_dimensions_pixels": jpeg_sof_dims,
    "png.ihdr_dimensions_pixels": png_ihdr_dims,
    "pdf.header_version": pdf_header_version,
    "zip.eocd_total_entries": zip_eocd_total_entries,
    "zip.central_directory_member_names": zip_central_directory_member_names,
    # ---- pre-built for likely next days (exact field tokens + a few aliases; anything else still raises) ----
    "gzip.original_filename": gzip_original_filename, "gzip.fname": gzip_original_filename,
    "gzip.mtime_unix": gzip_mtime_unix, "gzip.mtime": gzip_mtime_unix, "gzip.mtime_utc": gzip_mtime_utc,
    "gzip.os": gzip_os, "gzip.os_byte": gzip_os,
    "tar.member_count": tar_member_count, "tar.entry_count": tar_member_count,
    "tar.member_names": tar_member_names,
    "pe.coff_machine_u16_hex": _pe_field("machine", lambda v: "0x%04x" % v),
    "pe.machine": _pe_field("machine", lambda v: "0x%04x" % v), "pe.machine_name": _pe_field("machine", lambda v: PE_MACHINES.get(v, "0x%04x" % v)),
    "pe.number_of_sections": _pe_field("nsec", str), "pe.section_count": _pe_field("nsec", str),
    "pe.timedatestamp": _pe_field("tds", str), "pe.time_date_stamp": _pe_field("tds", str), "pe.timedatestamp_utc": _pe_field("tds", _utc),
    "pe.subsystem": _pe_field("subsystem", str),
    "pe.address_of_entry_point_rva_hex": _pe_field("entry", lambda v: "0x%08x" % v),  # D10: 8-digit zero-padded (0x65bd0 was rejected)
    "pe.entry_point": _pe_field("entry", lambda v: "0x%x" % v), "pe.address_of_entry_point": _pe_field("entry", lambda v: "0x%x" % v),
    "pe.optional_header_magic": _pe_field("magic", lambda v: "0x%x" % v),
    "elf.class": _elf_field(lambda e: e["class"]), "elf.ei_class": _elf_field(lambda e: e["class"]),
    "elf.machine": _elf_field(lambda e: ELF_MACHINES.get(e["machine"], str(e["machine"]))), "elf.e_machine": _elf_field(lambda e: str(e["machine"])),
    "elf.entry_point": _elf_field(lambda e: "0x%x" % e["entry"]), "elf.e_entry": _elf_field(lambda e: "0x%x" % e["entry"]),
    "elf.type": _elf_field(lambda e: ELF_TYPES.get(e["type"], str(e["type"]))), "elf.e_type": _elf_field(lambda e: str(e["type"])),
    "pdf.page_count": pdf_page_count, "pdf.pages": pdf_page_count,
    "pdf.info_producer": _pdf_info(b"Producer"), "pdf.producer": _pdf_info(b"Producer"),
    "pdf.info_creator": _pdf_info(b"Creator"), "pdf.creator": _pdf_info(b"Creator"),
    "pdf.info_title": _pdf_info(b"Title"), "pdf.title": _pdf_info(b"Title"),
    "pdf.info_author": _pdf_info(b"Author"), "pdf.author": _pdf_info(b"Author"),
    "exif.make": _exif_tag(0x010F), "exif.model": _exif_tag(0x0110),
    "exif.datetime_original": _exif_tag(0x9003), "exif.date_time_original": _exif_tag(0x9003), "exif.datetime": _exif_tag(0x0132),
    "exif.gps_present": exif_gps_present,
    "id3.title": _id3_frame("TIT2"), "id3.artist": _id3_frame("TPE1"), "id3.album": _id3_frame("TALB"),
    "id3.year": _id3_frame("TYER", "TDRC"),
    "png.chunk_count": png_chunk_count, "png.chunk_types": png_chunk_types,
    "png.ihdr_width": _png_ihdr(0), "png.ihdr_height": _png_ihdr(1), "png.ihdr_bit_depth": _png_ihdr(2),
    "png.ihdr_color_type": _png_ihdr(3),
    "file.magic_type": file_magic_type, "file.type": file_magic_type, "magic.file_type": file_magic_type,
    "ooxml.core_creator": _ooxml_core("creator"), "ooxml.core_created": _ooxml_core("created"),
    "ooxml.core_last_modified_by": _ooxml_core("lastModifiedBy"), "docx.core_creator": _ooxml_core("creator"),
}
try:                                    # header facts for ~20 more formats (hdr_facts.py); never overrides an existing field
    import hdr_facts as _hf
    _hf.register(FIELDS)
except Exception as _e:                 # the adapter must keep working without it
    print("AUTOSOLVE metadata: hdr_facts unavailable (%s)" % _e)
try:                                    # COMPLETE PE + ELF header tables, hex width taken from the field TYPE (hdr_struct.py); never overrides
    import hdr_struct as _hs
    _hs.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: hdr_struct unavailable (%s)" % _e)
try:                                    # header facts for ole2, iso, cab, zstd, lz4 (hdr_facts2.py): the five formats the format index listed as recognized but unanswerable
    import hdr_facts2 as _hf2
    _hf2.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: hdr_facts2 unavailable (%s)" % _e)
try:                                    # PE version-resource strings (pe_version.py): pe.version_original_filename etc. (D11)
    import pe_version as _pv
    _pv.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: pe_version unavailable (%s)" % _e)
try:                                    # zip EOCD / central-directory fields + pe debug / import / export / overlay / certificate fields (pe_zip_extra.py, D12 prebuild)
    import pe_zip_extra as _pzx
    _pzx.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: pe_zip_extra unavailable (%s)" % _e)
try:                                    # .NET metadata (dotnet_meta.py): dotnet.mvid_guid (D12 Managed Expectations)
    import dotnet_meta as _dn
    _dn.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: dotnet_meta unavailable (%s)" % _e)
try:                                    # MSI Property table (msi_meta.py): msi.product_code_guid etc. (D13 Product Placement)
    import msi_meta as _msi
    _msi.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: msi_meta unavailable (%s)" % _e)
try:                                    # Windows shell link (lnk_meta.py): lnk.target_path_windows etc. (D14 The Shortcut Home)
    import lnk_meta as _lnk
    _lnk.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: lnk_meta unavailable (%s)" % _e)
try:                                    # PRE-BUILT next formats (meta_next.py: tar/gzip/jks, webp/ogg/mp3/jpeg/png/exif/psd/swf, x509/eml/svg/rtf/plist/torrent/ttf/pdf/git, minidump/mbr/gpt/fs/vhd/vmdk); never overrides
    import meta_next as _mn
    _mn.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: meta_next unavailable (%s)" % _e)
try:                                    # Day 21 Package Deal: apk.package_name etc. from the binary AndroidManifest (apk_meta.py)
    import apk_meta as _apk
    _apk.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: apk_meta unavailable (%s)" % _e)
try:                                    # Day 17 Hear Me Out: media.primary_audio_codec_name = actual codec (ffprobe codec_name spelling) from the bytes (media_codec.py)
    import media_codec as _mc
    _mc.register(FIELDS)
except Exception as _e:
    print("AUTOSOLVE metadata: media_codec unavailable (%s)" % _e)
try:                                    # Day 16 Return to Sender: 'email.message_id' = the raw Message-ID header value (angle brackets kept, as in the header); eml.message_id already does that
    for _t in ("email.message_id", "email.header_message_id"):
        if _t not in FIELDS and "eml.message_id" in FIELDS:
            FIELDS[_t] = FIELDS["eml.message_id"]
        try:
            _mn.UNSURE.add(_t)          # bracket vs bare is a documented guess: lab-mode format retry applies
        except Exception:
            pass
except Exception as _e:
    print("AUTOSOLVE metadata: email.message_id alias failed (%s)" % _e)
try:                                    # Day 28 'Where It All Began' (2026-10-28 PORT): the GM question "disk.partition_start_lba_sequence" is a GPT-aware
                                        # version of the partition-start list. On a GPT disk with protective MBR, MBR has ONE entry of type 0xEE at LBA 1
                                        # (so mbr.partition_start_lbas = [1]), but the REAL partition starts live in the GPT entry table (gpt.partition_first_lbas).
                                        # The verified Day 28 answer is [34] (GPT first_lba of the single "HUNTRESS EVIDENCE" partition). Smart extractors below
                                        # choose GPT when present, fall back to MBR otherwise, so the alias loop populates `disk.*` with the right source.
    import meta_nf_sys as _mns

    def _disk_partition_start_lbas(data):
        g = _mns.gpt_parse(data) if data else None
        if g is not None:
            from meta_nf_common import jarr as _jarr
            return _jarr(e["first"] for e in g["ents"])
        m = _mns.mbr_parse(data) if data else None
        if m is None:
            return None
        from meta_nf_common import jarr as _jarr
        return _jarr(p["lba"] for p in m["parts"] if p["type"] != 0)

    def _disk_partition_sizes_bytes(data):
        g = _mns.gpt_parse(data) if data else None
        if g is not None:
            from meta_nf_common import jarr as _jarr
            return _jarr((e["last"] - e["first"] + 1) * 512 for e in g["ents"])
        m = _mns.mbr_parse(data) if data else None
        if m is None:
            return None
        from meta_nf_common import jarr as _jarr
        return _jarr(p["count"] * 512 for p in m["parts"] if p["type"] != 0)

    def _disk_partition_count(data):
        g = _mns.gpt_parse(data) if data else None
        if g is not None:
            return str(len(g["ents"]))
        m = _mns.mbr_parse(data) if data else None
        if m is None:
            return None
        return str(sum(1 for p in m["parts"] if p["type"] != 0))

    def _disk_partition_names(data):
        g = _mns.gpt_parse(data) if data else None
        if g is not None:
            from meta_nf_common import jarr as _jarr
            return _jarr(e["name"] for e in g["ents"])
        return None  # MBR has no partition names

    def _disk_partition_type_guids(data):
        g = _mns.gpt_parse(data) if data else None
        if g is not None:
            from meta_nf_common import jarr as _jarr
            return _jarr(str(e["type"]).upper() for e in g["ents"])
        return None

    # Register SMART disk.* first (so the alias loop's setdefault below doesn't override). Also register
    # explicit `_sequence` names since GM has used that wording.
    for _n in ("disk.partition_start_lbas", "disk.partition_start_lba_sequence"):
        FIELDS[_n] = _disk_partition_start_lbas
    for _n in ("disk.partition_sizes_bytes", "disk.partition_size_sequence_bytes", "disk.partition_size_bytes_sequence"):
        FIELDS[_n] = _disk_partition_sizes_bytes
    for _n in ("disk.partition_count",):
        FIELDS[_n] = _disk_partition_count
    for _n in ("disk.partition_names", "disk.partition_name_sequence"):
        FIELDS[_n] = _disk_partition_names
    for _n in ("disk.partition_type_guids", "disk.partition_type_guid_sequence"):
        FIELDS[_n] = _disk_partition_type_guids
    # Also expose GPT-named "start" aliases for cases where the GM says "gpt.partition_start_lbas".
    if "gpt.partition_first_lbas" in FIELDS:
        FIELDS.setdefault("gpt.partition_start_lbas", FIELDS["gpt.partition_first_lbas"])
        FIELDS.setdefault("gpt.partition_start_lba_sequence", FIELDS["gpt.partition_first_lbas"])

    # Now the legacy alias loop: fills in any other mbr.*/gpt.* -> disk.* that we didn't explicitly cover.
    for _k in [k for k in FIELDS if k.startswith("mbr.") or k.startswith("gpt.")]:
        _p = _k.split(".", 1)[1]
        FIELDS.setdefault("disk." + _p, FIELDS[_k])
        if _p.endswith("s") and not _p.endswith("ss"):
            FIELDS.setdefault("disk." + _p[:-1] + "_sequence", FIELDS[_k])
except Exception as _e:
    print("AUTOSOLVE metadata: disk.* smart extractor registration failed (%s)" % _e)

# -------- 2026-10-28 Day 28 'Where It All Began' PORT (WS agent-4): the TT/MM 26-token set includes spellings and canonical
# orderings not yet covered. `registry.hive_root_name` (GM says `registry.`, our regf parsers register `regf.`),
# `macho.cpu_type_set` numeric-ascending order on a multi-arch fat Mach-O (HS writeup: "Mach-O CPU-type sets are sorted for
# their canonical answer arrays"), and a byte-scan FALLBACK for `pe.version_original_filename` so a PE whose RT_VERSION resource
# tree is unusual (or synthesised) still answers from the UTF-16LE 'OriginalFilename\0\0' + value marker the HS solver uses
# (challenges/Day 28/.../scripts/solve_mastery.py:310 original_filename). All three are deterministic registry fixes: the
# format-name aliases are additive (never override a direct entry), the cpu_type_set override only re-orders a value already
# produced by the hdr_facts parser, and the byte-scan fallback only runs when the proper resource walk returned "none" and the
# bytes start with "MZ". ASCII only; a missing pre-req leaves the field unchanged.
try:
    _FMT_EXTRA = {"registry": "regf", "hive": "regf"}
    # extend the dispatcher's format-prefix synonym table (defined later in this module via _FMT_ALIAS)
    # by stashing the extras here; the attribute is read inside the dispatcher after this module is loaded.
    globals().setdefault("_FMT_ALIAS_PENDING", {}).update(_FMT_EXTRA)
    # Direct cross-format aliases so the alias path works even when _FMT_ALIAS is pre-populated at import time.
    for _reg_src, _reg_dst in (
        ("regf.root_key_name", ("registry.hive_root_name", "registry.root_key_name", "hive.root_key_name", "hive.hive_root_name", "registry.root_name")),
    ):
        if _reg_src in FIELDS:
            for _tok in _reg_dst:
                FIELDS.setdefault(_tok, FIELDS[_reg_src])
    # macho.cpu_type_set: force numeric-ascending order on multi-arch fat binaries (Day 28 HS writeup convention; a single-arch
    # thin Mach-O returns a 1-element list and the sort is a no-op). The underlying parser already emits an array of 8-digit
    # 0x-prefixed strings - we re-wrap the existing extractor rather than reparsing the bytes.
    if "macho.cpu_type_set" in FIELDS:
        _orig_mcts = FIELDS["macho.cpu_type_set"]

        def _macho_cpu_type_set_sorted(b, _f=_orig_mcts):
            v = _f(b)
            if not isinstance(v, str) or not v.startswith("["):
                return v
            try:
                import json as _j
                arr = _j.loads(v)
                if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
                    return v
                def _key(s):
                    try:
                        return int(s, 16) if s.lower().startswith("0x") else int(s)
                    except Exception:
                        return 0
                return _j.dumps(sorted(set(arr), key=_key), separators=(",", ":"))
            except Exception:
                return v
        FIELDS["macho.cpu_type_set"] = _macho_cpu_type_set_sorted

    # D30 relation.* family (2026-10-30 WS, ported from Seeing Double clone, agent-4). GM named nodes by
    # manifest `id` (alpha-01 ...), NOT filename / path / digest. Groups sorted inside, groups sorted by
    # first id, compact JSON. The D30 clone paid 345 s + 3 wasted submits establishing this rule; port it
    # so a Day 31 sibling (semantic_identity_groups / contains_edges / provenance_mismatch / fabricated_cluster)
    # has the shared adapter answer without a clone edit. Kill switch HUNTRESS_METADATA_RELATION=0.
    def _relation_identical_sha256_groups(b):
        """D30 cluster zip: groups of manifest ids whose FULL-FILE SHA-256 (from the member bytes, never the
        manifest's own claim) matches. Only groups of 2+ members; ids sorted inside a group, groups sorted by
        first id. Node = manifest `id` (e.g. "alpha-01"); fallback = file stem."""
        mem = _members(b)
        if not mem:
            return None
        ids = {}
        for name, data in mem:
            if os.path.basename(name) == "delivery-manifest.json":
                try:
                    for a in _json.loads(data.decode("utf-8", "replace")).get("artifacts", []):
                        ids[a.get("path")] = a.get("id")
                except Exception:
                    pass
        by = {}
        for name, data in mem:
            if os.path.basename(name) == "delivery-manifest.json":
                continue
            node = ids.get(name) or os.path.splitext(os.path.basename(name))[0]
            by.setdefault(hashlib.sha256(data).hexdigest(), []).append(node)
        groups = sorted(sorted(v) for v in by.values() if len(v) > 1)
        return _json.dumps(groups, separators=(",", ":"))

    if os.environ.get("HUNTRESS_METADATA_RELATION", "1") != "0":
        FIELDS.setdefault("relation.identical_sha256_groups", _relation_identical_sha256_groups)

    # D31 relation.* siblings (2026-10-30 WS, agent-4 D30 Seeing Double writeup predicted these as D30->D31 next-layer).
    # Zero LLM when D31 drops a predicted sibling: 3.9 ms for all 3 vs 27-38 s per agent spawn. Measured against the
    # scratchpad/d31_dryrun/palette_demo.py fixtures. Same node-naming (manifest id), same sorted-in-sorted-across
    # convention as _relation_identical_sha256_groups above. Kill switch HUNTRESS_METADATA_RELATION=0.
    def _relation_semantic_identity_groups(b):
        """D31 predicted sibling: group members whose text content is equal after whitespace-normalize + casefold.
        Node = manifest id. Ids sorted inside group, groups sorted by first id, compact JSON.
        HELD-SAFE: returns None when no delivery-manifest.json is present (project rule: HELD beats a wrong submit)."""
        import re as _re2
        mem = _members(b)
        if not mem:
            return None
        ids = {}
        for name, data in mem:
            if os.path.basename(name) == "delivery-manifest.json":
                try:
                    for a in _json.loads(data.decode("utf-8", "replace")).get("artifacts", []):
                        ids[a.get("path")] = a.get("id")
                except Exception:
                    pass
        if not ids:
            return None    # no manifest -> this is not the predicted D31 shape, let the agent handle it
        ws = _re2.compile(r"\s+")
        by = {}
        for name, data in mem:
            if os.path.basename(name) == "delivery-manifest.json":
                continue
            if name not in ids:
                continue   # ONLY return groups among manifest-known ids; stem fallback would guess silently
            norm = ws.sub(" ", data.decode("utf-8", "replace").casefold()).strip()
            by.setdefault(norm, []).append(ids[name])
        groups = sorted(sorted(v) for v in by.values() if len(v) > 1)
        return _json.dumps(groups, separators=(",", ":"))

    def _relation_contains_edges(b):
        """D31 predicted sibling: parent-child containment edges stored in containment.json inside the zip.
        Compact JSON array of [parent_id, child_id], sorted by (parent, child)."""
        mem = _members(b)
        if not mem:
            return None
        for name, data in mem:
            if os.path.basename(name) == "containment.json":
                try:
                    edges = _json.loads(data.decode("utf-8", "replace"))
                    edges = sorted([list(e) for e in edges if isinstance(e, (list, tuple)) and len(e) == 2],
                                   key=lambda e: (str(e[0]), str(e[1])))
                    return _json.dumps(edges, separators=(",", ":"))
                except Exception:
                    return None
        return None

    def _relation_provenance_mismatch(b):
        """D31 predicted sibling: ids whose manifest.producer_id disagrees with the embedded '# author=<name>' marker
        on the first line of the file. Compact JSON sorted array of ids.
        HELD-SAFE: returns None when the archive has no manifest, OR when zero members have BOTH producer_id and an
        author marker (nothing comparable = not the predicted D31 shape, let the agent handle it)."""
        import re as _re2
        mem = _members(b)
        if not mem:
            return None
        ids_by_path = {}
        for name, data in mem:
            if os.path.basename(name) == "delivery-manifest.json":
                try:
                    for a in _json.loads(data.decode("utf-8", "replace")).get("artifacts", []):
                        ids_by_path[a.get("path")] = a
                except Exception:
                    pass
        if not ids_by_path:
            return None
        comparable, miss = 0, []
        for name, data in mem:
            meta = ids_by_path.get(name)
            if not meta or not meta.get("producer_id"):
                continue
            m = _re2.search(rb"#\s*author\s*=\s*(\w+)", data)
            if not m:
                continue
            comparable += 1
            if m.group(1).decode() != meta["producer_id"]:
                miss.append(meta["id"])
        if comparable == 0:
            return None    # no file had both producer_id and an author marker; shape doesn't match
        return _json.dumps(sorted(miss), separators=(",", ":"))

    if os.environ.get("HUNTRESS_METADATA_RELATION", "1") != "0":
        FIELDS.setdefault("relation.semantic_identity_groups", _relation_semantic_identity_groups)
        FIELDS.setdefault("relation.contains_edges", _relation_contains_edges)
        FIELDS.setdefault("relation.provenance_mismatch", _relation_provenance_mismatch)

    # D31 graph.execution_chain_artifact_ids (2026-10-31, agent-4, No Artifact Left Behind). case-001.zip holds
    # extensionless nodes (ps1 stage scripts, PNG tEXt "next=", SQLite launch_queue.target, nested zip run.txt
    # "execute X", EML route.txt "open:/forwarded to:"). The real chain ends at the one node carrying "done <tag>"
    # (PNG tEXt); walk the execution edges BACKWARD from it to the unreferenced start. "forwarded to" is a DELIVERY
    # edge, never execution (decoy loop). Answer = compact JSON array start->done of member basenames.
    def _graph_execution_chain_artifact_ids(b):
        import re as _re3, io as _io3, zipfile as _zf3, base64 as _b643, zlib as _zl3
        mem = _members(b)
        if not mem:
            return None
        nodes = {}
        for name, data in mem:
            bn = os.path.basename(name)
            if bn and not bn.endswith(".json"):
                nodes[bn] = data
        if not nodes:
            return None
        names = set(nodes)
        refre = _re3.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

        def refs_in(text):
            return [t for t in refre.findall(text) if t in names]

        edges = []      # (src, dst, kind) kind in {"exec","forward"}
        done = []
        for n, d in nodes.items():
            if d[:8] == b"\x89PNG\r\n\x1a\n":
                pos = 8
                while pos + 8 <= len(d):
                    ln = int.from_bytes(d[pos:pos + 4], "big")
                    ty = d[pos + 4:pos + 8]
                    body = d[pos + 8:pos + 8 + ln]
                    pos += 12 + ln
                    if ty == b"tEXt" and b"\x00" in body:
                        txt = body.split(b"\x00", 1)[1].decode("utf-8", "replace").strip()
                        if txt.startswith("done"):
                            done.append(n)
                        elif txt.startswith("next="):
                            for r in refs_in(txt[5:]):
                                edges.append((n, r, "exec"))
                    if ty == b"IEND":
                        break
            elif d[:6] == b"SQLite":
                tg = []
                try:
                    import sqlite3 as _sq3
                    con = _sq3.connect(":memory:")
                    con.deserialize(d)
                    for (t,) in con.execute("select target from launch_queue").fetchall():
                        tg.append(str(t))
                except Exception:
                    tg = [t for t in refre.findall(d.decode("latin-1")) if t in names]
                for t in tg:
                    for r in refs_in(t):
                        edges.append((n, r, "exec"))
            elif d[:2] == b"PK":
                try:
                    zz = _zf3.ZipFile(_io3.BytesIO(d))
                    for x in zz.infolist():
                        if os.path.basename(x.filename) == "run.txt":
                            for r in refs_in(zz.read(x.filename).decode("utf-8", "replace")):
                                edges.append((n, r, "exec"))
                except Exception:
                    pass
            elif d[:5] == b"From:" or d[:8].lower().startswith(b"received") or b"Message-ID" in d[:400]:
                import email as _em3
                try:
                    msg = _em3.message_from_bytes(d)
                    for part in msg.walk():
                        if part.get_filename():
                            pl = part.get_payload(decode=True) or b""
                            txt = pl.decode("utf-8", "replace")
                            kind = "forward" if "forward" in txt.lower() else "exec"
                            for r in refs_in(txt):
                                edges.append((n, r, kind))
                except Exception:
                    pass
            elif d.lstrip()[:1] == b"{":
                # TT variant: {"task":"..","next":"<node>","owner":".."} task-ticket nodes
                try:
                    jo = _json.loads(d.decode("utf-8", "replace"))
                    nx = jo.get("next") if isinstance(jo, dict) else None
                    for r in refs_in(str(nx or "")):
                        edges.append((n, r, "exec"))
                except Exception:
                    pass
            else:
                txt = d.decode("utf-8", "replace")
                if txt.lstrip().startswith("#") or "ErrorActionPreference" in txt:
                    for ln_ in txt.splitlines():
                        if ln_.lstrip().startswith("#"):
                            continue
                        for r in _re3.findall(r"\.[\\/]+([A-Za-z0-9_.-]+)", ln_):
                            if r in names:
                                edges.append((n, r, "exec"))
        # STRUCTURE RULE (SS + TT verified): the decoy is a closed loop (every node has an incoming edge, includes the
        # delivery hops "forwarded to"/"continue with"); the real chain is the acyclic component with exactly one node
        # that nothing points to (source) and ends at a sink (PNG "done <tag>", or an EML note with no route).
        alle = []
        for s, t, k in edges:
            if s != t and (s, t) not in [(a, b2) for a, b2, _k in alle]:
                alle.append((s, t, k))
        outs, indeg = {}, {}
        for s, t, k in alle:
            outs.setdefault(s, []).append((t, k))
            indeg[t] = indeg.get(t, 0) + 1
        sources = [n for n in outs if indeg.get(n, 0) == 0]
        chains = []
        for s0 in sources:
            ch, seen_ = [s0], {s0}
            cur = s0
            ok = True
            while cur in outs:
                nxt = outs[cur]
                if len(nxt) > 1:
                    ex_ = [t for t, k in nxt if k == "exec"]
                    if len(ex_) != 1:
                        ok = False
                        break
                    t0 = ex_[0]
                else:
                    t0 = nxt[0][0]
                if t0 in seen_:
                    ok = False      # loops back: decoy, not the real chain
                    break
                ch.append(t0)
                seen_.add(t0)
                cur = t0
            if ok and len(ch) >= 2:
                chains.append(ch)
        if done:
            dch = [c for c in chains if c[-1] in done]
            if len(dch) == 1:
                chains = dch
        if len(chains) != 1:
            return None     # HELD-SAFE: exactly one source->sink chain expected
        return _json.dumps(chains[0], separators=(",", ":"))

    if os.environ.get("HUNTRESS_METADATA_GRAPH", "1") != "0":
        FIELDS.setdefault("graph.execution_chain_artifact_ids", _graph_execution_chain_artifact_ids)

    # pe.version_original_filename: byte-scan fallback. The HS Day 28 solve_mastery.py finds the UTF-16LE marker
    # 'OriginalFilename\0\0' and reads the double-null-terminated value immediately after it. We ONLY call this
    # when (a) the bytes look like a PE (MZ prefix) and (b) the registered proper-resource walk returned 'none'.
    for _pv_tok in ("pe.version_original_filename", "pe.original_filename",
                    "pe.version_info_original_filename", "pe.versioninfo_original_filename",
                    "pe.string_file_info_original_filename"):
        if _pv_tok in FIELDS:
            _orig_pv = FIELDS[_pv_tok]

            def _pe_version_original_filename_bytescan(b, _f=_orig_pv):
                v = _f(b)
                if v and v != "none":
                    return v
                if not b or b[:2] != b"MZ":
                    return v
                marker = "OriginalFilename".encode("utf-16-le") + b"\x00\x00"
                k = b.find(marker)
                if k < 0:
                    return v
                p = k + len(marker)
                e = p
                while e + 1 < len(b) and b[e:e + 2] != b"\x00\x00":
                    e += 2
                try:
                    out = b[p:e].decode("utf-16-le").strip()
                except Exception:
                    return v
                return out or v
            FIELDS[_pv_tok] = _pe_version_original_filename_bytescan
except Exception as _e:
    print("AUTOSOLVE metadata: Day 28 token aliases registration failed (%s)" % _e)

# ----------------------------------------------------------------------------- byte-level filename extractors (D29 2026-10-29): walk
# the ZIP (and one level of nested ZIP) for a member whose basename matches a role prefix. Used by prebrief coverage: on stand-in bytes
# a role-filename question raises `BytesWithoutMember`, which contract_preflight.split_unresolved maps to needs_real_bytes (not a missing
# extractor). On real TT/MM bytes compute()'s existing "exact filename" dispatcher at line 1041+ still answers the question (unchanged).
class BytesWithoutMember(ValueError):
    """stand-in bytes do not contain the role member; this is a bytes limit, not a missing extractor."""


def _role_filename(role_prefix, data):
    """return the basename of the single member whose basename starts with `role_prefix` (case-insensitive).
    Walks the top-level ZIP; if the top-level has no match it then walks any inner .zip members too.
    Raises BytesWithoutMember when no match; raises ValueError when more than one matches (ambiguous)."""
    import io, zipfile
    def _members(b):
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                return [i.filename for i in z.infolist() if not i.filename.endswith("/")]
        except Exception:
            return []
    def _hit(names):
        return [n for n in names if os.path.basename(n).lower().startswith(role_prefix.lower())]
    names = _members(data)
    if not names:
        raise BytesWithoutMember("bytes are not a readable ZIP")
    picks = _hit(names)
    if not picks:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for inner in [i.filename for i in z.infolist() if i.filename.lower().endswith(".zip")]:
                    picks.extend(_hit(_members(z.read(inner))))
        except Exception:
            pass
    if not picks:
        raise BytesWithoutMember("no member basename starts with %r" % role_prefix)
    bases = sorted({os.path.basename(p) for p in picks})
    if len(bases) > 1:
        raise ValueError("ambiguous %r match: %s" % (role_prefix, bases[:5]))
    return bases[0]


def roster_filename(data):
    return _role_filename("roster", data)


# D29 roster-filename family (2026-10-29): GM asks "What is the exact filename of the roster?" with id `roster-filename`
# or `set<N>.roster-filename`. The byte-level extractor is defensive for stand-in SS; compute()'s "exact filename" dispatcher
# (line 1041+) still handles the full MM per-set case where each set has its own bundle. The FIELDS entry lets prebrief see coverage.
FIELDS["roster-filename"] = roster_filename
FIELDS["archive.roster_filename"] = roster_filename
FIELDS["zip.roster_filename"] = roster_filename


DIGESTS ={"md5": "md5", "sha-1": "sha1", "sha1": "sha1", "sha-256": "sha256", "sha256": "sha256",
           "sha-512": "sha512", "sha512": "sha512", "sha-384": "sha384"}


# ----------------------------------------------------------------------------- dispatcher
def _qs(start):
    return [q for q in (start.get("questions") or []) if isinstance(q, dict) and q.get("id")]


def _sibling_member(q, qs):
    """For a filename question: the member base name its sibling questions (same id prefix) point at."""
    # Day 15 mastery: pick by the question's own words among this set's members (set2 'first evidence note' was wrongly answered with the copy)
    qtext = (q.get("question") or "").lower()
    setp = q["id"].split(".")[0] + "." if "." in q["id"] else ""
    cands = []
    for o in qs:
        if o["id"].startswith(setp) and "->" in (o.get("artifact") or ""):
            nm = os.path.basename(o["artifact"].split("->")[-1].strip())
            if nm not in cands:
                cands.append(nm)
    if "copy" in qtext:
        pick = [c for c in cands if "copy" in c.lower()]
    elif "roster" in qtext:
        pick = [c for c in cands if c.lower().startswith("roster")]
    elif "evidence note" in qtext or "evidence-note" in qtext:
        pick = [c for c in cands if c.lower().startswith("evidence-note") and "copy" not in c.lower()]
    else:
        pick = []
    if len(pick) == 1:
        return pick[0]
    prefix = re.sub(r"-filename$", "", q["id"])
    for o in qs:
        if o is not q and o["id"].startswith(prefix) and "->" in (o.get("artifact") or ""):
            return os.path.basename(o["artifact"].split("->")[-1].strip())
    return None


_FMT_ALIAS = {"email": "eml", "mail": "eml", "shortcut": "lnk", "windows_shortcut": "lnk",
              "registry": "regf", "hive": "regf"}                                                 # format-prefix synonyms (the FORMAT name, never a property); extend with a test when a new spelling appears
try:
    _FMT_ALIAS.update(globals().get("_FMT_ALIAS_PENDING") or {})
except Exception:
    pass
_FIELD_QUESTION_SIG = re.compile(r"(?:^|[.\s])determine\s+([a-z0-9_]+\.[a-z0-9_]+)\s+for\s+", re.I)


def exact_field_signature(q):
    """Return the exact registered metadata token from its typed question form, or None."""
    m = _FIELD_QUESTION_SIG.search((q.get("question") or "").strip() if isinstance(q, dict) else "")
    if not m:
        return None
    tok = m.group(1).lower()
    return tok if tok in FIELDS else None
_VALUE_QUALIFIERS = frozenset(("order", "ordered", "sorted", "document", "hex", "hexadecimal", "decimal", "dec", "utc", "local", "raw", "big", "little", "endian",
                               "unix", "iso", "epoch", "count", "total", "length", "offset", "base64", "bytes", "bits", "lowercase", "uppercase",
                               "first", "last", "min", "max", "reversed", "normalized", "compressed", "uncompressed"))
# words that only annotate WHICH width/kind of the same value is meant (pe.coff_machine_u16_hex vs pe.coff_machine_hex): they do not change what is returned
_BENIGN_WORDS = frozenset(("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "rva", "va", "info", "header", "field", "value", "data", "of", "the", "is", "has"))
_FORMAT_CHECK = (("hex", re.compile(r"^(0x)?[0-9a-fA-F]+$")), ("hexadecimal", re.compile(r"^(0x)?[0-9a-fA-F]+$")),
                 ("count", re.compile(r"^[0-9]+$")), ("total", re.compile(r"^[0-9]+$")), ("guid", re.compile(r"^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$")))


def _compose_dimensions(tok, data):
    """COMPOSITE field (2026-10-16): '<fmt>.<stem>_dimensions[_pixels]' is the registered '<stem>_width' and '<stem>_height' of the SAME format joined as 'WxH' - the form the GM accepted for jpeg.sof / png.ihdr /
    webp / psd dimensions (e.g. 257x146). Only when both parts are registered extractors and both read as plain integers; otherwise None (the caller falls through to the other resolvers, then HELD)."""
    fmt, _, prop = tok.partition(".")
    m = re.fullmatch(r"(?:(.*)_)?dimensions(_pixels)?", prop)
    if not m:
        return None
    stem = (m.group(1) + "_") if m.group(1) else ""
    for sfx in dict.fromkeys((m.group(2) or "", "_pixels", "")):
        kw, kh = "%s.%swidth%s" % (fmt, stem, sfx), "%s.%sheight%s" % (fmt, stem, sfx)
        if kw in FIELDS and kh in FIELDS:
            try:
                w, h = str(FIELDS[kw](data)).strip(), str(FIELDS[kh](data)).strip()
            except Exception:
                return None
            if re.fullmatch(r"\d+", w) and re.fullmatch(r"\d+", h):
                return "%sx%s" % (w, h)
    return None


def _infer_unregistered(tok, data):
    """UNKNOWN-FIELD INFERENCE (2026-10-16): a field name that is not registered is resolved through the extractors we ALREADY have, never by name similarity alone.
    1. artifact type = the token's format prefix; 2. candidates = registered fields of that format whose property words contain / are contained in the asked ones;
    3. a candidate that differs by a VALUE qualifier (hex, count, order, unit, endianness, ...) is a different value and is rejected; 4. every surviving candidate is RUN on this
    artifact; 5. accepted only when (a) two or more independent extractors return the SAME value (consensus = evidence), or (b) exactly one candidate that differs only by
    benign width/kind words (flagged as a guess by the caller); 6. the value must satisfy the format the name implies (hex digits, count digits, GUID). Disagreement = ambiguous = None.
    Returns (value, how) or (None, why)."""
    if "." not in tok:
        return None, "no format prefix"
    fmt, field = tok.split(".", 1)
    want = {w for w in re.split(r"[^a-z0-9]+", field.lower()) if w}
    if not want:
        return None, "empty name"
    cands = []
    for key, fn in list(FIELDS.items()):
        kfmt, _, kfield = key.partition(".")
        if kfmt != fmt or key == tok:
            continue
        have = {w for w in re.split(r"[^a-z0-9]+", kfield.lower()) if w}
        if not (want <= have or have <= want):
            continue
        diff = want ^ have
        if diff & _VALUE_QUALIFIERS:
            continue
        cands.append((key, fn, diff <= _BENIGN_WORDS))
    if not cands:
        return None, "no registered extractor of format %r has a compatible property" % fmt
    got = []
    for key, fn, benign in cands[:6]:                       # bounded: at most 6 extractor runs
        try:
            v = fn(data)
        except Exception:
            continue
        if v not in (None, "", [], {}):
            got.append((key, str(v), benign))
    if not got:
        return None, "candidates %s returned nothing on this artifact" % [c[0] for c in cands[:3]]
    vals = {re.sub(r"\s+", " ", g[1]).strip().lower() for g in got}
    if len(vals) != 1:
        return None, "ambiguous: %d candidates disagree" % len(got)
    if len(got) < 2 and not got[0][2]:
        return None, "single candidate %r differs by more than a width/kind word" % got[0][0]
    value = got[0][1]
    _LAST_KEY["inferred"] = got[0][0]
    for word, rx in _FORMAT_CHECK:
        if word in want and not rx.match(value.strip()):
            return None, "value does not satisfy the %s format its name implies" % word
    return value, ("consensus of %d extractors (%s)" % (len(got), ", ".join(g[0] for g in got[:3]))) if len(got) > 1 else ("single extractor %s (width/kind word only)" % got[0][0])


def _nearest_field(tok):
    """GRACEFUL DEGRADATION (2026-10-09): today's NEW field token is often just a rename/alias of a field we can
    already extract (png.width vs png.ihdr_width, pe.sections vs pe.number_of_sections). A hard raise halts the whole
    mode and forces a live adapter patch under the clock - the single biggest avoidable delay (Nimble, Day 09).

    The test is WORD CONTAINMENT, not loose overlap: the alias pattern is one name being a shortened or lengthened
    form of the other (png.width vs png.ihdr_width, pe.sections vs pe.number_of_sections). A merely shared generic
    word is NOT enough - pe.rich_header_hash shares "header" with pe.optional_header_magic but is a genuinely
    different field, and answering it with the wrong extractor would be a confident wrong answer. Ambiguous ties
    resolve to None for the same reason.
    """
    if "." not in tok:
        return None
    fmt, field = tok.split(".", 1)
    want = {w for w in re.split(r"[^a-z0-9]+", field.lower()) if w}
    if not want:
        return None
    matches = []
    for key, fn in FIELDS.items():
        kfmt, _, kfield = key.partition(".")
        if kfmt != fmt:
            continue
        have = {w for w in re.split(r"[^a-z0-9]+", kfield.lower()) if w}
        if want <= have or have <= want:                    # one name contains the other = a real alias
            if (want ^ have) & _VALUE_QUALIFIERS:           # the extra word changes WHAT is returned (order, base, unit, endianness...): a different value, not an alias (held-out test 2026-10-16: ..._targets answered by ..._targets_document_order)
                continue
            matches.append((len(want ^ have), key, fn))     # prefer the closest (fewest differing words)
    if not matches:
        return None
    matches.sort(key=lambda r: r[0])
    if len(matches) > 1 and matches[0][0] == matches[1][0] and matches[0][1] != matches[1][1]:
        print("AUTOSOLVE metadata: field %r is ambiguous (%s) - not guessing"
              % (tok, ", ".join(m[1] for m in matches[:3])), flush=True)
        return None
    print("AUTOSOLVE metadata: field %r not in FIELDS - using alias extractor %r"
          % (tok, matches[0][1]), flush=True)
    _LAST_KEY["nearest"] = matches[0][1]
    return matches[0][2]


def answer(q, qs, roots):
    text = (q.get("question") or "").strip()
    ref = q.get("artifact") or ""
    low = text.lower()
    m = _FIELD_QUESTION_SIG.search(low)     # Day 15: bundle questions read 'Inspect `x`. Determine fmt.field for x.'
    if m:
        tok = exact_field_signature(q) or m.group(1).lower()
        fn = FIELDS.get(tok)
        if not fn:                                       # a mapping the GM already ACCEPTED for this token (kb/field_recipes.<machine>.json, written after a CORRECT): one extractor call, no inference, not a guess
            try:
                import field_recipes
                _rc = field_recipes.lookup(tok)
                if _rc and _rc.get("extractor") in FIELDS:
                    fn = FIELDS[_rc["extractor"]]
                    print("AUTOSOLVE metadata: %r -> %r from a GM-confirmed recipe (no inference)" % (tok, _rc["extractor"]), flush=True)
            except Exception:
                fn = None
        if not fn:                                       # the GM spelled the FORMAT differently (Day 16: email.message_id; we register eml.message_id): same property under the format's other name
            _alt = _FMT_ALIAS.get(tok.split(".", 1)[0])
            fn = FIELDS.get(_alt + "." + tok.split(".", 1)[1]) if _alt else None
            if fn:
                ALIASED.add(q.get("id"))
                RESOLVED[q.get("id")] = (_alt + "." + tok.split(".", 1)[1], "fmt_alias")
                print("AUTOSOLVE metadata: format name %r -> registered %r (same property %r)" % (tok.split(".", 1)[0], _alt, tok.split(".", 1)[1]), flush=True)
        if not fn:
            fn = _nearest_field(tok)
            if fn:
                ALIASED.add(q.get("id"))        # right extractor probably, but the VALUE FORMAT is a guess: run() may retry formats on an untimed single solve
                RESOLVED[q.get("id")] = (_LAST_KEY.get("nearest"), "alias")
        if not fn:                                       # COMPOSITE: '<stem>_dimensions[_pixels]' = '<stem>_width' x '<stem>_height' of the same format (WxH, the accepted form)
            try:
                _dv = _compose_dimensions(tok, resolve(ref, roots).data)
            except Exception:
                _dv = None
            if _dv:
                TOKENS[q.get("id")] = tok
                ALIASED.add(q.get("id"))
                print("AUTOSOLVE metadata: %r composed from the registered width and height extractors of the same format -> %s" % (tok, _dv), flush=True)
                return _dv
        if not fn:
            # INFERENCE FROM THE REGISTRY (2026-10-16): run the already-registered extractors of this format that the name implies; accept only a validated consensus or a width/kind-only single match
            try:
                _iv, _how = _infer_unregistered(tok, resolve(ref, roots).data)
            except Exception:
                _iv, _how = None, "inference error"
            if _iv is not None:
                TOKENS[q.get("id")] = tok
                ALIASED.add(q.get("id"))
                RESOLVED[q.get("id")] = (_LAST_KEY.get("inferred"), "inferred")
                print("AUTOSOLVE metadata: %r inferred from registered extractors: %s" % (tok, _how), flush=True)
                return _iv
        if not fn:
            # GENERAL-TOOL FALLBACK (2026-10-14): no hand-built extractor for this field -> read it from exiftool, which understands ~every metadata format (this is why the .lnk should have been a 2s read, not a 65s
            # hand-parse). Only a CONFIDENT exiftool match is used (else it stays unknown -> HELD, and the residue carries the exiftool reading so the agent reads the field directly). Never a blind/ambiguous guess.
            try:
                import exif_meta
                _v, _tag = exif_meta.field(tok, resolve(ref, roots).data)
            except Exception:
                _v = None
            if _v:
                TOKENS[q.get("id")] = tok
                ALIASED.add(q.get("id"))
                print("AUTOSOLVE metadata: %r read from exiftool tag %r (general-tool fallback, no pre-built extractor)" % (tok, _tag), flush=True)
                return _v
            raise ValueError("unknown structured field %r in question %r" % (tok, text))
        TOKENS[q.get("id")] = tok
        try:
            if tok in _mn.UNSURE:                       # a pre-built field whose VALUE TEXT FORMAT is a documented guess: same treatment as an alias answer (lab-mode format retry; flagged in scan())
                ALIASED.add(q.get("id"))
        except Exception:
            pass
        val = fn(resolve(ref, roots).data)
        try:
            import field_formats
            return field_formats.apply_confirmed(tok, val, formats=_fmt_snapshot())      # a format the GM already ACCEPTED for this token (kb/field_formats.json)
        except Exception:
            return val
    if "digest" in low and "ascending digest order" in low:        # Day 15 synthesis: filenames sorted by full-file digest
        algo = next((a for lab, a in DIGESTS.items() if re.search(r"\b%s\b" % re.escape(lab), low)), None)
        mfiles = re.search(r"files:\s*(\[.*?\])", text, re.S | re.I)
        if algo and mfiles:
            names = _json.loads(mfiles.group(1))
            head = [p.strip() for p in ref.split("->")][:-1]
            dig = [(hashlib.new(algo, resolve(" -> ".join(head + [n]), roots).data).hexdigest(), n) for n in names]
            return _json.dumps([n for _d, n in sorted(dig)], separators=(",", ":"))
    if "exact filename" in low:
        if "copy" in low and "renamed" in low:           # Day 17 mastery: the renamed copy = the member of THIS zip with the same bytes as evidence-note.txt under a different name (no sibling question names it)
            try:
                _zn = resolve(ref, roots)
                # D24+ stores the original as evidence-note-<6hex>.txt (random suffix per attempt); D17-D23 used the bare name.
                _orig = [k for k in _zn.kids if re.fullmatch(r"evidence-note(?:-[0-9a-f]{6})?\.txt", os.path.basename(k.name))]
                if len(_orig) == 1:
                    _h = hashlib.sha256(_orig[0].data).hexdigest()
                    _dup = [os.path.basename(k.name) for k in _zn.kids if k is not _orig[0] and hashlib.sha256(k.data).hexdigest() == _h]
                    if len(_dup) == 1:
                        return _dup[0]
            except Exception:
                pass
        name = _sibling_member(q, qs)
        if not name and "roster" in low:                 # Day 20 time trial: no sibling names the roster; it is the member of THIS zip whose base name starts with 'roster'
            try:
                _rn = [os.path.basename(k.name) for k in resolve(ref, roots).kids if os.path.basename(k.name).lower().startswith("roster")]
                if len(_rn) == 1:
                    return _rn[0]
            except Exception:
                pass
        if not name:
            raise ValueError("filename question without a sibling member reference: %r" % text)
        return name
    if "size in bytes" in low:
        return str(len(resolve(ref, roots).data))
    for label, algo in DIGESTS.items():
        if re.search(r"\b%s\b" % re.escape(label), low) and ("digest" in low or "hash" in low):
            return hashlib.new(algo, resolve(ref, roots).data).hexdigest()
    m = re.search(r"first\s+([a-z\-]+|\d+)\s+bytes", low)
    if m and "hex" in low:
        n = int(m.group(1)) if m.group(1).isdigit() else NUMS.get(m.group(1))
        if n:
            return resolve(ref, roots).data[:n].hex()
    raise ValueError("no extractor for metadata question %r (id %s)" % (text, q.get("id")))


ALIASED = set()     # answer ids whose extractor was chosen by alias (uncertain value format)
TOKENS = {}         # answer id -> "format.field" token of the question
RESOLVED = {}       # answer id -> (registered extractor key, how) for answers that were NOT an exact registration (fmt_alias / alias / inferred): persisted as a recipe after the GM says CORRECT
_LAST_KEY = {}      # the extractor key chosen by the last _nearest_field / _infer_unregistered call


def run(gm, entry, for_time=False):
    """Same flow as ctf_gm.solve_mode (start -> download -> compute -> format gate -> submit), plus ONE extra step: if an UNTIMED single solve is
    graded wrong and some answers came from an alias extractor, retry bounded format variants of just those fields (field_formats.retry_submit)
    and remember the accepted format. Timed attempts are one shot: they never retry, they only benefit from formats confirmed earlier."""
    from ctf_gm import format_gate
    import field_formats
    timed = entry.endswith("/time_trial") or entry.endswith("/mastery")
    for attempt in range(1 if timed else 2):         # an EXPIRED untimed attempt is retried once; a timed route never is (a retry spends a fresh variant)
        ALIASED.clear(); TOKENS.clear(); RESOLVED.clear()
        st = gm.start(entry, for_time=for_time)
        blobs = [gm.download(entry, e, i) for i, e in enumerate(gm.artifacts(st))]
        answers, missing = compute_partial(st, blobs)
        if missing:                                  # solve locally first: a field with no local answer means NOTHING is submitted (a partial batch is the GM as an oracle)
            return {"result": "HELD", "why": "%d answer id(s) have no local extractor, e.g. %s: nothing submitted" % (len(missing), "; ".join(
                "%s (%s)" % (k, v) for k, v in sorted(missing.items())[:2])), "unresolved": sorted(missing), "reasons": missing, "answered": len(answers), "submitted": False}
        blocked = format_gate(st, answers)
        if blocked:
            return {"result": "gate_blocked", "problems": blocked}
        res = gm.submit(entry, answers)
        if str((res or {}).get("result", "")).upper() != "CORRECT" and "expired" in _state_words(res) and attempt < 1 and not timed:
            gm.retry(entry); continue
        break
    if str((res or {}).get("result", "")).upper() == "CORRECT":
        # ACCUMULATE: bank every field of every CORRECT (broad hook, user 2026-10-15: build on what we know daily, never reset).
        # D31 (2026-10-30 WS): the banking was blocking the mode loop before the next TT/MM op=start. For a Mastery with 420 ids
        # the per-token rewrite cost ~2s (D16 script measurement scaled: 3.67s for 750 ids). Async daemon thread removes it from
        # the hot path (mirrors HS autosolve_script.py 0bb04061). Fail-open on any exception, kill switch
        # HUNTRESS_METADATA_CONFIRM_ALL_ASYNC=0 restores synchronous behaviour.
        try:
            _pairs = [(TOKENS.get(aid, aid), answers.get(aid), answers.get(aid)) for aid in answers]
            if os.environ.get("HUNTRESS_METADATA_CONFIRM_ALL_ASYNC", "1") != "0":
                import threading
                def _bank_async(pairs):
                    try: field_formats.confirm_all(pairs, day=None)
                    except Exception: pass
                threading.Thread(target=_bank_async, args=(_pairs,), daemon=True).start()
            else:
                field_formats.confirm_all(_pairs, day=None)
        except Exception:
            pass
        try:                                         # RECIPE (2026-10-16): the token -> extractor mappings this CORRECT proved, so the Time Trial / Mastery / next day answer the same token with one extractor call
            import field_recipes
            _n = field_recipes.confirm([(TOKENS[aid], RESOLVED[aid][0], RESOLVED[aid][1]) for aid in answers if aid in RESOLVED and aid in TOKENS and RESOLVED[aid][0]], day=None)
            if _n:
                print("AUTOSOLVE metadata: %d recipe(s) banked for the timed modes (kb/field_recipes)" % _n, flush=True)
        except Exception:
            pass
        return res
    if for_time or timed or not ALIASED:
        return res
    if os.environ.get("HUNTRESS_ORACLE") != "lab":   # trying format variants is the GM used as an oracle: only in lab mode (user 2026-10-11: one considered attempt)
        res = dict(res or {})
        res["aliased_unconfirmed"] = sorted(ALIASED)
        return res
    print("AUTOSOLVE metadata: first answer rejected and %d answer(s) came from an alias - trying format variants (untimed single only)" % len(ALIASED), flush=True)
    r2, final, changes = field_formats.retry_submit(answers, set(ALIASED), lambda a: gm.submit(entry, a))
    if r2 is None:
        return res
    for aid, (raw, accepted) in changes.items():
        if field_formats.confirm(TOKENS.get(aid, aid), raw, accepted, day=None):
            print("AUTOSOLVE metadata: GM accepted %r for %s (raw %r) - remembered in kb/field_formats.json" % (accepted, TOKENS.get(aid, aid), raw), flush=True)
    return r2


def _state_words(d):
    """the GM's own state fields only (result / status / error / state, and one level down in 'attempt') - never prompt or question text"""
    if not isinstance(d, dict):
        return ""
    parts = [str(d.get(k) or "") for k in ("result", "status", "error", "state", "code")]
    if isinstance(d.get("attempt"), dict):
        parts += [str(d["attempt"].get(k) or "") for k in ("result", "status", "state")]
    return " ".join(parts).lower()


def compute_partial(start, blobs):
    """-> (answers, missing{answer_id: reason}). compute() first (the normal path); only if it raises is every field tried on its own, so every
    unresolvable one is NAMED instead of stopping at the first."""
    try:
        return compute(start, blobs), {}
    except Exception:
        pass
    roots = _roots(start, blobs)
    qs = _qs(start)
    ids = start.get("answer_ids") or [q["id"] for q in qs]
    byid = {q["id"]: q for q in qs}
    out, missing = {}, {}
    for aid in ids:
        aid = aid["id"] if isinstance(aid, dict) else aid
        if aid not in byid:
            missing[aid] = "no question text"
            continue
        try:
            out[aid] = answer(byid[aid], qs, roots)
        except Exception as e:
            missing[aid] = str(e)[:160]
    return out, missing


# 2026-10-18 (remediation W2): one format-catalog snapshot per compute() invocation, not one JSON read per field. Thread-local, so concurrent
# invocations never share a snapshot; reset at the START of every compute(), so a rule change in kb/field_formats.json takes effect on the
# next invocation. Values are unchanged: apply_confirmed(tok, val, formats=snap) == apply_confirmed(tok, val) for the same file contents.
import threading as _threading
_FMT_TLS = _threading.local()


def _fmt_snapshot():
    snap = getattr(_FMT_TLS, "fmt", None)
    if snap is None:
        import field_formats
        snap = _FMT_TLS.fmt = field_formats.load()
    return snap


def compute(start, blobs):
    _FMT_TLS.fmt = None                       # invocation scope: refreshed on every compute() call
    try:
        import hdr_facts
        hdr_facts.reset_fact_cache()
    except Exception:
        pass
    # meta_facts parse-once SHA-keyed inventory (2026-10-21 integration): populate the cache for each top-level blob
    # so a later extractor that opts in reads the inventory from memory. Attached to each root Node as .facts for
    # bounded consumption (duplicate-basename disambiguation, nested-member identity). Never raises; a parse failure
    # leaves facts=None and the existing path is unchanged.
    try:
        import meta_facts as _MF
        _bfacts = [_MF.facts(b) for b in blobs]
    except Exception:
        _bfacts = [None] * len(blobs)
    roots = _roots(start, blobs)
    for i, r in enumerate(roots):
        setattr(r, "facts", _bfacts[i] if i < len(_bfacts) else None)
    qs = _qs(start)
    ids = start.get("answer_ids") or [q["id"] for q in qs]
    byid = {q["id"]: q for q in qs}
    out = {}
    for aid in ids:
        aid = aid["id"] if isinstance(aid, dict) else aid
        if aid not in byid:
            raise ValueError("answer id %r has no question text" % aid)
        out[aid] = answer(byid[aid], qs, roots)
    return out


# ----------------------------------------------------------------------------- release_scan interface (2026-10-10, homestation)
_GENERIC = {"header", "field", "value", "info", "data", "size", "count", "number", "hex", "dec", "decimal", "u8", "u16", "u32", "u64", "of", "the", "is", "has",
            "name", "names", "type", "version", "id", "table", "index", "offset", "length", "flags", "magic"}


def _candidates(q, roots):
    """Ordered candidate VALUES for a `Determine <format>.<field>` question we have no extractor for: the values of the nearest extractors of the SAME format
    (most shared NON-generic words first), then the best one's format variants (Day 10: 0x65bd0 vs 0x00065bd0). Empty list = no idea; never a guess dressed as a fact."""
    m = re.match(r"determine\s+([a-z0-9_]+)\.([a-z0-9_]+)\s+for\s+", (q.get("question") or "").strip().lower())
    if not m:
        return []
    fmt, field = m.group(1), m.group(2)
    want = {w for w in re.split(r"[^a-z0-9]+", field) if w} - _GENERIC
    if not want:
        return []
    try:
        data = resolve(q.get("artifact") or "", roots).data
    except Exception:
        return []
    scored = []
    for key, fn in FIELDS.items():
        kfmt, _, kfield = key.partition(".")
        if kfmt != fmt:
            continue
        have = {w for w in re.split(r"[^a-z0-9]+", kfield) if w} - _GENERIC
        ov = len(want & have)                          # a merely shared GENERIC word (header, size, count ...) is not evidence: same rule as _nearest_field
        if ov:
            scored.append((-ov, len(have ^ want), key, fn))
    scored.sort(key=lambda r: (r[0], r[1], r[2]))
    vals = []
    for _, _, key, fn in scored[:14]:
        try:
            v = fn(data)
        except Exception:
            continue
        if isinstance(v, str) and v and v != "none" and v not in vals:
            vals.append(v)
    if vals:
        try:
            import field_formats
            for v in field_formats.variants(vals[0])[1:4]:
                if v not in vals:
                    vals.append(v)
        except Exception:
            pass
    return vals[:8]


def scan(task, blobs):
    """The shared per-lane scan (release_scan.py): resolved answers, ordered candidates for every field we cannot name (instead of raising on the first one,
    which hid the rest), and which extractor answered. No GM call."""
    ALIASED.clear(); TOKENS.clear(); RESOLVED.clear()
    roots = _roots(task, blobs)
    qs = _qs(task)
    ids = list(task.get("answer_ids") or [q["id"] for q in qs])
    byid = {q["id"]: q for q in qs}
    resolved, unresolved, ex = {}, {}, {}
    for aid in ids:
        aid = aid["id"] if isinstance(aid, dict) else aid
        q = byid.get(aid)
        if q is None:
            unresolved[aid] = []
            continue
        try:
            resolved[aid] = answer(q, qs, roots)
            tok = TOKENS.get(aid)
            ex[aid] = "autosolve_metadata:%s%s" % (tok or "generic", " (alias; value format is a guess)" if aid in ALIASED else "")
        except Exception:
            unresolved[aid] = _candidates(q, roots)
            if unresolved[aid]:
                ex[aid] = "autosolve_metadata:nearest-extractors"
    return {"resolved": resolved, "unresolved": unresolved, "extractor": ex}


if __name__ == "__main__":
    # usage: autosolve_metadata.py <challenge entry id> [--dry]   (dry: start+download+compute, print, no submit)
    import json
    from ctf_gm import GM, solve_mode
    gm = GM(timeout=60)
    cid = sys.argv[1]
    if "--dry" in sys.argv:
        st = gm.start(cid)
        bl = [gm.download(cid, e, i) for i, e in enumerate(gm.artifacts(st))]
        print(json.dumps(compute(st, bl)))
    else:
        r = solve_mode(gm, cid, compute)
        print(cid, r.get("result"), "remaining=%s" % r.get("remaining"))
