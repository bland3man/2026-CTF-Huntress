"""PE version-resource (VS_VERSION_INFO) string extractor, no dependencies.
register(FIELDS) adds pe.version_<key> for every StringFileInfo key (original_filename, file_description,
company_name, product_name, internal_name, file_version, product_version, legal_copyright, comments, ...)
plus pe.original_filename / pe.internal_name aliases. Walks the resource directory (type RT_VERSION=16).
"""
import struct
import re

KEYS = ["OriginalFilename", "InternalName", "FileDescription", "CompanyName", "ProductName", "FileVersion",
        "ProductVersion", "LegalCopyright", "LegalTrademarks", "Comments", "PrivateBuild", "SpecialBuild"]


def _snake(k):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()


def _sections(b, off):
    nsec = struct.unpack("<H", b[off + 6:off + 8])[0]
    osz = struct.unpack("<H", b[off + 20:off + 22])[0]
    s = off + 24 + osz
    return [struct.unpack("<IIII", b[s + i * 40 + 8:s + i * 40 + 24]) for i in range(nsec)]  # vsize,va,rawsize,rawptr


def _rva2off(secs, rva):
    for vs, va, rs, rp in secs:
        if va <= rva < va + max(vs, rs):
            return rp + rva - va
    return None


def _version_blobs(b):
    if b[:2] != b"MZ":
        return []
    off = struct.unpack("<I", b[0x3c:0x40])[0]
    if b[off:off + 4] != b"PE\0\0":
        return []
    magic = struct.unpack("<H", b[off + 24:off + 26])[0]
    ddbase = off + 24 + (112 if magic == 0x20b else 96)
    rva, size = struct.unpack("<II", b[ddbase + 16:ddbase + 24])
    secs = _sections(b, off)
    base = _rva2off(secs, rva)
    if not rva or base is None:
        return []

    def entries(o):
        n = sum(struct.unpack("<HH", b[o + 12:o + 16]))
        return [struct.unpack("<II", b[o + 16 + i * 8:o + 24 + i * 8]) for i in range(n)]
    out = []
    for nid, tgt in entries(base):
        if nid != 16 or not tgt & 0x80000000:
            continue
        for _n2, t2 in entries(base + (tgt & 0x7fffffff)):
            if not t2 & 0x80000000:
                continue
            for _n3, t3 in entries(base + (t2 & 0x7fffffff)):
                if t3 & 0x80000000:
                    continue
                drva, dsz = struct.unpack("<II", b[base + t3:base + t3 + 8])
                o = _rva2off(secs, drva)
                if o is not None:
                    out.append(b[o:o + dsz])
    return out


def _strings(blob):
    """Return {key: value} from every String entry found by a structural walk of VS_VERSION_INFO."""
    res = {}

    def node(o, end):
        if o + 6 > end:
            return None
        ln, vl, ty = struct.unpack("<HHH", blob[o:o + 6])
        if ln == 0:
            return None
        p = o + 6
        e = p
        while e + 1 < len(blob) and blob[e:e + 2] != b"\0\0":
            e += 2
        key = blob[p:e].decode("utf-16-le", "replace")
        p = (e + 2 + 3) & ~3
        return ln, vl, ty, key, p, o + ln

    def walk(o, end, depth):
        while o < end:
            n = node(o, end)
            if not n:
                break
            ln, vl, ty, key, p, nend = n
            if depth == 3 and ty == 1:
                v = blob[p:p + vl * 2].decode("utf-16-le", "replace").split("\0")[0] if vl else ""
                res.setdefault(key, v)
            elif depth < 3:
                walk(p + (vl if depth == 0 else 0), nend, depth + 1)
            o = (nend + 3) & ~3
    walk(0, len(blob), 0)
    return res


def version_strings(b):
    out = {}
    for blob in _version_blobs(b):
        try:
            for k, v in _strings(blob).items():
                out.setdefault(k, v)
        except Exception:
            pass
    return out


def _field(key):
    def f(b):
        return version_strings(b).get(key, "none")
    return f


def register(FIELDS):
    for k in KEYS:
        s = _snake(k)
        for name in ("pe.version_" + s, "pe.version_info_" + s, "pe.versioninfo_" + s, "pe.string_file_info_" + s):
            FIELDS.setdefault(name, _field(k))
        FIELDS.setdefault("pe." + s, _field(k))


if __name__ == "__main__":
    import sys
    print(version_strings(open(sys.argv[1], "rb").read()))
