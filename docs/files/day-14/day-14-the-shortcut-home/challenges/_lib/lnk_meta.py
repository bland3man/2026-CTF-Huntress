"""Windows shell link (.lnk) fields (Day 14 The Shortcut Home): lnk.target_path_windows and friends.

Parses ShellLinkHeader, LinkTargetIDList, LinkInfo (LocalBasePath + CommonPathSuffix, unicode variants
when present), and the StringData block. Target path = LocalBasePath + CommonPathSuffix; falls back to the
network path, then to the path rebuilt from the IDList item names.
"""
import struct


def _cstr(b, off, uni=False):
    if uni:
        end = off
        while end + 1 < len(b) and b[end:end + 2] != b"\0\0":
            end += 2
        return b[off:end].decode("utf-16-le", "replace")
    end = b.index(b"\0", off)
    return b[off:end].decode("cp1252", "replace")


def parse(b):
    b = bytes(b)
    if len(b) < 0x4C or struct.unpack("<I", b[:4])[0] != 0x4C or b[4:20] != bytes.fromhex("0114020000000000c000000000000046"):
        raise ValueError("not a shell link")
    flags = struct.unpack("<I", b[20:24])[0]
    out = {"flags": flags}
    pos = 0x4C
    if flags & 1:                                   # HasLinkTargetIDList
        sz = struct.unpack("<H", b[pos:pos + 2])[0]
        ids = b[pos + 2:pos + 2 + sz]
        names = []
        p = 0
        while p + 2 <= len(ids):
            isz = struct.unpack("<H", ids[p:p + 2])[0]
            if isz == 0:
                break
            item = ids[p + 2:p + isz]
            names.append(item)
            p += isz
        out["idlist_items"] = names
        pos += 2 + sz
    if flags & 2:                                   # HasLinkInfo
        li = b[pos:]
        size, hsize, lflags, vol_off, base_off, net_off, suf_off = struct.unpack("<IIIIIII", li[:28])
        base = suffix = ""
        if lflags & 1 and base_off:
            base = _cstr(li, base_off)
        if hsize >= 0x24:
            ub, us = struct.unpack("<II", li[28:36])
            if lflags & 1 and ub:
                base = _cstr(li, ub, True)
            if us:
                suffix = _cstr(li, us, True)
            elif suf_off:
                suffix = _cstr(li, suf_off)
        elif suf_off:
            suffix = _cstr(li, suf_off)
        out["local_base_path"] = base
        out["common_path_suffix"] = suffix
        if lflags & 2 and net_off:
            n = li[net_off:]
            nflags, name_off = struct.unpack("<II", n[4:12])
            out["net_name"] = _cstr(n, name_off)
        pos += size
    uni = bool(flags & 0x80)
    for key, bit in (("name", 4), ("relative_path", 8), ("working_dir", 0x10), ("arguments", 0x20), ("icon_location", 0x40)):
        if flags & bit:
            cnt = struct.unpack("<H", b[pos:pos + 2])[0]
            pos += 2
            ln = cnt * (2 if uni else 1)
            raw = b[pos:pos + ln]
            out[key] = raw.decode("utf-16-le" if uni else "cp1252", "replace")
            pos += ln
    return out


def _idlist_path(items):
    # rebuild from file/folder entries: type 0x2F = drive root ("C:\"), 0x31/0x32 = folder/file (short name at +12 area, long name unicode in extension block)
    parts = []
    for it in items:
        t = it[0] & 0x7F
        if t == 0x2F:
            parts.append(it[1:].split(b"\0", 1)[0].decode("cp1252").rstrip("\\"))
        elif t in (0x30, 0x31, 0x32, 0x35, 0x36):
            short = it[12:].split(b"\0", 1)[0].decode("cp1252", "replace")
            # long unicode name: scan extension block for the utf-16 name after the 0xBEEF0004 signature
            sig = it.find(b"\x04\x00\xef\xbe")
            longn = ""
            if sig >= 0:
                tail = it[sig + 4 + 4 + 2 + 2 + 2 + 2:]   # skip version(2)... via fixed fields
                # robust alternative: find the last utf-16 string in the block
                q = it[sig:]
                k = 0
                cands = []
                while k + 1 < len(q):
                    s = k
                    while k + 1 < len(q) and q[k + 1] == 0 and 32 <= q[k] < 127:
                        k += 2
                    if k - s >= 4:
                        cands.append(q[s:k].decode("utf-16-le"))
                    k = max(k, s) + 2
                longn = cands[0] if cands else ""
            parts.append(longn or short)
    return "\\".join(parts)


def target_path_windows(b):
    d = parse(b)
    base = d.get("local_base_path", "")
    if base:
        return base + d.get("common_path_suffix", "")
    if d.get("net_name"):
        return d["net_name"] + ("\\" + d["common_path_suffix"] if d.get("common_path_suffix") else "")
    return _idlist_path(d.get("idlist_items", []))


def _field(key):
    def f(b):
        v = parse(b).get(key)
        return "none" if v is None else v
    return f


def register(FIELDS):
    FIELDS["lnk.target_path_windows"] = target_path_windows
    FIELDS["lnk.target_path"] = target_path_windows
    FIELDS["lnk.local_base_path"] = _field("local_base_path")
    FIELDS["lnk.common_path_suffix"] = _field("common_path_suffix")
    FIELDS["lnk.working_dir"] = _field("working_dir")
    FIELDS["lnk.working_directory"] = _field("working_dir")
    FIELDS["lnk.arguments"] = _field("arguments")
    FIELDS["lnk.name"] = _field("name")
    FIELDS["lnk.description"] = _field("name")
    FIELDS["lnk.relative_path"] = _field("relative_path")
    FIELDS["lnk.icon_location"] = _field("icon_location")


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        d = open(f, "rb").read()
        print(f, target_path_windows(d), {k: v for k, v in parse(d).items() if k != "idlist_items"})
