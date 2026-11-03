#!/usr/bin/env python3
"""hdr_facts.py - pure-stdlib header "facts" for many file formats (2026-10-10). One place that turns bytes into named, answer-ready values.

Why: the homestation's audit (coord, 13:07) found we RECOGNIZE ~217 formats but could ANSWER `Determine <format>.<field>` for only 13, and that a universal
Mach-O was mis-identified as a Java class (same 4 magic bytes, CAFEBABE) - a confident WRONG answer. This module:
  * classify_cafebabe(): the one safe way to tell a Java class from a Mach-O universal binary (and CAFEBABF = fat64);
  * facts(b) -> (format, {field: str}) for the formats below, values already in answer form (decimal ints, 0x hex, compact JSON lists);
  * register(FIELDS): adds every `<format>.<field>` the adapter does not already have, so its word-containment alias matching works across them too.
Everything is read-only byte parsing with bounds checks; a malformed file returns {} (never raises, never guesses). ASCII only.

Value conventions (match the adapter's accepted history): counts/sizes = decimal; addresses/flags/checksums = 0x lowercase hex (8 digits where the field is a
32-bit RVA, per the GM-accepted Day 10 format); lists = compact JSON (no spaces); booleans = true/false; versions = dotted text.
The exact GM field NAMES for a future day are unknown, so each fact is registered under its natural name plus a few aliases; anything else falls to the
adapter's alias matcher or the agent, with these facts printed in the digest (header_facts_lines)."""
import json, struct, io, datetime, threading

jarr = lambda xs: json.dumps(list(xs), separators=(",", ":"))
hx = lambda v, w=0: ("0x%0" + str(w) + "x") % v if w else "0x%x" % v
boolean = lambda v: "true" if v else "false"


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def u(fmt, b, off):
    """struct.unpack_from that returns None when out of range."""
    try:
        return struct.unpack_from(fmt, b, off)[0]
    except struct.error:
        return None


# ------------------------------------------------------------------------------------------------ CAFEBABE: Java class vs Mach-O universal
def classify_cafebabe(b):
    """-> 'java-class' | 'macho-fat' | 'macho-fat64' | None for data starting CA FE BA BE / CA FE BA BF.
    Java class: bytes 4-5 minor (usually 0), bytes 6-7 major >= 45. Fat Mach-O: bytes 4-7 = nfat_arch (a small big-endian count), then 20-byte (fat) or 32-byte
    (fat64) arch records whose first field is a known CPU type. Both signals are required, so a lucky count cannot flip the answer."""
    if len(b) < 8 or b[:3] != b"\xca\xfe\xba":
        return None
    if b[3] == 0xBF:
        return "macho-fat64"
    if b[3] != 0xBE:
        return None
    nfat = u(">I", b, 4)
    major = u(">H", b, 6)
    cpu = u(">I", b, 8)
    plausible_cpu = cpu in MACHO_CPU if cpu is not None else False
    if nfat is not None and 1 <= nfat <= 32 and plausible_cpu:
        return "macho-fat"
    if major is not None and major >= 45:
        return "java-class"
    return "macho-fat" if (nfat is not None and 1 <= nfat <= 32) else None


# ------------------------------------------------------------------------------------------------ Mach-O
MACHO_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 18: "ppc", 0x01000012: "ppc64"}
MACHO_FILETYPE = {1: "object", 2: "execute", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib_stub", 10: "dsym", 11: "kext_bundle"}
_THIN = {b"\xce\xfa\xed\xfe": ("<", False), b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xce": (">", False), b"\xfe\xed\xfa\xcf": (">", True)}


def _macho_thin(b, base=0):
    e, is64 = _THIN.get(b[base:base + 4], (None, None))
    if e is None:
        return None
    cpu, sub, ftype, ncmds, szcmds, flags = struct.unpack_from(e + "IIIIII", b, base + 4) if len(b) >= base + 28 else (None,) * 6
    if cpu is None:
        return None
    f = {"cputype": hx(cpu), "cpu_hex8": hx(cpu, 8), "cpu_name": MACHO_CPU.get(cpu, hx(cpu)), "cpusubtype": hx(sub & 0x00FFFFFF), "filetype": str(ftype),
         "filetype_name": MACHO_FILETYPE.get(ftype, str(ftype)), "ncmds": str(ncmds), "sizeofcmds": str(szcmds), "flags": hx(flags, 8), "is_64bit": boolean(is64)}
    off, dylibs = base + (32 if is64 else 28), []
    for _ in range(min(ncmds, 4096)):                       # load commands: uuid / main / dylibs / build version
        if off + 8 > len(b):
            break
        cmd, size = struct.unpack_from(e + "II", b, off)
        if size < 8 or off + size > len(b):
            break
        if cmd == 0x1B and size >= 24:
            f["uuid"] = b[off + 8:off + 24].hex()
        elif cmd == 0x80000028 and size >= 24:
            f["entry_offset"] = hx(struct.unpack_from(e + "Q", b, off + 8)[0])
        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x1F, 0xD) and size > 24:
            name = b[off + (u(e + "I", b, off + 8) or 24):off + size].split(b"\x00")[0].decode("utf-8", "replace")
            if cmd != 0xD and name:
                dylibs.append(name)
        elif cmd == 0x32 and size >= 24:
            f["platform"] = str(u(e + "I", b, off + 8)); f["minos"] = _ver(u(e + "I", b, off + 12))
        off += size
    f["linked_dylibs"] = jarr(dylibs); f["dylib_count"] = str(len(dylibs))
    return f


def _ver(v):
    return "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF) if v is not None else "none"


def macho_facts(b):
    kind = classify_cafebabe(b)
    if kind in ("macho-fat", "macho-fat64"):
        n = u(">I", b, 4)
        if n is None or n > 64:
            return {}
        rec = 32 if kind == "macho-fat64" else 20
        arches, cpus, first = [], [], None
        for i in range(n):
            o = 8 + i * rec
            if o + rec > len(b):
                return {}
            cpu = struct.unpack_from(">I", b, o)[0]
            off = struct.unpack_from(">Q", b, o + 8)[0] if kind == "macho-fat64" else struct.unpack_from(">I", b, o + 8)[0]
            arches.append(MACHO_CPU.get(cpu, hx(cpu)))
            sl = _macho_thin(b, off) if off < len(b) else None      # the slice's own header is the truth when it parses
            cpus.append(sl["cpu_hex8"] if sl else hx(cpu, 8))     # GM form (Day 20, accepted): 8-digit hex strings, e.g. ["0x0100000c"]
            if first is None:
                first = off
        f = {"fat": "true", "fat64": boolean(kind == "macho-fat64"), "nfat_arch": str(n), "architectures": jarr(arches), "arch_count": str(n),
             "cpu_type_set": jarr(dict.fromkeys(cpus))}
        thin = _macho_thin(b, first) if first is not None else None
        if thin:
            f.update({"first_slice_" + k: v for k, v in thin.items()})
        return f
    if b[:4] in _THIN:
        f = _macho_thin(b)
        if f:
            f.update({"fat": "false", "nfat_arch": "0", "architectures": jarr([f["cpu_name"]]), "arch_count": "1",
                      "cpu_type_set": jarr([f["cpu_hex8"]])})
            return f
    return {}


# ------------------------------------------------------------------------------------------------ Java class
JAVA_NAMES = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4"}


def java_facts(b):
    if classify_cafebabe(b) != "java-class" or len(b) < 10:
        return {}
    minor, major, cpn = struct.unpack_from(">HHH", b, 4)
    f = {"minor_version": str(minor), "major_version": str(major), "java_version": JAVA_NAMES.get(major, str(major - 44) if major >= 49 else str(major)),
         "constant_pool_count": str(cpn)}
    i, cp, ok = 10, {}, True
    idx = 1
    while idx < cpn and ok:                                  # constant pool
        if i >= len(b):
            ok = False; break
        tag = b[i]; i += 1
        if tag == 1:
            ln = u(">H", b, i)
            if ln is None: ok = False; break
            cp[idx] = b[i + 2:i + 2 + ln].decode("utf-8", "replace"); i += 2 + ln
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18): i += 4
        elif tag in (5, 6): i += 8; idx += 1
        elif tag in (7, 8, 16, 19, 20): cp[idx] = ("ref", u(">H", b, i)); i += 2
        elif tag == 15: i += 3
        else: ok = False
        idx += 1
    if ok and i + 8 <= len(b):
        acc, this_i, sup_i = struct.unpack_from(">HHH", b, i)
        name = lambda k: (cp.get(cp.get(k, (0, 0))[1]) if isinstance(cp.get(k), tuple) else None)
        f["access_flags"] = hx(acc, 4)
        t, s = name(this_i), name(sup_i)
        if t: f["this_class"] = t.replace("/", ".")
        if s: f["super_class"] = s.replace("/", ".")
        f["is_interface"] = boolean(acc & 0x200)
        n_if = u(">H", b, i + 6)
        if n_if is not None: f["interfaces_count"] = str(n_if)
    return f


# ------------------------------------------------------------------------------------------------ Android DEX
def dex_facts(b):
    if b[:4] != b"dex\n" or len(b) < 0x70:
        return {}
    ver = b[4:7].decode("ascii", "replace")
    csum, = struct.unpack_from("<I", b, 8)
    names = ["file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off", "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off",
             "proto_ids_size", "proto_ids_off", "field_ids_size", "field_ids_off", "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off",
             "data_size", "data_off"]
    vals = struct.unpack_from("<20I", b, 32)
    f = {"version": ver, "checksum": hx(csum, 8), "signature": b[12:32].hex()}
    for n, v in zip(names, vals):
        f[n] = hx(v, 8) if n == "endian_tag" else str(v)
    return f


# ------------------------------------------------------------------------------------------------ SQLite
SQLITE_ENC = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}


def sqlite_facts(b):
    if b[:16] != b"SQLite format 3\x00" or len(b) < 100:
        return {}
    ps = struct.unpack_from(">H", b, 16)[0]
    ps = 65536 if ps == 1 else ps
    g = lambda o: struct.unpack_from(">I", b, o)[0]
    enc = g(56)
    f = {"page_size": str(ps), "write_version": str(b[18]), "read_version": str(b[19] if False else b[18]), "journal_mode": "wal" if b[18] == 2 else "legacy",
         "reserved_bytes": str(b[20]), "file_change_counter": str(g(24)), "database_size_pages": str(g(28)), "freelist_pages": str(g(36)),
         "schema_cookie": str(g(40)), "schema_format": str(g(44)), "text_encoding": SQLITE_ENC.get(enc, str(enc)), "text_encoding_code": str(enc),
         "user_version": str(g(60)), "application_id": hx(g(68), 8), "version_valid_for": str(g(92)), "sqlite_version_number": str(g(96))}
    f["read_version"] = str(b[19])
    try:                                                     # table names via the real engine (3.11+ deserialize); optional
        import sqlite3
        c = sqlite3.connect(":memory:")
        c.deserialize(bytes(b))
        names = [r[0] for r in c.execute("select name from sqlite_master where type='table' order by name")]
        f["table_names"] = jarr(names); f["table_count"] = str(len(names)); c.close()
    except Exception:
        pass
    return f


# ------------------------------------------------------------------------------------------------ GIF / BMP / ICO / TIFF
def gif_facts(b):
    if b[:3] != b"GIF" or len(b) < 13:
        return {}
    w, h, pk, bg, asp = struct.unpack_from("<HHBBB", b, 6)
    f = {"version": b[3:6].decode("ascii", "replace"), "width": str(w), "height": str(h), "global_color_table": boolean(pk & 0x80),
         "color_resolution_bits": str(((pk >> 4) & 7) + 1), "global_color_table_size": str(2 << (pk & 7)) if pk & 0x80 else "0",
         "background_color_index": str(bg), "pixel_aspect_ratio": str(asp)}
    i = 13 + ((2 << (pk & 7)) * 3 if pk & 0x80 else 0); frames = 0
    while i < len(b):                                        # walk blocks to count image descriptors
        t = b[i]; i += 1
        if t == 0x2C:
            frames += 1
            if i + 9 > len(b): break
            lpk = b[i + 8]; i += 9
            if lpk & 0x80: i += (2 << (lpk & 7)) * 3
            i += 1
            while i < len(b) and b[i]:
                i += b[i] + 1
            i += 1
        elif t == 0x21:
            i += 1
            while i < len(b) and b[i]:
                i += b[i] + 1
            i += 1
        else:
            break
    f["frame_count"] = str(frames)
    return f


def bmp_facts(b):
    if b[:2] != b"BM" or len(b) < 30:
        return {}
    size, off, dib = struct.unpack_from("<IxxxxII", b, 2)
    if dib < 12:
        return {}
    if dib == 12:
        w, h, planes, bpp = struct.unpack_from("<HHHH", b, 18); comp = 0; ncol = 0
    else:
        w, h, planes, bpp, comp = struct.unpack_from("<iiHHI", b, 18)
        ncol = u("<I", b, 46) or 0
    return {"file_size": str(size), "pixel_data_offset": str(off), "dib_header_size": str(dib), "width": str(w), "height": str(abs(h)), "top_down": boolean(h < 0),
            "planes": str(planes), "bit_count": str(bpp), "bits_per_pixel": str(bpp), "compression": str(comp), "colors_used": str(ncol)}


def ico_facts(b):
    if b[:4] not in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00") or len(b) < 6:
        return {}
    n = struct.unpack_from("<H", b, 4)[0]
    sizes = []
    for i in range(min(n, 256)):
        o = 6 + i * 16
        if o + 16 > len(b): break
        w, h = b[o] or 256, b[o + 1] or 256
        sizes.append("%dx%d" % (w, h))
    return {"type": "icon" if b[2] == 1 else "cursor", "image_count": str(n), "sizes": jarr(sizes)}


def tiff_facts(b):
    if b[:4] not in (b"II*\x00", b"MM\x00*") or len(b) < 8:
        return {}
    e = "<" if b[:2] == b"II" else ">"
    ifd = struct.unpack_from(e + "I", b, 4)[0]
    n = u(e + "H", b, ifd)
    f = {"byte_order": "little-endian" if e == "<" else "big-endian", "first_ifd_offset": str(ifd)}
    if n is None or n > 1024:
        return f
    f["ifd_entry_count"] = str(n)
    tags = {256: "image_width", 257: "image_length", 258: "bits_per_sample", 259: "compression", 262: "photometric", 277: "samples_per_pixel"}
    for k in range(n):
        o = ifd + 2 + k * 12
        if o + 12 > len(b): break
        tag, typ, cnt = struct.unpack_from(e + "HHI", b, o)
        if tag in tags:
            v = u(e + ("H" if typ == 3 else "I"), b, o + 8)
            if v is not None: f[tags[tag]] = str(v)
    return f


# ------------------------------------------------------------------------------------------------ audio / video containers
def wav_facts(b):
    if b[:4] != b"RIFF" or b[8:12] != b"WAVE":
        return {}
    f, i = {}, 12
    while i + 8 <= len(b):
        cid, ln = b[i:i + 4], struct.unpack_from("<I", b, i + 4)[0]
        if cid == b"fmt " and ln >= 16:
            tag, ch, sr, br, ba, bits = struct.unpack_from("<HHIIHH", b, i + 8)
            f.update({"format_tag": str(tag), "channels": str(ch), "sample_rate": str(sr), "byte_rate": str(br), "block_align": str(ba), "bits_per_sample": str(bits)})
        elif cid == b"data":
            f["data_bytes"] = str(ln)
            if f.get("byte_rate", "0") != "0": f["duration_seconds"] = "%.3f" % (ln / int(f["byte_rate"]))
        i += 8 + ln + (ln & 1)
    return f


def mp4_facts(b):
    if b[4:8] != b"ftyp" or len(b) < 16:
        return {}
    sz = struct.unpack_from(">I", b, 0)[0]
    f = {"major_brand": b[8:12].decode("latin-1").strip(), "minor_version": str(struct.unpack_from(">I", b, 12)[0]),
         "compatible_brands": jarr(b[o:o + 4].decode("latin-1").strip() for o in range(16, min(sz, len(b)) - 3, 4))}
    i = 0
    while i + 8 <= len(b):                                   # top-level atoms; moov -> mvhd timescale/duration
        asz, typ = struct.unpack_from(">I4s", b, i)
        if asz < 8: break
        if typ == b"moov":
            j = i + 8
            while j + 8 <= min(i + asz, len(b)):
                csz, ctyp = struct.unpack_from(">I4s", b, j)
                if csz < 8: break
                if ctyp == b"mvhd":
                    ver = b[j + 8]
                    if ver == 0: ts, du = struct.unpack_from(">II", b, j + 20)
                    else: ts, du = struct.unpack_from(">IQ", b, j + 28)
                    f["timescale"] = str(ts); f["duration_ticks"] = str(du)
                    if ts: f["duration_seconds"] = "%.3f" % (du / ts)
                j += csz
        i += asz
    return f


def flac_facts(b):
    if b[:4] != b"fLaC" or len(b) < 42 or (b[4] & 0x7F) != 0:
        return {}
    v = int.from_bytes(b[18:26], "big")
    return {"min_block_size": str(struct.unpack_from(">H", b, 8)[0]), "max_block_size": str(struct.unpack_from(">H", b, 10)[0]),
            "sample_rate": str(v >> 44), "channels": str(((v >> 41) & 7) + 1), "bits_per_sample": str(((v >> 36) & 31) + 1), "total_samples": str(v & 0xFFFFFFFFF),
            "md5": b[26:42].hex()}


# ------------------------------------------------------------------------------------------------ network captures
PCAP_LINK = {0: "null", 1: "ethernet", 101: "raw", 105: "ieee802_11", 113: "linux_sll", 228: "ipv4", 229: "ipv6", 276: "linux_sll2"}


def pcap_facts(b):
    magics = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False), b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}
    if b[:4] not in magics or len(b) < 24:
        return {}
    e, nano = magics[b[:4]]
    vmaj, vmin, zone, sig, snap, link = struct.unpack_from(e + "HHiIII", b, 4)
    link &= 0x0FFFFFFF
    f = {"version": "%d.%d" % (vmaj, vmin), "version_major": str(vmaj), "version_minor": str(vmin), "snaplen": str(snap), "linktype": str(link),
         "linktype_name": PCAP_LINK.get(link, str(link)), "nanosecond_resolution": boolean(nano), "byte_order": "little-endian" if e == "<" else "big-endian"}
    i, n, first, last = 24, 0, None, None
    while i + 16 <= len(b):
        s, frac, cap, orig = struct.unpack_from(e + "IIII", b, i)
        if cap > 0x40000: break
        t = s + frac / (1e9 if nano else 1e6)
        first = t if first is None else first; last = t
        n += 1; i += 16 + cap
    f["packet_count"] = str(n)
    if first is not None:
        f["first_timestamp_utc"] = utc(int(first)); f["last_timestamp_utc"] = utc(int(last))
    return f


def pcapng_facts(b):
    if b[:4] != b"\x0a\x0d\x0d\x0a" or len(b) < 28:
        return {}
    bom = b[8:12]
    e = "<" if bom == b"\x4d\x3c\x2b\x1a" else (">" if bom == b"\x1a\x2b\x3c\x4d" else None)
    if e is None:
        return {}
    vmaj, vmin = struct.unpack_from(e + "HH", b, 12)
    f = {"version": "%d.%d" % (vmaj, vmin), "byte_order": "little-endian" if e == "<" else "big-endian"}
    i, blocks, pk, links = 0, 0, 0, []
    while i + 12 <= len(b):
        typ, ln = struct.unpack_from(e + "II", b, i)
        if ln < 12 or i + ln > len(b): break
        blocks += 1
        if typ == 1: links.append(struct.unpack_from(e + "H", b, i + 8)[0])
        if typ in (2, 3, 6): pk += 1
        i += ln
    f.update({"block_count": str(blocks), "packet_count": str(pk), "interface_count": str(len(links)), "linktypes": jarr(str(x) for x in links)})
    return f


# ------------------------------------------------------------------------------------------------ WebAssembly / Windows artifacts
WASM_SECTIONS = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data", 12: "data_count"}


def _leb(b, i):
    r, s = 0, 0
    while i < len(b):
        c = b[i]; i += 1
        r |= (c & 0x7F) << s; s += 7
        if not c & 0x80: return r, i
    return None, i


def wasm_facts(b):
    if b[:4] != b"\x00asm" or len(b) < 8:
        return {}
    f = {"version": str(struct.unpack_from("<I", b, 4)[0])}
    i, secs, exports, imports = 8, [], [], 0
    while i < len(b):
        sid = b[i]; ln, j = _leb(b, i + 1)
        if ln is None or j + ln > len(b): break
        secs.append(WASM_SECTIONS.get(sid, str(sid)))
        if sid == 7:
            n, k = _leb(b, j)
            for _ in range(n or 0):
                nl, k = _leb(b, k); exports.append(b[k:k + nl].decode("utf-8", "replace")); k += nl + 1
                _, k = _leb(b, k)
        if sid == 2: imports, _ = _leb(b, j)
        i = j + ln
    f.update({"section_names": jarr(secs), "section_count": str(len(secs)), "export_names": jarr(exports), "export_count": str(len(exports)), "import_count": str(imports or 0)})
    return f


def _ft(v):
    return utc(v / 1e7 - 11644473600) if v else "none"


def lnk_facts(b):
    if b[:4] != b"L\x00\x00\x00" or b[4:20] != bytes.fromhex("0114020000000000c000000000000046") or len(b) < 76:
        return {}
    flags, attrs, ctime, atime, mtime, size, icon, show = struct.unpack_from("<IIQQQIiI", b, 20)
    return {"link_flags": hx(flags, 8), "file_attributes": hx(attrs, 8), "creation_time_utc": _ft(ctime), "access_time_utc": _ft(atime), "write_time_utc": _ft(mtime),
            "target_file_size": str(size), "icon_index": str(icon), "show_command": str(show), "has_link_target_idlist": boolean(flags & 1),
            "has_link_info": boolean(flags & 2), "has_name": boolean(flags & 4), "has_arguments": boolean(flags & 32), "is_unicode": boolean(flags & 128)}


def evtx_facts(b):
    if b[:8] != b"ElfFile\x00" or len(b) < 128:
        return {}
    first, last, nxt, hs, minor, major, hsz, nchunks, flags = struct.unpack_from("<QQQIHHHHxxI", b, 8)[:9] if False else (None,) * 9
    first, last, nxt = struct.unpack_from("<QQQ", b, 8)
    hs, minor, major, hsz, nchunks = struct.unpack_from("<IHHHH", b, 32)
    flags = u("<I", b, 120)
    return {"first_chunk": str(first), "last_chunk": str(last), "next_record_id": str(nxt), "header_size": str(hs), "minor_version": str(minor), "major_version": str(major),
            "version": "%d.%d" % (major, minor), "chunk_count": str(nchunks), "dirty": boolean((flags or 0) & 1), "full": boolean((flags or 0) & 2)}


def regf_facts(b):
    if b[:4] != b"regf" or len(b) < 0x70:
        return {}
    s1, s2, ts, major, minor, ftype, fmt, root, hlen = struct.unpack_from("<IIQIIIIII", b, 4)
    return {"primary_sequence": str(s1), "secondary_sequence": str(s2), "last_written_utc": _ft(ts), "version": "%d.%d" % (major, minor), "major_version": str(major),
            "minor_version": str(minor), "root_key_offset": hx(root), "hive_bins_data_size": str(hlen), "hive_name": b[0x30:0x70].decode("utf-16le", "ignore").split("\x00")[0]}


# ------------------------------------------------------------------------------------------------ small container headers
def bzip2_facts(b):
    if b[:3] != b"BZh" or len(b) < 4 or not (0x31 <= b[3] <= 0x39):
        return {}
    return {"block_size_level": chr(b[3]), "block_size_bytes": str((b[3] - 0x30) * 100000)}


def xz_facts(b):
    if b[:6] != b"\xfd7zXZ\x00" or len(b) < 12:
        return {}
    chk = {0: "none", 1: "crc32", 4: "crc64", 10: "sha256"}
    return {"check_type": chk.get(b[7] & 15, str(b[7] & 15)), "check_type_id": str(b[7] & 15)}


def sevenzip_facts(b):
    if b[:6] != b"7z\xbc\xaf\x27\x1c" or len(b) < 32:
        return {}
    nho, nhs = struct.unpack_from("<QQ", b, 12)
    return {"version": "%d.%d" % (b[6], b[7]), "version_major": str(b[6]), "version_minor": str(b[7]), "next_header_offset": str(nho), "next_header_size": str(nhs)}


def rar_facts(b):
    if b[:7] == b"Rar!\x1a\x07\x00":
        return {"version": "4"}
    if b[:8] == b"Rar!\x1a\x07\x01\x00":
        return {"version": "5"}
    return {}


# ------------------------------------------------------------------------------------------------ dispatch + registration
PARSERS = [("macho", macho_facts), ("java", java_facts), ("dex", dex_facts), ("sqlite", sqlite_facts), ("gif", gif_facts), ("bmp", bmp_facts), ("ico", ico_facts),
           ("tiff", tiff_facts), ("wav", wav_facts), ("mp4", mp4_facts), ("flac", flac_facts), ("pcap", pcap_facts), ("pcapng", pcapng_facts), ("wasm", wasm_facts),
           ("lnk", lnk_facts), ("evtx", evtx_facts), ("regf", regf_facts), ("bzip2", bzip2_facts), ("xz", xz_facts), ("7z", sevenzip_facts), ("rar", rar_facts)]
PARSER = dict(PARSERS)
ALIAS_FORMATS = {"class": "java", "java_class": "java", "mach_o": "macho", "macho_fat": "macho", "fat_macho": "macho", "universal": "macho", "sqlite3": "sqlite",
                 "wave": "wav", "riff": "wav", "mpeg4": "mp4", "m4a": "mp4", "ftyp": "mp4", "wasm": "wasm", "webassembly": "wasm", "registry": "regf",
                 "bz2": "bzip2", "sevenzip": "7z", "rar5": "rar", "pcapng": "pcapng", "cap": "pcap"}
# the same facts under a few natural alternative names (the GM's exact field names for a future day are unknown)
FACT_ALIASES = {"java.major_version": ["class_major_version", "major"], "java.minor_version": ["class_minor_version", "minor"],
                "java.java_version": ["java_release", "target_version"], "macho.nfat_arch": ["fat_arch_count", "number_of_architectures", "arch_count"],
                "macho.architectures": ["arch_list", "arches", "cpu_list", "slices"], "macho.cputype": ["cpu_type"], "macho.filetype": ["file_type"],
                "sqlite.page_size": ["database_page_size", "page_size_bytes"], "sqlite.text_encoding": ["encoding", "db_text_encoding"],
                "gif.width": ["logical_screen_width"], "gif.height": ["logical_screen_height"], "bmp.bit_count": ["bits_per_pixel_count", "bpp"],
                "wav.sample_rate": ["sample_rate_hz", "sampling_rate"], "wav.channels": ["channel_count", "num_channels"], "mp4.major_brand": ["brand", "ftyp_major_brand"],
                "pcap.linktype": ["link_type", "network", "data_link_type"], "pcap.packet_count": ["packets", "num_packets"], "dex.version": ["dex_version"]}


def facts(b):
    """-> (format, {field: value}) for the first parser that recognises `b` ({} / None when none does)."""
    for name, fn in PARSERS:
        try:
            f = fn(b)
        except Exception:
            f = {}
        if f:
            return name, f
    return None, {}


_FACT_TLS = threading.local()


def reset_fact_cache():
    """Reset parse-once facts at the start of one metadata solve invocation."""
    _FACT_TLS.cache = {}


def _facts_cached(b):
    # The Node tree keeps the original bytes object alive for a solve, so its
    # identity is a safe invocation-local key and avoids hashing large files
    # once per requested header field.
    cache = getattr(_FACT_TLS, "cache", None)
    if cache is None:
        cache = _FACT_TLS.cache = {}
    k = id(b)
    hit = cache.get(k)
    if hit is not None and hit[0] is b:
        return hit[1]
    result = facts(b)
    if len(cache) >= 64:
        cache.clear()
    cache[k] = (b, result)
    return result


def register(FIELDS):
    """Add `<format>.<field>` (and aliases) for every fact to the adapter's FIELDS, never overriding an existing entry. Returns how many were added."""
    n = 0

    def mk(fmt, key):
        return lambda b: _facts_cached(b)[1].get(key, "none")
    probe = {"macho": [], "java": []}
    for fmt, keys in SAMPLE_KEYS.items():
        for key in keys:
            names = [key] + FACT_ALIASES.get("%s.%s" % (fmt, key), [])
            for nm in names:
                tok = "%s.%s" % (fmt, nm)
                if tok not in FIELDS:
                    FIELDS[tok] = mk(fmt, key); n += 1
    for alias, fmt in ALIAS_FORMATS.items():
        for key in SAMPLE_KEYS.get(fmt, []):
            tok = "%s.%s" % (alias, key)
            if tok not in FIELDS:
                FIELDS[tok] = mk(fmt, key); n += 1
    return n


# every field name a parser can emit (kept in code, not discovered at runtime, so registration is deterministic and testable)
SAMPLE_KEYS = {
    "macho": ["fat", "fat64", "nfat_arch", "architectures", "cpu_type_set", "arch_count", "cputype", "cpu_name", "cpusubtype", "filetype", "filetype_name", "ncmds", "sizeofcmds", "flags",
              "is_64bit", "uuid", "entry_offset", "linked_dylibs", "dylib_count", "platform", "minos"],
    "java": ["minor_version", "major_version", "java_version", "constant_pool_count", "access_flags", "this_class", "super_class", "is_interface", "interfaces_count"],
    "dex": ["version", "checksum", "signature", "file_size", "header_size", "endian_tag", "string_ids_size", "type_ids_size", "proto_ids_size", "field_ids_size",
            "method_ids_size", "class_defs_size", "data_size", "map_off"],
    "sqlite": ["page_size", "write_version", "read_version", "journal_mode", "reserved_bytes", "file_change_counter", "database_size_pages", "freelist_pages", "schema_cookie",
               "schema_format", "text_encoding", "text_encoding_code", "user_version", "application_id", "version_valid_for", "sqlite_version_number", "table_names", "table_count"],
    "gif": ["version", "width", "height", "global_color_table", "color_resolution_bits", "global_color_table_size", "background_color_index", "pixel_aspect_ratio", "frame_count"],
    "bmp": ["file_size", "pixel_data_offset", "dib_header_size", "width", "height", "top_down", "planes", "bit_count", "bits_per_pixel", "compression", "colors_used"],
    "ico": ["type", "image_count", "sizes"],
    "tiff": ["byte_order", "first_ifd_offset", "ifd_entry_count", "image_width", "image_length", "bits_per_sample", "compression", "photometric", "samples_per_pixel"],
    "wav": ["format_tag", "channels", "sample_rate", "byte_rate", "block_align", "bits_per_sample", "data_bytes", "duration_seconds"],
    "mp4": ["major_brand", "minor_version", "compatible_brands", "timescale", "duration_ticks", "duration_seconds"],
    "flac": ["min_block_size", "max_block_size", "sample_rate", "channels", "bits_per_sample", "total_samples", "md5"],
    "pcap": ["version", "version_major", "version_minor", "snaplen", "linktype", "linktype_name", "nanosecond_resolution", "byte_order", "packet_count", "first_timestamp_utc",
             "last_timestamp_utc"],
    "pcapng": ["version", "byte_order", "block_count", "packet_count", "interface_count", "linktypes"],
    "wasm": ["version", "section_names", "section_count", "export_names", "export_count", "import_count"],
    "lnk": ["link_flags", "file_attributes", "creation_time_utc", "access_time_utc", "write_time_utc", "target_file_size", "icon_index", "show_command",
            "has_link_target_idlist", "has_link_info", "has_name", "has_arguments", "is_unicode"],
    "evtx": ["first_chunk", "last_chunk", "next_record_id", "header_size", "minor_version", "major_version", "version", "chunk_count", "dirty", "full"],
    "regf": ["primary_sequence", "secondary_sequence", "last_written_utc", "version", "major_version", "minor_version", "root_key_offset", "hive_bins_data_size", "hive_name"],
    "bzip2": ["block_size_level", "block_size_bytes"], "xz": ["check_type", "check_type_id"],
    "7z": ["version", "version_major", "version_minor", "next_header_offset", "next_header_size"], "rar": ["version"],
}


def header_facts_lines(b, max_items=40):
    """For the claim digest: one line of every fact for a recognised file, so the agent can answer any `Determine <format>.<field>` instantly."""
    fmt, f = facts(b)
    if not f:
        return []
    items = ["%s=%s" % (k, (v if len(v) <= 60 else v[:57] + "...")) for k, v in list(f.items())[:max_items]]
    return ["HEADER FACTS (%s; answer-ready, tokens are %s.<name>): %s" % (fmt, fmt, "; ".join(items))]


if __name__ == "__main__":
    import sys
    data = open(sys.argv[1], "rb").read()
    print("\n".join(header_facts_lines(data)) or "no header facts for this file")
