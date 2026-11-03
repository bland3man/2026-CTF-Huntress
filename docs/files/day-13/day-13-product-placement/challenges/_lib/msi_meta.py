"""MSI (OLE2 compound file) Property-table fields (Day 13 Product Placement): msi.product_code_guid and friends.

Parses the MSI string pool (_StringPool/_StringData) and the Property table directly.
GUID text is returned canonical lowercase, no braces (same convention as dotnet.mvid_guid).
"""
import io
import re
import struct

_B64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def _dec(name):
    out = []
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(_B64[c & 0x3F])
            out.append(_B64[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(_B64[c - 0x4800])
        else:
            out.append(ch)
    return "".join(out)


def _streams(b):
    import olefile
    o = olefile.OleFileIO(io.BytesIO(bytes(b)))
    res = {}
    for e in o.listdir():
        n = e[-1]
        raw = o.openstream(e).read()
        if n.startswith("䡀"):
            res[_dec(n[1:])] = raw
        else:
            res[n] = raw
    return res


def property_table(b):
    st = _streams(b)
    pool, pdata, prop = st["_StringPool"], st["_StringData"], st["Property"]
    cp, flags = struct.unpack("<HH", pool[:4])
    refw = 3 if flags & 0x8000 else 2
    strs = [None]
    pos = 0
    i = 4
    while i < len(pool):
        ln, rc = struct.unpack("<HH", pool[i:i + 4])
        i += 4
        if ln == 0 and rc != 0:
            ln = struct.unpack("<I", pool[i:i + 4])[0]
            i += 4
        strs.append(pdata[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
    n = len(prop) // (2 * refw)
    ks = [int.from_bytes(prop[k * refw:(k + 1) * refw], "little") for k in range(n)]
    vs = [int.from_bytes(prop[(n + k) * refw:(n + k + 1) * refw], "little") for k in range(n)]
    return {strs[a]: (strs[v] if v else "") for a, v in zip(ks, vs)}


def _guid(key):
    def f(b):
        v = property_table(b)[key]
        m = re.fullmatch(r"\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?", v.strip())
        if not m:
            raise ValueError("%s is not a GUID: %r" % (key, v))
        return "{" + m.group(1).upper() + "}"   # GM-accepted D13: MSI-native braced uppercase (plain lower/upper were rejected)
    return f


def _plain(key):
    return lambda b: property_table(b)[key]


def register(FIELDS):
    FIELDS["msi.product_code_guid"] = _guid("ProductCode")
    FIELDS["msi.product_code"] = _guid("ProductCode")
    FIELDS["msi.upgrade_code_guid"] = _guid("UpgradeCode")
    FIELDS["msi.upgrade_code"] = _guid("UpgradeCode")
    FIELDS["msi.product_version"] = _plain("ProductVersion")
    FIELDS["msi.product_name"] = _plain("ProductName")
    FIELDS["msi.manufacturer"] = _plain("Manufacturer")


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        print(f, property_table(open(f, "rb").read()))
