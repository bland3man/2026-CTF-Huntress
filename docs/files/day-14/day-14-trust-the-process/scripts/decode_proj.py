import base64, binascii, glob, os, re, json, sys


def decode_msbuild_descriptor(raw):
    """Decode a HUNTRESS_ANALYSIS_V1 msbuild .proj descriptor.

    The encoding is self-declared by the tag in the XML comment:
      HEX-  plain hex
      B64-  base64
      HB64- hex of a base64 string
      FRAG- dot-fragmented hex
    The <HuntressDescriptor> property carries the same payload.
    """
    m = re.search(r'HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-', raw)
    tag = m.group(1) if m else None
    m2 = re.search(r'<HuntressDescriptor>\s*(.*?)\s*</HuntressDescriptor>', raw, re.S)
    payload = m2.group(1).strip()
    if tag == 'FRAG':
        txt = binascii.unhexlify(payload.replace('.', '').replace('-', '')).decode()
    elif tag == 'HEX':
        txt = binascii.unhexlify(payload).decode()
    elif tag == 'B64':
        txt = base64.b64decode(payload).decode()
    elif tag == 'HB64':
        txt = base64.b64decode(binascii.unhexlify(payload).decode()).decode()
    else:
        raise ValueError('unknown descriptor tag %r' % tag)
    fields = {}
    for part in txt.split('|'):
        if '=' in part:
            k, v = part.split('=', 1)
            fields[k] = v
    return tag, txt, fields


if __name__ == '__main__':
    d = 'challenges/Day 14/Trust the Process/extracted'
    out = {}
    for p in sorted(glob.glob(os.path.join(d, '*.proj'))):
        raw = open(p, 'r', encoding='utf-8').read()
        tag, txt, fields = decode_msbuild_descriptor(raw)
        out[os.path.basename(p)] = fields
        print('===', os.path.basename(p), '[tag %s]' % tag)
        for k, v in fields.items():
            print('   %-22s %s' % (k, v))
        print()
    json.dump(out, open('challenges/Day 14/Trust the Process/decoded_proj.json', 'w'), indent=1)
    print('wrote decoded_proj.json')
