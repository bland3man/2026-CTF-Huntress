"""media.* fields (Day 17 Hear Me Out): the ACTUAL audio codec from the bytes, in ffprobe's codec_name spelling.
Never from the file name or extension. ffprobe first (the GM spells values like ffprobe: pcm_s16le, mp3, aac, flac, vorbis, opus),
then a pure-python fallback on the container/format tag."""
import os
import struct
import subprocess
import tempfile

WAV_TAGS = {1: None, 2: "adpcm_ms", 3: None, 6: "pcm_alaw", 7: "pcm_mulaw", 0x11: "adpcm_ima_wav", 0x55: "mp3", 0x50: "mp2",
            0x160: "wmav1", 0x161: "wmav2", 0xFF: "aac", 0x2000: "ac3", 0x2001: "dts", 0x674F: "vorbis", 0x7361: "adpcm_ima_wav"}


def _pcm_name(bits, tag, ext=False):
    if tag == 3:
        return {32: "pcm_f32le", 64: "pcm_f64le"}.get(bits, "pcm_f32le")
    return {8: "pcm_u8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}.get(bits, "pcm_s%dle" % bits)


def _fallback(b):
    if b[:4] == b"RIFF" and b[8:12] == b"WAVE":
        i = 12
        while i + 8 <= len(b):
            cid, ln = b[i:i + 4], struct.unpack_from("<I", b, i + 4)[0]
            if cid == b"fmt " and ln >= 16:
                tag, ch, sr, br, ba, bits = struct.unpack_from("<HHIIHH", b, i + 8)
                if tag == 0xFFFE and ln >= 40:
                    tag = struct.unpack_from("<H", b, i + 8 + 24)[0]
                if tag in (1, 3):
                    return _pcm_name(bits, tag)
                return WAV_TAGS.get(tag) or "unknown"
            i += 8 + ln + (ln & 1)
    if b[:4] == b"fLaC":
        return "flac"
    if b[:4] == b"OggS":
        return "opus" if b"OpusHead" in b[:200] else ("vorbis" if b"vorbis" in b[:200] else ("flac" if b"FLAC" in b[:200] else "unknown"))
    if b[:3] == b"ID3" or (len(b) > 1 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0):
        return "mp3"
    if b[:4] == b"FORM" and b[8:12] in (b"AIFF", b"AIFC"):
        return "pcm_s16be"
    if len(b) >= 12 and b[4:8] == b"ftyp":
        return _mp4_audio_codec(b)
    return None


_MP4_CONTAINERS = (b"moov", b"trak", b"mdia", b"minf", b"stbl")
_MP4_AUDIO_ENTRY = {b"alac": "alac", b"ac-3": "ac3", b"ec-3": "eac3", b"fLaC": "flac", b"Opus": "opus", b".mp3": "mp3", b"samr": "amr_nb", b"sawb": "amr_wb"}
_ESDS_OTI = {0x40: "aac", 0x66: "aac", 0x67: "aac", 0x68: "aac", 0x69: "mp3", 0x6B: "mp3", 0xA9: "dts", 0xDD: "vorbis"}


def _mp4_boxes(b, start, end):
    p = start
    while p + 8 <= end:
        size, typ = struct.unpack_from(">I4s", b, p)
        hdr = 8
        if size == 1 and p + 16 <= end:
            size, hdr = struct.unpack_from(">Q", b, p + 8)[0], 16
        elif size == 0:
            size = end - p
        if size < hdr or p + size > end:
            return
        yield typ, p + hdr, p + size
        p += size


def _mp4_audio_codec(b):
    """ISO-BMFF audio: first audio track's sample entry in stsd, spelled like ffprobe. mp4a reads the esds objectTypeIndication
    (0x40 = MPEG-4 AAC, 0x6B = MP3). Returns None when no audio track or an unrecognised entry (never a guess)."""
    def walk(start, end, depth=0):
        for typ, s, e in _mp4_boxes(b, start, end):
            if typ in _MP4_CONTAINERS and depth < 6:
                got = walk(s, e, depth + 1)
                if got:
                    return got
            elif typ == b"stsd" and s + 8 <= e:
                n_entries = struct.unpack_from(">I", b, s + 4)[0]
                if n_entries >= 1:
                    for etype, es, ee in _mp4_boxes(b, s + 8, e):
                        return _mp4_entry_codec(b, etype, es, ee)
        return None

    def track_is_audio(tstart, tend):
        for typ, s, e in _mp4_boxes(b, tstart, tend):
            if typ == b"mdia":
                for t2, s2, e2 in _mp4_boxes(b, s, e):
                    if t2 == b"hdlr" and s2 + 12 <= e2:
                        return b[s2 + 8:s2 + 12] == b"soun"
        return False

    for typ, s, e in _mp4_boxes(b, 0, len(b)):
        if typ == b"moov":
            for t2, s2, e2 in _mp4_boxes(b, s, e):
                if t2 == b"trak" and track_is_audio(s2, e2):
                    return walk(s2, e2)
    return None


def _mp4_entry_codec(b, etype, s, e):
    if etype in _MP4_AUDIO_ENTRY:
        return _MP4_AUDIO_ENTRY[etype]
    if etype != b"mp4a":
        return None
    k = b.find(b"esds", s, e)
    if k < 0:
        return None
    p = k + 4 + 4                                  # fourcc + version/flags
    if p >= e or b[p] != 0x03:
        return None
    p += 1
    while p < e and b[p] & 0x80:                   # variable-length size of ES_Descr
        p += 1
    p += 1 + 2 + 1                                 # last size byte, ES_ID, flags
    if p + 2 >= e or b[p] != 0x04:
        return None
    p += 1
    while p < e and b[p] & 0x80:
        p += 1
    p += 1
    return _ESDS_OTI.get(b[p]) if p < e else None


def _ffprobe(b, field="codec_name"):
    fd, p = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        r = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "a:0", "-show_entries", "stream=" + field,
                            "-of", "default=nw=1:nk=1", p], capture_output=True, timeout=30)
        out = r.stdout.decode("utf8", "replace").strip().splitlines()
        return out[0].strip() if out and out[0].strip() and out[0].strip() != "N/A" else None
    except Exception:
        return None
    finally:
        try:
            os.unlink(p)
        except Exception:
            pass


def primary_audio_codec_name(b):
    return _ffprobe(b) or _fallback(b) or "none"


def _probe_field(field):
    return lambda b: _ffprobe(b, field) or "none"


def _video_wh(b):
    """First video stream stored width/height (ffprobe v:0), as 'WxH' (the form the GM accepted for jpeg/png/webp dimensions).
    Fallback: the first visual sample entry (avc1/hvc1/...) inside stsd: width/height are u16 at +24/+26 of the entry payload."""
    fd, p = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(b)
        r = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height",
                            "-of", "csv=s=x:p=0", p], capture_output=True, timeout=30)
        out = r.stdout.decode("utf8", "replace").strip().splitlines()
        if out and out[0].strip().replace("x", "").isdigit() and "x" in out[0]:
            wh = out[0].strip().split("x")
            if len(wh) == 2 and int(wh[0]) > 0 and int(wh[1]) > 0:      # ffprobe reports a zero-sized entry as 0x0: not an answer (the stsd fallback below rejects it too)
                return out[0].strip()
    except Exception:
        pass
    finally:
        try:
            os.unlink(p)
        except Exception:
            pass
    for tag in (b"avc1", b"avc3", b"hvc1", b"hev1", b"mp4v", b"vp09", b"av01", b"encv"):
        i = b.find(tag)
        # 2026-10-18 (recovery lane): try EVERY occurrence. The first hit can be an ftyp compatible brand (Day 18 video-001.mp4 has 'avc1'
        # in ftyp at offset 24, which read (0,0) and made the fallback return None). A real sample entry has a box size that fits the file.
        while i >= 4:
            size = struct.unpack_from(">I", b, i - 4)[0]
            if i + 4 + 28 <= len(b) and 86 <= size <= len(b) - (i - 4):
                w, h = struct.unpack_from(">HH", b, i + 4 + 24)
                if w and h:
                    return "%dx%d" % (w, h)
            i = b.find(tag, i + 1)
    return None


def primary_video_dimensions(b):
    return _video_wh(b) or "none"


def register(FIELDS):
    FIELDS.setdefault("media.primary_video_dimensions", primary_video_dimensions)
    FIELDS.setdefault("media.video_dimensions", primary_video_dimensions)
    for k, fn in {
        "media.primary_audio_codec_name": primary_audio_codec_name,
        "media.audio_codec_name": primary_audio_codec_name,
        "media.primary_audio_codec_long_name": _probe_field("codec_long_name"),
        "media.primary_audio_sample_rate": _probe_field("sample_rate"),
        "media.primary_audio_channels": _probe_field("channels"),
        "media.primary_audio_bit_rate": _probe_field("bit_rate"),
    }.items():
        FIELDS.setdefault(k, fn)
