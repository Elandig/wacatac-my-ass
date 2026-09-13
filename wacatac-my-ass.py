#!/usr/bin/env python3
"""Pad a clean, unsigned Windows PE past ~100 MiB so the Microsoft Defender ML heuristic stops
flagging it as a Wacatac variant. Adds an inert data section; the program is unchanged. See README."""

import argparse
import array
import math
import os
import random
import struct
import sys
from collections import Counter

MiB = 1024 * 1024
FALIGN_FALLBACK = 0x200
SEC_CHARS = 0x40000040  # CNT_INITIALIZED_DATA | MEM_READ
_POOL = None


def word_pool():
    global _POOL
    if _POOL is None:
        cons, vows = "bcdfghjklmnpqrstvwxyz", "aeiou"
        _POOL = ["".join(random.choice(cons if k % 2 == 0 else vows)
                         for k in range(random.randint(3, 11)))
                 for _ in range(40000)]
    return _POOL

PRESETS = {
    "rdata": ".rdata",
    "rodata": ".rodata",
    "data": ".data",
    "text": ".text0",
    "pad": ".pad",
}


def resolve_section(v):
    if v in PRESETS:
        return PRESETS[v]
    return v if v.startswith(".") else "." + v


DWARF_CORE = [".debug_str", ".debug_info", ".debug_line"]
DWARF_EXTRA = [".debug_abbrev", ".debug_ranges", ".debug_loc", ".debug_aranges", ".debug_rnglists"]


def debug_layout():
    names = DWARF_CORE + random.sample(DWARF_EXTRA, random.randint(1, 3))
    weights = [random.uniform(0.6, 1.4) for _ in names]
    weights[0] *= 2.5   # .debug_str is normally the fattest
    tot = sum(weights)
    return [(nm, w / tot) for nm, w in zip(names, weights)]


def plan_sections(section, total):
    if section == "debug":
        layout, out, used = debug_layout(), [], 0
        for k, (nm, frac) in enumerate(layout):
            sz = total - used if k == len(layout) - 1 else int(total * frac)
            out.append((nm, make_pad(sz)))
            used += sz
        return out
    return [(resolve_section(section), make_pad(total))]


def die(msg, code=2):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def align(x, a):
    a = a or FALIGN_FALLBACK
    return (x + a - 1) // a * a


def pe_info(d):
    if d[:2] != b"MZ":
        die("not a PE file (no MZ header)")
    pe = u32(d, 0x3C)
    if d[pe:pe + 4] != b"PE\0\0":
        die("not a PE file (no PE signature)")
    optsz = u16(d, pe + 20)
    magic = u16(d, pe + 24)
    plus = magic == 0x20B
    return {
        "pe": pe,
        "nsec": u16(d, pe + 6),
        "plus": plus,
        "salign": u32(d, pe + 24 + 32),
        "falign": u32(d, pe + 24 + 36) or FALIGN_FALLBACK,
        "sectbl": pe + 24 + optsz,
        "checksum": pe + 88,               # OptionalHeader.CheckSum, same offset for PE32/PE32+
        "sizeofimage": pe + 24 + 56,
        "datadir": pe + 24 + (112 if plus else 96),
    }


def sections(d, i):
    out = []
    for k in range(i["nsec"]):
        o = i["sectbl"] + k * 40
        out.append({
            "name": d[o:o + 8].rstrip(b"\0").decode("latin1"),
            "vsize": u32(d, o + 8),
            "va": u32(d, o + 12),
            "rsize": u32(d, o + 16),
            "rptr": u32(d, o + 20),
        })
    return out


def is_signed(d, i):
    # data directory index 4 = certificate table; nonzero size means Authenticode present.
    return u32(d, i["datadir"] + 4 * 8 + 4) != 0


def has_debug_sections(d, i):
    # /N names index the COFF string table; resolve them so long .debug_* names are seen too
    ptr_sym, num_sym = u32(d, i["pe"] + 12), u32(d, i["pe"] + 16)
    strbase = ptr_sym + num_sym * 18 if ptr_sym else 0
    for s in sections(d, i):
        nm = s["name"]
        if nm.startswith("/") and strbase:
            try:
                off = strbase + int(nm[1:])
                nm = d[off:d.index(b"\0", off)].decode("latin1")
            except Exception:
                pass
        if nm.startswith(".debug"):
            return True
    return False


def content_end(d, i):
    """Last byte the PE structure accounts for: sections, plus a trailing COFF symbol/string
    table if binutils left one (GNU builds), rounded to file alignment. Anything past this is
    an overlay."""
    end = 0
    for s in sections(d, i):
        if s["rsize"]:
            end = max(end, s["rptr"] + s["rsize"])
    ptr_sym = u32(d, i["pe"] + 12)
    num_sym = u32(d, i["pe"] + 16)
    if ptr_sym:
        strtab = ptr_sym + num_sym * 18
        if strtab + 4 <= len(d):
            end = max(end, strtab + u32(d, strtab))
    return align(end, i["falign"])


def overlay_bytes(d, i):
    return len(d) - content_end(d, i)


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())


def worst_section_entropy(d, i):
    worst, name = 0.0, ""
    for s in sections(d, i):
        if s["rsize"]:
            e = entropy(d[s["rptr"]:s["rptr"] + s["rsize"]])
            if e > worst:
                worst, name = e, s["name"]
    return worst, name


def make_pad(n):
    pool = word_pool()
    buf = bytearray()
    while len(buf) < n:
        buf += " ".join(random.choices(pool, k=8000)).encode("ascii", "ignore") + b"\n"
    return bytes(buf[:n])


def pe_checksum(d, off):
    body = bytearray(d)
    body[off:off + 4] = b"\0\0\0\0"
    if len(body) & 1:
        body.append(0)
    words = array.array("H")
    words.frombytes(body)
    if sys.byteorder != "little":
        words.byteswap()
    s = sum(words)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (s + len(d)) & 0xFFFFFFFF


def set_checksum(d):
    i = pe_info(d)
    d = bytearray(d)
    struct.pack_into("<I", d, i["checksum"], pe_checksum(d, i["checksum"]))
    return bytes(d)


def inject(d, sects):
    i = pe_info(d)
    secs = sections(d, i)
    if not secs:
        die("no sections in this PE, refusing")
    end_of_table = i["sectbl"] + i["nsec"] * 40
    first_raw = min((s["rptr"] for s in secs if s["rptr"]), default=0)
    if first_raw:
        slots = (first_raw - end_of_table) // 40
        if slots < 1:
            die("no room in the PE headers to add a section (they're packed tight); can't pad this "
                "one without rebuilding it")
        if len(sects) > slots:
            # only `slots` headers fit; fold the overflow into the last kept section
            tail = sects[slots - 1:]
            sects = sects[:slots - 1] + [(tail[0][0], b"".join(c for _, c in tail))]

    d = bytearray(d)

    # names over 8 bytes live in the COFF string table, referenced from the header as /<offset>
    long = [n for n, _ in sects if len(n.encode()) > 8]
    name_field = {}
    sym_tail = b""
    if long:
        ptr_sym, num_sym = u32(d, i["pe"] + 12), u32(d, i["pe"] + 16)
        if ptr_sym:
            str_at = ptr_sym + num_sym * 18
            old_size = u32(d, str_at)
            symbols = bytes(d[ptr_sym:str_at])
            body = bytes(d[str_at + 4:str_at + old_size])
            d[ptr_sym:str_at + old_size] = b"\0" * (str_at + old_size - ptr_sym)
        else:
            old_size, symbols, body = 4, b"", b""
        extra, off = bytearray(), old_size
        for nm in dict.fromkeys(long):
            name_field[nm] = ("/%d" % off).encode().ljust(8, b"\0")
            extra += nm.encode() + b"\0"
            off += len(nm.encode()) + 1
        sym_tail = symbols + struct.pack("<I", old_size + len(extra)) + body + bytes(extra)

    va = align(max(s["va"] + (s["vsize"] or s["rsize"]) for s in secs), i["salign"])
    entries = []
    for name, content in sects:
        rptr = align(len(d), i["falign"])
        rsize = align(len(content), i["falign"])
        d += b"\0" * (rptr - len(d))
        d += content
        d += b"\0" * (rsize - len(content))
        entries.append((name, len(content), va, rsize, rptr))
        va = align(va + len(content), i["salign"])

    if sym_tail:
        struct.pack_into("<I", d, i["pe"] + 12, len(d))
        d += sym_tail
        d += b"\0" * (align(len(d), i["falign"]) - len(d))

    o = end_of_table
    for name, vsize, sva, rsize, rptr in entries:
        nm = name_field.get(name, name.encode()[:8].ljust(8, b"\0"))
        struct.pack_into("<8sIIII", d, o, nm, vsize, sva, rsize, rptr)
        struct.pack_into("<IIHHI", d, o + 24, 0, 0, 0, 0, SEC_CHARS)
        o += 40
    struct.pack_into("<H", d, i["pe"] + 6, i["nsec"] + len(entries))
    struct.pack_into("<I", d, i["sizeofimage"], va)
    return bytes(d)


def report(path, d):
    i = pe_info(d)
    signed = is_signed(d, i)
    worst, wname = worst_section_entropy(d, i)
    overlay = overlay_bytes(d, i)
    tag = "  (authenticode signature)" if signed and overlay else ""
    print(f"  {os.path.basename(path)}  {len(d) / MiB:.1f} MiB  {i['nsec']} sections  "
          f"{'PE32+' if i['plus'] else 'PE32'}")
    print(f"  signed:   {'yes' if signed else 'no'}")
    print(f"  overlay:  {overlay} bytes{tag}")
    print(f"  entropy:  {entropy(d):.2f} avg, worst {worst:.2f} ({wname or '-'})")


def cmd_check(path):
    d = open(path, "rb").read()
    report(path, d)


def cmd_checksum(path, out, inplace):
    d = open(path, "rb").read()
    d = set_checksum(d)
    dst = path if inplace else out
    open(dst, "wb").write(d)
    print(f"wrote PE checksum -> {dst}")


def cmd_pad(path, out, inplace, total_mb, add_mb, section, force):
    d = open(path, "rb").read()
    i = pe_info(d)

    if is_signed(d, i):
        die("this file is signed. padding invalidates the signature, so it shows as tampered and "
            "you lose the point of signing. pad the unsigned build first, then sign.")

    overlay = overlay_bytes(d, i)
    if overlay > 0 and not force:
        die(f"this file has {overlay} bytes stuck after the last section. it might be a "
            "self-extracting or self-checking exe that reads its own tail, and padding will "
            "break it. pass --force if you're sure.")

    if add_mb is not None:
        pad_len = add_mb * MiB
    else:
        pad_len = total_mb * MiB - len(d)
        if pad_len <= 0:
            print(f"already {len(d) / MiB:.1f} MiB, at or over the {total_mb} MiB target. "
                  "nothing to add, fixing the checksum only.")
            dst = path if inplace else out
            open(dst, "wb").write(set_checksum(d))
            print(f"wrote -> {dst}")
            return
        pad_len += random.randint(0, 4 * MiB)

    if section == "auto":
        if has_debug_sections(d, i):
            section = "rdata"
            print("binary already has debug sections; padding as a plain .rdata blob instead of "
                  "faking more (pass --section debug to override)")
        else:
            section = "debug"
            print("binary is stripped of debug info; padding as fake .debug_* sections so it looks "
                  "like a debug build (pass --section to override)")

    plan = plan_sections(section, pad_len)
    print(f"padding with {pad_len / MiB:.1f} MiB in: {', '.join(n for n, _ in plan)} ...")
    d = inject(d, plan)
    d = set_checksum(d)

    dst = path if inplace else out
    open(dst, "wb").write(d)
    print(f"wrote -> {dst}")
    report(dst, d)
    print()
    print("run it on Windows to make sure it still starts, then throw it at VirusTotal and check "
          "again in a few minutes - Defender's ml takes its time deciding. workaround, not a fix, "
          "sign your builds.")


def main():
    ap = argparse.ArgumentParser(
        prog="wacatac-my-ass.py",
        description="bloat a clean Windows binary past ~100 MB so Defender's ml stops crying malware",
        epilog="examples:\n"
               "  wacatac-my-ass.py mytool.exe                 pad to ~110 MiB -> mytool.padded.exe\n"
               "  wacatac-my-ass.py mytool.exe --section rdata one plain blob instead of fake debug\n"
               "  wacatac-my-ass.py mytool.exe --inplace       overwrite in place\n"
               "  wacatac-my-ass.py -c mytool.exe              audit only, change nothing\n"
               "  wacatac-my-ass.py --checksum-only mytool.exe fix a zeroed PE checksum\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("exe")
    ap.add_argument("-c", "--check", action="store_true", help="audit only, do not modify")
    ap.add_argument("--checksum-only", action="store_true", help="only recompute the PE checksum")
    ap.add_argument("-o", "--out", help="output path (default: <name>.padded<ext>)")
    ap.add_argument("--inplace", action="store_true", help="overwrite the input file")
    ap.add_argument("--total-mb", type=int, default=110, help="grow the file to at least this many MiB (default 110)")
    ap.add_argument("--add-mb", type=int, help="instead, add exactly this many MiB")
    ap.add_argument("--section", default="auto",
                    help="how to lay out the pad. auto (default): debug if the binary is stripped, "
                         "else rdata. force one: debug (fake .debug_* sections), rdata, rodata, "
                         "data, text, pad, or a literal like .foo")
    ap.add_argument("--force", action="store_true", help="pad even if the file has an existing overlay")
    a = ap.parse_args()

    if not os.path.isfile(a.exe):
        die(f"no such file: {a.exe}")
    stem, ext = os.path.splitext(a.exe)
    out = a.out or f"{stem}.padded{ext}"

    if a.check:
        cmd_check(a.exe)
    elif a.checksum_only:
        cmd_checksum(a.exe, out, a.inplace)
    else:
        cmd_pad(a.exe, out, a.inplace, a.total_mb, a.add_mb, a.section, a.force)


if __name__ == "__main__":
    main()
