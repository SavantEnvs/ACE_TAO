#!/usr/bin/env python3
"""Generate the seed corpora of the ace-cdr and tao-cdr targets.

Run from the repo root:  python3 mayhem/gen_cdr_seeds.py
It rewrites mayhem/ace-cdr/testsuite/ and mayhem/tao-cdr/testsuite/.

Input layout of both harnesses (mayhem/harnesses/fuzz_cdr.cpp, fuzz_tao_cdr.cpp):
  byte 0      bit 0 = byte order (1 = little endian), (byte >> 1) % 3 = GIOP 1.<minor>
  bytes 1..   a CDR stream, copied by the harness into a buffer aligned to
              ACE_CDR::MAX_ALIGNMENT, so CDR padding is relative to byte 1 (the stream start),
              as in a GIOP message body. The stream is a sequence of (opcode octet, value) items.
"""
import os
import shutil
import struct

ROOT = os.path.dirname(os.path.abspath(__file__))


class CDR:
    """Minimal CDR encoder; alignment is relative to the stream start."""

    def __init__(self, le, minor):
        self.le, self.minor, self.buf = le, minor, bytearray()

    def _p(self, fmt, *v):
        return struct.pack(("<" if self.le else ">") + fmt, *v)

    def align(self, n):
        while len(self.buf) % n:
            self.buf.append(0)
        return self

    def octet(self, v):
        self.buf.append(v & 0xFF)
        return self

    def raw(self, b):
        self.buf += b
        return self

    def short(self, v):
        self.align(2).raw(self._p("h", v))
        return self

    def ulong(self, v):
        self.align(4).raw(self._p("I", v))
        return self

    def long(self, v):
        self.align(4).raw(self._p("i", v))
        return self

    def ulonglong(self, v):
        self.align(8).raw(self._p("Q", v))
        return self

    def float(self, v):
        self.align(4).raw(self._p("f", v))
        return self

    def double(self, v):
        self.align(8).raw(self._p("d", v))
        return self

    def longdouble(self, v):
        # CDR long double: 16 bytes, 8-aligned (IEEE quad); the leading 8 bytes carry a double here.
        d = self._p("d", v)
        self.align(8).raw(d + bytes(8) if not self.le else bytes(8) + d)
        return self

    def string(self, s):
        b = s.encode() + b"\0"
        self.ulong(len(b)).raw(b)
        return self

    def wchar_unit(self, c):
        # ACE on Linux: wchar_maxbytes_ = sizeof (ACE_CDR::WChar) = 4, read as aligned 4-byte units.
        self.ulong(ord(c))
        return self

    def wstring(self, s):
        if self.minor == 2:          # GIOP 1.2: octet length, no terminator
            self.ulong(4 * len(s))
            for c in s:
                self.wchar_unit(c)
        else:                        # GIOP 1.0/1.1: char count including the terminator
            self.ulong(len(s) + 1)
            for c in s + "\0":
                self.wchar_unit(c)
        return self

    def wchar_item(self, op, c):
        """An opcode 20/21 item. Left out of byte-swapped GIOP 1.2 streams: there ACE reads the
        wchar octet-aligned and then byte-swaps it with ACE_CDR::swap_4, a misaligned 4-byte load
        (ACE_InputCDR::read_wchar, CDR_Stream.cpp:1424 -> read_array -> swap_4_array), an upstream
        bug that would make the seed itself crash."""
        if self.minor == 2 and not self.le:
            return self
        return self.octet(op).wchar(c)

    def wchar(self, c):
        if self.minor == 2:          # GIOP 1.2: octet length + the bytes
            self.octet(4).raw(self._p("I", ord(c)))
        else:
            self.wchar_unit(c)
        return self

    def fixed(self, digits, negative=False):
        """BCD, two digits per octet, last nibble = sign (0xC positive, 0xD negative)."""
        ds = digits if len(digits) % 2 == 1 else "0" + digits
        nib = [int(d) for d in ds] + [0xD if negative else 0xC]
        for i in range(0, len(nib), 2):
            self.octet((nib[i] << 4) | nib[i + 1])
        return self


def ace_cdr_seeds(le, minor):
    E = lambda: CDR(le, minor)  # noqa: E731
    out = {}
    e = E()
    for s in ("hello", "", "CDR string with spaces", "x" * 40):
        e.octet(0).string(s)          # read_string (Char*&)
    e.octet(2).string("std::string")  # read_string (std::string&)
    e.octet(4).string("ACE_CString")  # read_string (ACE_CString&)
    e.octet(6).string("skipped")      # skip_string
    e.octet(8).ulong(16).string("bounded")   # to_string with bound
    e.octet(8).ulong(3).string("too long")   # bound exceeded
    out["strings"] = e
    e = E()
    for s in ("wide", "", "wstring é中"):
        e.octet(1).wstring(s)
    e.octet(3).wstring("std::wstring")
    e.octet(7).wstring("skipped")
    e.octet(9).ulong(16).wstring("bounded")
    e.wchar_item(20, "W").wchar_item(21, "S")
    out["wstrings"] = e
    e = E()
    e.octet(5).fixed("12345").octet(5).fixed("9", True).octet(5).fixed("1234567890123456789012345")
    e.octet(5).fixed("1234567890123456789012345678901", True)
    e.octet(31).fixed("1234").fixed("567", True)
    e.octet(31).fixed("99999999999999").fixed("3")
    e.octet(31).fixed("1").fixed("0")
    out["fixed"] = e
    e = E()
    e.octet(10).ulong(3).raw(b"\x01\x00\x01")
    e.octet(11).ulong(5).raw(b"chars")
    e.octet(12).ulong(2).wchar_unit("a").wchar_unit("b")
    e.octet(13).ulong(3).short(1).short(-2).short(3)
    e.octet(14).ulong(2).long(7).long(-7)
    e.octet(15).ulong(2).ulonglong(1).ulonglong(2 ** 40)
    e.octet(16).ulong(2).float(1.5).float(-0.25)
    e.octet(17).ulong(2).double(3.25).double(-1e300)
    e.octet(18).ulong(1).longdouble(2.5)
    e.octet(19).ulong(4).raw(b"skip")
    out["arrays"] = e
    e = E()
    e.octet(22).octet(1).octet(23).octet(ord("c")).octet(24).short(-12345)
    e.octet(25).ulong(0xDEADBEEF).octet(26).ulonglong(0x0123456789ABCDEF)
    e.octet(27).float(3.5).octet(28).double(6.25).octet(29).longdouble(1.0)
    for k, w in ((0, 1), (1, 1), (2, 2), (3, 4), (4, 8), (5, 4), (6, 8), (7, 16)):
        e.octet(30).octet(k).align(min(w, 8)).raw(bytes(w))
    out["scalars"] = e
    e = E()
    e.octet(0).string("mix").octet(25).ulong(42).octet(1).wstring("mix")
    e.octet(5).fixed("314159").octet(17).ulong(1).double(2.0).wchar_item(20, "m")
    out["mixed"] = e
    return out


# CORBA TCKind values (TAO/tao/TypeCodeFactory, CORBA 3.x 15.3.5.1).
TK = dict(null=0, void=1, short=2, long=3, ushort=4, ulong=5, float=6, double=7, boolean=8,
          char=9, octet=10, any=11, TypeCode=12, objref=14, struct=15, enum=17, string=18,
          sequence=19, alias=21, longlong=23, wstring=27)


def encap(le, body):
    """An encapsulation: ulong length, then a byte-order octet and its body, aligned to its own start."""
    inner = CDR(le, 2)
    inner.octet(1 if le else 0)
    body(inner)
    return bytes(inner.buf)


def tao_cdr_seeds(le, minor):
    E = lambda: CDR(le, minor)  # noqa: E731
    out = {}
    e = E()
    e.octet(0).ulong(TK["long"]).long(-42)
    e.octet(0).ulong(TK["ulong"]).ulong(7)
    e.octet(0).ulong(TK["double"]).double(1.25)
    e.octet(0).ulong(TK["boolean"]).octet(1)
    e.octet(0).ulong(TK["longlong"]).ulonglong(2 ** 33)
    e.octet(0).ulong(TK["null"])
    out["any_scalars"] = e
    e = E()
    e.octet(0).ulong(TK["string"]).ulong(0).string("any string")
    e.octet(0).ulong(TK["string"]).ulong(8).string("bounded")
    e.octet(0).ulong(TK["wstring"]).ulong(0).wstring("wide")
    out["any_string"] = e
    e = E()
    seq = encap(le, lambda c: c.ulong(TK["long"]).ulong(0))
    e.octet(0).ulong(TK["sequence"]).ulong(len(seq)).raw(seq).ulong(3).long(1).long(2).long(3)
    st = encap(le, lambda c: c.string("IDL:Fuzz/S:1.0").string("S").ulong(2)
               .string("a").ulong(TK["long"]).string("b").ulong(TK["string"]).ulong(0))
    e.octet(0).ulong(TK["struct"]).ulong(len(st)).raw(st).long(5).string("member")
    en = encap(le, lambda c: c.string("IDL:Fuzz/E:1.0").string("E").ulong(2).string("X").string("Y"))
    e.octet(0).ulong(TK["enum"]).ulong(len(en)).raw(en).ulong(1)
    al = encap(le, lambda c: c.string("IDL:Fuzz/A:1.0").string("A").ulong(TK["short"]))
    e.octet(0).ulong(TK["alias"]).ulong(len(al)).raw(al).short(9)
    out["any_constructed"] = e
    e = E()
    e.octet(1).ulong(TK["long"])
    e.octet(1).ulong(TK["struct"]).ulong(len(st)).raw(st)
    obj = encap(le, lambda c: c.string("IDL:omg.org/CORBA/Object:1.0").string("Object"))
    e.octet(1).ulong(TK["objref"]).ulong(len(obj)).raw(obj)
    e.octet(7).ulong(TK["any"]).ulong(TK["long"]).long(1)
    out["typecodes"] = e
    e = E()
    e.octet(2).string("").ulong(0)  # nil object reference
    prof = encap(le, lambda c: c.octet(1).octet(minor).string("localhost").short(2809)
                 .ulong(3).raw(b"key").ulong(0))
    e.octet(2).string("IDL:Fuzz/I:1.0").ulong(1).ulong(0).ulong(len(prof)).raw(prof)  # TAG_INTERNET_IOP
    out["objref"] = e
    e = E()
    e.octet(3).ulong(16).string("bounded")
    e.octet(4).ulong(16).wstring("bounded")
    e.octet(5).ulong(0).string("std bounded")
    e.octet(6).ulong(0).wstring("std wide")
    out["bounded"] = e
    return out


def write(target, gen):
    d = os.path.join(ROOT, target, "testsuite")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for le in (0, 1):
        for minor in (0, 1, 2):
            for name, cdr in gen(le, minor).items():
                path = os.path.join(d, "%s-%s-1%d" % (name, "le" if le else "be", minor))
                with open(path, "wb") as f:
                    f.write(bytes([le | (minor << 1)]) + bytes(cdr.buf))


if __name__ == "__main__":
    write("ace-cdr", ace_cdr_seeds)
    write("tao-cdr", tao_cdr_seeds)
