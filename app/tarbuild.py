"""Helpers to build well-formed gzip+base64 TAR layers.

Used by the unit tests and by the HTTP smoke client; the production server
never generates layers itself.
"""

from __future__ import annotations

import base64
import gzip
import io


def _field(value: bytes, size: int) -> bytes:
    if len(value) > size:
        raise ValueError(f"field overflow: {value!r} does not fit in {size}")
    return value + b"\0" * (size - len(value))


def _octal(value: int, size: int) -> bytes:
    return ("%0*o" % (size - 1, value)).encode() + b"\0"


def entry_header(name: str, typeflag: bytes, size: int = 0, link: str = "") -> bytes:
    """Build a POSIX ustar header with a correct checksum."""
    name_b = name.encode()
    prefix = b""
    if len(name_b) > 100:
        parts = name.split("/")
        for k in range(1, len(parts)):
            pre = "/".join(parts[:k]).encode()
            rest = "/".join(parts[k:]).encode()
            if len(pre) <= 155 and len(rest) <= 100:
                prefix, name_b = pre, rest
        if len(name_b) > 100:
            raise ValueError(f"name too long for ustar: {name!r}")
    h = bytearray(512)
    h[0:100] = _field(name_b, 100)
    h[100:108] = _octal(0o755 if typeflag == b"5" else 0o644, 8)
    h[108:116] = _octal(0, 8)
    h[116:124] = _octal(0, 8)
    h[124:136] = _octal(size, 12)
    h[136:148] = _octal(1700000000, 12)
    h[148:156] = b"        "  # checksum computed over spaces
    h[156:157] = typeflag
    h[157:257] = _field(link.encode(), 100)
    h[257:263] = b"ustar\0"
    h[263:265] = b"00"
    h[265:297] = _field(b"audit", 32)
    h[297:329] = _field(b"audit", 32)
    h[345:500] = _field(prefix, 155)
    h[148:156] = ("%06o\0 " % sum(h)).encode()
    return bytes(h)


def tar_bytes(entries: list[tuple]) -> bytes:
    """Serialize entries ``(name, typeflag[, body[, link]])`` to a TAR blob."""
    out = bytearray()
    for spec in entries:
        name, typeflag = spec[0], spec[1]
        body = spec[2] if len(spec) > 2 else b""
        link = spec[3] if len(spec) > 3 else ""
        if isinstance(body, str):
            body = body.encode()
        out += entry_header(name, typeflag, len(body), link)
        out += body
        out += b"\0" * ((-len(body)) % 512)
    out += b"\0" * 1024  # two-block end-of-archive marker
    return bytes(out)


def layer_b64(entries: list[tuple]) -> str:
    """Build one layer as base64(gzip(tar(entries)))."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes(entries))
    return base64.b64encode(buf.getvalue()).decode()


# Convenience constructors -------------------------------------------------

def d(name: str) -> tuple:
    """Directory entry."""
    return (name, b"5")


def f(name: str, body: bytes | str = b"") -> tuple:
    """Regular file entry."""
    return (name, b"0", body)


def ln(name: str, target: str) -> tuple:
    """Hard link entry."""
    return (name, b"1", b"", target)


def wh(dir_path: str, name: str) -> tuple:
    """Whiteout entry deleting ``name`` inside ``dir_path``."""
    base = f"{dir_path}/.wh.{name}" if dir_path else f".wh.{name}"
    return (base, b"0")


def opq(dir_path: str) -> tuple:
    """Opaque-marker entry for ``dir_path``."""
    base = f"{dir_path}/.wh..wh..opq" if dir_path else ".wh..wh..opq"
    return (base, b"0")
