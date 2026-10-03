"""Strict TAR / gzip layer validation.

Each submitted layer must be exactly one gzip member that decompresses to
exactly one well-formed TAR archive:

* 512-byte block alignment, verified header checksums (ustar/POSIX or GNU
  magic), octal numeric fields (base-256 encodings are rejected);
* file data padded with zero bytes up to the 512-byte boundary;
* a two-block zero end-of-archive marker, after which only zero padding may
  follow, and no bytes may remain after the gzip member itself;
* only directories, regular files and hard links are accepted (symlinks,
  devices, FIFOs, PAX/GNU extension headers, ... are rejected);
* paths must be relative and canonical: no absolute paths, no ``..``, ``.``
  or empty components, no trailing slash on non-directories.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

BLOCK = 512
MAX_ENTRIES = 4096
MAX_DECOMPRESSED = 64 * 1024 * 1024
MAX_FILE_SIZE = 32 * 1024 * 1024

TYPE_FILE = "file"
TYPE_DIR = "dir"
TYPE_LINK = "link"

_ZERO_BLOCK = bytes(BLOCK)
_USTAR_MAGICS = (b"ustar\0", b"ustar ")  # POSIX ustar, old GNU


class TarError(ValueError):
    """Raised when a layer fails strict TAR/gzip validation."""


@dataclass(frozen=True)
class Entry:
    """One validated TAR member with a canonical relative path."""

    path: str
    type: str  # TYPE_FILE | TYPE_DIR | TYPE_LINK
    size: int = 0
    link: str | None = None  # canonical hard-link target


def gunzip_strict(data: bytes, limit: int = MAX_DECOMPRESSED) -> bytes:
    """Decompress exactly one gzip member, requiring full consumption.

    The gzip CRC32/ISIZE trailer is verified by zlib; trailing bytes after
    the member (including a second member) are rejected.
    """
    dobj = zlib.decompressobj(31)  # 15 + 16: gzip container, verifies CRC32
    out = bytearray()
    pos = 0
    buf = b""
    try:
        while not dobj.eof:
            if not buf:
                if pos >= len(data):
                    raise TarError("gzip stream truncated before end of member")
                buf = data[pos:pos + 65536]
                pos += len(buf)
            out += dobj.decompress(buf, limit + 1 - len(out))
            buf = dobj.unconsumed_tail
            if len(out) > limit:
                raise TarError("decompressed layer exceeds size limit")
    except zlib.error as exc:
        raise TarError(f"invalid gzip stream: {exc}") from exc
    trailing = dobj.unused_data + buf + data[pos:]
    if trailing:
        raise TarError("trailing data after gzip stream")
    return bytes(out)


def canonical_path(name: str, *, is_dir: bool) -> str:
    """Validate and canonicalize a TAR path; reject absolute/traversal."""
    if is_dir:
        name = name.rstrip("/")
    if not name:
        raise TarError("empty path in archive")
    if name.startswith("/"):
        raise TarError(f"absolute path rejected: {name!r}")
    parts = name.split("/")
    for part in parts:
        if part in ("", "."):
            raise TarError(f"non-canonical path rejected: {name!r}")
        if part == "..":
            raise TarError(f"path traversal rejected: {name!r}")
    return "/".join(parts)


def _cstring(field: bytes) -> str:
    raw = field.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TarError("non-UTF-8 name in header") from exc


def _octal(field: bytes, what: str) -> int:
    if field and field[0] & 0x80:
        raise TarError(f"base-256 encoded {what} field rejected")
    digits = field.strip(b" \0")
    if not digits:
        raise TarError(f"empty {what} field in header")
    if any(c < 0x30 or c > 0x37 for c in digits):
        raise TarError(f"invalid octal {what} field in header")
    return int(digits, 8)


def _parse_header(blk: bytes) -> Entry:
    stored = _octal(blk[148:156], "checksum")
    computed = sum(blk[:148]) + 8 * 0x20 + sum(blk[156:])
    if stored != computed:
        raise TarError("header checksum mismatch")
    if blk[257:263] not in _USTAR_MAGICS:
        raise TarError("unsupported tar magic (not ustar)")
    # Numeric fields must be well-formed octal even if we do not use them.
    _octal(blk[100:108], "mode")
    _octal(blk[108:116], "uid")
    _octal(blk[116:124], "gid")
    _octal(blk[136:148], "mtime")
    size = _octal(blk[124:136], "size")

    name = _cstring(blk[0:100])
    prefix = _cstring(blk[345:500])
    if prefix:
        name = prefix + "/" + name

    typeflag = blk[156:157]
    if typeflag in (b"0", b"\0"):
        if size > MAX_FILE_SIZE:
            raise TarError("regular file exceeds size limit")
        return Entry(canonical_path(name, is_dir=False), TYPE_FILE, size)
    if typeflag == b"5":
        if size != 0:
            raise TarError("directory entry with non-zero size")
        return Entry(canonical_path(name, is_dir=True), TYPE_DIR)
    if typeflag == b"1":
        if size != 0:
            raise TarError("hard link entry with non-zero size")
        target = _cstring(blk[157:257])
        if not target:
            raise TarError("hard link with empty target")
        return Entry(
            canonical_path(name, is_dir=False),
            TYPE_LINK,
            0,
            canonical_path(target, is_dir=False),
        )
    raise TarError(f"unsupported entry type {typeflag!r} "
                   "(only dirs, regular files, hard links allowed)")


def parse_tar(raw: bytes) -> list[Entry]:
    """Parse a fully decompressed TAR archive with strict boundary checks."""
    if len(raw) % BLOCK != 0:
        raise TarError("tar archive size is not a multiple of 512")
    entries: list[Entry] = []
    off = 0
    total = len(raw)
    while True:
        if off + BLOCK > total:
            raise TarError("missing end-of-archive marker (two zero blocks)")
        blk = raw[off:off + BLOCK]
        off += BLOCK
        if blk == _ZERO_BLOCK:
            if off + BLOCK > total or raw[off:off + BLOCK] != _ZERO_BLOCK:
                raise TarError("truncated end-of-archive marker")
            off += BLOCK
            if any(raw[off:]):
                raise TarError("non-zero data after end-of-archive marker")
            break
        entry = _parse_header(blk)
        span = (entry.size + BLOCK - 1) // BLOCK * BLOCK
        if off + span > total:
            raise TarError(f"truncated file data for {entry.path!r}")
        if any(raw[off + entry.size:off + span]):
            raise TarError(f"non-zero padding after file data for {entry.path!r}")
        off += span
        entries.append(entry)
        if len(entries) > MAX_ENTRIES:
            raise TarError("too many entries in layer")
    return entries


def parse_layer(gzdata: bytes) -> list[Entry]:
    """Validate one gzip-compressed TAR layer end to end."""
    return parse_tar(gunzip_strict(gzdata))
