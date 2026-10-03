"""Strict TAR/gzip validation tests."""

import base64
import gzip
import io
import unittest

from app import tarparse
from app.tarbuild import d, f, layer_b64, ln, tar_bytes
from app.tarparse import TarError


def decode(layer):
    return tarparse.parse_layer(base64.b64decode(layer))


def corrupt_gzip(layer, mutate):
    raw = bytearray(base64.b64decode(layer))
    mutate(raw)
    return bytes(raw)


class ValidLayerTests(unittest.TestCase):
    def test_roundtrip(self):
        entries = decode(layer_b64([
            d("a"), f("a/b.txt", "hello"), ln("a/c.txt", "a/b.txt"),
        ]))
        self.assertEqual([e.path for e in entries],
                         ["a", "a/b.txt", "a/c.txt"])
        self.assertEqual([e.type for e in entries],
                         [tarparse.TYPE_DIR, tarparse.TYPE_FILE, tarparse.TYPE_LINK])
        self.assertEqual(entries[1].size, 5)
        self.assertEqual(entries[2].link, "a/b.txt")

    def test_empty_archive_is_allowed(self):
        self.assertEqual(decode(layer_b64([])), [])

    def test_long_name_via_ustar_prefix(self):
        name = "d" * 90 + "/" + "n" * 90 + "/leaf.txt"  # 189 chars, splits 90/99
        entries = decode(layer_b64([f(name, "x")]))
        self.assertEqual(entries[0].path, name)

    def test_directory_trailing_slash_stripped(self):
        entries = decode(layer_b64([("a/b/", b"5")]))
        self.assertEqual(entries[0].path, "a/b")


class GzipBoundaryTests(unittest.TestCase):
    def test_trailing_garbage_after_gzip_member_rejected(self):
        raw = base64.b64decode(layer_b64([f("a", "x")])) + b"junk"
        with self.assertRaisesRegex(TarError, "trailing data"):
            tarparse.parse_layer(raw)

    def test_second_gzip_member_rejected(self):
        blob = base64.b64decode(layer_b64([f("a", "x")]))
        with self.assertRaisesRegex(TarError, "trailing data"):
            tarparse.parse_layer(blob + blob)

    def test_not_gzip_rejected(self):
        with self.assertRaises(TarError):
            tarparse.parse_layer(b"this is not gzip data at all........")

    def test_truncated_gzip_rejected(self):
        raw = base64.b64decode(layer_b64([f("a", "x" * 100)]))
        with self.assertRaises(TarError):
            tarparse.parse_layer(raw[:len(raw) // 2])

    def test_bad_gzip_crc_rejected(self):
        raw = corrupt_gzip(layer_b64([f("a", "x")]),
                           lambda b: b.__setitem__(-5, b[-5] ^ 0xFF))
        with self.assertRaises(TarError):
            tarparse.parse_layer(raw)

    def test_decompressed_size_not_multiple_of_512(self):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(b"\0" * 1000)  # not a multiple of 512
        with self.assertRaisesRegex(TarError, "multiple of 512"):
            tarparse.parse_layer(buf.getvalue())


class TarBoundaryTests(unittest.TestCase):
    def parse_raw(self, raw_tar):
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(raw_tar)
        return tarparse.parse_layer(buf.getvalue())

    def test_missing_end_marker_rejected(self):
        raw = tar_bytes([f("a", "x")])[:-1024]
        with self.assertRaisesRegex(TarError, "end-of-archive"):
            self.parse_raw(raw)

    def test_single_zero_block_rejected(self):
        raw = tar_bytes([f("a", "x")])[:-512]
        with self.assertRaisesRegex(TarError, "end-of-archive"):
            self.parse_raw(raw)

    def test_garbage_after_end_marker_rejected(self):
        raw = tar_bytes([f("a", "x")]) + bytes(512)
        raw = raw[:-512] + b"x" + bytes(511)  # non-zero block after marker
        with self.assertRaisesRegex(TarError, "after end-of-archive"):
            self.parse_raw(raw)

    def test_extra_zero_padding_after_marker_allowed(self):
        raw = tar_bytes([f("a", "x")]) + bytes(512 * 3)
        entries = self.parse_raw(raw)
        self.assertEqual([e.path for e in entries], ["a"])

    def test_truncated_file_data_rejected(self):
        raw = tar_bytes([f("a", "x" * 600)])[:-1024 - 512]
        with self.assertRaisesRegex(TarError, "truncated file data"):
            self.parse_raw(raw)

    def test_bad_checksum_rejected(self):
        raw = bytearray(tar_bytes([f("a", "x")]))
        raw[0] = ord("Z")  # rename without fixing the checksum
        with self.assertRaisesRegex(TarError, "checksum"):
            self.parse_raw(bytes(raw))

    def test_fixed_checksum_with_new_name_accepted(self):
        # Recomputing the checksum must make the header valid again.
        from app.tarbuild import entry_header
        hdr = bytearray(entry_header("good.txt", b"0", 0))
        hdr[0:8] = b"evil.txt"
        hdr[148:156] = b"        "
        hdr[148:156] = ("%06o\0 " % sum(hdr)).encode()
        entries = self.parse_raw(bytes(hdr) + bytes(1024))
        self.assertEqual(entries[0].path, "evil.txt")

    def test_non_zero_padding_rejected(self):
        raw = bytearray(tar_bytes([f("a", "x")]))
        raw[512 + 1] = 1  # padding byte of the 1-byte file
        with self.assertRaisesRegex(TarError, "padding"):
            self.parse_raw(bytes(raw))

    def test_bad_magic_rejected(self):
        raw = bytearray(tar_bytes([f("a", "x")]))
        raw[257:263] = b"notust"
        hdr = bytearray(raw[:512])
        hdr[148:156] = b"        "
        hdr[148:156] = ("%06o\0 " % sum(hdr)).encode()
        raw[:512] = hdr
        with self.assertRaisesRegex(TarError, "magic"):
            self.parse_raw(bytes(raw))


class EntryTypeTests(unittest.TestCase):
    def parse_entries(self, entries):
        return decode(layer_b64(entries))

    def test_symlink_rejected(self):
        with self.assertRaisesRegex(TarError, "unsupported entry type"):
            self.parse_entries([("a", b"2", b"", "target")])

    def test_pax_header_rejected(self):
        with self.assertRaisesRegex(TarError, "unsupported entry type"):
            self.parse_entries([("PaxHeaders.0/x", b"x", b"30 mtime=1\n")])

    def test_gnu_longname_rejected(self):
        with self.assertRaisesRegex(TarError, "unsupported entry type"):
            self.parse_entries([("././@LongLink", b"L", b"name\0")])

    def test_device_rejected(self):
        with self.assertRaisesRegex(TarError, "unsupported entry type"):
            self.parse_entries([("dev/null", b"3")])

    def test_dir_with_size_rejected(self):
        with self.assertRaisesRegex(TarError, "non-zero size"):
            self.parse_entries([("a", b"5", b"x")])

    def test_hardlink_with_empty_target_rejected(self):
        with self.assertRaisesRegex(TarError, "empty target"):
            self.parse_entries([("a", b"1")])


class PathValidationTests(unittest.TestCase):
    def assert_rejected(self, name, needle):
        with self.assertRaisesRegex(TarError, needle):
            decode(layer_b64([f(name, "x")]))

    def test_absolute_path_rejected(self):
        self.assert_rejected("/etc/passwd", "absolute")

    def test_dotdot_rejected(self):
        self.assert_rejected("../escape", "traversal")

    def test_embedded_dotdot_rejected(self):
        self.assert_rejected("a/../../escape", "traversal")

    def test_dot_component_rejected(self):
        self.assert_rejected("./a", "non-canonical")

    def test_double_slash_rejected(self):
        self.assert_rejected("a//b", "non-canonical")

    def test_trailing_slash_on_file_rejected(self):
        self.assert_rejected("a/", "non-canonical")

    def test_empty_name_rejected(self):
        self.assert_rejected("", "empty path")

    def test_absolute_hardlink_target_rejected(self):
        with self.assertRaisesRegex(TarError, "absolute"):
            decode(layer_b64([ln("a", "/etc/passwd")]))

    def test_traversal_hardlink_target_rejected(self):
        with self.assertRaisesRegex(TarError, "traversal"):
            decode(layer_b64([ln("a", "../escape")]))


if __name__ == "__main__":
    unittest.main()
