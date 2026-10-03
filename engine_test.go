package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

// --- test helpers ---------------------------------------------------------

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

func dirEnt(name string) tarEntry        { return tarEntry{name: name, typ: tar.TypeDir} }
func fileEnt(name, body string) tarEntry { return tarEntry{name: name, typ: tar.TypeReg, body: body} }
func linkEnt(name, target string) tarEntry {
	return tarEntry{name: name, typ: tar.TypeLink, link: target}
}
func markerEnt(name string) tarEntry          { return tarEntry{name: name, typ: tar.TypeReg} }
func typedEnt(name string, typ byte) tarEntry { return tarEntry{name: name, typ: typ} }

func buildTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644}
		switch e.typ {
		case tar.TypeDir:
			hdr.Mode = 0o755
		case tar.TypeReg:
			hdr.Size = int64(len(e.body))
		case tar.TypeLink:
			hdr.Linkname = e.link
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}

func gzipB64(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func layer(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	return gzipB64(t, buildTar(t, entries...))
}

func mustAdjudicate(t *testing.T, layers ...string) *AuditResult {
	t.Helper()
	res, err := adjudicate("test", layers)
	if err != nil {
		t.Fatalf("adjudicate: %v", err)
	}
	return res
}

func mustFail(t *testing.T, wantSub string, layers ...string) {
	t.Helper()
	_, err := adjudicate("test", layers)
	if err == nil {
		t.Fatalf("expected failure containing %q, got nil", wantSub)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("error %q does not contain %q", err.Error(), wantSub)
	}
}

func pathMap(res *AuditResult) map[string]PathInfo {
	m := make(map[string]PathInfo, len(res.Paths))
	for _, p := range res.Paths {
		m[p.Path] = p
	}
	return m
}

func delMap(res *AuditResult) map[string]Deletion {
	m := make(map[string]Deletion, len(res.Deletions))
	for _, d := range res.Deletions {
		m[d.Path] = d
	}
	return m
}

func assertPath(t *testing.T, res *AuditResult, path, typ string, layer int) {
	t.Helper()
	p, ok := pathMap(res)[path]
	if !ok {
		t.Fatalf("path %s missing from final list %v", path, res.Paths)
	}
	if p.Type != typ || p.Layer != layer {
		t.Fatalf("path %s: got type=%s layer=%d, want type=%s layer=%d", path, p.Type, p.Layer, typ, layer)
	}
}

func assertNoPath(t *testing.T, res *AuditResult, path string) {
	t.Helper()
	if _, ok := pathMap(res)[path]; ok {
		t.Fatalf("path %s should not survive, final list %v", path, res.Paths)
	}
}

func assertDeletion(t *testing.T, res *AuditResult, path, typ string, layer, deletedBy int, reason string) {
	t.Helper()
	d, ok := delMap(res)[path]
	if !ok {
		t.Fatalf("deletion evidence for %s missing, got %v", path, res.Deletions)
	}
	if d.Type != typ || d.Layer != layer || d.DeletedBy != deletedBy || d.Reason != reason {
		t.Fatalf("deletion %s: got %+v, want type=%s layer=%d deletedBy=%d reason=%s",
			path, d, typ, layer, deletedBy, reason)
	}
}

// --- union merge ------------------------------------------------------------

func TestUnionMergesLayers(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, dirEnt("etc"), fileEnt("etc/a.conf", "1")),
		layer(t, fileEnt("etc/b.conf", "2")),
	)
	assertPath(t, res, "/etc", typeDir, 0)
	assertPath(t, res, "/etc/a.conf", typeFile, 0)
	assertPath(t, res, "/etc/b.conf", typeFile, 1)
	if len(res.Paths) != 3 {
		t.Fatalf("want 3 paths, got %v", res.Paths)
	}
	if len(res.Deletions) != 0 {
		t.Fatalf("want no deletions, got %v", res.Deletions)
	}
}

func TestDirMergeKeepsLowerSourceLayer(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, dirEnt("m")),
		layer(t, dirEnt("m"), fileEnt("m/f", "x")),
	)
	assertPath(t, res, "/m", typeDir, 0)
	assertPath(t, res, "/m/f", typeFile, 1)
	if len(res.Deletions) != 0 {
		t.Fatalf("dir merge must not record deletions, got %v", res.Deletions)
	}
}

// --- whiteout (.wh.<name>) --------------------------------------------------

func TestWhiteoutDeletesLowerFile(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, dirEnt("app"), fileEnt("app/old-cal.bin", "revoked"), fileEnt("app/keep.txt", "k")),
		layer(t, markerEnt("app/.wh.old-cal.bin")),
	)
	assertNoPath(t, res, "/app/old-cal.bin")
	assertPath(t, res, "/app", typeDir, 0)
	assertPath(t, res, "/app/keep.txt", typeFile, 0)
	assertDeletion(t, res, "/app/old-cal.bin", typeFile, 0, 1, reasonWhiteout)
	if len(res.Deletions) != 1 {
		t.Fatalf("want exactly 1 deletion, got %v", res.Deletions)
	}
}

func TestWhiteoutDeletesLowerDirRecursively(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t,
			dirEnt("d"), fileEnt("d/a", "1"),
			dirEnt("d/sub"), fileEnt("d/sub/b", "2"),
			fileEnt("top.txt", "t"),
		),
		layer(t, markerEnt(".wh.d")),
	)
	for _, p := range []string{"/d", "/d/a", "/d/sub", "/d/sub/b"} {
		assertNoPath(t, res, p)
	}
	assertPath(t, res, "/top.txt", typeFile, 0)
	assertDeletion(t, res, "/d", typeDir, 0, 1, reasonWhiteout)
	assertDeletion(t, res, "/d/a", typeFile, 0, 1, reasonWhiteout)
	assertDeletion(t, res, "/d/sub", typeDir, 0, 1, reasonWhiteout)
	assertDeletion(t, res, "/d/sub/b", typeFile, 0, 1, reasonWhiteout)
	if len(res.Deletions) != 4 {
		t.Fatalf("want 4 deletions, got %v", res.Deletions)
	}
}

func TestWhiteoutUnknownPathIsNoop(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("a", "1")),
		layer(t, markerEnt(".wh.missing")),
	)
	assertPath(t, res, "/a", typeFile, 0)
	if len(res.Deletions) != 0 {
		t.Fatalf("whiteout of unknown path must not record evidence, got %v", res.Deletions)
	}
}

func TestWhiteoutDoesNotResurfaceLowerContent(t *testing.T) {
	// layer 0 and 1 both provide /f; layer 2 whites it out: nothing may
	// resurface from layer 0.
	res := mustAdjudicate(t,
		layer(t, fileEnt("f", "v0")),
		layer(t, fileEnt("f", "v1")),
		layer(t, markerEnt(".wh.f")),
	)
	assertNoPath(t, res, "/f")
	assertDeletion(t, res, "/f", typeFile, 1, 2, reasonWhiteout)
}

func TestWhiteoutSameLayerCreateThenDelete(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("f", "x"), markerEnt(".wh.f")),
	)
	assertNoPath(t, res, "/f")
	assertDeletion(t, res, "/f", typeFile, 0, 0, reasonWhiteout)
}

func TestRecreateAfterWhiteout(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, dirEnt("r"), fileEnt("r/old", "o")),
		layer(t, markerEnt(".wh.r")),
		layer(t, dirEnt("r"), fileEnt("r/new", "n")),
	)
	assertPath(t, res, "/r", typeDir, 2)
	assertPath(t, res, "/r/new", typeFile, 2)
	assertNoPath(t, res, "/r/old")
	assertDeletion(t, res, "/r", typeDir, 0, 1, reasonWhiteout)
	assertDeletion(t, res, "/r/old", typeFile, 0, 1, reasonWhiteout)
}

// --- opaque (.wh..wh..opq) --------------------------------------------------

func TestOpaqueClearsLowerChildrenOnly(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t,
			dirEnt("data"),
			fileEnt("data/keep.txt", "k"),
			fileEnt("data/stale.txt", "s"),
		),
		layer(t,
			fileEnt("data/before.txt", "b"), // same-layer child before the marker survives
			markerEnt("data/.wh..wh..opq"),
			fileEnt("data/after.txt", "a"), // same-layer child after the marker survives
		),
		layer(t, fileEnt("data/top.txt", "t")),
	)
	assertPath(t, res, "/data", typeDir, 0)
	assertPath(t, res, "/data/before.txt", typeFile, 1)
	assertPath(t, res, "/data/after.txt", typeFile, 1)
	assertPath(t, res, "/data/top.txt", typeFile, 2)
	assertNoPath(t, res, "/data/keep.txt")
	assertNoPath(t, res, "/data/stale.txt")
	assertDeletion(t, res, "/data/keep.txt", typeFile, 0, 1, reasonOpaque)
	assertDeletion(t, res, "/data/stale.txt", typeFile, 0, 1, reasonOpaque)
	if len(res.Deletions) != 2 {
		t.Fatalf("want 2 deletions, got %v", res.Deletions)
	}
}

func TestOpaqueClearsNestedSubtrees(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t,
			dirEnt("d"), dirEnt("d/sub"),
			fileEnt("d/sub/deep.txt", "x"),
			fileEnt("d/top.txt", "y"),
		),
		layer(t, markerEnt("d/.wh..wh..opq")),
	)
	assertPath(t, res, "/d", typeDir, 0)
	assertNoPath(t, res, "/d/sub")
	assertNoPath(t, res, "/d/sub/deep.txt")
	assertNoPath(t, res, "/d/top.txt")
	assertDeletion(t, res, "/d/sub", typeDir, 0, 1, reasonOpaque)
	assertDeletion(t, res, "/d/sub/deep.txt", typeFile, 0, 1, reasonOpaque)
	assertDeletion(t, res, "/d/top.txt", typeFile, 0, 1, reasonOpaque)
}

func TestOpaqueAtRoot(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("a", "1"), dirEnt("b"), fileEnt("b/c", "2")),
		layer(t, markerEnt(".wh..wh..opq"), fileEnt("fresh", "f")),
	)
	assertNoPath(t, res, "/a")
	assertNoPath(t, res, "/b")
	assertNoPath(t, res, "/b/c")
	assertPath(t, res, "/fresh", typeFile, 1)
	assertDeletion(t, res, "/a", typeFile, 0, 1, reasonOpaque)
	assertDeletion(t, res, "/b", typeDir, 0, 1, reasonOpaque)
	assertDeletion(t, res, "/b/c", typeFile, 0, 1, reasonOpaque)
}

// --- replacement ------------------------------------------------------------

func TestFileReplacesDir(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, dirEnt("x"), fileEnt("x/inner", "i")),
		layer(t, fileEnt("x", "now-a-file")),
	)
	assertPath(t, res, "/x", typeFile, 1)
	assertNoPath(t, res, "/x/inner")
	assertDeletion(t, res, "/x", typeDir, 0, 1, reasonReplaced)
	assertDeletion(t, res, "/x/inner", typeFile, 0, 1, reasonReplaced)
}

func TestDirReplacesFile(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("y", "was-a-file")),
		layer(t, dirEnt("y"), fileEnt("y/kid", "k")),
	)
	assertPath(t, res, "/y", typeDir, 1)
	assertPath(t, res, "/y/kid", typeFile, 1)
	assertDeletion(t, res, "/y", typeFile, 0, 1, reasonReplaced)
	if len(res.Deletions) != 1 {
		t.Fatalf("want 1 deletion, got %v", res.Deletions)
	}
}

func TestFileOverwriteRecordsReplacement(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("c", "v1")),
		layer(t, fileEnt("c", "v2")),
	)
	assertPath(t, res, "/c", typeFile, 1)
	assertDeletion(t, res, "/c", typeFile, 0, 1, reasonReplaced)
}

// --- hard links ---------------------------------------------------------------

func TestHardLinkInLayer(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t,
			fileEnt("real.txt", "content"),
			linkEnt("hard1.txt", "real.txt"),
			linkEnt("hard2.txt", "hard1.txt"), // chain through another hard link
		),
	)
	assertPath(t, res, "/real.txt", typeFile, 0)
	assertPath(t, res, "/hard1.txt", typeFile, 0)
	assertPath(t, res, "/hard2.txt", typeFile, 0)
	if got := pathMap(res)["/hard1.txt"].Link; got != "/real.txt" {
		t.Fatalf("hard1 link target = %q, want /real.txt", got)
	}
	if got := pathMap(res)["/hard2.txt"].Link; got != "/hard1.txt" {
		t.Fatalf("hard2 link target = %q, want /hard1.txt", got)
	}
}

func TestHardLinkDanglingRejected(t *testing.T) {
	mustFail(t, "dangles", layer(t, linkEnt("h", "no-such-file")))
}

func TestHardLinkToDirRejected(t *testing.T) {
	mustFail(t, "dangles", layer(t, dirEnt("d"), linkEnt("h", "d")))
}

func TestHardLinkToLowerLayerRejected(t *testing.T) {
	// targets must resolve within the same layer
	mustFail(t, "dangles",
		layer(t, fileEnt("f", "x")),
		layer(t, linkEnt("h", "f")),
	)
}

func TestHardLinkToWhitedOutFileRejected(t *testing.T) {
	mustFail(t, "dangles",
		layer(t, fileEnt("f", "x"), markerEnt(".wh.f"), linkEnt("h", "f")),
	)
}

func TestHardLinkAbsoluteTargetRejected(t *testing.T) {
	mustFail(t, "absolute", layer(t, fileEnt("f", "x"), linkEnt("h", "/f")))
}

// --- entry validation ---------------------------------------------------------

func TestAbsolutePathRejected(t *testing.T) {
	mustFail(t, "absolute path", layer(t, fileEnt("/abs.txt", "x")))
}

func TestTraversalRejected(t *testing.T) {
	mustFail(t, "traversal", layer(t, fileEnt("../escape.txt", "x")))
	mustFail(t, "traversal", layer(t, fileEnt("a/../../escape.txt", "x")))
	mustFail(t, "traversal", layer(t, fileEnt("..", "x")))
}

func TestDuplicateEntryRejected(t *testing.T) {
	mustFail(t, "duplicate", layer(t, fileEnt("dup", "1"), fileEnt("dup", "2")))
	mustFail(t, "duplicate", layer(t, dirEnt("d"), dirEnt("d/"))) // same canonical path
}

func TestUnsupportedTypesRejected(t *testing.T) {
	mustFail(t, "unsupported type", layer(t, typedEnt("ln", tar.TypeSymlink)))
	mustFail(t, "unsupported type", layer(t, typedEnt("dev", tar.TypeChar)))
	mustFail(t, "unsupported type", layer(t, typedEnt("blk", tar.TypeBlock)))
	mustFail(t, "unsupported type", layer(t, typedEnt("fifo", tar.TypeFifo)))
}

func TestWhiteoutDirRejected(t *testing.T) {
	mustFail(t, "must be a regular file", layer(t, dirEnt("d/.wh.x")))
}

func TestWhiteoutEmptyTargetRejected(t *testing.T) {
	mustFail(t, "empty target", layer(t, markerEnt(".wh.")))
}

func TestParentIsFileConflictRejected(t *testing.T) {
	mustFail(t, "placed a file",
		layer(t, fileEnt("a", "x")),
		layer(t, fileEnt("a/b", "y")),
	)
}

func TestEmptyLayerIsValid(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t, fileEnt("a", "1")),
		layer(t), // only the end-of-archive marker
	)
	assertPath(t, res, "/a", typeFile, 0)
}

func TestLayerCountLimits(t *testing.T) {
	mustFail(t, "at least one layer")
	mustFail(t, "at most 6 layers",
		layer(t), layer(t), layer(t), layer(t), layer(t), layer(t), layer(t))
	res := mustAdjudicate(t,
		layer(t), layer(t), layer(t), layer(t), layer(t), layer(t))
	if res.Layers != 6 {
		t.Fatalf("want 6 layers, got %d", res.Layers)
	}
}

// --- framing validation -------------------------------------------------------

func TestInvalidBase64Rejected(t *testing.T) {
	mustFail(t, "invalid base64", "!!!not-base64!!!")
}

func TestEmptyPayloadRejected(t *testing.T) {
	mustFail(t, "empty payload", "")
}

func TestTruncatedGzipRejected(t *testing.T) {
	good := gzipB64(t, buildTar(t, fileEnt("a", "x")))
	raw, _ := base64.StdEncoding.DecodeString(good)
	truncated := base64.StdEncoding.EncodeToString(raw[:len(raw)/2])
	mustFail(t, "gzip", truncated)
}

func TestTrailingGarbageAfterGzipRejected(t *testing.T) {
	good := gzipB64(t, buildTar(t, fileEnt("a", "x")))
	raw, _ := base64.StdEncoding.DecodeString(good)
	withJunk := base64.StdEncoding.EncodeToString(append(raw, []byte("junk")...))
	mustFail(t, "unconsumed bytes", withJunk)
}

func TestMultiStreamGzipRejected(t *testing.T) {
	good := gzipB64(t, buildTar(t, fileEnt("a", "x")))
	raw, _ := base64.StdEncoding.DecodeString(good)
	double := base64.StdEncoding.EncodeToString(append(append([]byte{}, raw...), raw...))
	mustFail(t, "unconsumed bytes", double)
}

func TestBadTarChecksumRejected(t *testing.T) {
	raw := buildTar(t, fileEnt("a", "x"))
	raw[0]++ // corrupt the name field without fixing the checksum
	mustFail(t, "invalid tar header", gzipB64(t, raw))
}

func TestMisalignedTarRejected(t *testing.T) {
	raw := buildTar(t, fileEnt("a", "x"))
	mustFail(t, "not aligned", gzipB64(t, raw[:len(raw)-100]))
}

func TestMissingEndMarkerRejected(t *testing.T) {
	raw := buildTar(t, fileEnt("a", "x"))
	raw[len(raw)-1] = 1 // last block is no longer zero
	mustFail(t, "end-of-archive marker", gzipB64(t, raw))
}

func TestGarbageAfterEndMarkerRejected(t *testing.T) {
	raw := buildTar(t, fileEnt("a", "x"))
	var b bytes.Buffer
	b.Write(raw)
	b.Write(bytes.Repeat([]byte{1}, tarBlock)) // junk block after the zero blocks
	b.Write(make([]byte, 2*tarBlock))          // fresh marker so only the junk is caught
	mustFail(t, "non-zero data after the tar end-of-archive marker", gzipB64(t, b.Bytes()))
}

func TestGarbageInsteadOfTarRejected(t *testing.T) {
	junk := bytes.Repeat([]byte{7}, 4*tarBlock)
	mustFail(t, "end-of-archive marker", gzipB64(t, junk))
}

// --- full scenario (mirrors the HTTP smoke audit) ------------------------------

func TestFullWhiteoutScenario(t *testing.T) {
	res := mustAdjudicate(t,
		layer(t,
			dirEnt("app"),
			fileEnt("app/config.txt", "v1"),
			fileEnt("app/old-cal.bin", "revoked-calibration"),
			dirEnt("data"),
			fileEnt("data/keep.txt", "keep"),
			fileEnt("data/stale.txt", "stale"),
			dirEnt("rebuild"),
			fileEnt("rebuild/legacy.txt", "legacy"),
			fileEnt("shape", "file-in-lower-layer"),
			dirEnt("plug"),
			fileEnt("plug/x.txt", "x"),
			fileEnt("real.txt", "real-content"),
			linkEnt("real-hard.txt", "real.txt"),
		),
		layer(t,
			markerEnt("app/.wh.old-cal.bin"),
			markerEnt("data/.wh..wh..opq"),
			fileEnt("data/fresh.txt", "fresh"),
			fileEnt("app/config.txt", "v2"),
			markerEnt(".wh.rebuild"),
		),
		layer(t,
			dirEnt("rebuild"),
			fileEnt("rebuild/new.txt", "new"),
			dirEnt("shape"),
			fileEnt("shape/inner.txt", "inner"),
			fileEnt("plug", "now-a-file"),
		),
	)

	wantPaths := []struct {
		path, typ string
		layer     int
	}{
		{"/app", typeDir, 0},
		{"/app/config.txt", typeFile, 1},
		{"/data", typeDir, 0},
		{"/data/fresh.txt", typeFile, 1},
		{"/plug", typeFile, 2},
		{"/real-hard.txt", typeFile, 0},
		{"/real.txt", typeFile, 0},
		{"/rebuild", typeDir, 2},
		{"/rebuild/new.txt", typeFile, 2},
		{"/shape", typeDir, 2},
		{"/shape/inner.txt", typeFile, 2},
	}
	if len(res.Paths) != len(wantPaths) {
		t.Fatalf("want %d paths, got %v", len(wantPaths), res.Paths)
	}
	for _, w := range wantPaths {
		assertPath(t, res, w.path, w.typ, w.layer)
	}
	if got := pathMap(res)["/real-hard.txt"].Link; got != "/real.txt" {
		t.Fatalf("hard link target = %q, want /real.txt", got)
	}

	wantDeletions := []struct {
		path, typ string
		layer     int
		deletedBy int
		reason    string
	}{
		{"/app/config.txt", typeFile, 0, 1, reasonReplaced},
		{"/app/old-cal.bin", typeFile, 0, 1, reasonWhiteout},
		{"/data/keep.txt", typeFile, 0, 1, reasonOpaque},
		{"/data/stale.txt", typeFile, 0, 1, reasonOpaque},
		{"/plug", typeDir, 0, 2, reasonReplaced},
		{"/plug/x.txt", typeFile, 0, 2, reasonReplaced},
		{"/rebuild", typeDir, 0, 1, reasonWhiteout},
		{"/rebuild/legacy.txt", typeFile, 0, 1, reasonWhiteout},
		{"/shape", typeFile, 0, 2, reasonReplaced},
	}
	if len(res.Deletions) != len(wantDeletions) {
		t.Fatalf("want %d deletions, got %v", len(wantDeletions), res.Deletions)
	}
	for _, w := range wantDeletions {
		assertDeletion(t, res, w.path, w.typ, w.layer, w.deletedBy, w.reason)
	}
}
