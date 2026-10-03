// engine.go implements the OCI whiteout union adjudication engine: it
// validates gzip+tar layer payloads, stacks them bottom-to-top into a union
// file tree, and produces the frozen final path list plus deletion evidence.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	maxLayers       = 6
	tarBlock        = 512
	whiteoutPrefix  = ".wh."
	opaqueMarker    = ".wh..wh..opq"
	maxLayerBytes   = 16 << 20  // 16 MiB compressed per layer
	maxDecompressed = 128 << 20 // 128 MiB decompressed per layer
)

// Node types recorded in the union tree.
const (
	typeDir  = "dir"
	typeFile = "file"
)

// Deletion reasons recorded as evidence.
const (
	reasonWhiteout = "whiteout" // explicit .wh.<name> marker
	reasonOpaque   = "opaque"   // cleared by a .wh..wh..opq marker
	reasonReplaced = "replaced" // shadowed by a same-path entry of a newer layer
)

// adjudicationError marks every failure produced while validating or
// applying layers; the HTTP layer maps it to 422 Unprocessable Entity.
type adjudicationError struct{ msg string }

func (e *adjudicationError) Error() string { return e.msg }

func adjErr(format string, args ...any) error {
	return &adjudicationError{msg: fmt.Sprintf(format, args...)}
}

// node is one entry of the union file tree.
type node struct {
	typ      string           // typeDir or typeFile
	layer    int              // layer that introduced this path (-1 for the root)
	link     string           // hard link target (canonical, relative) if any
	children map[string]*node // nil for files
}

func newDirNode(layer int) *node {
	return &node{typ: typeDir, layer: layer, children: make(map[string]*node)}
}

// PathInfo describes one surviving path of the frozen union view.
type PathInfo struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Layer int    `json:"layer"`
	Link  string `json:"link,omitempty"`
}

// Deletion is one piece of evidence that lower-layer content was removed.
type Deletion struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Layer     int    `json:"layer"`
	DeletedBy int    `json:"deletedBy"`
	Reason    string `json:"reason"`
}

// AuditResult is the frozen adjudication stored under an audit id.
type AuditResult struct {
	ID        string     `json:"id"`
	Layers    int        `json:"layers"`
	Paths     []PathInfo `json:"paths"`
	Deletions []Deletion `json:"deletions"`
}

// layerEntry is one validated tar member of a single layer.
type layerEntry struct {
	path   string // canonical relative path, e.g. "a/b/c"
	typ    string // typeDir or typeFile
	link   string // hard link target if this entry is a hard link
	white  bool   // .wh.<name> marker: delete the sibling path
	opaque bool   // .wh..wh..opq marker: clear lower-layer children of the directory
}

// adjudicate validates every layer and stacks them bottom-to-top. Any
// failure aborts the whole audit: callers must store nothing on error, so a
// failed layer never leaves a partial adjudication behind.
func adjudicate(id string, b64Layers []string) (*AuditResult, error) {
	if len(b64Layers) == 0 {
		return nil, adjErr("at least one layer is required")
	}
	if len(b64Layers) > maxLayers {
		return nil, adjErr("at most %d layers are allowed, got %d", maxLayers, len(b64Layers))
	}
	layers := make([][]layerEntry, len(b64Layers))
	for i, b64 := range b64Layers {
		entries, err := parseLayer(b64, i)
		if err != nil {
			return nil, err
		}
		layers[i] = entries
	}
	root := newDirNode(-1)
	var deletions []Deletion
	for i, entries := range layers {
		if err := applyLayer(root, entries, i, &deletions); err != nil {
			return nil, adjErr("layer %d: %v", i, err)
		}
	}
	sort.Slice(deletions, func(a, b int) bool {
		if deletions[a].Path != deletions[b].Path {
			return deletions[a].Path < deletions[b].Path
		}
		return deletions[a].DeletedBy < deletions[b].DeletedBy
	})
	res := &AuditResult{
		ID:        id,
		Layers:    len(b64Layers),
		Paths:     listPaths(root),
		Deletions: deletions,
	}
	if res.Paths == nil {
		res.Paths = []PathInfo{}
	}
	if res.Deletions == nil {
		res.Deletions = []Deletion{}
	}
	return res, nil
}

// parseLayer decodes one base64+gzip+tar payload and validates framing,
// checksums, alignment, gzip consumption and every entry.
func parseLayer(b64 string, idx int) ([]layerEntry, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, adjErr("layer %d: invalid base64: %v", idx, err)
	}
	if len(raw) == 0 {
		return nil, adjErr("layer %d: empty payload", idx)
	}
	if len(raw) > maxLayerBytes {
		return nil, adjErr("layer %d: compressed payload exceeds %d bytes", idx, maxLayerBytes)
	}

	// bytes.Reader implements flate.Reader, so the gzip reader consumes
	// exactly the bytes of one stream and br.Len() exposes trailing junk.
	br := bytes.NewReader(raw)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, adjErr("layer %d: invalid gzip stream: %v", idx, err)
	}
	gz.Multistream(false)
	data, err := io.ReadAll(io.LimitReader(gz, maxDecompressed+1))
	if err != nil {
		return nil, adjErr("layer %d: gzip stream error: %v", idx, err)
	}
	if err := gz.Close(); err != nil {
		return nil, adjErr("layer %d: gzip checksum error: %v", idx, err)
	}
	if len(data) > maxDecompressed {
		return nil, adjErr("layer %d: decompressed payload exceeds %d bytes", idx, maxDecompressed)
	}
	if br.Len() != 0 {
		return nil, adjErr("layer %d: %d unconsumed bytes after the gzip stream", idx, br.Len())
	}

	if len(data) == 0 || len(data)%tarBlock != 0 {
		return nil, adjErr("layer %d: tar payload of %d bytes is not aligned to %d-byte blocks", idx, len(data), tarBlock)
	}
	if len(data) < 2*tarBlock || !allZero(data[len(data)-2*tarBlock:]) {
		return nil, adjErr("layer %d: missing tar end-of-archive marker (two zero blocks)", idx)
	}

	tarBytes := bytes.NewReader(data)
	tr := tar.NewReader(tarBytes)
	var entries []layerEntry
	seen := make(map[string]bool)
	liveFiles := make(map[string]bool) // same-layer regular files a hard link may target
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, adjErr("layer %d: invalid tar header: %v", idx, err)
		}
		rel, err := cleanTarPath(hdr.Name)
		if err != nil {
			return nil, adjErr("layer %d: %v", idx, err)
		}
		if seen[rel] {
			return nil, adjErr("layer %d: duplicate entry %q", idx, rel)
		}
		seen[rel] = true

		base := path.Base(rel)
		isMarker := strings.HasPrefix(base, whiteoutPrefix)
		isOpaque := base == opaqueMarker

		switch hdr.Typeflag {
		case tar.TypeDir:
			if isMarker {
				return nil, adjErr("layer %d: whiteout marker %q must be a regular file, not a directory", idx, rel)
			}
			entries = append(entries, layerEntry{path: rel, typ: typeDir})
		case tar.TypeReg, tar.TypeRegA:
			switch {
			case isOpaque:
				entries = append(entries, layerEntry{path: rel, typ: typeFile, opaque: true})
			case isMarker:
				target := whiteoutTarget(rel)
				if target == "" {
					return nil, adjErr("layer %d: whiteout marker %q has an empty target name", idx, rel)
				}
				entries = append(entries, layerEntry{path: rel, typ: typeFile, white: true})
				// A whiteout earlier in the same layer revokes same-layer
				// files at or below its target, so a later hard link can no
				// longer resolve to them.
				for f := range liveFiles {
					if f == target || strings.HasPrefix(f, target+"/") {
						delete(liveFiles, f)
					}
				}
			default:
				entries = append(entries, layerEntry{path: rel, typ: typeFile})
				liveFiles[rel] = true
			}
		case tar.TypeLink:
			if isMarker {
				return nil, adjErr("layer %d: whiteout marker %q must be a regular file, not a hard link", idx, rel)
			}
			target, err := cleanTarPath(hdr.Linkname)
			if err != nil {
				return nil, adjErr("layer %d: hard link %q has invalid target: %v", idx, rel, err)
			}
			if !liveFiles[target] {
				return nil, adjErr("layer %d: hard link %q dangles: target %q is not a regular file earlier in the same layer", idx, rel, target)
			}
			entries = append(entries, layerEntry{path: rel, typ: typeFile, link: target})
			liveFiles[rel] = true
		default:
			return nil, adjErr("layer %d: entry %q has unsupported type %d: only directories, regular files and hard links are accepted", idx, rel, hdr.Typeflag)
		}
	}
	if rest := data[len(data)-tarBytes.Len():]; !allZero(rest) {
		return nil, adjErr("layer %d: non-zero data after the tar end-of-archive marker", idx)
	}
	return entries, nil
}

// cleanTarPath canonicalizes a tar member name and rejects absolute paths,
// traversal and the archive root itself.
func cleanTarPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute path %q is not allowed", name)
	}
	if strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("path %q contains a NUL byte", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal %q is not allowed", name)
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "", fmt.Errorf("path %q refers to the archive root", name)
	}
	return cleaned, nil
}

// whiteoutTarget maps "dir/.wh.<name>" to its sibling target "dir/<name>".
func whiteoutTarget(rel string) string {
	dir, base := path.Split(rel)
	name := strings.TrimPrefix(base, whiteoutPrefix)
	if name == "" {
		return ""
	}
	return dir + name
}

func parentDir(rel string) string {
	if d := path.Dir(rel); d != "." {
		return d
	}
	return ""
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]*node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lookup returns the directory node at dir ("" is the root), or nil.
func (n *node) lookup(dir string) *node {
	cur := n
	if dir == "" {
		return cur
	}
	for _, part := range strings.Split(dir, "/") {
		c, ok := cur.children[part]
		if !ok || c.typ != typeDir {
			return nil
		}
		cur = c
	}
	return cur
}

// ensureDir returns the directory node at dir, creating missing directories
// owned by layer idx. It fails when a regular file blocks the path.
func (n *node) ensureDir(dir string, idx int) (*node, error) {
	cur := n
	if dir == "" {
		return cur, nil
	}
	for _, part := range strings.Split(dir, "/") {
		c, ok := cur.children[part]
		if !ok {
			c = newDirNode(idx)
			cur.children[part] = c
		} else if c.typ != typeDir {
			return nil, adjErr("path under %q requires a directory, but layer %d placed a file at %q", dir, c.layer, part)
		}
		cur = c
	}
	return cur, nil
}

// applyLayer applies one validated layer to the union tree in stream order.
func applyLayer(root *node, entries []layerEntry, idx int, ev *[]Deletion) error {
	for _, e := range entries {
		switch {
		case e.opaque:
			// .wh..wh..opq clears lower-layer children of the directory;
			// entries from the same layer are kept.
			dir := parentDir(e.path)
			n, err := root.ensureDir(dir, idx)
			if err != nil {
				return err
			}
			for _, name := range sortedKeys(n.children) {
				c := n.children[name]
				if c.layer < idx {
					recordDeletion(joinAbs(dir, name), c, idx, reasonOpaque, ev)
					delete(n.children, name)
				}
			}
		case e.white:
			// .wh.<name> removes the sibling path entirely; lower-layer
			// content at that path does not resurface in later layers.
			target := whiteoutTarget(e.path)
			parent := root.lookup(parentDir(target))
			if parent == nil {
				continue // nothing to revoke
			}
			name := path.Base(target)
			c, ok := parent.children[name]
			if !ok {
				continue
			}
			recordDeletion("/"+target, c, idx, reasonWhiteout, ev)
			delete(parent.children, name)
		default:
			parent, err := root.ensureDir(parentDir(e.path), idx)
			if err != nil {
				return err
			}
			name := path.Base(e.path)
			if old, ok := parent.children[name]; ok {
				if e.typ == typeDir && old.typ == typeDir {
					continue // directories merge; keep the lower source layer
				}
				recordDeletion("/"+e.path, old, idx, reasonReplaced, ev)
				delete(parent.children, name)
			}
			fresh := &node{typ: e.typ, layer: idx, link: e.link}
			if e.typ == typeDir {
				fresh.children = make(map[string]*node)
			}
			parent.children[name] = fresh
		}
	}
	return nil
}

// recordDeletion appends evidence for a removed node and its whole subtree.
func recordDeletion(absPath string, n *node, by int, reason string, ev *[]Deletion) {
	*ev = append(*ev, Deletion{Path: absPath, Type: n.typ, Layer: n.layer, DeletedBy: by, Reason: reason})
	for _, name := range sortedKeys(n.children) {
		recordDeletion(absPath+"/"+name, n.children[name], by, reason, ev)
	}
}

func joinAbs(dir, name string) string {
	if dir == "" {
		return "/" + name
	}
	return "/" + dir + "/" + name
}

// listPaths flattens the union tree into the sorted final path list.
func listPaths(root *node) []PathInfo {
	var out []PathInfo
	var walk func(n *node, prefix string)
	walk = func(n *node, prefix string) {
		for _, name := range sortedKeys(n.children) {
			c := n.children[name]
			p := prefix + "/" + name
			pi := PathInfo{Path: p, Type: c.typ, Layer: c.layer}
			if c.link != "" {
				pi.Link = "/" + c.link
			}
			out = append(out, pi)
			if c.typ == typeDir {
				walk(c, p)
			}
		}
	}
	walk(root, "")
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
