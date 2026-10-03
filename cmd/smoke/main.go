// Command smoke is the HTTP smoke stage of the verify container. It submits
// an audit whose layers exercise opaque markers, whiteouts, replacement and
// re-creation, reads the frozen result back, and checks it path by path. It
// also probes the negative paths (frozen ids, rejected layers, atomicity).
// Exit code is 0 only when every check passes.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"time"
)

type pathInfo struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Layer int    `json:"layer"`
	Link  string `json:"link,omitempty"`
}

type deletion struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Layer     int    `json:"layer"`
	DeletedBy int    `json:"deletedBy"`
	Reason    string `json:"reason"`
}

type auditResult struct {
	ID        string     `json:"id"`
	Layers    int        `json:"layers"`
	Paths     []pathInfo `json:"paths"`
	Deletions []deletion `json:"deletions"`
}

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

func main() {
	base := os.Getenv("AUDIT_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	if err := run(base); err != nil {
		fmt.Fprintf(os.Stderr, "[smoke] FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[smoke] OK: all HTTP smoke checks passed")
}

func run(base string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	if err := waitForHealth(client, base); err != nil {
		return err
	}
	fmt.Println("[smoke] service is healthy")

	id := fmt.Sprintf("smoke-%d", time.Now().UnixNano())
	layers := []string{layer0(), layer1(), layer2()}

	created, code, err := postAudit(client, base, id, layers)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return fmt.Errorf("POST /audits: got status %d, want 201", code)
	}
	fmt.Println("[smoke] audit with opaque + rebuild paths accepted (201)")

	fetched, code, err := getAudit(client, base, id)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("GET /audits/%s: got status %d, want 200", id, code)
	}
	if !reflect.DeepEqual(created, fetched) {
		return fmt.Errorf("frozen result changed between POST and GET:\nPOST: %+v\nGET:  %+v", created, fetched)
	}
	if fetched.ID != id || fetched.Layers != 3 {
		return fmt.Errorf("unexpected audit header: id=%q layers=%d", fetched.ID, fetched.Layers)
	}
	if err := expectPaths(fetched); err != nil {
		return err
	}
	if err := expectDeletions(fetched); err != nil {
		return err
	}
	fmt.Println("[smoke] frozen union view matches expected whiteout adjudication")

	if code, _ := postAuditStatus(client, base, id, layers); code != http.StatusConflict {
		return fmt.Errorf("replayed POST /audits: got status %d, want 409 (results are frozen)", code)
	}
	fmt.Println("[smoke] replayed submission rejected (409, results frozen)")

	badID := id + "-bad"
	bad := layerFromEntries(tarEntry{name: "../escape.txt", typ: tar.TypeReg, body: "x"})
	if code, _ := postAuditStatus(client, base, badID, []string{bad}); code != http.StatusUnprocessableEntity {
		return fmt.Errorf("POST traversal layer: got status %d, want 422", code)
	}
	if _, code, _ := getAudit(client, base, badID); code != http.StatusNotFound {
		return fmt.Errorf("GET rejected audit: got status %d, want 404 (no partial adjudication)", code)
	}
	fmt.Println("[smoke] invalid layer rejected (422) and left no partial adjudication (404)")

	if _, code, _ := getAudit(client, base, "smoke-missing"); code != http.StatusNotFound {
		return fmt.Errorf("GET unknown audit: got status %d, want 404", code)
	}
	fmt.Println("[smoke] unknown audit lookup rejected (404)")
	return nil
}

// --- expected adjudication ----------------------------------------------------

func expectPaths(res *auditResult) error {
	want := map[string]pathInfo{
		"/app":             {Path: "/app", Type: "dir", Layer: 0},
		"/app/config.txt":  {Path: "/app/config.txt", Type: "file", Layer: 1},
		"/data":            {Path: "/data", Type: "dir", Layer: 0},
		"/data/fresh.txt":  {Path: "/data/fresh.txt", Type: "file", Layer: 1},
		"/plug":            {Path: "/plug", Type: "file", Layer: 2},
		"/real-hard.txt":   {Path: "/real-hard.txt", Type: "file", Layer: 0, Link: "/real.txt"},
		"/real.txt":        {Path: "/real.txt", Type: "file", Layer: 0},
		"/rebuild":         {Path: "/rebuild", Type: "dir", Layer: 2},
		"/rebuild/new.txt": {Path: "/rebuild/new.txt", Type: "file", Layer: 2},
		"/shape":           {Path: "/shape", Type: "dir", Layer: 2},
		"/shape/inner.txt": {Path: "/shape/inner.txt", Type: "file", Layer: 2},
	}
	got := make(map[string]pathInfo, len(res.Paths))
	for _, p := range res.Paths {
		got[p.Path] = p
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("final path list mismatch:\nwant:\n%s\ngot:\n%s", dump(want), dump(got))
	}
	return nil
}

func expectDeletions(res *auditResult) error {
	want := map[string]deletion{
		"/app/config.txt":     {Path: "/app/config.txt", Type: "file", Layer: 0, DeletedBy: 1, Reason: "replaced"},
		"/app/old-cal.bin":    {Path: "/app/old-cal.bin", Type: "file", Layer: 0, DeletedBy: 1, Reason: "whiteout"},
		"/data/keep.txt":      {Path: "/data/keep.txt", Type: "file", Layer: 0, DeletedBy: 1, Reason: "opaque"},
		"/data/stale.txt":     {Path: "/data/stale.txt", Type: "file", Layer: 0, DeletedBy: 1, Reason: "opaque"},
		"/plug":               {Path: "/plug", Type: "dir", Layer: 0, DeletedBy: 2, Reason: "replaced"},
		"/plug/x.txt":         {Path: "/plug/x.txt", Type: "file", Layer: 0, DeletedBy: 2, Reason: "replaced"},
		"/rebuild":            {Path: "/rebuild", Type: "dir", Layer: 0, DeletedBy: 1, Reason: "whiteout"},
		"/rebuild/legacy.txt": {Path: "/rebuild/legacy.txt", Type: "file", Layer: 0, DeletedBy: 1, Reason: "whiteout"},
		"/shape":              {Path: "/shape", Type: "file", Layer: 0, DeletedBy: 2, Reason: "replaced"},
	}
	got := make(map[string]deletion, len(res.Deletions))
	for _, d := range res.Deletions {
		got[d.Path] = d
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("deletion evidence mismatch:\nwant:\n%s\ngot:\n%s", dump(want), dump(got))
	}
	return nil
}

func dump[T any](m map[string]T) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		fmt.Fprintf(&b, "  %+v\n", m[k])
	}
	return b.String()
}

// --- HTTP helpers ---------------------------------------------------------------

func waitForHealth(client *http.Client, base string) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service at %s did not become healthy within 30s", base)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func postAudit(client *http.Client, base, id string, layers []string) (*auditResult, int, error) {
	body, err := json.Marshal(map[string]any{"id": id, "layers": layers})
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Post(base+"/audits", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("POST /audits: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, resp.StatusCode, fmt.Errorf("POST /audits: status %d: %s", resp.StatusCode, data)
	}
	var res auditResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("POST /audits: invalid JSON response: %w", err)
	}
	return &res, resp.StatusCode, nil
}

func postAuditStatus(client *http.Client, base, id string, layers []string) (int, error) {
	body, err := json.Marshal(map[string]any{"id": id, "layers": layers})
	if err != nil {
		return 0, err
	}
	resp, err := client.Post(base+"/audits", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("POST /audits: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func getAudit(client *http.Client, base, id string) (*auditResult, int, error) {
	resp, err := client.Get(base + "/audits/" + id)
	if err != nil {
		return nil, 0, fmt.Errorf("GET /audits/%s: %w", id, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var res auditResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("GET /audits/%s: invalid JSON: %w", id, err)
	}
	return &res, resp.StatusCode, nil
}

// --- layer fixtures ---------------------------------------------------------------
//
// Layer 0 carries calibration data that later layers revoke; layer 1 uses a
// whiteout plus an opaque marker; layer 2 re-creates a whited-out directory
// and swaps types on two paths.

func layer0() string {
	return layerFromEntries(
		tarEntry{name: "app", typ: tar.TypeDir},
		tarEntry{name: "app/config.txt", typ: tar.TypeReg, body: "v1"},
		tarEntry{name: "app/old-cal.bin", typ: tar.TypeReg, body: "revoked-calibration"},
		tarEntry{name: "data", typ: tar.TypeDir},
		tarEntry{name: "data/keep.txt", typ: tar.TypeReg, body: "keep"},
		tarEntry{name: "data/stale.txt", typ: tar.TypeReg, body: "stale"},
		tarEntry{name: "rebuild", typ: tar.TypeDir},
		tarEntry{name: "rebuild/legacy.txt", typ: tar.TypeReg, body: "legacy"},
		tarEntry{name: "shape", typ: tar.TypeReg, body: "file-in-lower-layer"},
		tarEntry{name: "plug", typ: tar.TypeDir},
		tarEntry{name: "plug/x.txt", typ: tar.TypeReg, body: "x"},
		tarEntry{name: "real.txt", typ: tar.TypeReg, body: "real-content"},
		tarEntry{name: "real-hard.txt", typ: tar.TypeLink, link: "real.txt"},
	)
}

func layer1() string {
	return layerFromEntries(
		tarEntry{name: "app/.wh.old-cal.bin", typ: tar.TypeReg},
		tarEntry{name: "data/.wh..wh..opq", typ: tar.TypeReg},
		tarEntry{name: "data/fresh.txt", typ: tar.TypeReg, body: "fresh"},
		tarEntry{name: "app/config.txt", typ: tar.TypeReg, body: "v2"},
		tarEntry{name: ".wh.rebuild", typ: tar.TypeReg},
	)
}

func layer2() string {
	return layerFromEntries(
		tarEntry{name: "rebuild", typ: tar.TypeDir},
		tarEntry{name: "rebuild/new.txt", typ: tar.TypeReg, body: "new"},
		tarEntry{name: "shape", typ: tar.TypeDir},
		tarEntry{name: "shape/inner.txt", typ: tar.TypeReg, body: "inner"},
		tarEntry{name: "plug", typ: tar.TypeReg, body: "now-a-file"},
	)
}

func layerFromEntries(entries ...tarEntry) string {
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
			panic(err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				panic(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(buf.Bytes()); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(gz.Bytes())
}
