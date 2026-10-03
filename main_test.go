package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newMux(s *server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /audits", s.handleCreateAudit)
	mux.HandleFunc("GET /audits/{id}", s.handleGetAudit)
	return mux
}

func doRequest(t *testing.T, mux http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, target, bytes.NewReader(raw))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestHealthEndpoint(t *testing.T) {
	w := doRequest(t, newMux(newServer()), "GET", "/healthz", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", w.Code)
	}
}

func TestCreateAndGetAuditRoundTrip(t *testing.T) {
	mux := newMux(newServer())
	payload := map[string]any{
		"id": "audit-1",
		"layers": []string{
			layer(t, dirEnt("etc"), fileEnt("etc/old.conf", "old")),
			layer(t, markerEnt("etc/.wh.old.conf"), fileEnt("etc/new.conf", "new")),
		},
	}

	w := doRequest(t, mux, "POST", "/audits", payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST: got %d, want 201: %s", w.Code, w.Body)
	}
	var created AuditResult
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("POST response not JSON: %v", err)
	}
	if created.ID != "audit-1" || created.Layers != 2 {
		t.Fatalf("unexpected audit header: %+v", created)
	}

	w = doRequest(t, mux, "GET", "/audits/audit-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want 200", w.Code)
	}
	var fetched AuditResult
	if err := json.Unmarshal(w.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("GET response not JSON: %v", err)
	}
	posted, _ := json.Marshal(created)
	got, _ := json.Marshal(fetched)
	if !bytes.Equal(posted, got) {
		t.Fatalf("frozen result changed between POST and GET:\n%s\n%s", posted, got)
	}
	assertPath(t, &fetched, "/etc", typeDir, 0)
	assertPath(t, &fetched, "/etc/new.conf", typeFile, 1)
	assertNoPath(t, &fetched, "/etc/old.conf")
	assertDeletion(t, &fetched, "/etc/old.conf", typeFile, 0, 1, reasonWhiteout)
}

func TestAuditIsFrozen(t *testing.T) {
	mux := newMux(newServer())
	payload := map[string]any{"id": "frozen", "layers": []string{layer(t, fileEnt("a", "1"))}}
	if w := doRequest(t, mux, "POST", "/audits", payload); w.Code != http.StatusCreated {
		t.Fatalf("first POST: got %d, want 201", w.Code)
	}
	w := doRequest(t, mux, "POST", "/audits", payload)
	if w.Code != http.StatusConflict {
		t.Fatalf("replay POST: got %d, want 409", w.Code)
	}
}

func TestGetUnknownAudit(t *testing.T) {
	w := doRequest(t, newMux(newServer()), "GET", "/audits/nope", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET unknown: got %d, want 404", w.Code)
	}
}

func TestCreateValidationErrors(t *testing.T) {
	mux := newMux(newServer())
	cases := []struct {
		name   string
		target string
		body   any
		want   int
	}{
		{"bad json", "/audits", nil, http.StatusBadRequest},
		{"bad id", "/audits", map[string]any{"id": "bad id!", "layers": []string{layer(t)}}, http.StatusBadRequest},
		{"missing layers", "/audits", map[string]any{"id": "x1"}, http.StatusBadRequest},
		{"empty layers", "/audits", map[string]any{"id": "x2", "layers": []string{}}, http.StatusUnprocessableEntity},
		{"too many layers", "/audits", map[string]any{"id": "x3", "layers": []string{layer(t), layer(t), layer(t), layer(t), layer(t), layer(t), layer(t)}}, http.StatusUnprocessableEntity},
		{"invalid layer", "/audits", map[string]any{"id": "x4", "layers": []string{"!!!"}}, http.StatusUnprocessableEntity},
		{"traversal layer", "/audits", map[string]any{"id": "x5", "layers": []string{layer(t, fileEnt("../e", "x"))}}, http.StatusUnprocessableEntity},
		{"unknown field", "/audits", map[string]any{"id": "x6", "layers": []string{layer(t)}, "extra": 1}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w *httptest.ResponseRecorder
			if tc.body == nil {
				r := httptest.NewRequest("POST", tc.target, bytes.NewReader([]byte("{oops")))
				w = httptest.NewRecorder()
				mux.ServeHTTP(w, r)
			} else {
				w = doRequest(t, mux, "POST", tc.target, tc.body)
			}
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}
}

func TestFailedAuditLeavesNoPartialAdjudication(t *testing.T) {
	mux := newMux(newServer())
	// second layer is corrupt: the whole audit must be rejected
	payload := map[string]any{
		"id":     "atomic",
		"layers": []string{layer(t, fileEnt("ok", "1")), "!!!not-base64!!!"},
	}
	if w := doRequest(t, mux, "POST", "/audits", payload); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST: got %d, want 422", w.Code)
	}
	if w := doRequest(t, mux, "GET", "/audits/atomic", nil); w.Code != http.StatusNotFound {
		t.Fatalf("GET after failed POST: got %d, want 404 (no partial adjudication)", w.Code)
	}
	// the id stays usable for a corrected retry
	payload["layers"] = []string{layer(t, fileEnt("ok", "1"))}
	if w := doRequest(t, mux, "POST", "/audits", payload); w.Code != http.StatusCreated {
		t.Fatalf("retry POST: got %d, want 201", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	w := doRequest(t, newMux(newServer()), "DELETE", "/audits/x", nil)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: got %d, want 405", w.Code)
	}
}

func TestConcurrentSameIDOnlyOneWins(t *testing.T) {
	mux := newMux(newServer())
	payload := map[string]any{"id": "race", "layers": []string{layer(t, fileEnt("a", "1"))}}
	const n = 8
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			w := doRequest(t, mux, "POST", "/audits", payload)
			codes <- w.Code
		}()
	}
	created, conflict := 0, 0
	for i := 0; i < n; i++ {
		switch <-codes {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected status in race")
		}
	}
	if created != 1 || conflict != n-1 {
		t.Fatalf(fmt.Sprintf("want 1 created and %d conflicts, got %d/%d", n-1, created, conflict))
	}
}
