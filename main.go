// main.go wires the adjudication engine into an HTTP service:
//
//	POST /audits        submit up to 6 base64+gzip+tar layers (bottom to top)
//	GET  /audits/{id}   fetch the frozen adjudication (paths + deletion evidence)
//	GET  /healthz       liveness probe used by the Compose healthcheck
//
// The binary also supports a "healthcheck" subcommand so the distroless
// image can probe itself without extra tools.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	defaultPort    = "8080"
	maxRequestBody = 140 << 20 // 140 MiB, covers 6 max-size base64 layers
)

var auditIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type auditRequest struct {
	ID     string   `json:"id"`
	Layers []string `json:"layers"`
}

type server struct {
	mu     sync.RWMutex
	audits map[string]*AuditResult
}

func newServer() *server {
	return &server{audits: make(map[string]*AuditResult)}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	srv := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("POST /audits", srv.handleCreateAudit)
	mux.HandleFunc("GET /audits/{id}", srv.handleGetAudit)
	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("layer-audit service listening on :%s", port)
	log.Fatal(httpSrv.ListenAndServe())
}

// runHealthcheck probes the local service; exit 0 only when healthy.
func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleCreateAudit(w http.ResponseWriter, r *http.Request) {
	var req auditRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return
	}
	if !auditIDRe.MatchString(req.ID) {
		writeError(w, http.StatusBadRequest, "invalid audit id: must match "+auditIDRe.String())
		return
	}
	if req.Layers == nil {
		writeError(w, http.StatusBadRequest, "layers is required")
		return
	}
	res, err := adjudicate(req.ID, req.Layers)
	if err != nil {
		var ae *adjudicationError
		if errors.As(err, &ae) {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Store only after every layer applied cleanly: a failed audit leaves
	// nothing behind and the id stays available for a corrected retry.
	s.mu.Lock()
	if _, exists := s.audits[req.ID]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "audit "+req.ID+" already exists; stored results are frozen")
		return
	}
	s.audits[req.ID] = res
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, res)
}

func (s *server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	res, ok := s.audits[id]
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "audit "+id+" not found")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
