#!/bin/sh
# verify pipeline: build checks -> whiteout rule tests -> HTTP smoke.
# Any failure aborts with a non-zero exit code; success exits 0.
set -eu

echo "[verify] 1/3 build checks (go vet, go build)"
go vet ./...
go build -buildvcs=false ./...

echo "[verify] 2/3 whiteout rule tests (go test)"
go test -buildvcs=false ./... -count=1

echo "[verify] 3/3 HTTP smoke against ${AUDIT_URL:-http://app:8080}"
go build -buildvcs=false -o /tmp/smoke ./cmd/smoke
/tmp/smoke

echo "[verify] ALL CHECKS PASSED"
