#!/bin/sh
# Verify container entrypoint: whiteout-rule tests and build checks first,
# then an HTTP smoke audit (opaque + rebuild paths) against the app service.
# The container exits with the status of the first failing step (or 0).
set -eu
cd "$(dirname "$0")/.."
PY=$(command -v python3 || command -v python)

echo "==> [1/3] whiteout rule tests"
"$PY" -m unittest discover -s tests -t . -v

echo "==> [2/3] build check (byte-compile all modules)"
"$PY" -m compileall -q app tests
"$PY" -c "import app.server, app.smoke, app.engine, app.tarparse"

echo "==> [3/3] HTTP smoke against ${APP_ADDR:-http://app:8080}"
"$PY" -m app.smoke

echo "==> VERIFY OK"
