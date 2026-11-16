#!/bin/sh
# Start the local-only Open Sovereign Router demo UI. Pass --port N to choose a port (0 = any free port).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
PYTHONPYCACHEPREFIX=${PYTHONPYCACHEPREFIX:-$(mktemp -d)} exec python3 scripts/demo_ui/server.py "$@"
