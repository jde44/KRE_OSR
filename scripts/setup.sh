#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
PYTHONPYCACHEPREFIX=${PYTHONPYCACHEPREFIX:-$(mktemp -d)} PYTHONPATH="$ROOT/src" python3 -c 'import open_sovereign_router; print("offline setup check: pass")'
