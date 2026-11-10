#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHONPYCACHEPREFIX=${PYTHONPYCACHEPREFIX:-$(mktemp -d)} python3 scripts/validate_release.py
