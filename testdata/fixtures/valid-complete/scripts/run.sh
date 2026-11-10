#!/usr/bin/env bash
# Prints a fixed greeting. Safe fixture payload.
set -euo pipefail
echo "fixture: run.sh executed"
python3 "$(dirname "$0")/util.py"
