#!/usr/bin/env bash
# Demo helper executed by the demo skill.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$here/util.py"
