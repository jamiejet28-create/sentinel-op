#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 sentinel.py init
python3 sentinel.py record --prompt "v0.1 demo: record README as proof artifact" --file README.md || true
python3 sentinel.py list
echo "Demo complete. Tag with: git tag v0.1.0 && git push origin v0.1.0"
