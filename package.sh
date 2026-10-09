#!/usr/bin/env bash
# Build dist/sentinel-op-<VERSION>.zip with no bytecode and no git metadata.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
VER="$(tr -d '[:space:]' < "$ROOT/VERSION")"
OUT="${ROOT}/dist"
NAME="sentinel-op-${VER}"
rm -rf "$OUT"
mkdir -p "$OUT/$NAME/.sentinel/records"
cp "$ROOT/sentinel.py" "$ROOT/test_sentinel.py" "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/VERSION" "$ROOT/RELEASE.md" "$ROOT/demo.sh" "$OUT/$NAME/"
cp "$ROOT/.sentinel/meta.json" "$ROOT/.sentinel/.gitignore" "$OUT/$NAME/.sentinel/"
cp "$ROOT/.sentinel/records/"*.jsonld "$OUT/$NAME/.sentinel/records/"
find "$OUT" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$OUT" -type f -name '*.pyc' -delete
( cd "$OUT" && zip -qr "${NAME}.zip" "$NAME" )
echo "Wrote ${OUT}/${NAME}.zip"
