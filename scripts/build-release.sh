#!/usr/bin/env bash
# Cross-compile zta release binaries with a stamped version, into dist/.
# Usage: scripts/build-release.sh [VERSION]   (defaults to git describe)
set -euo pipefail

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="dist"
PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)

rm -rf "$OUT"
mkdir -p "$OUT"

for p in "${PLATFORMS[@]}"; do
  os="${p%/*}"; arch="${p#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  name="zta_${VERSION}_${os}_${arch}${ext}"
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$OUT/$name" ./cmd/zta
done

# Checksums for integrity verification (supply-chain hygiene).
( cd "$OUT" && sha256sum zta_* > SHA256SUMS )

echo
echo "artifacts (version ${VERSION}):"
ls -1 "$OUT"
