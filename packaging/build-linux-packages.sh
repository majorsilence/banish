#!/usr/bin/env bash
# Builds .deb and .rpm packages from the published single-file binaries.
#   packaging/build-linux-packages.sh <version> <linux-x64|linux-arm64> <dir with banish, banish-agent, banish-api> <out dir>
# Needs nfpm (https://nfpm.goreleaser.com) on the PATH. Run it from the repository root.
set -euo pipefail
VERSION="${1:?version}"; RID="${2:?rid}"; SRC="${3:?binary dir}"; OUT="${4:?output dir}"
case "$RID" in
  linux-x64)   export ARCH=amd64 ;;
  linux-arm64) export ARCH=arm64 ;;
  *) echo "unsupported rid $RID" >&2; exit 1 ;;
esac
export VERSION SRC
mkdir -p "$OUT"
for fmt in deb rpm; do
  nfpm package --config packaging/linux/nfpm.yaml --packager "$fmt" --target "$OUT/"
done
ls -l "$OUT"
