#!/usr/bin/env bash
# Fills the Homebrew formula and winget manifests with the version and checksums of a release.
#   packaging/generate-manifests.sh <version> <dir with the release .tar.gz/.zip/.msi files> <out dir>
set -euo pipefail
VERSION="${1:?version}"; ASSETS="${2:?assets dir}"; OUT="${3:?out dir}"
sha() { sha256sum "$ASSETS/$1" | cut -d' ' -f1; }
mkdir -p "$OUT/winget"
fill() {
  sed -e "s/@VERSION@/$VERSION/g" \
      -e "s/@SHA_ARM64@/$(sha "banish-$VERSION-osx-arm64.tar.gz")/" \
      -e "s/@SHA_X64@/$(sha "banish-$VERSION-osx-x64.tar.gz")/" \
      -e "s/@SHA_MSI_X64@/$(sha "banish-$VERSION-win-x64.msi" | tr a-f A-F)/" \
      -e "s/@SHA_MSI_ARM64@/$(sha "banish-$VERSION-win-arm64.msi" | tr a-f A-F)/" "$1"
}
fill packaging/homebrew/banish.rb.tmpl > "$OUT/banish.rb"
for t in packaging/winget/*.tmpl; do
  name="$(basename "$t" .tmpl)"
  fill "$t" > "$OUT/winget/$name"
done
ls -R "$OUT"
