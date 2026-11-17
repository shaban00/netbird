#!/usr/bin/env bash
#
# Build the fork's GoReleaser config for one of upstream's desktop app (UI)
# configs, so the fork keeps upstream's UI build definitions without editing
# upstream files:
#
#   .goreleaser_ui.yaml              Linux amd64 (GTK4) and Windows
#   .goreleaser_ui_linux_arm64.yaml  Linux arm64 (GTK4)
#   .goreleaser_ui_gtk3.yaml         Linux amd64 (GTK3, older distros)
#   .goreleaser_ui_darwin.yaml       macOS
#
# Each uploads into the release created by .goreleaser.yaml (see
# goreleaser-config.sh). Changes made to upstream's config:
#   - NetBird's package-server uploads are removed
#   - fork tags (vX.Y.Z-<suffix>.N) are full releases, not prereleases, and
#     GitHub's "Latest release" follows SKIP_LATEST, as in the main config
#     (upstream leaves both to its signing pipeline)
#   - the Linux packages (GTK4 netbird-ui and GTK3 netbird-ui-gtk3) get an
#     Arch Linux package (.pkg.tar.zst) next to the .deb, versioned like the
#     CLI's: <upstream version>-<N> for tag v<upstream version>-spydasec.N.
#     The two conflict, as their .debs do. Pacman's replaces is dropped: it
#     would swap one for the other on an upgrade from a repository.
#
# Usage: goreleaser-ui-config.sh IN OUT

set -euo pipefail

in=${1:?usage: goreleaser-ui-config.sh IN OUT}
out=${2:?usage: goreleaser-ui-config.sh IN OUT}
ARCH_PACKAGER=${ARCH_PACKAGER:-${GHCR_NAMESPACE:-spydasec}}
# Arch package release (pkgrel), as in goreleaser-config.sh.
ARCH_PKGREL=1
if [[ "${RELEASE_TAG:-}" =~ -spydasec\.([0-9]+)$ ]] && (( 10#${BASH_REMATCH[1]} >= 1 )); then
  ARCH_PKGREL=$(( 10#${BASH_REMATCH[1]} ))
fi
export ARCH_PACKAGER ARCH_PKGREL

yq '
  del(.uploads) |
  del(.brews) |
  .nfpms += [
    .nfpms[]? |
    select((.formats | contains(["deb"])) and (.package_name == "netbird-ui" or .package_name == "netbird-ui-gtk3")) |
    . * {
      "id": (.id | sub("_deb"; "_archlinux")),
      "formats": ["archlinux"],
      "release": strenv(ARCH_PKGREL),
      "dependencies": (
        if .package_name == "netbird-ui-gtk3"
        then ["netbird", "gtk3", "webkit2gtk-4.1", "xdg-utils"]
        else ["netbird", "gtk4", "webkitgtk-6.0", "xdg-utils"]
        end
      ),
      "archlinux": {"packager": strenv(ARCH_PACKAGER)}
    } |
    del(.replaces)
  ] |
  (.release.make_latest | key) head_comment = "" |
  .release.prerelease = "false" |
  .release.make_latest = "{{ if eq .Env.SKIP_LATEST \"false\" }}true{{ else }}false{{ end }}"
' "$in" > "$out"

# Fail rather than publish to NetBird's package servers.
if yq '.uploads, .brews' "$out" | grep -qv '^null$' || grep -qE 'pkgs\.(wiretrustee\.com|netbird\.io)' "$out"; then
  echo "error: $out still publishes to NetBird's package servers" >&2
  exit 1
fi

echo "wrote $out:"
yq '.nfpms[]? | "  package " + .id + ": " + (.formats | join(","))' "$out"
yq '.archives[] | "  archive " + (.name_template // "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}")' "$out"
