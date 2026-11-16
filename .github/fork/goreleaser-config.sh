#!/usr/bin/env bash
#
# Build the fork's GoReleaser config from upstream's, so the fork keeps
# upstream's build definitions without editing upstream files.
#
#   in:  .goreleaser.generated.yaml (written by release_files/rpm-provides.sh)
#   out: .goreleaser.fork.yaml
#
# Changes made to upstream's config:
#   - images go to $DOCKERHUB_NAMESPACE/<image> and ghcr.io/$GHCR_NAMESPACE/<image>,
#     with a netbird- prefix so they read clearly next to other projects
#     (management -> netbird-management; netbird, netbird-server and nblink keep
#     their names)
#   - the Homebrew tap and NetBird's package-server uploads are removed
#   - fork tags (vX.Y.Z-<suffix>.N) are full releases, not prereleases
#   - GitHub's "Latest release" follows SKIP_LATEST, like the Docker latest tags
#   - an Arch Linux package (.pkg.tar.zst) is built from the same binaries as
#     upstream's .deb, with pacman hooks from .github/fork/archlinux. Its
#     version is <upstream version>-<N> for tag v<upstream version>-spydasec.N:
#     Arch versions cannot hold the suffix, and N is what pkgrel is for.
#
# RPM signing needs no change: it only runs when GPG_RPM_KEY_FILE is set.

set -euo pipefail

in=${1:-.goreleaser.generated.yaml}
out=${2:-.goreleaser.fork.yaml}
: "${DOCKERHUB_NAMESPACE:?set DOCKERHUB_NAMESPACE, e.g. spydasec}"
: "${GHCR_NAMESPACE:?set GHCR_NAMESPACE, e.g. spydasec}"
ARCH_PACKAGER=${ARCH_PACKAGER:-$GHCR_NAMESPACE}
# Arch package release (pkgrel): N from RELEASE_TAG vX.Y.Z-spydasec.N. GoReleaser
# does not template nfpm's release field, so it is filled in here. Arch needs
# it to be at least 1 (a dry run builds as ...spydasec.0).
ARCH_PKGREL=1
if [[ "${RELEASE_TAG:-}" =~ -spydasec\.([0-9]+)$ ]] && (( 10#${BASH_REMATCH[1]} >= 1 )); then
  ARCH_PKGREL=$(( 10#${BASH_REMATCH[1]} ))
fi
export DOCKERHUB_NAMESPACE GHCR_NAMESPACE ARCH_PACKAGER ARCH_PKGREL

# The Arch Linux package is derived from upstream's .deb definition.
if [[ "$(yq '[.nfpms[] | select(.id == "netbird_deb")] | length' "$in")" != "1" ]]; then
  echo "error: $in has no nfpm entry with id netbird_deb to build the Arch Linux package from" >&2
  exit 1
fi

yq '
  del(.brews) |
  del(.uploads) |
  .dockers_v2[].images |= map(
    sub("^ghcr\.io/netbirdio/"; "ghcr.io/" + strenv(GHCR_NAMESPACE) + "/") |
    sub("^netbirdio/"; strenv(DOCKERHUB_NAMESPACE) + "/") |
    with(select(test("/(netbird|nb)[^/]*$") | not); . |= sub("/(?P<name>[^/]+)$"; "/netbird-${name}"))
  ) |
  .nfpms += [
    (.nfpms[] | select(.id == "netbird_deb")) * {
      "id": "netbird_archlinux",
      "formats": ["archlinux"],
      "release": strenv(ARCH_PKGREL),
      "dependencies": ["ca-certificates"],
      "scripts": {
        "postinstall": ".github/fork/archlinux/post_install.sh",
        "preremove": ".github/fork/archlinux/pre_remove.sh"
      },
      "archlinux": {
        "packager": strenv(ARCH_PACKAGER),
        "scripts": {"postupgrade": ".github/fork/archlinux/post_upgrade.sh"}
      }
    }
  ] |
  .release.prerelease = "false" |
  .release.make_latest = "{{ if eq .Env.SKIP_LATEST \"false\" }}true{{ else }}false{{ end }}"
' "$in" > "$out"

# Fail rather than publish anything under upstream's names.
if yq '.dockers_v2[].images[]' "$out" | grep -qvE '/(netbird|nblink)[^/]*$' ||
  yq '.dockers_v2[].images[]' "$out" | grep -qE '/netbird-(netbird|nb)'; then
  echo "error: $out has an image without the netbird- prefix, or with it twice" >&2
  exit 1
fi
if yq '.dockers_v2[].images[]' "$out" | grep -q 'netbirdio/'; then
  echo "error: $out still pushes images to netbirdio" >&2
  exit 1
fi
if yq '.brews, .uploads' "$out" | grep -qv '^null$'; then
  echo "error: $out still publishes to NetBird's Homebrew tap or package servers" >&2
  exit 1
fi

echo "wrote $out:"
yq '.dockers_v2[].images[]' "$out" | sort | sed 's/^/  /'
