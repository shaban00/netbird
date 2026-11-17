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
#   - upstream's install/getting-started/enterprise scripts are replaced by
#     the fork's install-*.sh scripts in $FORK_RELEASE_FILES (written by
#     release-scripts.py)
#   - the release notes start with how to install this release
#   - binaries check this fork's releases for updates, not NetBird's (see
#     fork-ldflags.sh), and each release carries the version file they read
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
: "${FORK_RELEASE_FILES:?set FORK_RELEASE_FILES to the directory release-scripts.py wrote}"
for f in install-client.sh install-server.sh install-relay.sh install-signal.sh install-recorder.sh version; do
  [[ -f "$FORK_RELEASE_FILES/$f" ]] || { echo "error: $FORK_RELEASE_FILES/$f is missing" >&2; exit 1; }
done
GITHUB_OWNER=${GITHUB_OWNER:-$GHCR_NAMESPACE}
ARCH_PACKAGER=${ARCH_PACKAGER:-$GHCR_NAMESPACE}
# Arch package release (pkgrel): N from RELEASE_TAG vX.Y.Z-spydasec.N. GoReleaser
# does not template nfpm's release field, so it is filled in here. Arch needs
# it to be at least 1 (a dry run builds as ...spydasec.0).
ARCH_PKGREL=1
if [[ "${RELEASE_TAG:-}" =~ -spydasec\.([0-9]+)$ ]] && (( 10#${BASH_REMATCH[1]} >= 1 )); then
  ARCH_PKGREL=$(( 10#${BASH_REMATCH[1]} ))
fi
FORK_LDFLAGS=$(bash "$(dirname "$0")/fork-ldflags.sh" "$GITHUB_OWNER")
export DOCKERHUB_NAMESPACE GHCR_NAMESPACE ARCH_PACKAGER ARCH_PKGREL FORK_RELEASE_FILES GITHUB_OWNER FORK_LDFLAGS

# The Arch Linux package is derived from upstream's .deb definition.
if [[ "$(yq '[.nfpms[] | select(.id == "netbird_deb")] | length' "$in")" != "1" ]]; then
  echo "error: $in has no nfpm entry with id netbird_deb to build the Arch Linux package from" >&2
  exit 1
fi

yq '
  ("https://github.com/" + strenv(GITHUB_OWNER) + "/netbird/releases/latest/download") as $dl |
  del(.brews) |
  del(.uploads) |
  (.builds[].ldflags[]? | select(contains("netbird/version.version="))) |= . + " " + strenv(FORK_LDFLAGS) |
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
  .release.extra_files = [{"glob": strenv(FORK_RELEASE_FILES) + "/*.sh"}, {"glob": strenv(FORK_RELEASE_FILES) + "/version"}] |
  .checksum.extra_files = [{"glob": strenv(FORK_RELEASE_FILES) + "/*.sh"}, {"glob": strenv(FORK_RELEASE_FILES) + "/version"}] |
  .release.header = "## Install\n\n" +
    "Client (Linux and macOS):\n\n" +
    "```sh\ncurl -fsSL " + $dl + "/install-client.sh | sh\n```\n\n" +
    "Or download a package below: `.deb`, `.rpm`, Arch Linux `.pkg.tar.zst`, or an archive.\n\n" +
    "Desktop app (`netbird-ui-*`): Linux packages and archives (GTK4, or `netbird-ui-gtk3` for distros without WebKitGTK 6.0), Windows and macOS archives. They are not code-signed, so Windows SmartScreen and macOS Gatekeeper ask before running them.\n\n" +
    "Self-hosted server (Docker; asks about PostgreSQL, the reverse proxy and CrowdSec):\n\n" +
    "```sh\ncurl -fsSL " + $dl + "/install-server.sh | bash\n```\n\n" +
    "Standalone services (Docker), each on its own host:\n\n" +
    "```sh\n" +
    "curl -fsSL " + $dl + "/install-relay.sh | bash\n" +
    "curl -fsSL " + $dl + "/install-signal.sh | bash\n" +
    "curl -fsSL " + $dl + "/install-recorder.sh | bash\n" +
    "```\n\n" +
    "Images: `" + strenv(DOCKERHUB_NAMESPACE) + "/netbird-*` on Docker Hub and `ghcr.io/" + strenv(GHCR_NAMESPACE) + "/netbird-*`.\n" |
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
if yq '.release.extra_files[].glob, .checksum.extra_files[].glob' "$out" | grep -qv "^$FORK_RELEASE_FILES/"; then
  echo "error: $out still attaches upstream's release scripts" >&2
  exit 1
fi
if yq '.brews, .uploads' "$out" | grep -qv '^null$'; then
  echo "error: $out still publishes to NetBird's Homebrew tap or package servers" >&2
  exit 1
fi

echo "wrote $out:"
yq '.dockers_v2[].images[]' "$out" | sort | sed 's/^/  /'
