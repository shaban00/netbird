#!/usr/bin/env bash
#
# Print the -ldflags the fork adds to every NetBird binary, so that update
# checks follow this fork's releases instead of NetBird's:
#
#   version.versionURL                 clients, the desktop app and the
#                                      management server's "outdated" log
#   instance.managementVersionURL      the dashboard's "Update available"
#   instance.dashboardReleasesURL      the dashboard's latest version
#
# The version file is attached to every fork release (release-scripts.py).
#
# Usage: fork-ldflags.sh GITHUB_OWNER

set -euo pipefail

owner=${1:?usage: fork-ldflags.sh GITHUB_OWNER}
[[ "$owner" =~ ^[A-Za-z0-9-]+$ ]] || { echo "error: invalid GitHub owner: $owner" >&2; exit 1; }

version_url="https://github.com/${owner}/netbird/releases/latest/download/version"
dashboard_url="https://api.github.com/repos/${owner}/netbird-dashboard/releases/latest"
pkg=github.com/netbirdio/netbird

printf '%s' "-X ${pkg}/version.versionURL=${version_url}" \
  " -X ${pkg}/management/server/instance.managementVersionURL=${version_url}" \
  " -X ${pkg}/management/server/instance.dashboardReleasesURL=${dashboard_url}"
