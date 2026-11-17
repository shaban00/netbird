#!/usr/bin/env python3
"""Write the install scripts attached to the fork's releases.

  install-client.sh    installs the NetBird client from this fork's release
                       binaries; generated from upstream's
                       release_files/install.sh
  install-server.sh    self-hosted server (Caddy, optional PostgreSQL,
                       reverse proxy and CrowdSec)
  install-relay.sh     standalone relay
  install-signal.sh    standalone Signal server
  install-recorder.sh  SSH session recorder

The last four live in .github/fork/scripts with @@GITHUB_OWNER@@,
@@DOCKERHUB_NAMESPACE@@ and @@IMAGE_TAG@@ placeholders, which are filled in
here so each release's scripts deploy that release's images.
install-server.sh also gets @@MCP_READ_TOOLS@@, the read-only tools of the
MCP catalog (management/internals/modules/mcpapi/catalog.go), so its
read-only choice names only tools this release's server knows.
It also gets @@DASHBOARD_TAG@@, the newest fork release of the dashboard
image on Docker Hub (or DASHBOARD_TAG when set), so a later dashboard release
does not change what an older server release installs.

Each edit to upstream's install.sh must match exactly once. If upstream
changes the script so that an edit no longer applies, this fails instead of
publishing a half-converted script.

It also writes OUT_DIR/version, the release's version without the v
(0.83.1-spydasec.1). Attached to every release, it is served at
releases/latest/download/version, which the fork's binaries check for updates
in place of https://pkgs.netbird.io/releases/latest/version.

Usage: release-scripts.py OUT_DIR
Environment: GITHUB_OWNER (owner of the fork's repository),
             DOCKERHUB_NAMESPACE (Docker Hub namespace of the fork's images),
             RELEASE_TAG (the release's tag, e.g. v0.83.1-spydasec.1),
             DASHBOARD_TAG (optional: the dashboard image tag to pin)
"""

import json
import os
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = pathlib.Path(__file__).resolve().parent / "scripts"
SERVICE_SCRIPTS = [
    "install-server.sh",
    "install-relay.sh",
    "install-signal.sh",
    "install-recorder.sh",
]


def replace_once(text: str, old: str, new: str, script: str) -> str:
    count = text.count(old)
    if count != 1:
        sys.exit(f"error: {script}: expected exactly one match for {old!r}, found {count}")
    return text.replace(old, new)


def install_client_sh(owner: str) -> str:
    script = "release_files/install.sh"
    text = (ROOT / script).read_text()
    edits = [
        # Releases come from this fork.
        ('OWNER="netbirdio"', f'OWNER="{owner}"'),
        # "latest" is looked up on GitHub, not on upstream's package server.
        (
            'local URL="https://pkgs.netbird.io/releases/latest"',
            'local URL="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"',
        ),
        # Accept fork tags such as v0.83.1-spydasec.1.
        (
            "grep -Eo '\\\"tag_name\\\":\\s*\\\"v([0-9]+\\.){2}[0-9]+\"'",
            "grep -Eo '\\\"tag_name\\\":\\s*\\\"v([0-9]+\\.){2}[0-9]+(-[0-9A-Za-z.]+)?\"'",
        ),
        (
            "grep -oE 'v[0-9]+\\.[0-9]+\\.[0-9]+'",
            "grep -oE 'v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?'",
        ),
        # The fork has no apt/yum repositories, Homebrew tap or macOS installer:
        # always install the release binaries (upstream's USE_BIN_INSTALL mode).
        (
            'PACKAGE_MANAGER="bin"\nINSTALL_DIR=""\n',
            'PACKAGE_MANAGER="bin"\nINSTALL_DIR=""\n'
            "# Fork releases are installed from their binaries.\n"
            "USE_BIN_INSTALL=true\n",
        ),
        # The desktop app installs on Linux as upstream's does. On macOS this
        # installer only takes the app from NetBird's signed .zip, which fork
        # releases do not have (they have an unsigned archive), so skip it.
        (
            '\t\t\tOS_TYPE="darwin"\n',
            '\t\t\tOS_TYPE="darwin"\n'
            '            SKIP_UI_APP=true # fork releases have no signed macOS app\n',
        ),
        (
            "set -e\n",
            f"# Installs the NetBird client from the {owner}/netbird releases:\n"
            "#\n"
            f"#   curl -fsSL https://github.com/{owner}/netbird/releases/latest/download/install-client.sh | sh\n"
            "#\n"
            "# Generated from upstream's release_files/install.sh by\n"
            "# .github/fork/release-scripts.py.\n"
            "set -e\n",
        ),
    ]
    for old, new in edits:
        text = replace_once(text, old, new, script)
    return text


def mcp_read_tools() -> str:
    catalog = (ROOT / "management/internals/modules/mcpapi/catalog.go").read_text()
    tools = re.findall(r'^\s*read\("([a-z_]+)"', catalog, re.MULTILINE)
    if len(tools) < 10 or "list_peers" not in tools:
        sys.exit(f"error: found only {len(tools)} read-only MCP tools in catalog.go")
    return ",".join(tools)


def dashboard_tag(namespace: str, suffix: str) -> str:
    """Newest fork release tag of NAMESPACE/netbird-dashboard on Docker Hub.

    Fork releases are tagged 2.97.0-spydasec.1; older ones kept the leading v.
    The -rootless and -ubi variants and latest are skipped. When a version has
    both forms, the one without the v wins.
    """
    pattern = re.compile(rf"(v?)(\d+)\.(\d+)\.(\d+)-{re.escape(suffix)}\.(\d+)")
    url = f"https://hub.docker.com/v2/repositories/{namespace}/netbird-dashboard/tags?page_size=100"
    best = None
    while url:
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                page = json.load(resp)
        except OSError as err:
            sys.exit(f"error: listing {namespace}/netbird-dashboard tags on Docker Hub: {err}")
        for tag in page.get("results", []):
            m = pattern.fullmatch(tag["name"])
            if m:
                key = (tuple(int(g) for g in m.groups()[1:]), m.group(1) == "")
                if best is None or key > best[0]:
                    best = (key, tag["name"])
        url = page.get("next")
    if best is None:
        sys.exit(f"error: no {namespace}/netbird-dashboard image tagged like 2.97.0-{suffix}.1 on Docker Hub")
    return best[1]


def service_script(name: str, values: dict[str, str]) -> str:
    text = (SCRIPTS / name).read_text()
    for key, value in values.items():
        text = text.replace(f"@@{key}@@", value)
    left = sorted(set(re.findall(r"@@[A-Z_]+@@", text)))
    if left:
        sys.exit(f"error: {name}: placeholders left unfilled: {', '.join(left)}")
    if "netbirdio/" in text:
        sys.exit(f"error: {name} references a netbirdio image")
    return text


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    owner = os.environ.get("GITHUB_OWNER") or sys.exit("error: set GITHUB_OWNER")
    namespace = os.environ.get("DOCKERHUB_NAMESPACE") or sys.exit("error: set DOCKERHUB_NAMESPACE")
    tag = os.environ.get("RELEASE_TAG") or sys.exit("error: set RELEASE_TAG")
    if not re.fullmatch(r"v\d+\.\d+\.\d+-[0-9A-Za-z.]+", tag):
        sys.exit(f"error: RELEASE_TAG {tag!r} must look like v0.83.1-spydasec.1")
    values = {
        "GITHUB_OWNER": owner,
        "DOCKERHUB_NAMESPACE": namespace,
        # Image tags drop the tag's leading v.
        "IMAGE_TAG": tag[1:],
        "MCP_READ_TOOLS": mcp_read_tools(),
        "DASHBOARD_TAG": os.environ.get("DASHBOARD_TAG")
        or dashboard_tag(namespace, tag.split("-", 1)[1].rsplit(".", 1)[0]),
    }

    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    scripts = [("install-client.sh", install_client_sh(owner))]
    scripts += [(name, service_script(name, values)) for name in SERVICE_SCRIPTS]
    print(f"dashboard image: {namespace}/netbird-dashboard:{values['DASHBOARD_TAG']}")
    for name, text in scripts:
        path = out / name
        path.write_text(text)
        path.chmod(0o755)
        print(f"wrote {path}")
    (out / "version").write_text(tag[1:] + "\n")
    print(f"wrote {out / 'version'}")


if __name__ == "__main__":
    main()
