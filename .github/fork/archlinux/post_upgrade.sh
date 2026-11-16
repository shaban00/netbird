# Arch Linux post_upgrade hook (pacman calls it with the new and old version).
# Re-register the service so it runs the new binary, as upstream does on a
# deb/rpm upgrade.
systemctl stop netbird 2>/dev/null || true
/usr/bin/netbird service uninstall 2>/dev/null || true
/usr/bin/netbird service install
/usr/bin/netbird service start
