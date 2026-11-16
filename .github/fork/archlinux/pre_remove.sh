# Arch Linux pre_remove hook (pacman calls it with the old version).
# Stop and unregister the service before the binary is removed, as upstream
# does on a deb/rpm removal.
systemctl stop netbird 2>/dev/null || true
/usr/bin/netbird service uninstall || true
systemctl daemon-reload 2>/dev/null || true
