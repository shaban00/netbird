# Arch Linux post_install hook (pacman calls it with the new version).
# nfpm pastes this file into a function in the package's .INSTALL, so it must
# not exit. Upstream's release_files/post_install.sh reads deb/rpm arguments
# and cannot tell pacman's install, upgrade and removal apart; these hooks do
# the same work for each case.
/usr/bin/netbird service install
/usr/bin/netbird service start
