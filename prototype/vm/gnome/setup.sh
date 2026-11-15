set -euo pipefail
exec > /dev/ttyS0 2>&1
test "$(systemd-detect-virt --vm)" = kvm
test "$(getenforce)" = Enforcing
grep -Fq 'root=live:CDLABEL=Fedora-WS-Live-45' /proc/cmdline
test ! -e /usr/share/polkit-1/actions/io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
test ! -e /etc/xdg/autostart/selinux-lens-probe.desktop
install -m 0644 /mnt/action.policy /usr/share/polkit-1/actions/io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
install -D -m 0644 /mnt/gnome-probe.desktop /etc/xdg/autostart/selinux-lens-probe.desktop
systemctl start dbus.socket systemd-logind.service
systemctl start polkit.service
systemd-run --unit=selinux-lens-vm-watch --no-block /usr/bin/bash /mnt/watch.sh
systemctl start --no-block graphical.target
