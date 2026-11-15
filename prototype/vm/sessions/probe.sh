#!/usr/bin/bash
set -euo pipefail
exec > /dev/ttyS0 2>&1
test "$(systemd-detect-virt --vm)" = kvm
grep -Fq 'root=live:CDLABEL=Fedora-WS-Live-45' /proc/cmdline
test "$(getenforce)" = Enforcing
rpm -q fedora-release-workstation systemd polkit dbus-broker util-linux kbd

policy=/usr/share/polkit-1/actions/io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
test ! -e "$policy"
install -m 0644 /mnt/action.policy "$policy"
trap 'unlink "$policy"' EXIT
systemctl start dbus.socket systemd-logind.service systemd-user-sessions.service
systemctl start polkit.service
useradd --create-home --shell /bin/bash lens-probe
/usr/bin/python3 -c 'from secrets import token_urlsafe; print("lens-probe:" + token_urlsafe())' |
    /usr/sbin/chpasswd
install -o lens-probe -g lens-probe -m 0700 -d /run/selinux-lens-sessions
useradd --create-home --groups wheel --shell /bin/bash lens-admin
umask 077
/usr/bin/python3 -c 'from secrets import token_hex; print(token_hex(24))' > /run/selinux-lens-sessions/lab-admin-password
{ printf 'lens-admin:'; cat /run/selinux-lens-sessions/lab-admin-password; } | /usr/sbin/chpasswd
chown lens-probe:lens-probe /run/selinux-lens-sessions/lab-admin-password
umask 022
printf '%s\n' 'exec /usr/bin/python3 /mnt/probe.py login >>"$HOME/session-probe.log" 2>&1' \
    > /home/lens-probe/.bash_profile
chown lens-probe:lens-probe /home/lens-probe/.bash_profile
for tty in 7 8; do
    unit="/etc/systemd/system/getty@tty$tty.service.d"
    mkdir -p "$unit"
    cat > "$unit/lab.conf" <<'UNIT'
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin lens-probe --noclear %I
UNIT
done
remote_unit=/etc/systemd/system/getty@tty9.service.d
mkdir -p "$remote_unit"
cat > "$remote_unit/lab.conf" <<'UNIT'
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin lens-probe --noclear --login-options "-h 192.0.2.2 -f -- lens-probe" %I
UNIT
systemctl daemon-reload
if ! /usr/bin/python3 /mnt/matrix.py; then
    find /run/selinux-lens-sessions -maxdepth 1 \( -name '*.log' -o -name '*.json' \) \
        -type f -exec tail -n 20 '{}' +
    cat /sys/class/tty/tty0/active
    loginctl show-seat seat0 --no-pager
    journalctl --no-pager -u getty@tty7 -u getty@tty8 -u getty@tty9 -n 24
    if test -f /home/lens-probe/session-probe.log; then
        tail -20 /home/lens-probe/session-probe.log
    fi
    journalctl --no-pager -t login -n 20
    loginctl list-sessions --no-pager
    exit 1
fi
printf 'END SELINUX LENS SESSION MATRIX\n'
