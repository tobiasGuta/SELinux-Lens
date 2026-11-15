#!/usr/bin/bash
set -euo pipefail
exec > /dev/ttyS0 2>&1
printf '\nBEGIN SELINUX LENS GUEST PROBE\n'
[[ "$(systemd-detect-virt --vm)" == kvm ]]
grep -Fq 'root=live:CDLABEL=Fedora-WS-Live-45' /proc/cmdline
test "$(getenforce)" = Enforcing
printf 'PASS isolated KVM guest with SELinux Enforcing\n'
rpm -q fedora-release-workstation systemd polkit dbus-broker audit
policy=/usr/share/polkit-1/actions/io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
test ! -e "$policy"
scratch=$(mktemp -d)
trap 'if test -f "$policy"; then unlink "$policy"; fi; if test -f "$scratch/synthetic.log"; then unlink "$scratch/synthetic.log"; fi; rmdir "$scratch"' EXIT
install -m 0644 /mnt/action.policy "$policy"
systemctl start dbus.socket systemd-logind.service
if ! systemctl start polkit.service; then
    systemctl --no-pager status polkit.service dbus.service
    journalctl --no-pager -u polkit.service -n 16
    exit 1
fi
runuser -u nobody -- /usr/bin/python3 /mnt/probe.py
epoch=$(date -d '35 seconds ago' +%s)
cat > "$scratch/synthetic.log" <<EOF
type=AVC msg=audit($epoch.123:42): avc: denied { read } for pid=11 comm="fictional" name="fixture" dev="vda" ino=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0 tclass=file permissive=1
type=SYSCALL msg=audit($epoch.123:42): arch=c000003e syscall=257 success=yes exit=0 a0=ffff a1=1 a2=0 a3=0 items=1 ppid=10 pid=11 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=1 comm="fictional" exe="/fictional" subj=system_u:system_r:httpd_t:s0 key=(null)
type=PATH msg=audit($epoch.123:42): item=0 name="/fictional/fixture" inode=42
type=EOE msg=audit($epoch.123:42):
EOF
result=$(LC_ALL=C /usr/sbin/ausearch --input "$scratch/synthetic.log" -m AVC,USER_AVC -ts recent)
grep -Fq 'permissive=1' <<<"$result"
grep -Fq 'type=PATH ' <<<"$result"
printf 'PASS real guest ausearch read only the synthetic file\n'
unlink "$policy"
test ! -e "$policy"
printf 'PASS draft guest policy file removed\n'
printf 'END SELINUX LENS GUEST PROBE\n'
