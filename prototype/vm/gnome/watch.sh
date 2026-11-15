set -eu
exec > /dev/ttyS0 2>&1
for ((i=0; i<75; i++)); do
    if test -s /tmp/selinux-lens-gnome-result.txt; then
       printf '\nGNOME PROBE RESULTS\n'
       cat /tmp/selinux-lens-gnome-result.txt
       loginctl list-sessions --no-pager
       break
    fi
    sleep 1
done
if ! test -s /tmp/selinux-lens-gnome-result.txt; then
    printf '\nGNOME PROBE DID NOT START\n'
    systemctl status --no-pager gdm.service || :
    loginctl list-sessions --no-pager || :
fi
unlink /etc/xdg/autostart/selinux-lens-probe.desktop
unlink /usr/share/polkit-1/actions/io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
systemctl --no-block poweroff
