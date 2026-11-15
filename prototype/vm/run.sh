#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || ( "$1" != baseline && "$1" != gnome ) ]]; then
    printf 'Usage: bash prototype/vm/run.sh {baseline|gnome} DOWNLOADED_MEDIA_DIRECTORY\n' >&2
    exit 2
fi
if [[ $EUID == 0 || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    printf 'Run from a regular desktop account with access to /dev/kvm.\n' >&2
    exit 2
fi

mode=$1
media=$(cd -- "$2" && pwd -P)
scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
iso=Fedora-Workstation-Live-45-1.4.x86_64.iso
checksums=Fedora-Workstation-45-1.4-x86_64-CHECKSUM
action=io.github.tobiasguta.SELinuxLens.read-recent-avcs.policy
work=$(mktemp -d)
printf 'VM logs and temporary media: %s\n' "$work"

test -r "$media/$iso"
signature=$(gpgv --status-fd 1 --keyring "$media/fedora.gpg" \
    --output "$work/checksums" "$media/$checksums")
grep -Fq '[GNUPG:] VALIDSIG 4F50A6114CD5C6976A7F1179655A4B02F577861E ' <<<"$signature"
(cd -- "$media" && sha256sum --check --ignore-missing "$work/checksums")

mkdir "$work/guest"
cp -- "$scripts/$mode/"* "$work/guest/"
cp -- "$scripts/../$action" "$work/guest/action.policy"
xorriso -osirrox on -indev "$media/$iso" \
    -extract /boot/x86_64/loader/linux "$work/vmlinuz" \
    -extract /boot/x86_64/loader/initrd "$work/initrd.img"
xorriso -as mkisofs -quiet -R -V LENS_VM_PROBE -o "$work/probe.iso" "$work/guest"

case "$mode" in
    baseline) program=probe.sh; success=poweroff ;;
    gnome) program=setup.sh; success=none ;;
esac
boot='root=live:CDLABEL=Fedora-WS-Live-45 rd.live.image ro console=ttyS0,115200n8'
boot+=' systemd.run="/usr/bin/mount -o ro /dev/disk/by-label/LENS_VM_PROBE /mnt"'
boot+=" systemd.run=\"/usr/bin/bash /mnt/$program\""
boot+=" systemd.run_success_action=$success systemd.run_failure_action=poweroff"

timeout --kill-after=5s 160 qemu-system-x86_64 -name selinux-lens-validation \
    -machine q35,accel=kvm -cpu host -m 6144 -smp 4 -nic none -device virtio-vga \
    -display none -monitor none -serial "file:$work/guest.log" -no-reboot \
    -cdrom "$media/$iso" -drive "file=$work/probe.iso,media=cdrom,readonly=on,format=raw" \
    -kernel "$work/vmlinuz" -initrd "$work/initrd.img" -append "$boot"

case "$mode" in
    baseline)
        grep -E '^(PASS |END SELINUX LENS GUEST PROBE)' "$work/guest.log"
        grep -q '^END SELINUX LENS GUEST PROBE' "$work/guest.log"
        ;;
    gnome)
        grep -E '^(GNOME PROBE RESULTS|GNOME caller)' "$work/guest.log"
        grep -q '^GNOME caller noninteractive Polkit:' "$work/guest.log"
        if grep -q '^GNOME probe error:' "$work/guest.log"; then
            grep '^GNOME probe error:' "$work/guest.log" >&2
            exit 1
        fi
        ;;
esac
