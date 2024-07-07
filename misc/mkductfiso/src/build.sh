#!/bin/bash

# ####
# run this on archlinux (docker works) with archiso, cdrkit, p7zip installed
# ####

p() {
	printf "\e[36m[i]=> %s \n\e[39m" "$1"
}

BUILD_DIR=$(pwd)
SOLVE_DIR="../solve"
OUTNAME="ductf_data_disk.iso"

set -e

if [ "$EUID" -ne 0 ]; then
	p "Please run as root"
	exit 1
fi

p "Cleaning up old work dir"
[ -d "work" ] && rm -rf work
[ -d "work" ] || mkdir work

p "Creating basic arch releng iso"
mkarchiso -v -w work -o . releng/

p "Cleaning up previous repackaged iso"
[ -d "repack" ] && rm -rf repack
[ -d "repack" ] || mkdir repack

p "Extracting new iso into 'repack'"
DATE=$(date '+%Y.%m.%d')
7z x "ductflinux-$DATE-x86_64.iso" -orepack/
cd repack/arch/x86_64 || exit 1

p "Unsquashing airootfs"
unsquashfs airootfs.sfs
[ -e "airootfs.sfs" ] && rm airootfs.sfs

p "Copying secret sauce grep!"
cp ../../../grep-backdoored squashfs-root/usr/bin/grep

p "Resquashing!"
mksquashfs squashfs-root airootfs.sfs -comp xz
sha512sum airootfs.sfs >airootfs.sha512

p "Cleaning up"
[ -e "squashfs-root" ] && rm -rf squashfs-root

cd ../../../

p "Purging initramfs-linux.img"
rm repack/arch/boot/x86_64/initramfs-linux.img

p "Creating iso with xorriso"
xorriso -as mkisofs \
	-iso-level 3 \
	-full-iso9660-filenames \
	-volid "DUCTF_LINUX" \
	-appid "DUCTF LINUX" \
	-publisher "DUCTF Linux <https://duc.tf>" \
	-preparer "prepared by joseph and pix" \
	-no-emul-boot \
	-boot-load-size 4 \
	-boot-info-table \
	-isohybrid-mbr repack/boot/syslinux/isohdpfx.bin \
	-eltorito-boot boot/syslinux/isolinux.bin \
	-eltorito-catalog boot/syslinux/boot.cat \
	-no-emul-boot \
	-output "$OUTNAME" \
	repack

p "ISO Found at: $OUTNAME"
