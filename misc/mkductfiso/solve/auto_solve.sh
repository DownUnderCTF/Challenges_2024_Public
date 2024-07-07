#!/bin/bash

ISO_NAME="./ductf_data_disk.iso"

p() {
	printf "\e[36m[i]=> %s \n\e[39m" "$1"
}

if [ "$EUID" -ne 0 ]; then
	p "Please run as root"
	exit 1
fi

if [ ! -e "$ISO_NAME" ]; then
	p "Missing ISO to solve"
	exit 1
fi

## Create a new ISO to extract ramfs.
[ -d "solve_work" ] && rm -rf solve_work
[ -d "solve_work" ] || mkdir solve_work

p "Creating arch iso for initramfs"
sudo cp

[ -d "solve_releng" ] && rm -rf solve_releng
[ -d "solve_releng" ] || mkdir solve_releng
cp -vr /usr/share/archiso/configs/releng/* ./solve_releng
mkarchiso -v -w solve_work -o . solve_releng

p "Unpacking our boi"
DATE=$(date '+%Y.%m.%d')
7z x "archlinux-$DATE-x86_64.iso" -osolve_iso_dir

p "Extracing initramfs"
cp solve_iso_dir/arch/boot/x86_64/initramfs-linux.img .

#############
### Fix ISO.
#############

7z x "$ISO_NAME" -ofix

p "Copying initramfs"
cp -vr initramfs-linux.img ./fix/arch/boot/x86_64/initramfs-linux.img

p "Go remove faulty microcode from archiso_sys-linux and archiso_pxe-linux"
p "I ceeb figuring out the sed command"
p "Run this command to repackage:"
p 'xorriso -as mkisofs \
	-iso-level 3 \
	-full-iso9660-filenames \
	-volid "DUCTF_LINUX" \
	-appid "DUCTF LINUX" \
	-publisher "DUCTF Linux <https://duc.tf>" \
	-preparer "prepared by joseph and pix" \
	-no-emul-boot \
	-boot-load-size 4 \
	-boot-info-table \
	-isohybrid-mbr fix/boot/syslinux/isohdpfx.bin \
	-eltorito-boot boot/syslinux/isolinux.bin \
	-eltorito-catalog boot/syslinux/boot.cat \
	-no-emul-boot \
	-output fixed.iso \
	fix'

# p "Fixing initrd"
# cp -v solve_work/iso/boot/syslinux/archiso_pxe-linux.cfg ./fix/boot/syslinux/archiso_pxe-linux.cfg
# cp -v solve_work/iso/boot/syslinux/archiso_sys-linux.cfg ./fix/boot/syslinux/archiso_sys-linux.cfg

# p "Remaking"
# xorriso -as mkisofs \
# 	-iso-level 3 \
# 	-full-iso9660-filenames \
# 	-volid "DUCTF_LINUX" \
# 	-appid "DUCTF LINUX" \
# 	-publisher "DUCTF Linux <https://duc.tf>" \
# 	-preparer "prepared by joseph and pix" \
# 	-no-emul-boot \
# 	-boot-load-size 4 \
# 	-boot-info-table \
# 	-isohybrid-mbr fix/boot/syslinux/isohdpfx.bin \
# 	-eltorito-boot boot/syslinux/isolinux.bin \
# 	-eltorito-catalog boot/syslinux/boot.cat \
# 	-no-emul-boot \
# 	-output fixed.iso \
# 	fix
#
# p "Done"
