# WRITEUP!

Running the solve script against the ISO -> 

It will prepare a fresh arch ISO and use it to get a working `initramfs `from!

You can either take the `squashfs` and put it into the new ISO or patch the 
`archiso_sys-linux.cfg` file to remove the extra `initrd` call preventing it from 
booting. Once this has been removed you can repackage up the iso with:

```bash
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
	-isohybrid-mbr fix/boot/syslinux/isohdpfx.bin \
	-eltorito-boot boot/syslinux/isolinux.bin \
	-eltorito-catalog boot/syslinux/boot.cat \
	-no-emul-boot \
	-output fixed.iso \
	fix
```

Boot the ISO and get your flag!

In the event it doesn't correctly run - you can run the command inside the 
`.zlogin` and get the flag directly as long as you're on an arch based system!

```bash 
grep -Fqa 'accessibility=' /proc/cmdline
```

<3
