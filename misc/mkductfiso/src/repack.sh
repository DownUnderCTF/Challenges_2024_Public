xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid "DUCTF_LINUX" \
  -appid "DUCTF LINUX" \
  -publisher "DUCTF Linux <https://duc.tf>" \
  -preparer "prepared by ductf" \
  -no-emul-boot \
  -boot-load-size 4 \
  -boot-info-table \
  -isohybrid-mbr repack/boot/syslinux/isohdpfx.bin \
  -eltorito-boot boot/syslinux/isolinux.bin \
  -eltorito-catalog boot/syslinux/boot.cat \
  -no-emul-boot \
  -output repacked.iso \
  repack
