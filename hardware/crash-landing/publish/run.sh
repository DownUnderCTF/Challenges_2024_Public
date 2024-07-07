# make sure qemu-system-arm is patched with qemu.patch
qemu-system-arm -M netduino2 -kernel crash_landing.bin -serial stdio