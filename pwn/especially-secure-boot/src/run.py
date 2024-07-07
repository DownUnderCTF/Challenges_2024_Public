#!/usr/bin/env python3

import subprocess
import tempfile
from base64 import b64decode

FLASH_BASE = open('./flash-base.bin', 'rb').read()

def main():
    prog = input('Program to flash (base64) or leave empty to execute Hello World: ')
    prog = b64decode(prog)
    if len(prog) > 0x80000:
        print('Program is too large!')
        exit(1)
    flash = bytearray(FLASH_BASE)
    flash[0x20000:0x20000+len(prog)] = prog
    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(flash)
        tmpf.flush()
        subprocess.run(['./qemu-system-xtensa', '-nographic', '-machine', 'esp32', '-drive', f'file={tmpf.name},if=mtd,format=raw', '-drive', 'file=./qemu-efuse.bin,if=none,format=raw,id=efuse', '-global', 'driver=nvram.esp32.efuse,property=drive,value=efuse', '-seed', '1234'])

if __name__ == "__main__":
    main()
