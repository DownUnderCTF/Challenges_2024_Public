from pwn import u64, p64

dat = open('mem.bin', 'rb').read()
qwords = [u64(dat[i:i+8]) for i in range(0, len(dat), 8)]
for i, qw in enumerate(qwords):
    if 0x400000 <= qw <= 0x405000:
        idx = (qw - 0x400000)//8
        if qwords[idx] == 0:
            print('ok!', hex(0x400000 + 8*i))
