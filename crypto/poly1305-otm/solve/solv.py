from pwn import *
import itertools
from Crypto.Hash.Poly1305 import Poly1305_MAC

# context.log_level = 'debug'

TARGET_MSG = b'I have broken Poly1305 one time MAC!'

EXPECTED_NIBBLE_CARRIES = [
    {0: 0/16, 1: 4/16, 2:  8/16, 3: 12/16},
    {0: 1/16, 1: 5/16, 2:  9/16, 3: 13/16},
    {0: 2/16, 1: 6/16, 2: 10/16, 3: 14/16},
    {0: 3/16, 1: 7/16, 2: 11/16, 3: 15/16},
]

def solve():
    def oracle(msg):
        conn.sendlineafter(b'> ', b'1')
        conn.sendlineafter(b'message: ', msg.hex().encode())
        return bytes.fromhex(conn.recvline().decode())

    def recover_s(oracle):
        fixed_addr_part = 0x5500000005e0
        LAST_MAC = b''
        N_ITER_EACH = 8

        # get s[12] & 0xf0, s[13] & 0x03
        nibbles_12f = []
        nibbles_13c = []
        for _ in range(N_ITER_EACH):
            m = oracle(b'\x00')
            nibbles_12f.append((m[12] & 0xf0) >> 4)
            nibbles_13c.append(m[13] & 0x03)
        print(f'{nibbles_12f = }')
        print(f'{nibbles_13c = }')

        # get s[9] & 0xf0, s[10] & 0x03 
        nibbles_9f = []
        nibbles_10c = []
        for _ in range(N_ITER_EACH):
            m = oracle(b'\x00' * 2)
            nibbles_9f.append((m[9] & 0xf0) >> 4)
            nibbles_10c.append(m[10] & 0x03)
        print(f"{nibbles_9f = }")
        print(f'{nibbles_10c = }')

        # get s[10] & 0xf0, s[11] & 0x03 
        nibbles_10f = []
        nibbles_11c = []
        for _ in range(N_ITER_EACH):
            m = oracle(b'\x00' * 3)
            nibbles_10f.append((m[10] & 0xf0) >> 4)
            nibbles_11c.append(m[11] & 0x03)
        print(f'{nibbles_10f = }')
        print(f'{nibbles_11c = }')

        # get s[11] & 0xf0, s[12] & 0x03 
        nibbles_11f = []
        nibbles_12c = []
        for _ in range(N_ITER_EACH):
            m = oracle(b'\x00' * 4)
            nibbles_11f.append((m[11] & 0xf0) >> 4)
            nibbles_12c.append(m[12] & 0x03)
            LAST_MAC = m
        print(f'{nibbles_11f = }')
        print(f'{nibbles_12c = }')

        nibbles_raw = [
            # [nibbles_9f, nibbles_9c],
            [nibbles_10f, nibbles_10c],
            [nibbles_11f, nibbles_11c],
            [nibbles_12f, nibbles_12c],
        ]

        nibble_9u = 0xf if set(nibbles_9f) == {0x0, 0xf} else min(nibbles_9f)
        possible_bytes = [[(nibble_9u << 4) | 0]]

        # now we guess the upper parts of the lower nibbles 10, 11, 12 based on the carry bits found in the corresponding upper nible
        for nfs, ncs in nibbles_raw:
            if set(nfs) == {0x0, 0xf}:
                nu = 0xf
            else:
                nu = min(nfs)
            nl = min(ncs)
            pct = 1 - nfs.count(nu) / len(nfs)
            pl = min(EXPECTED_NIBBLE_CARRIES[nl].items(), key=lambda x: abs(x[1] - pct))[0]
            nl1 = nl | (pl << 2)
            s1 = (nu << 4) | nl1
            if pct == 0:
                nl2 = nl | (3 << 2)
                s2 = ((nu - 1) << 4) | nl2
            elif pl == 1:
                nl2 = nl | (2 << 2)
                s2 = (nu << 4) | nl2
            elif pl == 2:
                nl2 = nl | (1 << 2)
                s2 = (nu << 4) | nl2
            elif pl == 0:
                nl2 = nl | (1 << 2)
                s2 = (nu << 4) | nl2
            else:
                possible_bytes.append([s1])
                continue
            possible_bytes.append([s1, s2])

        possible_bytes.append([min(nibbles_13c)])
        possibles = []
        for recovered_unknown in itertools.product(*possible_bytes):
            if not all(0 < x < 0x100 for x in recovered_unknown): continue
            unknown = fixed_addr_part | 2**8 * int.from_bytes(bytes(recovered_unknown), 'little')
            lower_relative = unknown - 0xe0
            possibles.append(((unknown << 64) | lower_relative).to_bytes(16, 'little'))

        return possibles, LAST_MAC

    # conn = process('../src/chall', cwd='../src/', level='error')
    conn = remote('0.0.0.0', 1337)
    possible_s, last_mac = recover_s(oracle)
    # print('last_mac:', last_mac.hex())
    p = 2**130 - 5
    for s in possible_s:
        # print(s.hex())
        r = int(pow(2, -32, p) * (int.from_bytes(last_mac, 'little') - int.from_bytes(s, 'little')) % p)
        if r > 2**128:
            continue
        r = r.to_bytes(16, 'little')
        mac = Poly1305_MAC(r, s, TARGET_MSG).digest()
        conn.sendlineafter(b'> ', b'2')
        conn.sendlineafter(b'mac: ', mac.hex().encode())
        flag = conn.recvline().decode()
        print(flag)
        if 'DUCTF' in flag:
            conn.close()
            return True
    conn.close()
    return False

for i in range(10):
    if solve():
        print('solved after', i+1, 'attempts')
        break
