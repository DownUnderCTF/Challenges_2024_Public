from pwn import *

"""
if this solution looks overcomplicated, that's because it was written to work
if line 15 of the challenge script is
            eval(aes.decrypt(ct))
instead of
            print(eval(aes.decrypt(ct)))
(i didn't realise i left the print in there by the time we released the challenge)
"""

def oracle(ct):
    # returns True if eval succeeded
    conn.sendlineafter(b'ct: ', ct.hex().encode())
    o = conn.recvline(timeout=1)
    return o is None or ('invalid ct' not in o.decode())

conn = process(['python3', '../src/decrypt-then-eval.py'])
# conn = remote('0.0.0.0', 1337)

# for the first character, lets find a number
results = []
for b in range(256):
    cand = bytes([b])
    results.append(oracle(cand))
    if set(results[-7:]) == {True}:
        break
z = bytes([len(results) - 1])

# now try to make the result <number>j to build up X0000000000j
for i in range(10):
    for b in range(256):
        cand = z + bytes([b])
        if oracle(cand):
            # see if its j
            b2 = ord('j') ^ b ^ ord('0')
            cand2 = z + bytes([b2])
            b3 = ord('j') ^ b ^ ord('1')
            cand3 = z + bytes([b3])
            if oracle(cand2) and oracle(cand3):
                z = cand2
                break

# guess the first number
for n in range(10):
    conn.sendlineafter(b'ct: ', xor(z, b'print(FLAG)', str(n).encode() + b'0' * 10).hex().encode())
    r = conn.recvline().decode()
    if 'DUCTF' in r:
        print(r)
        break
