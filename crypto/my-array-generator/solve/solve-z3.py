from z3 import *
import random

"""
The flag is a 32 byte value used as the key for MyArrayGenerator which is an
LFSR-like stream cipher. 1280 bytes of plaintext/ciphertext are given, so we
have access to 1280 bytes of the keystream output. Noting that the registers
are basically only ever XORs of the initial key words, we can reimplement the
generator in Z3. The conditional XOR by 0xFFFFFFFF in the update method can be
dealt with by ignoring it in the generator itself and considering it only later
when trying to solve the system. As its effect is only equivalent to XORing the
output keystream byte by 0xFF, combining this with the fact that the initial
key words are ASCII only is enough to solve.
"""

random.seed(1234)
F = 2**14
class MyZ3ArrayGenerator:
    def __init__(self, registers):
        self.registers = registers
        self.carry = self.registers.pop()
        for _ in range(F):
            self.update()

    def shift(self):
        self.registers = self.registers[1:]

    def update(self):
        r1 = self.registers[1]
        self.carry ^= r1
        self.shift()
        self.registers.append(self.registers[-1] ^ self.carry)

    def get_keystream(self):
        byte_index = random.randint(0, 3)
        byte_mask = 0xFF << (8 * byte_index)
        return LShR(self.registers[-1] & byte_mask, 8 * byte_index)


plaintext, ciphertext = '', ''
exec(open('../publish/output.txt', 'r').read())
plaintext = bytes.fromhex(plaintext)
ciphertext = bytes.fromhex(ciphertext)

key_words = [BitVec(f'k{i}', 32) for i in range(8)]
registers = key_words * 16
stream = MyZ3ArrayGenerator(registers)

solver = Solver()
for kw in key_words:
    for i in range(4):
        b = LShR(kw, 8 * i) & 0xFF
        solver.add(And(0x20 < b, b < 0x7f))

for p, c in list(zip(plaintext, ciphertext))[:80]: # only need 80 bytes
    stream.update()
    kz = stream.get_keystream()
    ks = p ^ c
    solver.add(Or(kz == ks, kz == ks ^ 0xff))

assert solver.check() == sat
model = solver.model()
flag = b''.join([int(model[k].as_long()).to_bytes(4, 'big') for k in key_words]).decode()
print(flag)
