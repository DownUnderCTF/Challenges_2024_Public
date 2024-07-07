#!/usr/bin/env sage
from pwn import *

KEY_SIZE = 32
F = 2**14


# A modified version of the provided class for symbolic encryption.
class MyArrayGenerator:
    def __init__(self, key: bytes, n_registers: int = 128):
        self.key = key
        self.n_registers = n_registers

    def prepare(self):
        self.registers = [0 for _ in range(self.n_registers)]
        self.key_extension(self.key)

        self.carry = self.registers.pop()
        self.key_initialisation(F)

    def key_extension(self, key):
        for i in range(len(self.registers)):
            self.registers[i] = key[i % len(key)]

    def key_initialisation(self, F: int):
        for _ in range(F):
            self.update()

    def shift(self):
        self.registers = self.registers[1:]

    def update(self):
        r0, r1, r2, r3 = self.registers[:4]

        self.carry += r1        # The XORs with 0xffffffff cancel each other
                                # out, so we do not actually need to consider
                                # them.

        self.shift()
        self.registers.append(self.registers[-1] + self.carry)

    def encrypt(self, plaintext: bytes) -> bytes:
        self.prepare()

        keystream = []
        for b in plaintext:
            self.update()
            keystream.append(self.get_keystream())

        return keystream

    def get_keystream(self):
        return random.randint(0, 3), self.registers[-1]


# plaintext, ciphertext
exec(open("../publish/output.txt", "r").read())
plaintext = bytes.fromhex(plaintext)
ciphertext = bytes.fromhex(ciphertext)


def solve():
    # Calculate keystream symbolically
    K = GF(2)
    R = PolynomialRing(K, "s0,s1,s2,s3,s4,s5,s6,s7")

    random.seed(int(1234))
    cipher = MyArrayGenerator(R.gens())

    keystream = cipher.encrypt(b"\x00" * 1280)
    real_keystream = bytes(x ^^ y for x, y in zip(plaintext, ciphertext))

    # Find instances where the keystream is just a monomial, and note down what
    # byte of the key is revealed.
    key_samples = {}
    for (a, z_sym), z in zip(keystream, real_keystream):
        if z_sym.is_monomial():
            if (z_sym, a) not in key_samples:
                key_samples[z_sym, a] = set()
            key_samples[(z_sym, a)].add(z)

    # For each index, there are roughly two bytes that are possible.
    # To distinguish, choose the char which is ASCII
    flag = ""
    for z in R.gens():
        for t in range(3, -1, -1):
            if (z, t) not in key_samples:
                print(f"Missing sample {(z, t)}")
                continue

            possibilities = key_samples[(z, t)]
            found = False
            for possibility in possibilities:
                if not (possibility & 0x80):  # is ascii
                    flag += chr(possibility)
                    found = True
            if not found:
                flag += chr(next(iter(possibilities)) ^^ int(0xFF))
    print(flag)

if __name__ == "__main__":
    solve()
