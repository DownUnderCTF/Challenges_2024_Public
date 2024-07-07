#!/usr/bin/env python3

from pwn import *

import json
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, GCD
import json
import secrets
from tqdm import *


CURVE = "p256"


# ECDH helpers from from pycryptodome/Crypto/Protocol/DH.py
def _compute_ecdh(key_priv, key_pub):
    # See Section 5.7.1.2 in NIST SP 800-56Ar3
    pointP = key_pub.pointQ * key_priv.d
    if pointP.is_point_at_infinity():
        raise ValueError("Invalid ECDH point")
    return pointP.xy


def key_agreement(**kwargs):
    static_priv = kwargs.get("static_priv", None)
    static_pub = kwargs.get("static_pub", None)

    count_priv = 0
    count_pub = 0
    curve = None

    def check_curve(curve, key, name, private):
        if not isinstance(key, ECC.EccKey):
            raise TypeError("'%s' must be an ECC key" % name)
        if private and not key.has_private():
            raise TypeError("'%s' must be a private ECC key" % name)
        if curve is None:
            curve = key.curve
        elif curve != key.curve:
            raise TypeError("'%s' is defined on an incompatible curve" % name)
        return curve

    if static_priv is not None:
        curve = check_curve(curve, static_priv, "static_priv", True)
        count_priv += 1

    if static_pub is not None:
        curve = check_curve(curve, static_pub, "static_pub", False)
        count_pub += 1

    if (count_priv + count_pub) < 2 or count_priv == 0 or count_pub == 0:
        raise ValueError("Too few keys for the ECDH key agreement")

    return _compute_ecdh(static_priv, static_pub)


# Paillier encryption, from https://github.com/mikeivanov/paillier/
class Paillier_PublicKey:
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1

    def encrypt(self, pt):
        while True:
            r = secrets.randbelow(self.n)
            if r > 0 and GCD(r, self.n) == 1:
                break

        x = pow(r, self.n, self.n_sq)
        ct = (pow(self.g, pt, self.n_sq) * x) % self.n_sq
        return ct


class Paillier_PrivateKey:
    def __init__(self, p, q, n):
        assert p * q == n
        self.l = (p - 1) * (q - 1)
        self.m = inverse(self.l, n)

    def decrypt(self, pub, ct):
        x = pow(ct, self.l, pub.n_sq) - 1
        pt = ((x // pub.n) * self.m) % pub.n
        return pt


def e_add(pub, a, b):
    """Add one encrypted integer to another"""
    return a * b % pub.n_sq


def e_add_const(pub, a, n):
    """Add constant n to an encrypted integer"""
    return a * pow(pub.g, n, pub.n_sq) % pub.n_sq


def e_mul_const(pub, a, n):
    """Multiplies an ancrypted integer by a constant"""
    return pow(a, n, pub.n_sq)


def generate_paillier_keypair(n_length):
    p = getPrime(n_length // 2)
    q = getPrime(n_length // 2)
    n = p * q
    return Paillier_PublicKey(n), Paillier_PrivateKey(p, q, n)


class Lindel17_Alice:
    def __init__(self, conn):
        self.conn = conn
        self.bit_index = 1
        self.bob_known = 0

    def send_request(self, **kwargs):
        self.conn.sendline(json.dumps(kwargs))
        response = json.loads(self.conn.recvline())
        return response

    def gen_keys(self):
        while True:
            self.alice_ecdsa_priv = ECC.generate(curve=CURVE)
            if self.alice_ecdsa_priv.d.is_odd():
                break

        # Send Alice's public key to Bob.
        bob_gen_keys = self.send_request(
            action="gen_keys",
            x=int(self.alice_ecdsa_priv.public_key().pointQ.x),
            y=int(self.alice_ecdsa_priv.public_key().pointQ.y),
        )

        # Generate ECDSA shared secret
        x, y = bob_gen_keys["bob_ecdsa_pub"]
        self.bob_ecdsa_pub = ECC.construct(curve=CURVE, point_x=x, point_y=y)
        shared_ecdsa_pub_x, shared_ecdsa_pub_y = key_agreement(static_pub=self.bob_ecdsa_pub, static_priv=self.alice_ecdsa_priv)
        self.shared_ecdsa_pub = ECC.construct(curve=CURVE, point_x=shared_ecdsa_pub_x, point_y=shared_ecdsa_pub_y)
        self.sig_scheme = DSS.new(self.shared_ecdsa_pub, "fips-186-3")

        # Unpack Paillier encrypted keys
        self.paillier_pub = Paillier_PublicKey(bob_gen_keys["paillier_pub"]["n"])
        self.bob_ecdsa_priv_enc = bob_gen_keys["bob_ecdsa_priv_enc"]

    def mul_share(self):
        # k = 2^l
        self.alice_nonce_priv = ECC.construct(curve=CURVE, d=int(pow(2, self.bit_index)))

        bob_mul_share = self.send_request(
            action="mul_share",
            x=int(self.alice_nonce_priv.public_key().pointQ.x),
            y=int(self.alice_nonce_priv.public_key().pointQ.y),
        )
        x, y = bob_mul_share["bob_nonce_pub"]
        bob_nonce_pub = ECC.construct(curve=CURVE, point_x=x, point_y=y)

        self.r, _ = key_agreement(static_pub=bob_nonce_pub, static_priv=self.alice_nonce_priv)

    def sign_and_validate(self, message=b"Test Message"):
        m = int(Integer.from_bytes(SHA256.new(message).digest()[: self.sig_scheme._order_bytes]))

        q = int(self.alice_ecdsa_priv._curve.order)
        n = self.paillier_pub.n
        n_sq = self.paillier_pub.n_sq
        k_a = int(self.alice_nonce_priv.d)
        x_a = int(self.alice_ecdsa_priv.d)

        epsilon = inverse(k_a, q) - inverse(k_a, n)
        if self.r.is_even():
            self.r += q
        self.r = int(self.r)

        zeta = (inverse(k_a, q) * m) % q
        canary = self.bob_known * self.r * epsilon * x_a
        partial_sig = self.bob_ecdsa_priv_enc
        partial_sig = e_mul_const(self.paillier_pub, partial_sig, self.r * inverse(k_a, n) * x_a)
        partial_sig = e_add_const(self.paillier_pub, partial_sig, zeta + canary)

        response = self.send_request(
            action="sign_and_validate",
            message=message.hex(),
            partial_sig_ciphertext=partial_sig % n_sq,
        )
        if "error" in response and response["error"] == "invalid signature parameters":
            self.bob_known = self.bob_known + pow(2, self.bit_index - 1)
        self.bit_index += 1

    def get_flag(self):
        # Test if whether the highest bit should be set
        if self.bob_known + pow(2, self.bit_index - 1) < self.alice_ecdsa_priv._curve.order:
            bob_ecdsa_priv = ECC.construct(curve=CURVE, d=self.bob_known + pow(2, self.bit_index - 1))
            if bob_ecdsa_priv.public_key().pointQ == self.bob_ecdsa_pub.pointQ:
                self.bob_known = self.bob_known + pow(2, self.bit_index - 1)

        q = int(self.alice_ecdsa_priv._curve.order)
        shared_ecdsa_priv = ECC.construct(curve=CURVE, d=int(self.bob_known) * int(self.alice_ecdsa_priv.d) % q)
        assert shared_ecdsa_priv.public_key().pointQ == self.shared_ecdsa_pub.pointQ
        sig_scheme = DSS.new(shared_ecdsa_priv, "fips-186-3")

        message = b"We, Alice and Bob, jointly agree to declare war on the emus"
        signature = sig_scheme.sign(SHA256.new(message))

        response = self.send_request(action="get_flag", message=message.hex(), signature=signature.hex())
        print(response)


def solve():
    conn = connect("localhost", 1337)
    conn.recvline()

    try:
        self = alice = Lindel17_Alice(conn)
        alice.gen_keys()

        for _ in tqdm(range(255)):
            alice.mul_share()
            alice.sign_and_validate()

        alice.get_flag()
    except json.decoder.JSONDecodeError:
        alice.conn.recvall()


if __name__ == "__main__":
    solve()
