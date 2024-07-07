from pwn import *
import json
from hashlib import sha256
from tqdm import tqdm
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import ECC

"""
This challenge is based around CVE-2023-33242 which exploits improper handling
of aborts in some implementations of the Lindell17 TSS protocol.

The Lindell17 scheme allows for two parties to generate separate shares of an
ECDSA key and only sign messages if both parties are willing. Although the
scheme described in Lindell17 uses zero knowledge proofs, these seem to be
omitted in the challenge for brevity.

During key generation, we (playing as Alice) provide an ECDSA public key. Bob
generates his own ECDSA key pair and runs a standard ECDH to get the shared
ECDSA public key. He also generates a Paillier key pair and encrypts his ECDSA
private key and sends this, along with the Paillier public key and his ECDSA
public key.
When signing a message m, Alice and Bob both generate random nonces kA and kB
and share with each other the values of kA*G and kB*G. The ECDSA nonce value is
then kA*kB. To generate the signature, Alice provides a Paillier-encrypted
partial signature c3, which should be
    c3 = kA^-1 r xB xA + kA^-1 m + rho q
where m is the message hash and rho is random. This is computed
homomorphically, so Alice would actually compute
    c3 = paillier_add(
        paillier_mul(kA^-1 r xA, bob_enc_priv_key),
        kA^-1 m + rho q
    )
Bob would then decrypt this and compute s = kA^-1 paillier_dec(c3). The
signature would then be (r, s), where r is the x coordinate of the shared nonce
point kA*kB*G. Bob verifies whether the signature against the shared public key
and outputs it if it is valid, or aborts otherwise.

The issue with the described protocol is that Alice may learn information about
Bob's private key based on whether or not an abort occurred. This is dealt with
in the original description of Lindell17 but is a flaw in some implementations.
The attack is described in https://eprint.iacr.org/2023/1234.pdf, however this
attack is for when the shared ECDSA private key is xA + xB. In this case, it is
xA * xB. The same idea can still be applied; we choose the provided partial
signature such that it will be valid only when the xB and yB are equal mod 2^l,
for l = 1, ... 256. Here, yB is the recovered bits of xB, starting with yB = 0
when l starts at 1. To do this, we send c3 as the value (homomorphically)

    c3 = xB xA r [2^-l]n + kA^-1 m + yB r (kA^-1 - [2^-l]n) xA

When Bob multiplies this with kB^-1, it becomes
    kB^-1 xB xA r [2^-l] + kA^-1 kB^-1 m  + kB^-1 yB r (kA^-1 - [2^-l]) xA
  = kB^-1 xA xB r [2^-l] + (kA kB)^-1 m + (kA kB)^-1 (xA yB r) - kB^-1 xA yB r [2^-l]
        (mod paillier_n) (mod q)
    also note that paillier_n ~ 2048 bits while q ~ 256 bits

For this to be a valid signature, we require it to be equal to
    s = (kA kB)^-1 (m + xA xB r) (mod q)

So, if
    kB^-1 xA xB r [2^-l] + (kA kB)^-1 m + (kA kB)^-1 (xA yB r) - kB^-1 xA yB r [2^-l]
  = (kA kB)^-1 (m + xA xB) r
then we have
    xA xB r [2^-l] + kA^-1 xA yB r - xA yB r [2^-l]
  = kA^-1 xA xB r
and so
    xA xB r = xA yB r (mod 2^l)
which implies
    xB = yB (mod 2^l)
(given that both xA and r are invertible mod 2^l, i.e. odd)

After recovering xB, we simply sign the target message with the private key as
the shared private key xA * xB.
"""

CURVE = 'p256'
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
TARGET_MESSAGE = 'We, Alice and Bob, jointly agree to declare war on the emus'
# context.log_level = 'debug'

def gen_keys():
    alice_priv = ECC.construct(d=12345, curve=CURVE)
    conn.sendline(json.dumps({
        'action': 'gen_keys',
        'x': int(alice_priv.pointQ.x),
        'y': int(alice_priv.pointQ.y)
    }).encode())
    ret = json.loads(conn.recvline().decode())
    paillier_g = ret['paillier_pub']['g']
    paillier_n = ret['paillier_pub']['n']
    bob_ecdsa_priv_enc = ret['bob_ecdsa_priv_enc']
    return alice_priv, paillier_g, paillier_n, bob_ecdsa_priv_enc

def mul_share(R2: ECC.EccPoint):
    conn.sendline(json.dumps({
        'action': 'mul_share',
        'x': int(R2.x),
        'y': int(R2.y)
    }).encode())
    ret = json.loads(conn.recvline().decode())
    R1 = ret['bob_nonce_pub']
    return ECC.EccPoint(*R1, curve=CURVE)

def sign_and_validate_oracle(partial_sig, msg):
    # returns whether or not sig succeeds

    conn.sendline(json.dumps({
        'action': 'sign_and_validate',
        'partial_sig_ciphertext': partial_sig,
        'message': msg.hex() 
    }).encode())
    ret = json.loads(conn.recvline().decode())
    if 'error' in ret:
        return False
    return True

# conn = process(['python3', '../src/server.py'])
conn = remote('0.0.0.0', 1337)
print(conn.recvline().decode())

alice_priv, paillier_g, paillier_n, bob_ecdsa_priv_enc = gen_keys()
paillier_n2 = paillier_n**2
yB = 0
msg = b'asdf'
xA = int(alice_priv.d)
m = bytes_to_long(sha256(msg).digest())
for l in tqdm(range(1, 256)):
    kA = 1 << l
    R2 = ECC.construct(d=kA, curve=CURVE)
    R1 = mul_share(R2.pointQ)
    R = R1 * kA
    r = int(R.x)

    yB_cand = (1 << (l - 1)) | yB
    t = pow(2, -l, paillier_n)
    if r % 2 == 0:
        r += q
    kAinv = pow(kA, -1, q)
    zeta = kAinv * m
    c3 = pow(bob_ecdsa_priv_enc, xA * r * t, paillier_n2) * pow(paillier_g, zeta + yB_cand * r * (kAinv - t) * xA,paillier_n2) % paillier_n2

    if sign_and_validate_oracle(c3, msg):
        yB = yB_cand
    print(bin(yB)[2:].zfill(l))

xB = yB
x = xA * xB
m = bytes_to_long(sha256(TARGET_MESSAGE.encode()).digest())
R = ECC.construct(d=1234, curve=CURVE)
r = int(R.pointQ.x)
s = pow(1234, -1, q) * (m + x * r) % q
sig = b''.join(long_to_bytes(w, 32) for w in (r, s))

conn.sendline(json.dumps({
    'action': 'get_flag',
    'message': TARGET_MESSAGE.encode().hex(),
    'signature': sig.hex()
}).encode())

conn.interactive()
