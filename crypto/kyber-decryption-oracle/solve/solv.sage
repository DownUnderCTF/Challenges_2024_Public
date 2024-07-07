from pwn import *
from collections import namedtuple
from hashlib import sha256, sha512
import plyvel
import numpy as np

import kyber_util
from lwe_lattice import LWELattice

PARALLEL_LEVEL = 26
N = 256 // PARALLEL_LEVEL
BRT_entry = namedtuple('BRTEntry', ['finished', 'h', 'value', 'next_states'])
# from https://github.com/AdrianAstrm/Adaptive-and-Parallel-Key-Mismatch-Attack-on-Kyber/blob/master/adaptive_parallel_key_mismatch_attack/BRT_kyber512.c
BRT_TABLE: dict[str, BRT_entry] = {
    'STATE_1': BRT_entry(False, 5, None, ('STATE_2', 'STATE_4')),
    'STATE_2': BRT_entry(False, 6, None, ('STATE_3', 'FIN_3')),
    'STATE_3': BRT_entry(False, 7, None, ('FIN_1', 'FIN_2')),
    'STATE_4': BRT_entry(False, 4, None, ('FIN_4', 'STATE_5')),
    'STATE_5': BRT_entry(False, 3, None, ('FIN_5', 'STATE_6')),
    'STATE_6': BRT_entry(False, 2, None, ('FIN_6', 'FIN_7')),
    'FIN_1': BRT_entry(True, None, 3, (None, None)),
    'FIN_2': BRT_entry(True, None, 2, (None, None)),
    'FIN_3': BRT_entry(True, None, 1, (None, None)),
    'FIN_4': BRT_entry(True, None, 0, (None, None)),
    'FIN_5': BRT_entry(True, None, -1, (None, None)),
    'FIN_6': BRT_entry(True, None, -2, (None, None)),
    'FIN_7': BRT_entry(True, None, -3, (None, None)),
}
DATABASES = [plyvel.DB(f'./precomp-dbs/precomp-leveldb-{offset}') for offset in range(N + 1)]

QUERIES_USED = 0

def oracle(ct, offset):
    global QUERIES_USED
    QUERIES_USED += 1
    conn.sendlineafter(b'> ', ct.hex().encode())
    h = conn.recvline().decode()
    h = bytes.fromhex(h)
    x = DATABASES[offset].get(h[:4])
    m = int.from_bytes(x, 'little') << (offset * PARALLEL_LEVEL)
    m = int(m).to_bytes(32, 'little')
    return m

def oracle_get(ct):
    global QUERIES_USED
    QUERIES_USED += 1
    conn.sendlineafter(b'> ', ct.hex().encode())
    h = conn.recvline().decode().strip()
    h = bytes.fromhex(h)
    return h

def oracle_slow(h, bits_active):
    for hw in range(len(bits_active)):
        for positions in Combinations(bits_active, hw):
            m = sum(1 << b for b in positions)
            m = int(m).to_bytes(32, 'little')
            if sha256(m).digest() == h:
                return m
    return None

def craft_ct(h_vec, block_idx):
    Pb = copy((kyber_util.R^2).zero())
    Pb[block_idx] = round(kyber_util.q/16)
    c2 = kyber_util.R(h_vec)
    ct = kyber_util.polyvec_compress(Pb) + kyber_util.poly_pack(c2)
    return ct

# conn = process(['python3', '../src/kyber-decryption-oracle.py'], cwd='../src/')
conn = remote('0.0.0.0', '1337')
pk = bytes.fromhex(conn.recvline().decode().split('pk: ')[1])

"""
# ADAPTIVE
s = []
for block_idx in range(kyber_util.k):
    states = ['STATE_1' for _ in range(256)]

    qset = list(range(PARALLEL_LEVEL))
    qset_next = PARALLEL_LEVEL

    while True:
        h = [0] * 256
        for i in range(PARALLEL_LEVEL):
            be = BRT_TABLE[states[qset[i]]]
            if not be.finished:
                h[qset[i]] = be.h
        ct = craft_ct(h, block_idx)
        m = oracle(ct)
        for i in range(PARALLEL_LEVEL):
            be = BRT_TABLE[states[qset[i]]]
            if not be.finished:
                next_state = m[qset[i] // 8] & (1 << (qset[i] % 8))
                states[qset[i]] = be.next_states[next_state and 1]
                be = BRT_TABLE[states[qset[i]]]
                if be.finished:
                    if qset_next < 256:
                        qset[i] = qset_next
                        qset_next += 1
        cnt = sum([1 for i in range(256) if states[i].startswith('FIN')])
        if cnt == 256:
            break
"""

# NON-ADAPTIVE
states = [['STATE_1' for _ in range(256)] for _ in range(kyber_util.k)]
for block_idx in range(kyber_util.k):

    qset = list(range(PARALLEL_LEVEL))
    qset_next = PARALLEL_LEVEL

    for k in range(N - block_idx):
        h = [0] * 256
        for j in range(3):
            for i in range(PARALLEL_LEVEL):
                be = BRT_TABLE[states[block_idx][qset[i]]]
                if not be.finished:
                    h[qset[i]] = be.h
            ct = craft_ct(h, block_idx)
            m = oracle(ct, k)
            for i in range(PARALLEL_LEVEL):
                be = BRT_TABLE[states[block_idx][qset[i]]]
                if not be.finished:
                    next_state = m[qset[i] // 8] & (1 << (qset[i] % 8))
                    states[block_idx][qset[i]] = be.next_states[next_state and 1]
        for i in range(PARALLEL_LEVEL):
            qset[i] = qset_next
            qset_next += 1

qset = list(range(PARALLEL_LEVEL * N, 256))
for j in range(3):
    h = [0] * 256
    for i in range(len(qset)):
        be = BRT_TABLE[states[0][qset[i]]]
        if not be.finished:
            h[qset[i]] = be.h
    ct = craft_ct(h, 0)
    m = oracle(ct, N)
    for i in range(len(qset)):
        be = BRT_TABLE[states[0][qset[i]]]
        if not be.finished:
            next_state = m[qset[i] // 8] & (1 << (qset[i] % 8))
            states[0][qset[i]] = be.next_states[next_state and 1]

need = []
for block_idx in range(kyber_util.k):
    cnt = sum([1 for i in range(256) if states[block_idx][i].startswith('FIN')])
    if block_idx == 0:
        need.append(256 - cnt)
    else:
        need.append(PARALLEL_LEVEL*(N-1) - cnt)
    print(block_idx, 'have', cnt)
    print('need', need[block_idx], 'left')

last_query_results = []
for block_idx in range(kyber_util.k):
    qset = [i for i, s in enumerate(states[block_idx][:PARALLEL_LEVEL*(N+(1-2*block_idx))]) if not s.startswith('FIN')]
    h = [0] * 256
    for qi in qset:
        h[qi] = BRT_TABLE[states[block_idx][qi]].h
    ct = craft_ct(h, block_idx)
    m_hash = oracle_get(ct)
    last_query_results.append(m_hash)

flag_enc = bytes.fromhex(conn.recvline().decode().split('flag_enc: ')[1])
conn.close()

print(f'Used {QUERIES_USED} queries')
print('Finished online part, postprocessing offline...')

for block_idx in range(kyber_util.k):
    qset = [i for i, s in enumerate(states[block_idx][:PARALLEL_LEVEL*(N+(1-2*block_idx))]) if not s.startswith('FIN')]
    m = oracle_slow(last_query_results[block_idx], qset)
    if m is None:
        print('attack failed! could not find correct plaintext', block_idx)
        exit(1)
    for qi in qset:
        be = BRT_TABLE[states[block_idx][qi]]
        next_state = m[qi // 8] & (1 << (qi % 8))
        states[block_idx][qi] = be.next_states[next_state and 1]

my_s0 = [BRT_TABLE[states[0][i]].value if states[0][i].startswith('FIN') else None for i in range(256)]
my_s1 = [BRT_TABLE[states[1][i]].value if states[1][i].startswith('FIN') else None for i in range(256)]

t, A_seed = kyber_util.unpack_pk(pk)
A = kyber_util.gen_matrix(A_seed)

t = kyber_util.polyvec_invntt(t)
A = Matrix(kyber_util.R, [kyber_util.polyvec_invntt(a) for a in A])

def rotMatrix(poly):
  n = len(poly)
  A = np.array( [[0]*n for _ in range(n)] )
  for i in range(n):
    for j in range(n):
      c = 1
      if j < i:
        c = -1
      A[i][j] = c * poly[(j-i)%n]
  return A
def format_A(A):
    return np.block([[rotMatrix(list(A[i][j])) for j in range(kyber_util.k)] for i in range(kyber_util.k)])

t = np.array(list(t[0]) + list(t[1]))
A = format_A(A.T)

my_s = my_s0 + my_s1
lwh = LWELattice(A, t, kyber_util.q, verbose=True)
for i in range(256 + PARALLEL_LEVEL*(N-2)):
    lwh.integratePerfectHint([0]*i+[1]+[0]*(511-i), my_s[i])
lwh.reduce(maxBlocksize=40)
s = list(lwh.s)

print(f'recovered secret key:', s)
s = (kyber_util.ctypes.c_int16 * int(2 * 256))(*s)
kyber_util.kyber_lib.pqcrystals_kyber512_ref_polyvec_ntt(s)
s = vector(kyber_util.R, [kyber_util.R(s[:256]), kyber_util.R(s[256:])])
s_bytes = kyber_util.polyvec_to_bytes(s)
key = sha512(s_bytes).digest()
flag = xor(flag_enc, key[:len(flag_enc)]).decode()

print(flag)
