from sage.all import *
import ctypes
import hashlib

kyber_lib = ctypes.CDLL('../src/libpqcrystals_kyber512_ref.so')
q = 3329
k = 2
F = GF(q)
P = PolynomialRing(F, 'X')
P.inject_variables()
R = P.quotient_ring(X**256 + 1, 'Xbar')

def poly_to_bytes(p):
    buf = ctypes.c_buffer(int(384))
    poly = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_poly_tobytes(buf, poly)
    return bytes(buf)

def bytes_to_poly(b):
    poly = (ctypes.c_int16 * int(256))()
    kyber_lib.pqcrystals_kyber512_ref_poly_frombytes(poly, ctypes.c_buffer(b))
    return R(list(poly))

def poly_pack(p):
    r = [0] * 128
    for i in range(0, 256, 8):
        t = [0] * 8
        for j in range(8):
            t[j] = int(p[i+j])
        r[i//2 + 0] = t[0] | (t[1] << 4)
        r[i//2 + 1] = t[2] | (t[3] << 4)
        r[i//2 + 2] = t[4] | (t[5] << 4)
        r[i//2 + 3] = t[6] | (t[7] << 4)
    return bytes(r)

def poly_compress(p):
    buf = ctypes.c_buffer(int(128))
    poly = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_poly_compress(buf, poly)
    return bytes(buf)

def polyvec_compress(pv):
    buf = ctypes.c_buffer(int(k * 320))
    polyvec = (ctypes.c_int16 * int(k * 256))(*(list(pv[0]) + list(pv[1])))
    kyber_lib.pqcrystals_kyber512_ref_polyvec_compress(buf, polyvec)
    return bytes(buf)

def polyvec_to_bytes(pv):
    buf = ctypes.c_buffer(int(k * 384))
    polyvec = (ctypes.c_int16 * int(k * 256))(*(list(pv[0]) + list(pv[1])))
    kyber_lib.pqcrystals_kyber512_ref_polyvec_tobytes(buf, polyvec)
    return bytes(buf)

def bytes_to_polyvec(b):
    polyvec = (ctypes.c_int16 * int(k * 256))()
    kyber_lib.pqcrystals_kyber512_ref_polyvec_frombytes(polyvec, ctypes.c_buffer(b))
    return vector(R, [R(list(polyvec)[:256]), R(list(polyvec)[256:])])

def compressed_bytes_to_polyvec(b):
    polyvec = (ctypes.c_int16 * int(k * 256))()
    kyber_lib.pqcrystals_kyber512_ref_polyvec_decompress(polyvec, ctypes.c_buffer(b))
    return vector(R, [R(list(polyvec)[:256]), R(list(polyvec)[256:])])

def poly_frommsg(m):
    poly = (ctypes.c_int16 * int(256))()
    kyber_lib.pqcrystals_kyber512_ref_poly_frommsg(poly, ctypes.c_buffer(m))
    return R(list(poly))

def unpack_pk(pk_bytes):
    buf = pk_bytes[:k * 384]
    pv = bytes_to_polyvec(buf)
    seed = pk_bytes[k * 384:]
    return pv, seed

def gen_matrix(seed, transposed=0):
    out = ((ctypes.c_int16 * int(k * 256)) * int(k))()
    kyber_lib.pqcrystals_kyber512_ref_gen_matrix(out, ctypes.c_buffer(seed), transposed)
    o0 = list(out)[0]
    o1 = list(out)[1]
    r0 = vector(R, [R(list(o0)[:256]), R(list(o0)[256:])])
    r1 = vector(R, [R(list(o1)[:256]), R(list(o1)[256:])])
    return Matrix(R, [r0, r1])

def poly_invntt(p):
    t = (ctypes.c_int16 * int(256))(*list(p))
    kyber_lib.pqcrystals_kyber512_ref_invntt(t)
    t = R(list(t)) / 2**16
    return t

def polyvec_invntt(pv):
    return vector(R, [poly_invntt(p) for p in pv])
