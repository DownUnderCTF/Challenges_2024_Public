import operator
import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse
from functools import reduce

flag = b"DUCTF{btw_y0u_c4n_als0_us3_CRT_f0r_p4rt14l_fr4ct10ns}"
m =  bytes_to_long(flag)
e = 3

ns = []
cs = []

for _ in range(3):
    n = getPrime(512) * getPrime(512)
    c = pow(m, e, n)
    ns.append(n)
    cs.append(c)


N = reduce(operator.mul, ns)
crt = ns[1] * ns[2] * inverse(ns[1] * ns[2], ns[0]) * cs[0]
crt += ns[0] * ns[1] * inverse(ns[0] * ns[1], ns[2]) * cs[2]
crt += ns[0] * ns[2] * inverse(ns[0] * ns[2], ns[1]) * cs[1]

assert crt % ns[0] == cs[0]
assert crt % ns[1] == cs[1]
assert crt % ns[2] == cs[2]

cbrt, exact = gmpy2.iroot(crt % N, e)
assert exact
assert m == cbrt
assert long_to_bytes(cbrt) == flag

print("e = ", e)
print("c_1 = ", cs[0])
print("c_2 = ", cs[1])
print("c_3 = ", cs[2])
print("n_1 = ", ns[0])
print("n_2 = ", ns[1])
print("n_3 = ", ns[2])
