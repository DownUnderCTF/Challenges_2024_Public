import random, itertools, math

def decode_7_bits_to_permutation(bits, n):
    permutation = [0] * n
    unused = [True] * n
    for i in range(n - 1):
        divisor = math.factorial(n - i - 1)
        index = bits // divisor
        bits %= divisor
        count = -1
        for j in range(n):
            if unused[j]:
                count += 1
                if count == index:
                    permutation[i] = j
                    unused[j] = False
                    break
    for i in range(n):
        if unused[i]:
            permutation[n - 1] = i
            break
    return permutation

COLOURS = [0, 1, 2, 3, 4]
FLAG = b'DUCTF{y0u_ar3_g00d_at_pr3ssing_butt0ns_z8y2hzjbx0y7xy19alewp8z9x01pvzq9xy}'

print(len(FLAG))
for c in FLAG:
    w = decode_7_bits_to_permutation(c % 120, 5)
    print('{' + ', '.join(map(str, w)) + '},')

