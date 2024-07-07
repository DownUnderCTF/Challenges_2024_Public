import random
from string import ascii_letters, digits

FLAG = list(ascii_letters + digits + '!?')
random.shuffle(FLAG)
FLAG = ''.join(FLAG).encode()
print(FLAG.decode())

permutation = list(range(64))
random.shuffle(permutation)

bits = []
j = 0
for i in range(128):
    if i not in FLAG:
        bits.append(-1)
    else:
        bits.append(permutation[j])
        j += 1

conds = [-1] * 128
for i in range(len(FLAG)):
    r = sum(1 << bits[c] for c in FLAG[:i])
    conds[FLAG[i]] = r


funcs = []
for i in range(128):
    n = hex(i)[2:].zfill(2)
    if i not in FLAG:
        funcs.append(f'void func{n}() {{ out |= -1; }}')
    else:
        c = conds[i]
        b = 1 << bits[i]
        funcs.append(f'void func{n}() {{ !(out & {c}) && (out ^= {b}); }}')
print('\n'.join(funcs))

# FLAG: tAb1HFK5h3ZgEX7UTMQfsivcPOaJ?nRy8jrYLVB9Ilempw6xWq2zC0d!SDukG4No
