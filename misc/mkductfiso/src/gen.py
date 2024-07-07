h1 = b'accessibility=/proc/cmdline'
h2 = [161, 177, 154, 74, 120, 102, 68, 84, 240, 29, 18, 141, 140, 144, 120, 173, 198]
flag = b'DUCTF{D4Mn_YuO_R34LLy_G0t-tH4t-T0_Bo0t?!#<3}'
assert len(h1)+len(h2) == len(flag)

flag_enc = b''

w = 13
for i, x in enumerate(h1):
    w *= x
    w += 1
    w %= 256
    flag_enc += bytes([flag[i] ^ w])
print(w)
for i, x in enumerate(h2):
    w *= x
    w += 1
    w %= 256
    print(w)
    flag_enc += bytes([flag[len(h1)+i] ^ w])
print(flag_enc, list(flag_enc), len(flag_enc))
