from Crypto.Cipher import AES

nonce = bytes.fromhex('FF 06 72 45 C6 AE 7B 9F C1 36 D4 8E') # unk_4A068 passed into Aead..encrypt
key = bytes.fromhex('95 87 E8 E7 DE C0 3C 28 A2 8C A1 F7 35 27 23 81 6C 21 6E 10 71 4A 62 0B 9E 36 78 93 38 96 90 CF') # unk_4A074 passed into Aes256Enc...KeyInit
# then some calls to AesGcm and input is passed then compared against ct
ct = bytes.fromhex('65E74F390F161629CD3071C33256A6FA')[::-1] # xmmword_4A000
ct += bytes.fromhex('ADF63090ED7FF4C81247EACCDB05FA2E')[::-1] # xmmword_4A010
ct += bytes.fromhex('8EA036FE9AB32E3BD1B5CFA2A750B1AB')[::-1] # xmmword_4A020
ct += bytes.fromhex('6179CBE7049F1890')[::-1]
ct += bytes.fromhex('385BD95C')[::-1]

aes = AES.new(key, mode=AES.MODE_GCM, nonce=nonce)
flag = aes.decrypt(ct)
print(flag)
