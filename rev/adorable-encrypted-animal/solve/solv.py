from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA256
from hashlib import sha256

cat = open('../publish/cat.png.aea', 'rb')
key = bytes.fromhex('27b750649a0698ffcd3085f4be57b011da80be70163d4a4ff9fb883f2db5a2f1')

cat.seek(12, 0)
salt = cat.read(0x20)
info = b'AEA_AMK\x01\x00\x00\x00'
mkey = HKDF(key, len(key), salt, SHA256, context=info)

cat.seek(0x70, 1)

cluster_header_ct = cat.read(0x2800)

cluster_intmd_key = HKDF(mkey, len(mkey), b'', SHA256, context=b'AEA_CK\x00\x00\x00\x00')
cluster_keyiv_data = b''.join(HKDF(cluster_intmd_key, len(cluster_intmd_key), b'', SHA256, context=b'AEA_CHEK', num_keys=3))
cluster_key = cluster_keyiv_data[32:64]
cluster_iv = cluster_keyiv_data[64:80]

ch_aes = AES.new(cluster_key, AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=int.from_bytes(cluster_iv, 'big')))
aes = AES.new(cluster_key, AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=int.from_bytes(cluster_iv, 'big')))
pt = aes.decrypt(cluster_header_ct)
segments = [pt[i:i+40] for i in range(0, len(pt), 40) if pt[i:i+40] != b'\x00'*40]
assert len(segments) == 1

cat.seek(0x2020, 1)

seg = segments[0]
seg_raw_size = int.from_bytes(seg[4:8], 'little')
ct = cat.read(seg_raw_size)

cluster_intmd_key = HKDF(mkey, len(mkey), b'', SHA256, context=b'AEA_CK\x00\x00\x00\x00')
cluster_keyiv_data = b''.join(HKDF(cluster_intmd_key, len(cluster_intmd_key), b'', SHA256, context=b'AEA_SK\x00\x00\x00\x00', num_keys=3))
mac_key = cluster_keyiv_data[0:32]
cluster_key = cluster_keyiv_data[32:64]
cluster_iv = cluster_keyiv_data[64:80]

hmac = HMAC.new(mac_key, digestmod=SHA256)
hmac.update(ct)
hmac.update(b'\x00'*8)
k2 = hmac.digest()

aes = AES.new(cluster_key, AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=int.from_bytes(cluster_iv, 'big')))
catpng = aes.decrypt(ct)

k1 = ch_aes.encrypt(b'x' * 8 + sha256(catpng).digest())[8:]

print('k1:', k1.hex())
print('k2:', k2.hex())

# open('cat-dec.png', 'wb').write(catpng)

flag = open('../publish/flag.txt.aea', 'rb')

flag.seek(12, 0)
salt = flag.read(0x20)
info = b'AEA_AMK\x01\x00\x00\x00'
key = strxor(k1, k2)
print('flag key:', key.hex())
mkey = HKDF(key, len(key), salt, SHA256, context=info)

flag.seek(0x70, 1)

cluster_header_ct = flag.read(0x2800)

cluster_intmd_key = HKDF(mkey, len(mkey), b'', SHA256, context=b'AEA_CK\x00\x00\x00\x00')
cluster_keyiv_data = b''.join(HKDF(cluster_intmd_key, len(cluster_intmd_key), b'', SHA256, context=b'AEA_CHEK', num_keys=3))
cluster_key = cluster_keyiv_data[32:64]
cluster_iv = cluster_keyiv_data[64:80]

aes = AES.new(cluster_key, AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=int.from_bytes(cluster_iv, 'big')))
pt = aes.decrypt(cluster_header_ct)
segments = [pt[i:i+40] for i in range(0, len(pt), 40) if pt[i:i+40] != b'\x00'*40]
assert len(segments) == 1

flag.seek(0x2020, 1)

seg = segments[0]
seg_raw_size = int.from_bytes(seg[4:8], 'little')
ct = flag.read(seg_raw_size)

cluster_intmd_key = HKDF(mkey, len(mkey), b'', SHA256, context=b'AEA_CK\x00\x00\x00\x00')
cluster_keyiv_data = b''.join(HKDF(cluster_intmd_key, len(cluster_intmd_key), b'', SHA256, context=b'AEA_SK\x00\x00\x00\x00', num_keys=3))
cluster_key = cluster_keyiv_data[32:64]
cluster_iv = cluster_keyiv_data[64:80]

aes = AES.new(cluster_key, AES.MODE_CTR, counter=Counter.new(nbits=128, initial_value=int.from_bytes(cluster_iv, 'big')))
flag = aes.decrypt(ct)

print(flag.decode())
