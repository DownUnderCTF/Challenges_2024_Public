from multiprocessing import Pool
from hashlib import sha256
from tqdm import tqdm
from time import time
import plyvel

PARALLEL_LEVEL = 26
N = 256 // PARALLEL_LEVEL

def precompute(offset):
    print('precomputing for offset', offset)
    start = time()
    db = DATABASES[offset]
    for x in tqdm(range(1 << PARALLEL_LEVEL)):
        m = x << (offset * PARALLEL_LEVEL)
        h = sha256(m.to_bytes(32, 'little')).digest()[:4]
        db.put(h, int(x).to_bytes(4, 'little'))
    print('took', round(time() - start, 2), 'seconds for offset', offset)

def precompute_last():
    print('precomputing for offset', N)
    start = time()
    T = 256 - N * PARALLEL_LEVEL
    db = DATABASES[N]
    for x in tqdm(range(1 << T)):
        m = x << (N * PARALLEL_LEVEL)
        h = sha256(m.to_bytes(32, 'little')).digest()[:4]
        db.put(h, int(x).to_bytes(4, 'little'))
    print('took', round(time() - start), 2, 'seconds for offset', N)

DATABASES = [plyvel.DB(f'./precomp-dbs/precomp-leveldb-{offset}', create_if_missing=True) for offset in range(N + 1)]
with Pool(3) as p:
    r = list(p.imap(precompute, list(range(N))))
precompute_last()
