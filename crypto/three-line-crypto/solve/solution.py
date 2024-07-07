"""
This uses a hill climbing approach.
Use gen_www.sh to get a corpus of english text for digrams.

We do the following:
	Initialize key to a random value;
	Iterate over every 2-mutation (setting two key positions to two values)
	If the 'englishness' of the text improves, measured by Bhattacharyya coefficient, save it
	Repeat

With high probability this will converge on the answer. Takes 10-20 min to run on my PC with pypy3.
"""

import random
import math
from collections import Counter
import sys

def display(b):
	return bytes([c if 32 <= c <= 126 else ord('.') for c in b])

def digrams(x):
	return [x[i:i+2] for i in range(len(x)-2)]

x = digrams(open('www.txt', 'rb').read())
print(len(x))
u = Counter(x)

FREQUENCY_TABLE = {i : u.get(i) / len(x) for i in set(x)}

def englishness(a):
    c = Counter(digrams(a))
    total_characters = len(a)
    coefficient = sum(
        math.sqrt(FREQUENCY_TABLE.get(char, 0) * y/total_characters)
        for char, y in c.items()
    )

    return coefficient

def run_encryption(key, ct):
	pt = []
	y = 0
	for x in ct:
		d = key[y % 16] ^ x
		pt.append(d)
		y = d
	return bytes(pt)

def gen_key():
	return [random.randint(0, 255) for _ in range(16)]

text = open('../src/passage.enc.txt', 'rb').read()

import itertools

key_champion = gen_key()
champion = 0
l = list(itertools.product(range(256), range(16), range(256), range(16)))

try:
	while 1:
		random.shuffle(l)
		for a,b,c,d in l:
			key = key_champion[:]
			key[b] = a
			key[d] = c
			plain = run_encryption(key, text)
			if englishness(plain) > champion:
				champion = englishness(plain)
				key_champion = key
				print(champion, display(plain[:100]))
				sys.stdout.flush()
				break
		else:
			break
finally:
	sys.stdout.buffer.write(run_encryption(key_champion, text))
	sys.stdout.flush()
