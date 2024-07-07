possibilities = [set(range(16)) for _ in range(16)]

def all_indicies_of_char(s, c):
	return {i for i, u in enumerate(s) if u == c}

for s, r in (("aaaabbbbccccdddd", "ccaccdabdbdbbada"), ("abcdabcdabcdabcd", "bcaadbdcdbcdacab")):
	for i in range(16):
		possibilities[i] &= all_indicies_of_char(r, s[i])

assert all(len(u) == 1 for u in possibilities)
perm = [list(u)[0] for u in possibilities]

# apply perm in inverse
print('DUCTF{', ''.join("owuwspdgrtejiiud"[perm[i]] for i in range(16)), '}', sep='')