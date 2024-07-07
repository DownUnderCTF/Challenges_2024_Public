#!/usr/bin/env sage
import random
import operator
import itertools
from functools import reduce
from tqdm import tqdm
from sage.structure.coerce_maps import CallableConvertMap
from sage.groups.group_semidirect_product import GroupSemidirectProduct, GroupSemidirectProductElement
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import ChaCha20

#####
##### Copied from cbkap.sage
#####


class ColouredBurauGroupElement(GroupSemidirectProductElement):
    """
    An element of the coloured Burau group M ⋊ G
    """

    def evaluate(self, codomain):
        """
        Let τ_i be a fixed element of GF(p)^n and φ: M -> N be the evaluation
        map at τ_i. This method applies the map (φ × 1) to `self`. The result is
        coerced into an element of `codomain`
        """

        parent = self.parent()
        M, _ = parent.cartesian_factors()
        t_i = M.base_ring().gens()

        mat, perm = self.cartesian_factors()
        sub_map = {t: tau for t, tau in zip(t_i, parent.tau_i)}
        return codomain((mat.matrix().subs(sub_map), perm))

    def _act_on_(self, x, self_on_left):
        """
        The Algebraic Eraser operation, as a right group action of M ⋊ G on N × G.
        """

        if self_on_left != self.parent().act_to_right():
            raise ValueError("Group action side-mismatch")

        codomain = x.parent()
        x = x.cartesian_factors()
        actor = self.parent()
        return (actor(x) * self).evaluate(codomain)


class ColouredBurauGroup(GroupSemidirectProduct):
    """
    The coloured Burau group M ⋊ G.
    """

    def __init__(self, M, G, tau_i):
        self.M = M
        self.G = G
        self.Element = ColouredBurauGroupElement
        self.tau_i = tau_i
        super().__init__(M, G, twist=self._twist_, print_tuple=True, act_to_right=False)

    def _twist_(self, g, a):
        """
        Applies the twist homomorphism given by the permutation action of G
        on the indeterminates {t_1, ... t_n}.
        """

        t_i = self.M.base_ring().gens()

        sub_map = {t: gt for t, gt in zip(t_i, g(t_i))}
        return a.subs(sub_map)

    def _coerce_map_from_(self, S):
        """
        Extends ``GroupSemidirectProduct` to enable coercion from the Braid
        group on n strands via the coloured Burau representation.
        """

        if S == BraidGroup(self.G.degree()):

            def f(braid_element):
                cb = self._coloured_burau_matrix_(braid_element)
                perm = braid_element.permutation(self.G)
                return self((cb, perm))

            return CallableConvertMap(S, self, f, parent_as_first_arg=False)
        return None

    def gens(self):
        Bn = BraidGroup(self.G.degree())
        return tuple(self(b) for b in Bn.gens())

    def random_element(self, length, gens=None):
        if gens is None:
            gens = self.gens()

        syllables = list(gens) + [b.inverse() for b in gens]
        word = prod(random.choices(syllables, k=length))
        return word

    def _coloured_burau_matrix_(self, braid_element):
        t_i = self.M.base_ring().gens()
        b_i = braid_element.parent().gens()

        accumulator = self.M.one()
        for artin_generator, exponent in braid_element.syllables():
            i = b_i.index(artin_generator)
            coloured_burau = (artin_generator**exponent).burau_matrix(reduced="simple").subs(t=t_i[i])
            accumulator *= coloured_burau

        return accumulator


#####
##### Solve script
#####


def construct_matrix_equation(LHS, RHS):
    mons = LHS.base_ring().gens()
    K = LHS.base_ring().base_ring()
    return matrix(K, [[e.monomial_coefficient(monomial) for monomial in mons] for e in (LHS - RHS).list()])


def minkwitz_1998(A_perms, target):
    S = PermutationGroup(A_perms)  # with left action
    m = S.degree()
    k = list(range(1, m + 1))

    # Build up a table of short word generators for each level of the stabilizer chain
    B = {i: dict() for i in k}
    syllables = list(A_perms) + [a.inverse() for a in A_perms]
    for l in range(1, 3):
        words = list(itertools.product(syllables, repeat=l))
        for w in tqdm(words, desc="Enumerating words"):
            g = reduce(operator.mul, w)
            for i in k:
                x = g(i)
                # Propagate up
                for j in range(1, i):
                    if x not in B[j] or len(w) < len(B[j][x]):
                        B[j][x] = w
                if x not in B[i] or len(w) < len(B[i][x]):
                    B[i][x] = w
                    break
                else:
                    w_ = B[i][x]
                    w = w + tuple(s.inverse() for s in reversed(w_))
                    g = g * reduce(operator.mul, w_).inverse()

    # Walk along [1,...m] and reverse transpositions to factorize `target` over
    # A_perm. If needed: we can repeat the process with different starting
    # pertubations to get even shorter factorizations.
    inverse = tuple()
    curr = target
    for i in k:
        if curr(i) > i:
            inverse = B[i][curr(i)] + inverse
            curr = curr * reduce(operator.mul, B[i][curr(i)]).inverse()

    # Convert the factorisation into indices and exponents
    assert reduce(operator.mul, inverse) == target
    index_map = {a: i for i, a in enumerate(A_perms)}
    i_epsilon = []
    for s in inverse:
        if s in index_map:
            i_epsilon.append((index_map[s], 1))
        else:
            i_epsilon.append((index_map[s.inverse()], -1))
    return i_epsilon


def decrypt_flag(shared_secret, nonce, ct):
    # Flatten matrix into a reasonable byte-string
    secret_coefficients = shared_secret.change_ring(ZZ).list()
    password = b"".join("{:03x}".format(coeff).encode("ascii") for coeff in secret_coefficients)

    # Derive symmetric key
    salt = b"DownUnderCTF 2024"
    key = PBKDF2(password, salt, 32, count=1000000)

    # Decrypt flag
    cipher = ChaCha20.new(key=key, nonce=nonce)
    pt = cipher.decrypt(ct)
    print(pt)


n = 16
p = 743
L = LaurentPolynomialRing(GF(p), "t", n)
L.inject_variables()

K = GF(p)
M = GL(n - 1, L)
N = GL(n - 1, K)
G = SymmetricGroup(n)

load("../publish/output.sage")

# Cleanup output a bit
tau_i = tuple(K(tau) for tau in tau_i)
MG = ColouredBurauGroup(M, G, tau_i)
NG = N.cartesian_product(G)
kappa = matrix(K, kappa)
A = [MG((mat, perm)) for mat, perm in tqdm(A, desc="converting A")]
alice = NG((alice_public_matrix, alice_public_perm))
bob = NG((bob_public_matrix, bob_public_perm))

# Find alpha = (a, 1) in A with a != 1.
o, alpha = min((cand[1].order(), cand) for cand in A)
alpha = alpha**o
assert alpha[0] != M.one()

# Phase 1: Construct the matrix equations
# 1: d phi(alpha) = q phi(^h alpha)q^-1d
# 2: d gamma = gamma d
#
# This gives us Bob's secret matrix d up to a scalar.
q = bob[0]
R = PolynomialRing(K, (n - 1) ** 2, "d")
ds = R.gens()
d = matrix(R, [ds[i : i + n - 1] for i in range(0, (n - 1) ** 2, n - 1)])
LHS1 = d * alpha.evaluate(NG)[0]
RHS1 = (bob * alpha)[0] * q.inverse() * d
Eq1 = construct_matrix_equation(LHS1, RHS1)
Eq2 = construct_matrix_equation(d * kappa, kappa * d)
candidate_d = Eq1.stack(Eq2).right_kernel().basis_matrix().list()
candidate_d = matrix(K, [candidate_d[i : i + n - 1] for i in range(0, (n - 1) ** 2, n - 1)])

# Phase 2: express g as a short word of A_perms using Minkwitz's algorithm
A_perms = [x[1] for x in A]
g = G(alice_public_perm)

i_epsilon = minkwitz_1998(A_perms, g)

h = G(bob_public_perm)
phi_delta = reduce(operator.mul, tqdm([A[i] ** e for i, e in i_epsilon], desc="calculating phi_delta"), NG.one())
phi_h_delta = phi_delta * MG((M.one(), h))
shared_secret = candidate_d * alice[0] * phi_delta[0].inverse() * candidate_d.inverse() * q * phi_h_delta[0]

decrypt_flag(shared_secret, bytes.fromhex(nonce), bytes.fromhex(ct))
