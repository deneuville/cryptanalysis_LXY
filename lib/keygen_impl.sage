import random

# n is the ring degree
def keygen(n, u, seed):
    random.seed(seed)
    s1_vec = gen_random_fix_vec(n, u)
    s2_vec = gen_random_fix_vec(n, u)

    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x^n-1, 'a');a = S.gen()
    s1 = S(s1_vec); s2 = S(s2_vec)
    pk = s2/s1
    pk_lst = pk.list()
    sk = (s1, s2)
    sk_lst = s1.list(), s2.list()
    return pk_lst, sk_lst
