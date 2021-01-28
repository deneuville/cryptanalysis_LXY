
def verify(pk, signatures, w, msg):
    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x^n-1, 'a');a = S.gen()
    h = S(pk)
    z1_lst, z2_lst, ch_lst = signatures
    z1 = S(z1_lst); z2 = S(z2_lst); ch = S(ch_lst)
    y = h*z1+z2
    wt_z = wt(z1)+wt(z2)
    if hash_function(n, w, msg, y) == ch.list() and wt_z <= int(2*n*tau)+Xi and wt_z >= int(2*n*tau)-Xi:
        return True
    else:
        return False