import random

def sign(n, tau, w, reject_rate, M, pk, sk, msg):
    random.seed(msg)
    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x^n-1, 'a');a = S.gen()
    h = S(pk)
    s1_lst, s2_lst = sk
    s1 = S(s1_lst); s2 = S(s2_lst)
    counter = 0
    while True:
        counter = counter + 1
        if counter > 1000:
            print ('Run signing too many times')
        
        e1_vec = gen_binom_vec(n, tau)
        e2_vec = gen_binom_vec(n, tau)
        e1 = S(e1_vec); e2 = S(e2_vec)
        y = h*e1+e2
        ch_vec = hash_function(n, w, msg, y)
        ch = S(ch_vec)

	print "length e1 = %d" % len(e1.list())
	print "weight e1 = %d" % e1.list().count(1)
        print "length e2 = %d" % len(e2.list())
        print "weight e2 = %d" % e2.list().count(1)


        z1=s1*ch+e1; z2=s2*ch+e2
        wt_z =  wt(z1)+wt(z2)
        
        if wt_z < int(2*n*tau)-Xi or wt_z > int(2*n*tau)+Xi:
            continue

        if random.random() < reject_rate[wt_z]/M:
	    print ch.list()
            return z1.list(),z2.list(),ch.list()
