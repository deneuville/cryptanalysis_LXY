
import random
import hashlib
import numpy
import time

###The following functions were written by the authors
#########################################################################################

def gen_random_fix_vec(n, w):
    vec = [1]*w+(n-w)*[0]
    random.shuffle(vec)
    return vec

def gen_binom_vec(n, tau):
    return [1 if random.random()<tau else 0 for _ in range(n)]

def wt(poly):
    return poly.list().count(1)

def hash_function(n, w, msg, y):
    r = int(hashlib.sha512((msg+str(y)).encode('utf-8')).hexdigest(), base=16)
    s = set()
    while len(s) < w and r != 0:
        s.add(r%n)
        r = r//n
    if len(s) >= w:
        lst = n*[0]
        for ele in s:
            lst[ele] = 1
        return lst
    else:
        print ('Error in hash function')

        
#################  Key generation   ########################################

# n is the ring degree
def keygen(n, u, seed):
    random.seed(seed)
    s1_vec = gen_random_fix_vec(n, u)
    s2_vec = gen_random_fix_vec(n, u)

    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x**n-1, 'a');a = S.gen()
    s1 = S(s1_vec); s2 = S(s2_vec)
    pk = s2/s1
    pk_lst = pk.list()
    sk = (s1, s2)
    sk_lst = s1.list(), s2.list()
    return pk_lst, sk_lst

###############################
###Signature generation

def sign(n, tau, w, reject_rate, M, pk, sk, msg):
    random.seed(msg)
    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x**n-1, 'a');a = S.gen()
    h = S(pk)
    s1_lst, s2_lst = sk
    s1 = S(s1_lst); s2 = S(s2_lst)
    counter = 0
    while True:
        counter = counter + 1
        if counter > 1000:
            print ('Run signing too many times')
#        print(counter)
        e1_vec = gen_binom_vec(n, tau)
        e2_vec = gen_binom_vec(n, tau)
        e1 = S(e1_vec); e2 = S(e2_vec)
        y = h*e1+e2
        ch_vec = hash_function(n, w, msg, y)
        ch = S(ch_vec)

        z1=s1*ch+e1; z2=s2*ch+e2
        wt_z =  wt(z1)+wt(z2)
        
        if wt_z < int(2*n*tau)-Xi or wt_z > int(2*n*tau)+Xi:
            continue

        if random.random() < reject_rate[wt_z]/M:
            return z1.list(),z2.list(),ch.list()

##############################################################################
############################# OUR ATTACK  ####################################

def fromPosToVec(pos,n):
    vec = [0]*n
    for i in pos:
        vec[i]=1
    return vec


n = 66467; u=49; w=6; tau=0.23925; Xi=70  #scheme parameters
params_id = 80 # security level parameter
seed = 0 #seed for key generation


#n = 248579; u=75; w=8; tau=0.24305; Xi=135  #scheme parameters
#params_id = 128 # security level parameter
#seed = 0 #seed for key generation

print("####################################################")

# print parameters
print('parameters n=%d, u=%d, w=%d, tau=%.8f, Xi=%d' % (n, u, w, tau, Xi))

#Compute parameters, precompute values for rejection sampling phase

# N is the code length, U is the secret key weight, s is the weight of shifted vector.
N=2*n; U=2*u; s=2*u*w

# load libraries
lib_path = './lib/'
load(lib_path + 'rejection_sampling.py')


#Compute parameters for rejection sampling
sampling_time=time.time()
rate_dict, M = rejection_sampling_rate(N, s, tau, Xi)
stop = time.time()
sampling_time = stop-sampling_time
print("Rejection sampling initialized")

#Key generation
keygen_time=time.time()
pk,sk = keygen(n,u,seed)
stop = time.time()
keygen_time = stop-keygen_time
print("Key pair generated")
#print("Key generation done, starting collecting signatures")

msg_space = Set(Integers(2**30)) #message space

occurrences_e0 = vector(ZZ,n)
occurrences_e1 = vector(ZZ,n)

num_signatures = 0 #number of considered signatures
flag_attack = 0 #flag_attack = 1 when the secret key is recovered

e0_supp = vector(vector(sk[0]).support())  #support of first poly in the secret key
e1_supp = vector(vector(sk[1]).support())  #support of second poly in the secret key

total_signing_time=time.time()
total_signing_time-=total_signing_time
total_cryptanalysis_time=time.time()
total_cryptanalysis_time-=total_cryptanalysis_time
total_exec_time=time.time()

#####Test attack
while flag_attack == 0:
    
    num_signatures += 1
    #select a random message and sign it
    msg = str(msg_space.random_element())
#    print("Still not enough, collecting another signature")
#    print("=======================================")
    signing_time=time.time()
    z1,z2,ch = sign(n, tau, w, rate_dict, M, pk, sk, msg)    
    stop = time.time()
    tmp=stop-signing_time
    total_signing_time+=tmp
    print("Collected signature %d in %.2f seconds"%(num_signatures,tmp))
#    print("Number of collected signatures = "+str(num_signatures))
    
    cryptanalysis_time=time.time()
    #Analyze the signature
    supp_ch = vector(ch).support()
    supp_z1 = vector(z1).support()
    supp_z2 = vector(z2).support()
    
    #Update number of occurences
    for j in supp_ch:
        for t in supp_z1:
            np = (t-j)%n
            occurrences_e0[np]+=1
        for t in supp_z2:
            np = (t-j)%n
            occurrences_e1[np]+=1    
            
    #Select positions with the highest number of occurrences
    perm_e0 = numpy.argsort(occurrences_e0)
    guess_pos_0 = vector(perm_e0[n-u:n])
    guess_pos_0 = vector(sorted(guess_pos_0)).row()

    perm_e1 = numpy.argsort(occurrences_e1)
    guess_pos_1 = vector(perm_e1[n-u:n])
    guess_pos_1 = vector(sorted(guess_pos_1)).row()

    R=PolynomialRing(GF(2), 'x', implementation='NTL');x=R.gen();S=R.quotient(x**n-1, 'a');a = S.gen()

    guessed_e0 = S(fromPosToVec(guess_pos_0.list(), n))
    guessed_e1 = S(fromPosToVec(guess_pos_1.list(), n))

    # test whether guessed_e0 is invertible
    g, _, a = parent(guessed_e0).modulus().xgcd(guessed_e0._polynomial)
    if g.degree()==0: # if guessed_e0 is invertible
        candidate = guessed_e1/guessed_e0
        if pk == candidate.list():
            flag_attack = 1
            stop=time.time()
            total_cryptanalysis_time+=stop-cryptanalysis_time
            print("====================================================")
            print("Attack successful! Number of used signatures = %d" % num_signatures)
            print("sampling time : %.2f seconds" % sampling_time)
            print("keygen time : %.2f seconds" % keygen_time)
            print("signing time : %.2f seconds (~ %.2f seconds per sig)" % (total_signing_time, total_signing_time/(1.*num_signatures)))
            print("cryptanalysis time : %.2f seconds" % total_cryptanalysis_time)

            if guessed_e0.list()!=sk[0] or guessed_e1.list()!=sk[1]:
                print("Candidate secret key differs from actual secret key.")
            else:
        		print("Candidate secret key matches actual secret key.")

            print("====================================================")
            print("\tTOTAL ELAPSED TIME: %.2f seconds" % (stop-total_exec_time))
            print("####################################################")
        else:
            stop=time.time()
            total_cryptanalysis_time+=stop-cryptanalysis_time
    else:
        stop=time.time()
        total_cryptanalysis_time+=stop-cryptanalysis_time

