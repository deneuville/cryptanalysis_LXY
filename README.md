# cryptanalysis_LXY
Cryptanalysis of Li et al. code-based signature scheme (ePrint 2020/1250)

This repository hosts a Sage implementation of the key recovery attack against the [code-based signature scheme proposed by Li, Xing and Yeo](https://eprint.iacr.org/2020/1250).

It uses the [Sage implementation of the signature scheme provided by the authors](https://github.com/zhli271828/rand_code_sign).

This is a joint work with M. Baldi, E. Persichetti, and P. Santini.

## Running the attack

Li *et al.* proposed two sets of parameters targeting 80 and 128 bits of classical security (see Table of Section 6.7 of [LXY20]).

The key recovery script is set to atatck the 80 bits of security parameter set by default.

To run the attack over the parameter set targeting 128 bits of security, the simplest way is to uncomment (removing the '#' character at the beginning of the line) lines 97 to 99.

In a nutshell, the attack works by iteratively collecting signatures, gathering information about the support of the secret key, and stop when a candidate secret key is found. 

The candidate secret key is then compared to the actual secret key used for signing. Notice that when the attack stops, either the candidate secret key corresponds to the actual secret key (full key-recovery), or the candidate secret key differs from the actual one, but still allows to forge signatures.

Note that the attack itself is rather efficient, most of the execution time is spent in the generation of the signatures.

## Example of output for each parameter set

Below are some sample cryptanalysis results for both parameter sets. (obtained with Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz running SageMath 7.5.1)

### Cryptanalysis for the first set of parameters (80 bits)
```
deneuville@deneuville$ sage attack.sage
####################################################
parameters n=66467, u=49, w=6, tau=0.23925000, Xi=70
Rejection sampling initialized
Key pair generated
Collected signature 1 in 2.30 seconds
Collected signature 2 in 76.37 seconds
Collected signature 3 in 62.79 seconds
Collected signature 4 in 57.13 seconds
Collected signature 5 in 42.11 seconds
Collected signature 6 in 11.13 seconds
====================================================
Attack successful! Number of used signatures = 6
sampling time : 78.87 seconds
keygen time : 0.54 seconds
signing time : 251.83 seconds (~ 41.97 seconds per sig)
cryptanalysis time : 14.00 seconds
Candidate secret key matches actual secret key.
====================================================
	TOTAL ELAPSED TIME: 265.84 seconds
####################################################
```

### Cryptanalysis for the first set of parameters (128 bits)
```
deneuville@deneuville$ sage attack.sage
####################################################
parameters n=248579, u=75, w=8, tau=0.24305000, Xi=135
Rejection sampling initialized
Key pair generated
Collected signature 1 in 347.49 seconds
Collected signature 2 in 1539.56 seconds
Collected signature 3 in 453.60 seconds
Collected signature 4 in 408.82 seconds
Collected signature 5 in 297.67 seconds
====================================================
Attack successful! Number of used signatures = 5
sampling time : 796.53 seconds
keygen time : 2.75 seconds
signing time : 3047.14 seconds (~ 609.43 seconds per sig)
cryptanalysis time : 38.06 seconds
Candidate secret key matches actual secret key.
====================================================
	TOTAL ELAPSED TIME: 3085.20 seconds
####################################################
```

## Technical details and reference

The technical details about the cryptanalysis will be soon provided in a complete paper. 

[LXY20] Li, Z., Xing, C. and Yeo, S. L., *A New Code Based Signature Scheme without Trapdoors*. [ePrint2020/1250](https://eprint.iacr.org/2020/1250)

