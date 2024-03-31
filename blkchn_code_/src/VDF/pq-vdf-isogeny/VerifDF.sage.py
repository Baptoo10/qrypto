

# This file was *autogenerated* from the file ../VDF/pq-vdf-isogeny/VerifDF.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0); _sage_const_9 = Integer(9); _sage_const_10 = Integer(10); _sage_const_11 = Integer(11); _sage_const_12 = Integer(12); _sage_const_13 = Integer(13); _sage_const_14 = Integer(14); _sage_const_15 = Integer(15); _sage_const_16 = Integer(16); _sage_const_17 = Integer(17); _sage_const_18 = Integer(18); _sage_const_19 = Integer(19); _sage_const_20 = Integer(20); _sage_const_21 = Integer(21); _sage_const_22 = Integer(22); _sage_const_23 = Integer(23); _sage_const_24 = Integer(24)
from time import process_time_ns
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-ld", "--leader", help="Launched by the leader", type=bool, default=False)
parser.add_argument("-vf", "--verify", help="Launched for the verification", type=bool, default=False)
args = parser.parse_args()


path = "../VDF/pq-vdf-isogeny/"

load(f"{path}setup.sage")
load(f"{path}eval.sage")
load(f"{path}verify.sage")
load(f'{path}util.sage')
proof.arithmetic(False)# Speeds things up in Sage


#extracting values from leader_result.sage file
with open("leader_result.sage", "r") as f:
    sage_result = f.read()

exec(sage_result)

fline = sage_result.split("\n")
#remakes structures
Fp = GF(p)
Fpx = Fp['x']; (x,) = Fpx._first_ngens(1)
k = int((l-_sage_const_1 )/_sage_const_2 )
_ = GF(p)['I']; (I,) = _._first_ngens(1)
K = GF(p**_sage_const_2 , modulus=I**_sage_const_2 +_sage_const_1 , names=('i',)); (i,) = K._first_ngens(1)
Fpk = GF(p**k, x**k+_sage_const_2 , names=('a',)); (a,) = Fpk._first_ngens(1)

E1 = EllipticCurve(K, [_sage_const_0 , E1a2, _sage_const_0 , E1a4, E1a6])
E1p = EllipticCurve(K, [_sage_const_0 , E1pa2, _sage_const_0 , E1pa4, E1pa6])

P10 = int(fline[_sage_const_9 ])*i+int(fline[_sage_const_10 ])
P11 = int(fline[_sage_const_11 ])*i+int(fline[_sage_const_12 ])
P1 = E1(P10, P11); P1
print(type(P10))
print(type(P1))
print(type(E1))

Q10 = int(fline[_sage_const_13 ])*i+int(fline[_sage_const_14 ])
Q11 = int(fline[_sage_const_15 ])*i+int(fline[_sage_const_16 ])
Q1 = E1((Q10, Q11))

P1p0 = int(fline[_sage_const_17 ])*i+int(fline[_sage_const_18 ])
P1p1 = int(fline[_sage_const_19 ])*i+int(fline[_sage_const_20 ])
P1p = E1p(P1p0, P1p1)

Q1p0 = int(fline[_sage_const_21 ])*i+int(fline[_sage_const_22 ])
Q1p1 = int(fline[_sage_const_23 ])*i+int(fline[_sage_const_24 ])
Q1p = E1p(Q1p0, Q1p1)
    
result_verify = Verify(j, P1, Q1, P1p, Q1p, E1, E1p, p, b, c, d, l)

if result_verify:
    print("Verification successful!")
else:
    print("Verification failed!")

