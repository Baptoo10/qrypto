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
Fpx.<x> = Fp[]
k = int((l-1)/2)
_.<I> = GF(p)[]
K.<i> = GF(p^2, modulus=I^2+1)
Fpk.<a> = GF(p^k, x^k+2)

E1 = EllipticCurve(K, [0, E1a2, 0, E1a4, E1a6])
E1p = EllipticCurve(K, [0, E1pa2, 0, E1pa4, E1pa6])

P10 = int(fline[9])*i+int(fline[10])
P11 = int(fline[11])*i+int(fline[12])
P1 = E1(P10, P11); P1
print(type(P10))
print(type(P1))
print(type(E1))

Q10 = int(fline[13])*i+int(fline[14])
Q11 = int(fline[15])*i+int(fline[16])
Q1 = E1((Q10, Q11))

P1p0 = int(fline[17])*i+int(fline[18])
P1p1 = int(fline[19])*i+int(fline[20])
P1p = E1p(P1p0, P1p1)

Q1p0 = int(fline[21])*i+int(fline[22])
Q1p1 = int(fline[23])*i+int(fline[24])
Q1p = E1p(Q1p0, Q1p1)
    
result_verify = Verify(j, P1, Q1, P1p, Q1p, E1, E1p, p, b, c, d, l)

if result_verify:
    print("Verification successful!")
else:
    print("Verification failed!")