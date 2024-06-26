

# This file was *autogenerated* from the file VDF.sage
from sage.all_cmdline import *   # import sage library

_sage_const_32 = Integer(32); _sage_const_256 = Integer(256)
from time import process_time_ns
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-ld", "--leader", help="Launched by the leader", type=bool, default=False)
parser.add_argument("-vf", "--verify", help="Launched for the verification", type=bool, default=False)
args = parser.parse_args()

if args.leader == False and args.verify == False:
    # If it's launched for other reasons than consensus
    path = ""
else:
    path = "./"

load(f"{path}setup.sage")
load(f"{path}eval.sage")
load(f"{path}verify.sage")
load(f'{path}util.sage')
proof.arithmetic(False)# Speeds things up in Sage

lam = _sage_const_32  # Security level
mu = _sage_const_256  # Desired prime size (bit)
t = int(sage_eval('2^7')) # Desired puzzle complexities

if args.leader == True:
    # SETUP
    p,b,l,c,d,j = Setup(lam,mu,t)

    # EVALUATE
    P1,Q1,P1p,Q1p,E1,E1p = Eval(p,b,l,j)
    leader_tuple = (p, b, l, c, d, j, P1, Q1, P1p, Q1p, E1, E1p)

    f_data = "output_leader.sobj"
    save(leader_tuple, f_data)
    
    print("Results saved to output_leader.sobj")

if args.verify == True:
    #get back data
    leader_tuple = load("output_leader.sobj")

    p, b, l, c, d, j, P1, Q1, P1p, Q1p, E1, E1p = leader_tuple
    print("Results get from output_leader.sobj")
    
    print(f"{p}\\{b}\\{l}\\{c}\\{d}\\{j}\\{P1}\n\n{Q1}\n\n{P1p}\n\n{Q1p}\n\n{E1}\n\n{E1p}")
    #print(d*P1)
    #call Verify function
    result_verify = Verify(j, P1, Q1, P1p, Q1p, E1, E1p, p, b, c, d, l)

    if result_verify:
        print("Verification successful!")
    else:
        print("Verification failed!")

