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
    path = "../VDF/pq-vdf-isogeny/"

load(f"{path}setup.sage")
load(f"{path}eval.sage")
load(f"{path}verify.sage")
load(f'{path}util.sage')
proof.arithmetic(False)# Speeds things up in Sage

lam = 32 # Security level
mu = 256 # Desired prime size (bit)
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

    p1, b1, l1, c1, d1, j1, P11, Q11, P1p1, Q1p1, E11, E1p1 = leader_tuple
    print("Results get from output_leader.sobj")
    
    #print(f"{P1}\n\n{Q1}\n\n{P1p}\n\n{Q1p}\n\n{E1}\n\n{E1p}")
    #print(d*P1)
    #call Verify function
    result_verify = Verify(j1, P11, Q11, P1p1, Q1p1, E11, E1p1, p1, b1, c1, d1, l1)

    if result_verify:
        print("Verification successful!")
    else:
        print("Verification failed!")
