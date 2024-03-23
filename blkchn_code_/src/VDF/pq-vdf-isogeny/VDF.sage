from time import process_time_ns
import argparse

load("setup.sage")
load("eval.sage")
load("verify.sage")
load('util.sage')
proof.arithmetic(False)# Speeds things up in Sage


parser = argparse.ArgumentParser()
parser.add_argument("-lambda", "--lam", help="Security level", type=int, default=32)
parser.add_argument("-mu", "--mu", help="Desired prime size", type=int, default=256)
parser.add_argument("-t", "--time", help="Desired puzzle complexities",type=str, default='2^7')
args = parser.parse_args()

lam = args.lam
mu = args.mu
t = int(sage_eval(args.time))
 
# SETUP
p,b,l,c,d,j = Setup(lam,mu,t)

# EVALUATE
P1,Q1,P1p,Q1p,E1,E1p = Eval(p,b,l,j)

# VERIFICATION
Verify(j,P1,Q1,P1p,Q1p,E1,E1p,p,b,c,d,l)

