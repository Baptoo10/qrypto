

# This file was *autogenerated* from the file VDF.sage
from sage.all_cmdline import *   # import sage library

_sage_const_32 = Integer(32); _sage_const_256 = Integer(256)
from time import process_time_ns
import argparse

load("setup.sage")
load("eval.sage")
load("verify.sage")
load('util.sage')
proof.arithmetic(False)# Speeds things up in Sage


parser = argparse.ArgumentParser()
parser.add_argument("-lambda", "--lam", help="Security level", type=int, default=_sage_const_32 )
parser.add_argument("-mu", "--mu", help="Desired prime size", type=int, default=_sage_const_256 )
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


