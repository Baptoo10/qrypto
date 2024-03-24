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

    print(p, "\n", j)

    # EVALUATE
    P1,Q1,P1p,Q1p,E1,E1p = Eval(p,b,l,j)

    result = [str(P1), str(Q1), str(P1p), str(Q1p)]

    str_result = ""
    for point in result:
        lpoint = point[1:-1].split(" : ")[:-1]
        for coord in lpoint:
            lint = coord.split("*i + ")
            str_result += lint[0] + "\n" + lint[1] + "\n"
    
    # write the results to a file
    with open("leader_result.sage", "w") as f:
        f.write("# Results of Setup function\n")
        f.write("p = {}\n".format(p))
        f.write("b = {}\n".format(b))
        f.write("l = {}\n".format(l))
        f.write("c = {}\n".format(c))
        f.write("d = {}\n".format(d))
        f.write("j = {}\n\n".format(j))

        f.write("# Results of Eval function\n")
        f.write(str_result)
        f.write("E1a2 = {}\n".format(E1.a2()))
        f.write("E1a4 = {}\n".format(E1.a4()))
        f.write("E1a6 = {}\n".format(E1.a6()))
        f.write("E1pa2 = {}\n".format(E1p.a2()))
        f.write("E1pa4 = {}\n".format(E1p.a4()))
        f.write("E1pa6 = {}\n".format(E1p.a6()))

    print("Results saved to leader_result.sage")
    print(f"{P1}\n\n{Q1}\n\n{P1p}\n\n{Q1p}\n\n{E1}\n\n{E1p}\n\n")
    print(type(P1))
    print(type(E1))

if args.verify == True:
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
    
    #print(f"{P1}\n\n{Q1}\n\n{P1p}\n\n{Q1p}\n\n{E1}\n\n{E1p}")
    #print(d*P1)
    #call Verify function
    result_verify = Verify(j, P1, Q1, P1p, Q1p, E1, E1p, p, b, c, d, l)

    if result_verify:
        print("Verification successful!")
    else:
        print("Verification failed!")

