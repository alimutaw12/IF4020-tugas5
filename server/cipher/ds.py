import hashlib
import random
from sympy import nextprime

def generate_global_keys():
    rand = random.randint(10, 50)

    q = nextprime(rand)
    p = q
    while True:
        p = nextprime(p)
        if ((p - 1) % q == 0):
            break

    a = 2
    while True:
        aq = a ** q
        if ((aq - 1) % p == 0):
            break
        else:
            a += 1
    
    return {"a": a, "p": p, "q": q}