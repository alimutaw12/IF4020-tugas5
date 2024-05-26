import random
import hashlib
from sympy import nextprime

def generate_ds_keys(a, p, q):
    s = random.randint(1, q)
    v = pow(a, s, p)
    return s, v

def sign_message(s, message, a, p ,q):
    r = random.randint(1, q)
    x = pow(a, r, p)
    e = int(hashlib.sha256(message.encode() + str(x).encode()).hexdigest(), 16) % q
    y = (r + s * e) % q
    return e, y