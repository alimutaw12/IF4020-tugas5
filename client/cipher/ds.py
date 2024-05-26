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

def verify_signature(v, message, signature, a, p, q):
    e, y = signature
    x_a = (pow(a, y, p) * pow(v, q - e, p)) % p
    e_a = int(hashlib.sha256(message.encode() + str(x_a).encode()).hexdigest(), 16) % q
    return e == e_a