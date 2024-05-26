import random

def generate_ds_keys(a, p, q):
    s = random.randint(1, q)
    v = pow(a, s, p)
    return s, v