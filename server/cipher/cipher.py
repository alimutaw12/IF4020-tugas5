from cipher.operations import *
from cipher.helper import *
from datetime import datetime
import time    
import hashlib

def encrypt(plaintext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10, mode='ecb'):
    # start timer
    start = time.time()

    print(plaintext)

    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    plaintext = bytes(plaintext)

    # add padding to plaintext to be multiple of 16
    plaintext = plaintext + bytes(16 - len(plaintext) % 16)
    
    # split plaintext into blocks of 16 bytes
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    # make 10 keys
    keys = keySchedule(key, num_rounds)

    blocks = CBC(blocks, keys, IV)
    print(blocks)

    # join blocks of 16 bytes into one ciphertext
    ciphertext = b''
    for i in range(len(blocks)):
        ciphertext += blocks[i]
    progressbar(11, 11, 11)

    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return ciphertext

def decrypt(ciphertext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=10, mode='ecb'):
    #start timer
    start = time.time()

    ciphertext = charToBytes(ciphertext)
    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    ciphertext = bytes(ciphertext)
    
    # split ciphertext into blocks of 16 bytes
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    # make 10 keys
    keys = keySchedule(key, num_rounds)
    keys = keys[::-1]

    resultingBlock = CBC_decrypt(blocks, keys, IV)

    # join blocks of 16 bytes into one ciphertext
    plaintext = b''
    for i in range(len(resultingBlock)):
        plaintext += resultingBlock[i]
    progressbar(11, 11, 11)
    
    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return plaintext.rstrip(b'\x00')