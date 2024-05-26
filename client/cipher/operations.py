import numpy as np
from cipher.helper import *

a = -3
b = 2455155546008943817740293915197451784769108058161191238065
p = 6277101735386680763835789423207666416083908700390324961279

# Fungsi untuk operasi modulus
def modinv(a, p):
    """Menghitung invers modular dari a mod p"""
    return pow(a, p - 2, p)

def ec_add(P, Q):
    """Penambahan titik pada kurva eliptik"""
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    if P == Q:
        lmbda = (3 * P[0] ** 2 + a) * modinv(2 * P[1], p) % p
    else:
        lmbda = (Q[1] - P[1]) * modinv(Q[0] - P[0], p) % p
    x_r = (lmbda ** 2 - P[0] - Q[0]) % p
    y_r = (lmbda * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

def scalar_mult(k, P):
    """Perkalian skalar pada titik P"""
    N = P
    Q = (None, None)
    while k:
        if k & 1:
            Q = ec_add(Q, N)
        N = ec_add(N, N)
        k >>= 1
    return Q

def keySchedule(key, num=10):
    # 128 bit key
    # generates num-1 additional keys, with original key as first key
    keys = []
    if num > 0:
        keys.append(key)
    for i in range(num-1):
        key = r4Shift(key)
        key = S1Process(key)
        keys.append(key)
    return keys

def S1Process(x):
    # process block of 16 bytes (or 128 bit) through S1-box
    S1 = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]

    return bytes([(S1[x[i] >> 4][x[i] & 0xf]) for i in range(16)])

def S1Process_reverse(x):
    # inverse of S1-box
    S1_inv = [
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    ]

    return bytes([(S1_inv[x[i] >> 4][x[i] & 0xf]) for i in range(16)])

def PProcess(x, matrix, matrix2):
    bins = np.zeros(128, dtype=np.uint8)
    for i in range(16):
        for j in range(8):
            bins[i*8+j] = int(hex2bin(x[i])[j])
    
    split_bins = [[], [], [], []]

    j = -1
    for i in range(128):
        if i % 32 == 0:
            j = j + 1
        split_bins[j].append(bins[i])

    # permutation
    split_bins2 = [[], [], [], []]
    for i in range(len(split_bins)):
        for j in range(len(split_bins[i])):
            if i % 2 == 0:
                split_bins2[i].append(split_bins[i][matrix[j]])
            else:
                split_bins2[i].append(split_bins[i][matrix2[j]])

    bins2 = []
    for i in range(len(split_bins2)):
        for j in range(len(split_bins2[i])):
            bins2.append(split_bins2[i][j])
    
    hexa = b''
    for i in range(16):
        byte = int(bin2hex(''.join(str(x) for x in bins2[i*8:(i+1)*8])), 16)
        hexa += bytes([byte])

    return hexa

def P1Process(x):
    # process block of 16 bytes (or 128 bit) through P1box
    P1 = [
        0x0E, 0x1C, 0x09, 0x12, 0x13, 0x14, 0x1B, 0x1A, 0x11, 0x1F, 0x17, 0x0B, 
        0x05, 0x0C, 0x0F, 0x04, 0x06, 0x15, 0x19, 0x08, 0x0D, 0x00, 0x1E, 0x02, 
        0x1D, 0x07, 0x16, 0x03, 0x01, 0x0A, 0x10, 0x18
    ]

    P2 = [
        0x02, 0x07, 0x14, 0x12, 0x17, 0x0E, 0x1F, 0x10, 0x04, 0x19, 0x0A, 0x0F, 
        0x1D, 0x09, 0x03, 0x0B, 0x15, 0x18, 0x01, 0x0C, 0x00, 0x1B, 0x05, 0x16, 
        0x1E, 0x13, 0x08, 0x11, 0x06, 0x1A, 0x0D, 0x1C
    ]

    # 20, 18, 0, 14, 8, 22, 28, 1, 26, 13, 10, 15, 19, 30, 5, 11, 7, 27, 3, 25, 2, 
    # 16, 23, 4, 17, 9, 29, 21, 31, 12, 24, 6

    # 00: 0, 01: 1, 02: 2, 03: 3, 04: 4, 05: 5, 06: 6, 07: 7, 08: 8, 09: 9, 0A: 10, 
    # 0B: 11, 0C: 12, 0D: 13, 0E: 14, 0F: 15, 10: 16, 11: 17, 12: 18, 13: 19, 14: 20, 
    # 15: 21, 16: 22, 17: 23, 18: 24, 19: 25, 1A: 26, 1B: 27, 1C: 28, 1D: 29, 1E: 30, 1F: 31

    # 14, 28, 9, 18, 19, 20, 27, 26, 17, 31, 23, 11, 5, 12, 
    # 15, 4, 6, 21, 25, 8, 13, 0, 30, 2, 29, 7, 22, 3, 1, 10, 16,24

    return PProcess(x, P1, P2)

def P1Process_reverse(x):
    # process block of 16 bytes (or 128 bit) through P1InverseBox
    P1_inverse = [
        0x15, 0x1C, 0x17, 0x1B, 0x0F, 0x0C, 0x10, 0x19, 0x13, 0x02, 0x1D, 0x0B,
        0x0D, 0x14, 0x00, 0x0E, 0x1E, 0x08, 0x03, 0x04, 0x05, 0x11, 0x1A, 0x0A,
        0x1F, 0x12, 0x07, 0x06, 0x01, 0x18, 0x16, 0x09
    ]

    P2_inverse = [
        0x14, 0x12, 0x00, 0x0E, 0x08, 0x16, 0x1C, 0x01, 0x1A, 0x0D, 0x0A, 0x0F,
        0x13, 0x1E, 0x05, 0x0B, 0x07, 0x1B, 0x03, 0x19, 0x02, 0x10, 0x17, 0x04, 
        0x11, 0x09, 0x1D, 0x15, 0x1F, 0x0C, 0x18, 0x06
    ]

    # 00: 0, 01: 1, 02: 2, 03: 3, 04: 4, 05: 5, 06: 6, 07: 7, 08: 8, 09: 9, 0A: 10, 
    # 0B: 11, 0C: 12, 0D: 13, 0E: 14, 0F: 15, 10: 16, 11: 17, 12: 18, 13: 19, 14: 20, 
    # 15: 21, 16: 22, 17: 23, 18: 24, 19: 25, 1A: 26, 1B: 27, 1C: 28, 1D: 29, 1E: 30, 1F: 31

    # 21, 28, 23, 27, 15, 12, 
    # 16, 25, 19, 2, 29, 
    # 11, 13, 20, 0, 14, 
    # 30, 8, 3, 4, 5,
    # 17, 26, 10, 31, 18,
    # 7, 6, 1, 24, 22,
    # 9

    return PProcess(x, P1_inverse, P2_inverse)

def r4Shift(x):
    # 4-byte (32 bits) right shift of 16 bytes number (or 128 bit)
    num = int.from_bytes(x, byteorder='big')
    return (((num >> 32) & 0xffffffffffffffffffffffff) | (num << 96) & (0xffffffff << 96)).to_bytes(16, byteorder='big')

def r4Shift_reverse(x):
    # reverse of r4Shift
    num = int.from_bytes(x, byteorder='big')
    return (((num << 32) & (0xffffffffffffffffffffffff << 32)) | ((num >> 96) & 0xffffffff)).to_bytes(16, byteorder='big')

def progressbar(current_value,total_value,bar_lengh): 
    percentage = int((current_value/total_value)*100)                                            
    progress = int((bar_lengh * current_value ) / total_value)                                   
    loadbar = "Progress: {}%".format(percentage)
    print(loadbar) 

def ECB(blocks, keys, IV):
    print('mode ECB')
    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(blocks)):
            blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            
            blocks[i] = S1Process(blocks[i])
            blocks[i] = r4Shift(blocks[i])
            blocks[i] = P1Process(blocks[i])
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def ECB_decrypt(blocks, keys, IV):
    print('mode ECB')
    resultingBlock = blocks.copy()
    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(resultingBlock)):
            resultingBlock[i] = P1Process_reverse(blocks[i])
            resultingBlock[i] = r4Shift_reverse(resultingBlock[i])
            resultingBlock[i] = S1Process_reverse(resultingBlock[i])
            
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")

        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1
    
    return resultingBlock

def CBC(blocks, keys, IV):
    print('mode CBC')
    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(blocks)):
            if i == 0:
                blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            else:
                blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
            blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            
            blocks[i] = S1Process(blocks[i])
            blocks[i] = r4Shift(blocks[i])
            blocks[i] = P1Process(blocks[i])
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def CBC_decrypt(blocks, keys, IV):
    print('mode CBC')
    resultingBlock = blocks.copy()
    # encrypt each block
    lo = 1
    for k in keys:
        for i in range(len(resultingBlock)):
            resultingBlock[i] = P1Process_reverse(blocks[i])
            resultingBlock[i] = r4Shift_reverse(resultingBlock[i])
            resultingBlock[i] = S1Process_reverse(resultingBlock[i])
            
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")

            if i == 0:
                resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            else:
                resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1
    
    return resultingBlock

def CFB(blocks, keys, IV):
    print('mode CFB')
    lo = 1
    for k in keys:
        for i in range(len(blocks)):
            if i == 0:
                block = IV
            else:
                block = blocks[i-1]

            block = (int.from_bytes(block,byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            block = S1Process(block)
            block = r4Shift(block)
            block = P1Process(block)
            block = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(block,byteorder="big")).to_bytes(16,byteorder="big")

            blocks[i] = block
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def CFB_decrypt(blocks, keys, IV):
    print('mode CFB')
    lo = 1
    resultingBlock = blocks.copy()
    for k in keys:
        for i in range(len(resultingBlock)):
            if i == 0:
                block = IV
            else:
                block = blocks[i-1]

            block = (int.from_bytes(block,byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            block = S1Process(block)
            block = r4Shift(block)
            block = P1Process(block)
            block = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(block,byteorder="big")).to_bytes(16,byteorder="big")

            resultingBlock[i] = block
        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def OFB(blocks, keys, IV):
    print('mode OFB')
    lo = 1
    for k in keys:
        temp = IV
        for i in range(len(blocks)):
            if i == 0:
                block = IV
            else:
                block = temp

            block = (int.from_bytes(block,byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            block = S1Process(block)
            block = r4Shift(block)
            block = P1Process(block)
            temp = block
            block = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(block,byteorder="big")).to_bytes(16,byteorder="big")

            blocks[i] = block
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def OFB_decrypt(blocks, keys, IV):
    print('mode OFB')
    lo = 1
    resultingBlock = blocks.copy()
    for k in keys:
        temp = IV
        for i in range(len(resultingBlock)):
            if i == 0:
                block = IV
            else:
                block = temp

            block = (int.from_bytes(block,byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            block = S1Process(block)
            block = r4Shift(block)
            block = P1Process(block)
            temp = block
            block = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(block,byteorder="big")).to_bytes(16,byteorder="big")

            resultingBlock[i] = block
        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def counter(blocks, keys):
    print('mode CTR')
    lo = 1
    count = 1
    for k in keys:
        for i in range(len(blocks)):
            counter = bytes(count)
            counter = counter + bytes(16 - len(counter) % 16)
            vector = S1Process(counter)
            vector = r4Shift(vector)
            vector = P1Process(vector)
            vector = (int.from_bytes(vector,byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(vector,byteorder="big")).to_bytes(16,byteorder="big")
        count += 1
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks

def counter_decrypt(blocks, keys, num_rounds=16):
    print('mode CTR')
    lo = 1
    resultingBlock = blocks.copy()

    count = 1
    # encrypt each block
    for k in keys:
        for i in range(len(resultingBlock)):
            counter = bytes(count)
            counter = counter + bytes(16 - len(counter) % 16)
            resultingBlock[i] = S1Process(counter)
            resultingBlock[i] = r4Shift(resultingBlock[i])
            resultingBlock[i] = P1Process(resultingBlock[i])
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(blocks[i],byteorder="big")).to_bytes(16,byteorder="big")
        count += 1
        blocks = resultingBlock.copy()
        progressbar(lo, 11, 11)
        lo = lo + 1

    return blocks