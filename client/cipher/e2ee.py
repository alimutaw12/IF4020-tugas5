import random
from cipher.operations import *

# Definisi kurva eliptik (y^2 = x^3 + ax + b) dan titik dasar (G)
a = -3
b = 2455155546008943817740293915197451784769108058161191238065
p = 6277101735386680763835789423207666416083908700390324961279
G = (602046282375688656758213480587526111916698976636884684818,
     174050332293622031404857552280219410364023488927386650641)
random_k = 6071903517562526516181135139011885144117101134194147892658

# Enkripsi
def encrypt(G, public_key, message, k):
    C1 = scalar_mult(k, G)
    C2 = ec_add(message, scalar_mult(k, public_key))
    return (C1, C2)

def decrypt(private_key, C1, C2):
    S = scalar_mult(private_key, C1)
    I = (S[0], -1 * S[1])
    message = ec_add(C2, I)
    return message

# Fungsi untuk mengonversi string ke dalam bentuk bilangan bulat
def string_to_int(message):
    return [ord(char) for char in message]

# Fungsi untuk mengonversi bilangan bulat kembali menjadi string
def int_to_string(int_list):
    return "".join([chr(num % 255) for num in int_list])

# Enkripsi
def encrypt_message(public_key, message):
    int_message = string_to_int(message)
    encrypted = [encrypt(G, public_key, (0, char), random_k) for char in int_message]
    return encrypted

# Dekripsi
def decrypt_message(private_key, encrypted_string):
    encrypted = split_encrypted_message_string(encrypted_string)
    decrypted = [decrypt(private_key, point[0], point[1]) for point in encrypted]
    int_message = [point[1] for point in decrypted]
    return int_to_string(int_message)

def split_encrypted_message_string(encrypted_string):
    results = []
    strings = encrypted_string.split('||')
    for i in range(len(strings)):
        points = strings[i].split('&&')
        point_array = []
        for j in range(len(points)):
            point = points[j].split(',')
            point0 = int(point[0].replace('(', ''))
            point1 = int(point[1].replace(')', ''))
            point_array.append((point0, point1))
        results.append((point_array[0], point_array[1]))
    return results

def point_to_string(point):
    return f"({point[0]},{point[1]})"

def generate_e2ee_key():
    private_key = random.randint(1, p-1)
    public_key = scalar_mult(private_key, G)
    return {"private_key": private_key, "public_key": public_key}

# Generate kunci privat dan publik
# private_key_A = random.randint(1, p-1)
# private_key_A = 6142377013754190839186311013910539581696466620887266069510
# public_key_A = scalar_mult(private_key_A, G)

# private_key_B = random.randint(1, p-1)
# private_key_B = 611179626811744455798348043673079186555110843196290254950
# public_key_B = scalar_mult(private_key_B, G)

# Menghitung kunci bersama
# shared_key_A = scalar_mult(private_key_A, public_key_B)
# shared_key_B = scalar_mult(private_key_B, public_key_A)

# Validasi kunci bersama
# assert shared_key_A == shared_key_B

# print ("private_key_A: ", private_key_A)
# print ("private_key_B: ", private_key_B)
# # print ("public_key_A: ", public_key_A)
# print ("public_key_B: ", public_key_B)
# print ("random_k: ", random_k)

# # Pesan
# message = "He"

# encrypted_message = encrypt_message(public_key_B, message)
# print("Encrypted message:", encrypted_message)

# encrypted_string = ",".join([point_to_string(point[0]) + point_to_string(point[1]) for point in encrypted_message])
# print("Encrypted message string:", encrypted_string)

# private_key_B = 611179626811744455798348043673079186555110843196290254950
# decrypted_message = decrypt_message(private_key_B, encrypted_message)
# print("Decrypted message:", decrypted_message)

# M = 69
# C1, C2 = encrypt(G, public_key_B, (0, M), random_k)
# print(C1)
# print(C2)

# decrypted_message = decrypt(private_key_B, C1, C2)
# print(decrypted_message)