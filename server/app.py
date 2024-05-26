from flask import Flask
from flask_socketio import SocketIO, emit
from cipher.operations import *
from cipher.helper import *
from cipher.cipher import *
from cipher.ds import *
import os
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

shared_key = {}

# Handler for a message recieved over 'connect' channel
@socketio.on('connect')
def test_connect():
    filename = 'dsglobalkey.txt'

    fileexist = os.path.isfile(filename)
    if not fileexist:
        key = generate_global_keys()
        key_string = json.dumps(key)
        file = open(f'{filename}', 'wb')
        file.write(charToBytes(key_string))
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    global_keys = json.loads(bytesToChar(key))
    print(global_keys)

    emit('after connect',  {
        'data':'Lets dance 22',
        'ds_a': global_keys['a'],
        'ds_p': global_keys['p'],
        'ds_q': global_keys['q']
    })

@socketio.on('hello')
def test_hello():
    G = get_global()
    emit('after hello',  {'G0': str(G[0]), 'G1': str(G[1])})

@socketio.on('send_public_key')
def send_public_key(message):
    pk0 = int(message['pk0'])
    pk1 = int(message['pk1'])
    public_key_client = (pk0, pk1)
    private_key_server = 4536969182346693165882493075232911813691897037253721855276
    shared_key_B = scalar_mult(private_key_server, public_key_client)
    print(public_key_client)
    print(shared_key_B)
    port = int(message['port'])
    print('port ', port)
    shared_key[port] = {}
    shared_key[port]['shared_key0'] = str(shared_key_B[0])
    shared_key[port]['shared_key1'] = str(shared_key_B[1])
    print(shared_key)
    emit('send_shared_key',  {'shared_key0': str(shared_key_B[0]), 'shared_key1': str(shared_key_B[1])})

@socketio.on('get_cipher_text')
def get_cipher_text(message):
    # print(shared_key)
    print(message)
    port = int(message['port'])
    sum_shared_key = int(shared_key[port]['shared_key0']) + int(shared_key[port]['shared_key1'])
    sum_shared_key = str(sum_shared_key)
    chunks = len(sum_shared_key)
    chunks, chunk_size = len(sum_shared_key), 16
    sum_shared_key = [sum_shared_key[i:i+chunk_size] for i in range(0, chunks, chunk_size)]
    print(sum_shared_key)
    shared = 0
    for i in range(len(sum_shared_key)):
        shared += int(sum_shared_key[i])
    print("Kunci bersama +: ", (shared_key[port]['shared_key0'] + shared_key[port]['shared_key1']))
    print("shared : ", shared)
    shared = str(shared)
    shared = [shared[i:i+16] for i in range(0, len(shared), 16)]
    print("shared : ", shared[0])
    
    bcd = charToBytes(message['ciphertext'])
    ghj = decrypt(message['ciphertext'], shared[0])
    print(ghj)

# Notice how socketio.run takes care of app instantiation as well.
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0')