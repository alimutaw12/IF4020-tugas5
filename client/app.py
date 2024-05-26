from flask import Flask, render_template, jsonify, request, send_file, url_for
from flask_socketio import SocketIO, emit
from cipher.cipher import *
from cipher.operations import *
from cipher.helper import *
from routes.e2ee_bp import e2ee_bp
from routes.ds_bp import ds_bp
import os
import json
import random
from cipher.ds import *

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

app.register_blueprint(e2ee_bp, url_prefix='/e2ee')
app.register_blueprint(ds_bp, url_prefix='/ds')

shared_key = {
    'shared_key0': 0,
    'shared_key1': 0,
}

@app.route("/")
def main():
    return render_template('index.html')

@app.route("/als")
def als():
    return render_template('als.html')

# Handler for a message recieved over 'connect' channel
@socketio.on('connect')
def test_connect():
    emit('after connect',  {'data':'Lets dance'})

@socketio.on('generate_ds_key')
def generate_ds_key(message):
    filename = 'dsglobalkey.txt'

    fileexist = os.path.isfile(filename)
    if not fileexist:
        key = message
        key_string = json.dumps(key)
        file = open(f'{filename}', 'wb')
        file.write(charToBytes(key_string))
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    global_keys = json.loads(bytesToChar(key))

    port = request.host.split(':')[1] if ':' in request.host else '80'
    filename = 'dskey-pub'+ port +'.txt'

    fileexist = os.path.isfile(filename)
    if not fileexist:
        key = generate_ds_keys(global_keys['a'], global_keys['p'], global_keys['q'])
        key_string = json.dumps(key[0])
        file = open(f'{filename}', 'wb')
        file.write(charToBytes(key_string))

        filenamePri = 'dskey-pri'+ port +'.txt'
        key_string = json.dumps(key[1])
        file = open(f'{filenamePri}', 'wb')
        file.write(charToBytes(key_string))
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    ds_key = json.loads(bytesToChar(key))

@socketio.on('generate_als_public_key')
def generate_als_public_key(message):
    G0 = int(message['g0'])
    G1 = int(message['g1'])
    p = int(message['p'])
    G = (G0, G1)
    private_key = random.randint(1, p-1)
    public_key = scalar_mult(private_key, G)
    emit('receive_public_key',  {'pk0': str(public_key[0]), 'pk1': str(public_key[1])})

@socketio.on('store_shared_key')
def store_shared_key(message):
    shared_key['shared_key0'] = int(message['shared_key0'])
    shared_key['shared_key1'] = int(message['shared_key1'])
    emit('success_store_shared_key')

@socketio.on('als_encrypt_message')
def als_encrypt_message(message):
    sum_shared_key = shared_key['shared_key0'] + shared_key['shared_key1']
    sum_shared_key = str(sum_shared_key)
    chunks = len(sum_shared_key)
    chunks, chunk_size = len(sum_shared_key), 16
    sum_shared_key = [sum_shared_key[i:i+chunk_size] for i in range(0, chunks, chunk_size)]
    shared = 0
    for i in range(len(sum_shared_key)):
        shared += int(sum_shared_key[i])
    shared = str(shared)
    shared = [shared[i:i+16] for i in range(0, len(shared), 16)]

    plaintext = str.encode(message['data'])
    ciphertext = encrypt(plaintext, shared[0])
    byte_ciphertext = bytesToChar(ciphertext)

    emit('send_cipher_text',  {'ciphertext': byte_ciphertext})

# Notice how socketio.run takes care of app instantiation as well.
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0')