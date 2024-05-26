from flask import render_template, redirect, url_for, request, abort
import mysql.connector
from cipher.e2ee import *
from cipher.operations import *
from cipher.helper import *
import os
import json

def index():
    port = request.host.split(':')[1] if ':' in request.host else '80'
    filename = 'e2eekey-' + port + '.txt'
    fileexist = os.path.isfile(filename)
    if not fileexist:
        key = generate_e2ee_key()
        # print(key)
        key_string = json.dumps(key)
        # print(key_string)
        file = open(f'{filename}', 'wb')
        file.write(charToBytes(key_string))
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    key_json = json.loads(bytesToChar(key))
    # print(key_json)

    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )
    mycursor = mydb.cursor()
    sql = "SELECT * FROM chats WHERE port ='"+port+"'"
    mycursor.execute(sql)
    chats = mycursor.fetchall()

    return render_template('e2ee.html', key=key_json, chats=chats)

def create():
    return render_template('e2ee_create.html')

def store():
    sender = request.host.split(':')[1] if ':' in request.host else '80'
    port = request.form.get('port')
    title = request.form.get('title')
    message = request.form.get('message')
    receiver_public_key = request.form.get('public_key').split(',')
    public_key = (int(receiver_public_key[0]), int(receiver_public_key[1]))
    encrypted_message = encrypt_message(public_key, message)
    encrypted_string = "||".join([point_to_string(point[0]) + '&&' + point_to_string(point[1]) for point in encrypted_message])
    # print(title)
    # print(encrypted_string)

    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO chats (sender, port, title, message) VALUES (%s, %s, %s, %s)"
    val = (sender, port, title, encrypted_string)
    mycursor.execute(sql, val)

    mydb.commit()

    return redirect('/e2ee')

def read(chat_id):
    port = request.host.split(':')[1] if ':' in request.host else '80'
    filename = 'e2eekey-' + port + '.txt'
    fileexist = os.path.isfile(filename)
    if not fileexist:
        key = generate_e2ee_key()
        # print(key)
        key_string = json.dumps(key)
        # print(key_string)
        file = open(f'{filename}', 'wb')
        file.write(charToBytes(key_string))
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    key_json = json.loads(bytesToChar(key))

    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()
    sql = "SELECT * FROM chats WHERE id ='"+str(chat_id)+"'"
    mycursor.execute(sql)
    chat = mycursor.fetchone()
    
    return render_template('e2ee_read.html', key=key_json, chat=chat)

def readDecrypted(chat_id):
    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()
    sql = "SELECT * FROM chats WHERE id ='"+str(chat_id)+"'"
    mycursor.execute(sql)
    chat = mycursor.fetchone()

    private_key = request.form.get('private_key')
    decrypted_message = decrypt_message(private_key, chat[4])

    return render_template('e2ee_read_decrypted.html', chat=chat, decrypted_message=decrypted_message)