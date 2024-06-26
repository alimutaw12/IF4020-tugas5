from flask import render_template, redirect, url_for, request, abort
import mysql.connector
import os
import json
from cipher.operations import *
from cipher.ds import *

def index():
    port = request.host.split(':')[1] if ':' in request.host else '80'
    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )
    mycursor = mydb.cursor()
    sql = "SELECT * FROM documents WHERE port ='"+port+"'"
    mycursor.execute(sql)
    documents = mycursor.fetchall()

    return render_template('ds.html', documents=documents)

def create():
    return render_template('ds_create.html')

def store():
    sender = request.host.split(':')[1] if ':' in request.host else '80'
    port = request.form.get('port')
    title = request.form.get('title')
    message = request.form.get('message')
    is_signature = request.form.get('is_signature')
    e = "NULL"
    y = "NULL"

    if (int(is_signature) == 1):
        filename = 'dsglobalkey.txt'

        fileexist = os.path.isfile(filename)
        if not fileexist:
            return redirect('/ds')
            
        file = open(f'{filename}', 'rb')
        key = file.read()
        global_keys = json.loads(bytesToChar(key))

        filename = 'dskey-pub'+ sender +'.txt'

        fileexist = os.path.isfile(filename)
        if not fileexist:
            return redirect('/ds')
        
        file = open(f'{filename}', 'rb')
        key = file.read()
        ds_key = json.loads(bytesToChar(key))

        s = ds_key
        a = global_keys['a']
        p = global_keys['p']
        q = global_keys['q']

        e, y = sign_message(s, message, a, p, q)

    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO documents (sender, port, title, message, is_signature, e, y) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    val = (sender, port, title, message, is_signature, e, y)
    mycursor.execute(sql, val)

    mydb.commit()

    return redirect('/ds')

def read(document_id):
    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()
    sql = "SELECT * FROM documents WHERE id ='"+str(document_id)+"'"
    mycursor.execute(sql)
    document = mycursor.fetchone()
    
    return render_template('ds_read.html', document=document)

def verify(document_id):
    filename = 'dsglobalkey.txt'

    fileexist = os.path.isfile(filename)
    if not fileexist:
        return redirect('/ds')
        
    file = open(f'{filename}', 'rb')
    key = file.read()
    global_keys = json.loads(bytesToChar(key))

    mydb = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE')
    )

    mycursor = mydb.cursor()
    sql = "SELECT * FROM documents WHERE id ='"+str(document_id)+"'"
    mycursor.execute(sql)
    document = mycursor.fetchone()

    signature = (int(document[6]), int(document[7]))
    v = int(request.form.get('verify_key'))
    message2 = document[4]
    a = global_keys['a']
    p = global_keys['p']
    q = global_keys['q']

    is_valid = verify_signature(v, message2, signature, a, p, q)
    
    return render_template('ds_verify.html', document=document, is_valid=is_valid)