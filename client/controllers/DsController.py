from flask import render_template, redirect, url_for, request, abort
import mysql.connector
import os
import json
from cipher.operations import *
from cipher.ds import *

def index():
    port = request.host.split(':')[1] if ':' in request.host else '80'
    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="password",
        database="crypto"
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

        port = request.host.split(':')[1] if ':' in request.host else '80'
        filename = 'dskey'+ port +'.txt'

        fileexist = os.path.isfile(filename)
        if not fileexist:
            return redirect('/ds')
        
        file = open(f'{filename}', 'rb')
        key = file.read()
        ds_key = json.loads(bytesToChar(key))

        s = ds_key[0]
        a = global_keys['a']
        p = global_keys['p']
        q = global_keys['q']

        e, y = sign_message(s, message, a, p, q)

    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="password",
        database="crypto"
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO documents (sender, port, title, message, is_signature, e, y) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    val = (sender, port, title, message, is_signature, e, y)
    mycursor.execute(sql, val)

    mydb.commit()

    return redirect('/ds')