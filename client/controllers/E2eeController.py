from flask import render_template, redirect, url_for, request, abort
import mysql.connector
from cipher.e2ee import *

def index():
    port = request.host.split(':')[1] if ':' in request.host else '80'
    return render_template('e2ee.html')

def create():
    return render_template('e2ee_create.html')

def store():
    port = request.form.get('port')
    title = request.form.get('title')
    message = request.form.get('message')
    public_key = (1048450282941745839176924670126544470682118729496579804884, 5339366457203833815362571174160493094808527088711151396932)
    encrypted_message = encrypt_message(public_key, message)
    encrypted_string = "||".join([point_to_string(point[0]) + '&&' + point_to_string(point[1]) for point in encrypted_message])
    # print(title)
    # print(encrypted_string)

    mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="password",
        database="crypto"
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO chats (port, title, message) VALUES (%s, %s, %s)"
    val = (port, title, encrypted_string)
    mycursor.execute(sql, val)

    mydb.commit()

    return redirect('/e2ee')