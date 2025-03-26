from ast import Import
from flask import Flask, render_template, request, redirect, session
import sqlite3
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "6gctpxYDLDUe6d33vGD1P45mvzaKgMx9"



DATABASE = "/home/ture/Documents/Obsidian Vaults/Ture Hansson Vault 1/Computer Science/School Coding Projects/2025/Databases/Maori-Engish-Dictionary/dictionary.db"

def create_connection(db_file):
    try:
        connection = sqlite3.Connection(db_file)
        return connection
    except sqlite3.Error as e:
        print(e)
    return None

@app.route('/')
def render_homepage():
    return render_template('home.html')

@app.route('/dictionary')
def render_dictionary():
    con = create_connection(DATABASE)
    query = "SELECT maori, english, definition, level FROM Vocab_List"
    cur = con.cursor()
    cur.execute(query)
    words_list = cur.fetchall()
    print(words_list)
    con.close()
    return render_template('dictionary.html', words=words_list)




app.run(host='0.0.0.0', debug=True)
