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


# parses a list into every webpage
@app.context_processor
def inject_list():
    con = create_connection(DATABASE)
    query = "SELECT * FROM Categories"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    print(category_list)
    con.close()
    return dict(categories=category_list)


@app.route('/')
def render_homepage():
    return render_template('home.html')

@app.route('/dictionary/<cat_id>')
def render_dictionary(cat_id):
    con = create_connection(DATABASE)
    query = "SELECT id, maori, english, definition, level FROM Vocab_List WHERE cat_id=?"
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    words_list = cur.fetchall()
    print(words_list)
    con.close()
    return render_template('dictionary.html', words=words_list)

@app.route('/word/<word_id>')
def render_word(word_id):
    con = create_connection(DATABASE)
    query = """
SELECT Vocab_List.*, Users.username AS author_name
FROM Vocab_List
JOIN Users ON Vocab_List.author_id = Users.id
WHERE Vocab_List.id=?;
"""
    cur = con.cursor()
    cur.execute(query, (word_id,))
    word_info_list = cur.fetchone()
    print(f"Word info = {word_info_list}")
    con.close()
    return render_template('word.html', word=word_info_list)


app.run(host='0.0.0.0', debug=True)
