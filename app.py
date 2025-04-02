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

def is_logged_in():
    if session.get("email") is None:
        print("Not logged in")
        return False
    else:
        print("logged in")
        return True



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
    is_teacher = False
    if session.get("role_id") == str(1):
        print("User is a teacher")
        is_teacher = True

    return dict(categories=category_list, logged_in=is_logged_in(), teacher=is_teacher)


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


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if is_logged_in():
        return redirect('/')
    
    con = create_connection(DATABASE)
    cur = con.cursor()
        
    query1 = "SELECT * FROM Role"
    cur.execute(query1)
    role_list = cur.fetchall()
    print(role_list)
    con.close()




    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').title().strip()
        lname = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        password2 = request.form.get('password2').strip()
        role_id = request.form.get('role').lower().strip()
        
        if password != password2:
            return redirect(r"\signup?error=Passwords+do+not+match")
        
        if len(password) < 8: 
            return redirect(r"\signup?error=Password+is+too+short")
        

        hashed_password = bcrypt.generate_password_hash(password)

        con = create_connection(DATABASE)
        cur = con.cursor()
        
        query1 = "SELECT * FROM Role"
        cur.execute(query1)
        role_list = cur.fetchall()
        print(role_list)



        query2 = "INSERT INTO Users (username, email, password, fname, lname, role_id) VALUES (?, ?, ?, ?, ?, ?)"

        try:
            cur.execute(query2, (username, email, hashed_password, fname, lname, role_id))

        except sqlite3.IntegrityError:
            con.close()
            return redirect(r'\signup?error=Email+already+in+use')
        
        con.commit()
        con.close()

        return redirect("/login")
    
    return render_template('signup.html', roles=role_list)




@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/')

    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = "SELECT id, username, fname, password, role_id FROM Users WHERE email = ?"
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close

        try:
            user_id = user_data[0]
            username = user_data[1]
            first_name = user_data[2]
            db_password = user_data[3]
            role_id = user_data[4]
        except IndexError:
            return r1edirect(r"/login?error=Invalid+username+or+password")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(r"/login?error=Invalid+username+or+password")

        session['email'] = email
        session['user_id'] = user_id
        session['first_name'] = first_name
        session['username'] = username
        session['role_id'] = role_id
        print(session)
        return redirect('/')



    return render_template('login.html')

@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+You+Next+Time}')


@app.route('/admin')
def render_admin():
     if not is_logged_in():
         return redirect('/?message=Need+To+Be+Logged+in')
     con = create_connection(DATABASE)
     query = "SELECT * FROM Categories"
     cur = con.cursor()
     cur.execute(query)
     category_list = cur.fetchall()
     con.close()
     return render_template("admin.html", categories=category_list)
 
 
@app.route('/add_category', methods=['POST'])
def add_category():
    if not is_logged_in():
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        print(request.form)
        cat_name = request.form.get('name').lower().strip()
        print(cat_name)
        con = create_connection(DATABASE)
        query = "INSERT INTO Categories ('name') VALUES (?)"
        cur = con.cursor()
        cur.execute(query, (cat_name, ))
        con.commit()
        con.close()
    return redirect('/admin')
 
 
@app.route('/delete_category', methods=['POST'])
def render_delete_category():
    if not is_logged_in():
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        print(request.form)
        category = request.form.get('name').lower().strip()
        print(f"The category info is {category}")
        category = category.split(",")
        cat_id = category[0]
        cat_name = category[1]
        return render_template("delete_confirm.html", id=cat_id, name=cat_name, type="category")
    return redirect('/admin')

@app.route('/confirm_category_delete/<cat_id>')
def confirm_category_delete(cat_id):
    if not is_logged_in():
        return redirect('/?message=Need+To+Be+Logged+in')
    
    con = create_connection(DATABASE)
    query1 = "PRAGMA foreign_keys = ON"
    query2 = """
    DELETE FROM Categories WHERE id = ?
    """
    cur = con.cursor()
    cur.execute(query1)
    cur.execute(query2, (cat_id, ))
    con.commit()
    con.close()
    return redirect('/admin')

app.run(host='0.0.0.0', debug=True)
