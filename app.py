"""
This is a Flask-based web application for a Maori-English dictionary.
The application allows users to:
- View a list of Maori words and their English translations.
- View detailed information about specific words.
- Sign up and log in to the application.
- Teachers can add, modify, and delete words or categories in the dictionary.

The application uses SQLite as the database and bcrypt
for secure password hashing.
It also includes role-based access control to differentiate
between regular users and teachers.
"""

import sqlite3  # Standard library imports should come first
from datetime import date  # Standard library imports should come first
from flask import Flask, render_template, request, redirect, session, flash
# Third-party imports should follow standard imports
from flask_bcrypt import Bcrypt
from werkzeug.utils import escape

# Initialize the Flask application
# Flask is a lightweight WSGI web application framework in Python
app = Flask(__name__)

# Initialize Bcrypt for password hashing
# Bcrypt is used to securely hash and check passwords
bcrypt = Bcrypt(app)

# Secret key for session management
# This key is used to sign session cookies for security
app.secret_key = "6gctpxYDLDUe6d33vGD1P45mvzaKgMx9"

# Path to the SQLite database file
# This database stores all the data for the application
DATABASE = "/home/ture/Maori-Engish-Dictionary/dictionary.db"


def create_connection(db_file):
    """
    Establishes a connection to the specified SQLite database file.

    Args:
        db_file (str): The file path to the SQLite database.

    Returns:
        sqlite3.Connection: A connection object to the SQLite database if
        successful.
        None: If an error occurs during the connection attempt.

    Notes:
        - Enables foreign key constraints by setting the PRAGMA foreign_keys
        to ON.
        - Prints the error message to the console if a connection error occurs.
    """
    try:
        # Attempt to connect to the SQLite database
        connection = sqlite3.Connection(db_file)
        # Enable foreign key constraints for referential integrity
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error as e:
        # Print the error message if the connection fails
        print(e)
    return None


def is_logged_in():
    """
    Checks if a user is logged in by verifying
    the presence of an email in the session.

    Returns:
        bool: True if the user is logged in
        (email exists in the session),
        False otherwise.

    Notes:
        - The session is a dictionary-like object that stores data for the
          current user session.
        - If the "email" key exists in the session, the user
        is considered logged in.
    """
    if session.get("email") is None:
        # If no email is found in the session, the user is not logged in
        print("Not logged in")
        return False
    # If an email is found in the session, the user is logged in
    print("logged in")
    return True


def check_if_teacher():
    """
    Checks if the current user has a role ID of 1,
    indicating they are a teacher.

    Returns:
        bool: True if the user's role ID is 1 (teacher), False otherwise.

    Notes:
        - The "role_id" key in the session indicates the user's role.
        - A role ID of 1 corresponds to a teacher.
    """
    if session.get("role_id") == str(1):
        # If the role ID is 1, the user is a teacher
        print(session)
        return True
    # If the role ID is not 1, the user is not a teacher
    return False


@app.context_processor
def inject_list():
    """
    Injects variables into the Jinja2 template context
    for use in rendering templates.

    This context processor performs the following:
    1. Connects to the database and retrieves all
    categories from the
       `Categories` table.
    2. Checks if the current user is logged in.
    3. Determines if the current user is a teacher.

    Returns:
        dict: A dictionary containing:
            - `categories` (list): A list of categories
            fetched from the database.
            - `logged_in` (bool): A flag indicating whether
            the user is logged in.
            - `teacher` (bool): A flag indicating whether
            the user is a teacher.

    Notes:
        - The returned dictionary is available in all
        Jinja2 templates.
        - This allows templates to dynamically display
        content based on the user's
          login status and role.
    """
    # Connect to the database
    con = create_connection(DATABASE)
    # SQL query to fetch all categories
    query = "SELECT * FROM Categories"
    cur = con.cursor()
    cur.execute(query)
    # Fetch all rows from the query result
    category_list = cur.fetchall()
    print(category_list)
    # Close the database connection
    con.close()
    # Check if the current user is a teacher
    is_teacher = check_if_teacher()

    # Return a dictionary with categories, login status, and teacher status
    return {
        "categories": category_list,
        "logged_in": is_logged_in(),
        "teacher": is_teacher,
    }


@app.route('/')
def render_homepage():
    """
    Renders the homepage of the application.

    Returns:
        Response: The rendered HTML content for the homepage.

    Notes:
        - The homepage is the default route of the application.
        - It displays general information about the application.
    """
    # Render the home.html template
    return render_template('home.html')


def validate_integer(value, field_name):
    """
    Validates that the input value is an integer.

    Args:
        value (str): The input value to validate.
        field_name (str): The name of the field
        being validated (for error messages).

    Returns:
        int: The validated integer value.

    Raises:
        ValueError: If the value is not a valid integer.
    """
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid input for {field_name}: Must be an integer."
        ) from exc


def validate_string(value, field_name, max_length=255):
    """
    Validates that the input value is a string
    and does not exceed the maximum length.

    Args:
        value (str): The input value to validate.
        field_name (str): The name of the field
        being validated (for error messages).
        max_length (int): The maximum allowed
        length for the string.

    Returns:
        str: The validated string value.

    Raises:
        ValueError: If the value is not a valid
        string or exceeds the maximum length.
    """
    if not isinstance(value, str):
        raise ValueError(f"Invalid input for {field_name}: Must be a string.")
    if len(value) > max_length:
        raise ValueError(
            f"Invalid input: {field_name}: Exceeds max length: {max_length}."
        )
    return value.strip()


@app.route('/dictionary/')
def render_dictionary():
    """
    Renders the dictionary page with a list of words filtered by category ID.

    This function retrieves the `cat_id` parameter from the request arguments,
    queries the database for vocabulary words associated
    with the given category ID,
    and renders the 'dictionary.html' template with the retrieved words.

    Returns:
        str: Rendered HTML template for the dictionary page.

    Notes:
        - The `cat_id` parameter is expected to be passed
        as a query string argument.
        - The database connection is closed after the query execution.
        - The `words_list` contains tuples with the following structure:
          (id, maori, english, definition, level).
    """
    # Get the category ID from the query parameters and validate it
    cat_id = request.args.get('cat_id')
    try:
        cat_id = validate_integer(cat_id, "Category ID")
    except ValueError as e:
        flash(str(e), "error")  # Flash error message
        return redirect('/')
    print(f"cat_id = {cat_id}")
    # Connect to the database
    con = create_connection(DATABASE)
    # SQL query to fetch words by category ID
    query = """
    SELECT id, maori, english, definition, level
    FROM Vocab_List
    WHERE cat_id=?
    """
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    # Fetch all rows from the query result
    words_list = cur.fetchall()
    print(words_list)
    # Close the database connection
    con.close()
    # Render the dictionary.html template with the words and category ID
    return render_template('dictionary.html', words=words_list, cat_id=cat_id)


@app.route('/word/')
def render_word():
    """
    Renders the details of a specific word based on the provided word ID.

    This function retrieves the word information from the database, including
    details from the `Vocab_List` table and the author's username from the
    `Users` table. The retrieved data is then passed to the 'word.html'
    template
    for rendering.

    Returns:
        str: Rendered HTML template for the word details page.

    Notes:
        - The function establishes a connection to the database using
          `create_connection`.
        - The SQL query joins the `Vocab_List` and `Users` tables to
        fetch the
          word details along with the author's username.
        - The database connection is closed after the query execution.
    """
    # Get the word ID from the query parameters and validate it
    word_id = request.args.get('word_id')
    try:
        word_id = validate_integer(word_id, "Word ID")
    except ValueError as e:
        flash(str(e), "error")  # Flash error message
        return redirect('/')
    # Connect to the database
    con = create_connection(DATABASE)
    # SQL query to fetch word details and author information
    query = """
    SELECT Vocab_List.*, Users.username AS author_name
    FROM Vocab_List
    JOIN Users ON Vocab_List.author_id = Users.id
    WHERE Vocab_List.id=?
    """
    cur = con.cursor()
    cur.execute(query, (word_id,))
    # Fetch the first row from the query result
    word_info_list = cur.fetchone()
    print(f"Word info = {word_info_list}")
    # Close the database connection
    con.close()
    # Render the word.html template with the word details and word ID
    return render_template('word.html', word=word_info_list, word_id=word_id)


@app.route("/modify_word", methods=["POST", "GET"])
def modify_word():
    """
    Handles the modification of a word in the vocabulary list.

    This function allows a teacher to update the details of a word
    in the database.
    It checks if the user is logged in as a teacher, processes the
    form data from
    a POST request, and updates the corresponding word in the database.

    Returns:
        - A redirect to a message page if the user is not logged in
        as a teacher.
        - A redirect to the updated word's detail page after successful
        modification.

    Request Parameters:
        - word_id (str): The ID of the word to be modified
        (retrieved from query parameters).

    Form Data:
        - english (str): The updated English translation of the word.
        - definition (str): The updated definition of the word.
        - level (str): The updated difficulty level of the word.

    Database:
        Updates the `Vocab_List` table with the new values for
        the specified word ID.
    """
    # Ensure the user is a teacher
    if not check_if_teacher():
        return redirect("/message/Need+To+Be+Logged+In")
    if request.method == "POST":
        # Validate and sanitize inputs
        word_id = request.args.get("word_id")
        try:
            word_id = validate_integer(word_id, "Word ID")
            english = validate_string(
                request.form.get("english"), "English Translation"
            )
            definition = validate_string(
                request.form.get("definition"), "Definition"
            )
            level = validate_integer(request.form.get("level"), "Level")
        except ValueError as e:
            flash(str(e), "error")  # Flash error message
            return redirect(f"/word?word_id={word_id}")
        print(f"word_id = {word_id}")

        # Connect to the database
        con = create_connection(DATABASE)
        # SQL query to update the word details
        query = """
        UPDATE Vocab_List
        SET definition = ?, english = ?, level = ?
        WHERE id = ?
        """
        cur = con.cursor()
        cur.execute(query, (definition, english, level, word_id))
        # Commit the changes to the database
        con.commit()
        # Close the database connection
        con.close()

    # Redirect to the updated word's detail page
    return redirect(f"/word?word_id={word_id}")


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    """
    Handles the signup process for new users.

    This function renders the signup page and processes
    user input to create a new account.
    It performs the following tasks:
    - Redirects logged-in users to the home page.
    - Fetches the list of roles from the database to populate the signup form.
    - Validates user input, including password confirmation and length.
    - Hashes the user's password for secure storage.
    - Inserts the new user into the database.
    - Handles errors such as duplicate email addresses.
    - Redirects the user to the login page upon successful signup.

    Returns:
        - A redirect to the home page if the user is already logged in.
        - A redirect to the signup page with an error message
        if validation fails.
        - A redirect to the login page upon successful signup.
        - The rendered signup page with a list of roles if the
        request method is GET.
    """
    if is_logged_in():
        # If the user is already logged in, redirect them to the home page
        return redirect('/')

    # Connect to the database to fetch roles for the signup form
    con = create_connection(DATABASE)
    cur = con.cursor()

    # SQL query to fetch all roles
    query1 = "SELECT * FROM Role"
    cur.execute(query1)
    # Fetch all roles from the query result
    role_list = cur.fetchall()
    print(role_list)
    # Close the database connection
    con.close()

    if request.method == 'POST':
        try:
            # Validate and sanitize inputs
            fname = validate_string(
                request.form.get('fname').title(), "First Name"
            )
            lname = validate_string(
                request.form.get('lname').title(), "Last Name"
            )
            email = validate_string(
                request.form.get('email').lower(), "Email"
            )
            username = validate_string(
                request.form.get('username'), "Username"
            )
            password = validate_string(
                request.form.get('password'), "Password", max_length=128
            )
            password2 = validate_string(
                request.form.get('password2'),
                "Password Confirmation", max_length=128
            )
            role_id = validate_integer(request.form.get('role'), "Role ID")
            if password != password2:
                raise ValueError("Passwords do not match.")
            if len(password) < 8:
                raise ValueError(
                    "Password is too short. Must be at least 8 characters."
                )
        except ValueError as e:
            flash(str(e), "error")  # Flash error message
            return redirect('/signup')
        # If the request method is POST, process the form data
        print(request.form)

        # Hash the password using bcrypt for secure storage
        hashed_password = bcrypt.generate_password_hash(password)

        # Reconnect to the database to insert the new user
        con = create_connection(DATABASE)
        cur = con.cursor()

        # SQL query to insert the new user into the Users table
        query2 = """
        INSERT INTO Users (username, email, password, fname, lname, role_id)
         VALUES (?, ?, ?, ?, ?, ?)
        """

        try:
            # Execute the query with the provided user data
            cur.execute(
                query2, (
                    username, email, hashed_password, fname, lname, role_id
                )
            )
        except sqlite3.IntegrityError:
            # Handle duplicate email error
            con.close()
            flash("Email already in use.", "error")  # Flash error message
            return redirect("/signup")

        # Commit the changes to the database
        con.commit()
        con.close()
        # Flash success message
        flash("Signup successful! Please log in.", "success")
        return redirect("/login")

    # Render the signup.html template with the list of roles
    return render_template('signup.html', roles=role_list)


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    """
    Handles the login functionality for the application.

    If the user is already logged in, they are redirected to the home page.
    Otherwise, the function processes login requests submitted via POST.

    Steps:
    1. Retrieves and sanitizes the email and password from the login form.
    2. Queries the database for user information based on the provided email.
    3. Validates the provided password against the stored hashed password.
    4. If authentication is successful, stores user details in the session
        and redirects to the home page.
    5. If authentication fails, redirects back to the login page
    with an error message.

    Returns:
        - Redirect to the home page if the user is logged in
        or login is successful.
        - Redirect to the login page with an error message
        if authentication fails.
        - Renders the login page if the request method is not POST.

    Raises:
        - IndexError: If the user data fetched from the database
        is incomplete or invalid.

    Note:
        - The function uses bcrypt for password hashing and Flask's session
        for user session management.
        - Ensure the `create_connection` function and `DATABASE` constant
        are properly defined elsewhere
        in the application.
    """
    if is_logged_in():
        # If the user is already logged in, redirect them to the home page
        return redirect('/')

    if request.method == "POST":
        # If the request method is POST, process the login form data
        # Retrieve and sanitize email
        email = request.form['email'].strip().lower()
        # Retrieve and sanitize password
        password = request.form['password'].strip()

        # SQL query to fetch user data based on the provided email
        query = """
        SELECT id, username, fname, password, role_id FROM
         Users WHERE email = ?
        """
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        # Fetch the user data from the query result
        user_data = cur.fetchone()
        con.close()

        try:
            # Extract user details from the query result
            user_id = user_data[0]
            username = user_data[1]
            first_name = user_data[2]
            db_password = user_data[3]
            role_id = user_data[4]
        except (IndexError, TypeError):
            # Flash error message
            flash("Invalid username or password.", "error")
            return redirect("/login")

        # Validate the provided password against
        # the hashed password in the database
        if not bcrypt.check_password_hash(db_password, password):
            # Flash error message
            flash("Invalid username or password.", "error")
            return redirect("/login")

        # Store user details in the session for authentication
        session['email'] = email
        session['user_id'] = user_id
        session['first_name'] = first_name
        session['username'] = username
        session['role_id'] = role_id
        print(session)

        flash("Login successful!", "success")  # Flash success message
        return redirect('/')

    # Render the login.html template if the request method is GET
    return render_template('login.html')


@app.route('/logout')
def logout():
    """ # Flash error message
    Logs the user out by clearing all session data and redirects to the
    home page with a farewell message.

    This function performs the following steps:
    1. Prints the current session keys for debugging purposes.
    2. Iterates through all session keys and removes them from the session.
    3. Prints the session keys again to confirm the session is cleared.
    4. Redirects the user to the home page with a message
    indicating a successful logout.

    Returns:
        werkzeug.wrappers.response.Response: A redirect response to the
        home page with a query parameter message.
    """
    # Print the current session keys for debugging purposes
    print(list(session.keys()))
    # Iterate through all session keys and remove them from the session
    for key in list(session.keys()):
        session.pop(key)
    # Print the session keys again to confirm the session is cleared
    print(list(session.keys()))
    flash("You have been logged out.", "success")
    # Redirect the user to the home page with a farewell message
    return redirect('/')


@app.route('/admin/')
def render_admin():
    """
    Renders the admin page if the user is authenticated as a teacher.

    This function checks if the user has teacher privileges.
    If not, it redirects
    the user to the home page with an appropriate message.
    If the user is a teacher,
    it retrieves a list of categories from the database
    and renders the admin page
    with the retrieved data.

    Returns:
        Response: A redirect to the home page if the user is not a teacher.
        TemplateResponse: The rendered admin page with the list of categories
        if the user is a teacher.
    """
    # Check if the user is a teacher
    if check_if_teacher() is False:
        # Redirect to the home page with a message if the user is not a teacher
        return redirect('/?message=Need+To+Be+Logged+in')
    # Connect to the database
    con = create_connection(DATABASE)
    # SQL query to fetch all categories
    query = "SELECT * FROM Categories"
    cur = con.cursor()
    cur.execute(query)
    # Fetch all categories from the query result
    category_list = cur.fetchall()
    # Close the database connection
    con.close()
    # Render the admin.html template with the list of categories
    return render_template("admin.html", categories=category_list)


@app.route('/add_category_to_database/', methods=['POST'])
def add_category():
    """
    Handles the addition of a new category to the database.

    This function checks if the user is logged in as a teacher before allowing
    the addition of a new category. If the user is not logged in as a teacher,
    they are redirected to the home page with an appropriate message. If the
    request method is POST, it retrieves the category name from the form data,
    processes it, and inserts it into the Categories table in the database.

    Returns:
        - A redirect to the home page with a message if the user is
        not a teacher.
        - A redirect to the admin page after successfully adding the category.
    """
    # Check if the user is a teacher
    if check_if_teacher() is False:
        # Redirect to the home page with a message if the user is not a teacher
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        # If the request method is POST, process the form data
        print(request.form)
        # Retrieve and sanitize the category name from the form data
        cat_name = request.form.get('name').lower().strip()
        print(cat_name)
        # Connect to the database
        con = create_connection(DATABASE)
        # SQL query to insert the new category into the Categories table
        query = "INSERT INTO Categories ('name') VALUES (?);"
        cur = con.cursor()
        cur.execute(query, (cat_name,))
        # Commit the changes to the database
        con.commit()
        # Close the database connection
        con.close()
    # Redirect to the admin page after successfully adding the category
    return redirect('/admin')


@app.route('/add_word_to_database/', methods=['POST'])
def add_word():
    """
    Handles the addition of a new word to the vocabulary list.

    This function checks if the user is logged in as a teacher before allowing
    the addition of a new word. It processes a POST request containing the
    details of the word to be added, including its Maori and English
    translations, definition, level, and associated category.
    The word is  # Flash error messagethen
    inserted into the database along with metadata such as the author's ID and
    the date of entry.

    Returns:
        - A redirect to the homepage with an error message if the user is not
          logged in as a teacher.
        - A redirect to the dictionary page for the associated category after
          successfully adding the word.

    Request Parameters:
        - maori (str): The Maori word to be added.
        - english (str): The English translation of the Maori word.
        - definition (str): The definition of the word.
        - level (str): The difficulty level of the word.
        - id (str): The category ID associated with the word (from query args).

    Session Variables:
        - user_id (int): The ID of the currently logged-in user.

    Database:
        Inserts a new record into the `Vocab_List`
        table with the following fields:
        - maori
        - english
        - cat_id
        - definition
        - date_of_entry
        - author_id
        - level
        - image (default: "noimage")
    """
    # Check if the user is a teacher
    if check_if_teacher() is False:
        # Redirect to the home page with a message if the user is not a teacher
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        try:  # Flash error message
            # Validate and sanitize inputs
            maori = validate_string(
                request.form.get('maori').lower(), "Maori Word"
            )
            english = validate_string(request.form.get('english').lower(),
                                      "English Translation")
            definition = validate_string(
                request.form.get('definition'), "Definition"
            )
            level = validate_integer(request.form.get('level'), "Level")
            cat_id = validate_integer(request.args.get('id'), "Category ID")
        except ValueError as e:
            flash(str(e), "error")  # Flash error message
            # Redirect back to the dictionary page
            return redirect(f'/dictionary/?cat_id={request.args.get("id")}')
        # If the request method is POST, process the form data

        # Get the current date and format it as a string
        today = date.today()
        today = today.strftime("%Y.%m.%d")

        image = "noimage"  # Default image name
        author_id = session.get("user_id")  # Author ID from session
        date_of_entry = today  # Date of entry

        # Connect to the database
        con = create_connection(DATABASE)
        # SQL query to insert the new word into the Vocab_List table
        query = """
        INSERT INTO Vocab_List (maori, english, cat_id, definition,
         date_of_entry, author_id, level, image) VALUES
         (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cur = con.cursor()
        cur.execute(query, (maori, english, cat_id, definition,
                            date_of_entry, author_id, level, image))
        # Commit the changes to the database
        con.commit()
        # Close the database connection
        con.close()

        flash("Word added successfully!", "success")  # Flash success message
    # Redirect to the dictionary page for the associated category
    return redirect(f"/dictionary/?cat_id={cat_id}")


@app.route('/delete_from_database/', methods=['POST'])
def delete_from_category():
    """
    Handles the deletion of an item from a specified category.

    This function checks if the user is a teacher before proceeding.
    If the user
    is not logged in as a teacher, they are redirected to the home page with an
    appropriate message. If the request method is POST, it retrieves the table
    name and item ID from the request,
    and renders a confirmation page for deletion.
    Otherwise, it redirects to the admin page.

    Returns:
        Response: A redirect to the home page if the user is not a teacher.
        Response: A rendered template for deletion confirmation if the request
                  method is POST.
        Response: A redirect to the admin page for other cases.
    """
    # Check if the user is a teacher
    if check_if_teacher() is False:
        # Redirect to the home page with a message if the user is not a teacher
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        try:
            # Validate and sanitize inputs
            table = validate_string(request.args.get('table'), "Table Name")
            item_id = validate_integer(request.form.get('id'), "ID")
        except ValueError as e:
            flash(str(e), "error")  # Flash error message
            return redirect('/admin')
        # Render the delete confirmation page with the table name and item ID
        return render_template("delete_confirm.html", id=item_id, table=table)
    # Redirect to the admin page for other cases
    return redirect('/admin')


@app.route('/confirm_delete/')
def confirm_delete():
    """
    Handles the deletion of a record from a specified table in the database.

    This function checks if the user is logged in as a teacher
    before proceeding.
    If the user is not authorized, they are redirected to the home page with an
    appropriate message. If authorized, the function retrieves
    the table name and
    record ID from the request arguments, deletes the corresponding record from
    the database, and then redirects to the home page.

    Returns:
        werkzeug.wrappers.response.Response:
        A redirect response to the home page.

    Raises:
        sqlite3.Error: If there is an issue executing the SQL query.

    Notes:
        - The function assumes the existence of a `check_if_teacher`
        function to
          verify user authorization.
        - The `create_connection` function is used to establish a connection to
          the database.
        - The `DATABASE` constant should point to the database file path.
    """
    # Check if the user is a teacher
    if check_if_teacher() is False:
        # Redirect to the home page with a message if the user is not a teacher
        return redirect('/?message=Need+To+Be+Logged+In')
    try:
        # Validate and sanitize inputs
        cat_id = validate_integer(request.args.get('cat_id'), "Category ID")
        table = validate_string(request.args.get('table'), "Table Name")
    except ValueError as e:
        flash(str(e), "error")  # Flash error message
        return redirect('/admin')

    # Connect to the database
    con = create_connection(DATABASE)
    # SQL query to delete the record from the specified table
    query = f"DELETE FROM {table} WHERE id = ?"
    cur = con.cursor()
    # Execute the query with the provided category ID
    cur.execute(query, (cat_id,))
    # Commit the changes to the database
    con.commit()
    # Close the database connection
    con.close()
    # Redirect to the home page after successful deletion
    return redirect('/')


# Start the Flask application
app.run(host='0.0.0.0', debug=True)
