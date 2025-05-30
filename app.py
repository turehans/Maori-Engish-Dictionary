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

# Define constants for role IDs, messages, and validation
TEACHER_ROLE_ID = "1"
WELCOME_MESSAGE = "Welcome to the Maori-English Dictionary!"
LOGOUT_MESSAGE = "You have been logged out."
NEED_TEACHER_MESSAGE = "You need to be a teacher to perform this action."
PASSWORD_MIN_LENGTH = 8
MAX_STRING_LENGTH = 255  # Global variable for maximum string length

# Define a global dictionary for field-specific maximum lengths
FIELD_MAX_LENGTHS = {
    "First Name": 20,
    "Last Name": 20,
    "Email": 254,
    "Username": 30,
    "Password": 71,
    "Password Confirmation": 71,
    "Maori Word": 30,
    "English Translation": 30,
    "Definition": 255,
    "Category Name": 30,
    "Table Name": 30,
}

FIELD_MAX_INT = {
        "Level": 10,
        "Role ID": 2,
}


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
        - Logs detailed error messages if a connection error occurs.
    """
    connection = None
    try:
        # Attempt to connect to the SQLite database
        connection = sqlite3.Connection(db_file)
        # Enable foreign key constraints for referential integrity
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.OperationalError as e:
        print(f"OperationalError: Unable to connect to {db_file}. Error: {e}")
    except sqlite3.DatabaseError as e:
        print(f"DatabaseError: An issue occurred with {db_file}. Error: {e}")
    except Exception as e:
        print(f"UnexpectedError: An unexpected error occurred. Error: {e}")
    return None


def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    """
    Executes a SQL query on the database.

    Args:
        query (str): The SQL query to execute.
        params (tuple): Parameters to bind to the query (default: ()).
        fetch_one (bool): Whether to fetch a single result (default: False).
        fetch_all (bool): Whether to fetch all results (default: False).

    Returns:
        list or tuple or None: Query results if fetch_one or fetch_all is True,
        otherwise None.

    Notes:
        - Ensures the database connection is properly closed after execution.
        - Logs errors if the query fails.
    """
    con = create_connection(DATABASE)
    if not con:
        print("Error: Unable to establish a database connection.")
        return None
    try:
        cur = con.cursor()
        cur.execute(query, params)
        if fetch_one:
            result = cur.fetchone()
        elif fetch_all:
            result = cur.fetchall()
        else:
            con.commit()
            result = None
        return result
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        con.close()


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
        return False
    return True


def check_if_teacher():
    """
    Checks if the current user has a role ID of TEACHER_ROLE_ID,
    indicating they are a teacher.
    """
    if session.get("role_id") == TEACHER_ROLE_ID:
        return True
    return False


@app.context_processor
def inject_list():
    """
    Injects variables into the Jinja2 template context
    for use in rendering templates.

    This context processor performs the following:
    1. Retrieves all categories from the `Categories`
    table using `execute_query`.
    2. Checks if the current user is logged in.
    3. Determines if the current user is a teacher.

    Returns:
        dict: A dictionary containing:
            - `categories` (list): A list of categories fetched from the
            database.
            - `logged_in` (bool): A flag indicating whether the user
            is logged in.
            - `teacher` (bool): A flag indicating whether the user
            is a teacher.

    Notes:
        - The returned dictionary is available in all Jinja2 templates.
        - This allows templates to dynamically display content
        based on the user's
          login status and role.
    """
    # SQL query to fetch all categories
    query = "SELECT * FROM Categories"
    # Fetch categories using the execute_query function
    category_list = execute_query(query, fetch_all=True)
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
    """
    flash(WELCOME_MESSAGE, "success")
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
    max_size = FIELD_MAX_INT.get(field_name)

    try:
        int_value = int(value)
    except (ValueError, TypeError):
        raise ValueError(
                f"Invalid input for {field_name}, must be an integer"
                )

    if max_size is None:
        return int(value)
    elif int_value > max_size or int_value < 1:
        raise ValueError(
                f"Invalid: {field_name} must be between {max_size} and 1"
                )
    return int_value


def validate_string(value, field_name):
    """
    Validates that the input value is a string
    and does not exceed the maximum length defined in FIELD_MAX_LENGTHS.

    Args:
        value (str): The input value to validate.
        field_name (str): The name of the field
        being validated (for error messages).

    Returns:
        str: The validated string value.

    Raises:
        ValueError: If the value is not a valid
        string or exceeds the maximum length.
    """
    max_length = FIELD_MAX_LENGTHS.get(field_name, MAX_STRING_LENGTH)
    if not isinstance(value, str):
        raise ValueError(f"Invalid input for {field_name}: Must be a string.")
    if len(value) > max_length:
        raise ValueError(
            f"Invalid input for {field_name}: Exceeds length of {max_length}."
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

    # SQL query to fetch words by category ID
    query = """
    SELECT id, maori, english, definition, level
    FROM Vocab_List
    WHERE cat_id = ?
    """
    # Fetch words using the execute_query function
    words_list = execute_query(query, params=(cat_id,), fetch_all=True)

    # Render the dictionary.html template with the words and category ID
    return render_template('dictionary.html', words=words_list, cat_id=cat_id)


@app.route('/word/')
def render_word():
    """
    Renders the details of a specific word based on the provided word ID.

    This function retrieves the word information from the database, including
    details from the `Vocab_List` table and the author's username from the
    `Users` table. The retrieved data is then passed to the 'word.html'
    template for rendering.

    Returns:
        str: Rendered HTML template for the word details page.
    """
    # Get the word ID from the query parameters and validate it
    word_id = request.args.get('word_id')
    try:
        word_id = validate_integer(word_id, "Word ID")
    except ValueError as e:
        flash(str(e), "error")  # Flash error message
        return redirect('/')

    # SQL query to fetch word details and author information
    query = """
    SELECT Vocab_List.*, Users.username AS author_name
    FROM Vocab_List
    JOIN Users ON Vocab_List.author_id = Users.id
    WHERE Vocab_List.id = ?
    """
    # Fetch word details using the execute_query function
    word_info_list = execute_query(query, params=(word_id,), fetch_one=True)

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
        flash("You need to be a teacher to modify words.", "error")
        return redirect("/?message=Need+To+Be+Logged+In")
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

        # SQL query to update the word details
        query = """
        UPDATE Vocab_List
        SET definition = ?, english = ?, level = ?
        WHERE id = ?
        """
        # Execute the update query using the execute_query function
        execute_query(query, params=(definition, english, level, word_id))

    flash("Word modified successfully!", "success")
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

    # SQL query to fetch all roles
    query = "SELECT * FROM Role"
    role_list = execute_query(query, fetch_all=True)

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
                    request.form.get('password'), "Password"
                    )
            password2 = validate_string(
                    request.form.get('password2'), "Password Confirmation"
                    )
            role_id = validate_integer(
                    request.form.get('role'), "Role ID"
                    )
            if password != password2:
                raise ValueError("Passwords do not match.")
            if len(password) < PASSWORD_MIN_LENGTH:
                raise ValueError(
                        f"Password is under {PASSWORD_MIN_LENGTH} characters."
                        )
        except ValueError as e:
            flash(str(e), "error")  # Flash error message
            return redirect('/signup')

        # Hash the password using bcrypt for secure storage
        hashed_password = bcrypt.generate_password_hash(password)

        # SQL query to insert the new user into the Users table
        query = """
        INSERT INTO Users (username, email, password, fname, lname, role_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            execute_query(query, params=(
                username, email, hashed_password, fname, lname, role_id
                ))
        except sqlite3.IntegrityError:
            flash("Email already in use.", "error")
            return redirect("/signup")

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
        try:
            # Validate and sanitize inputs
            email = validate_string(
                    request.form.get('email').strip().lower(), "Email"
                    )

            # Escape the email to prevent SQL injection
            password = validate_string(
                    request.form.get('password').strip(), "Password"
                    )
        except ValueError as e:
            flash(str(e), "error")
            return redirect("/login")

        # SQL query to fetch user data based on the provided email
        query = """
        SELECT id, username, fname, password
         ,role_id FROM Users WHERE email = ?
        """
        user_data = execute_query(query, params=(email,), fetch_one=True)

        if not user_data:
            flash("Invalid username or password.", "error")
            return redirect("/login")

        user_id, username, first_name, db_password, role_id = user_data

        if not bcrypt.check_password_hash(db_password, password):
            flash("Invalid username or password.", "error")
            return redirect("/login")

        # Store user details in the session
        session['email'] = email
        session['user_id'] = user_id
        session['first_name'] = first_name
        session['username'] = username
        session['role_id'] = role_id

        flash("Login successful!", "success")
        return redirect('/')

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
    # Iterate through all session keys and remove them from the session
    for key in list(session.keys()):
        session.pop(key)
    flash(LOGOUT_MESSAGE, "success")
    # Redirect the user to the home page with a farewell message
    return redirect('/')


@app.route('/admin/')
def render_admin():
    """
    Renders the admin page if the user is authenticated as a teacher.

    This function checks if the user has teacher privileges.
    If not, it redirects
    the user to the home page with an appropriate message.


    Returns:
        Response: A redirect to the home page if the user is not a teacher.
        TemplateResponse: The rendered admin page with the list of categories
        if the user is a teacher.
    """
    # Check if the user is a teacher
    if not check_if_teacher():
        # Redirect to the home page with a messages

        flash("You need to be a teacher to access this page.", "error")
        return redirect('/?message=Need+To+Be+Logged+in')

    return render_template("admin.html")


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
    if not check_if_teacher():
        flash(NEED_TEACHER_MESSAGE, "error")
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        try:
            # Validate and sanitize the category name
            cat_name = validate_string(
                request.form.get('name').lower().strip(), "Category Name"
            )
        except ValueError as e:
            flash(str(e), "error")
            return redirect('/admin')

        # SQL query to insert the new category into the Categories table
        query = "INSERT INTO Categories ('name') VALUES (?);"
        execute_query(query, params=(cat_name,))
        flash("Category added successfully!", "success")
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
    if not is_logged_in():
        flash("Need to be logged in", "error")
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        try:
            # Validate and sanitize inputs
            maori = validate_string(
                request.form.get('maori').lower(), "Maori Word"
            )
            english = validate_string(
                request.form.get('english').lower(), "English Translation"
            )
            definition = validate_string(
                request.form.get('definition'), "Definition"
            )
            level = validate_integer(request.form.get('level'), "Level")
            cat_id = validate_integer(request.args.get('id'), "Category ID")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(f'/dictionary/?cat_id={request.args.get("id")}')

        # Get the current date and format it as a string
        today = date.today().strftime("%Y.%m.%d")
        image = "noimage"  # Default image name
        author_id = session.get("user_id")  # Author ID from session

        # SQL query to insert the new word into the Vocab_List table
        query = """
        INSERT INTO Vocab_List (maori, english, cat_id, definition,
         date_of_entry, author_id, level, image) VALUES
         (?, ?, ?, ?, ?, ?, ?, ?)
        """
        execute_query(query, params=(maori, english, cat_id, definition,
                                     today, author_id, level, image))
        flash("Word added successfully!", "success")
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
    if not check_if_teacher():
        flash("You need to be a teacher to delete items.", "error")
        return redirect('/?message=Need+To+Be+Logged+in')
    if request.method == 'POST':
        try:
            # Validate and sanitize inputs
            table = validate_string(request.args.get('table'), "Table Name")
            item_id = validate_integer(request.form.get('id'), "ID")
        except ValueError as e:
            flash(str(e), "error")
            return redirect('/admin')

        flash("Item deletion confirmed. Proceed to delete.", "success")
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
    # Ensure the user is a teacher
    if not check_if_teacher():
        flash("You need to be a teacher to confirm deletion.", "error")
        return redirect('/?message=Need+To+Be+Logged+In')
    try:
        # Validate and sanitize inputs
        cat_id = validate_integer(request.args.get('cat_id'), "Category ID")
        table = validate_string(request.args.get('table'), "Table Name")
    except ValueError as e:
        flash(str(e), "error")  # Flash error message
        return redirect('/admin')

    # SQL query to delete the record from the specified table
    query = f"DELETE FROM {table} WHERE id = ?"
    execute_query(query, params=(cat_id,))
    flash("Item deleted successfully!", "success")
    return redirect('/')


# Start the Flask application
app.run(host='0.0.0.0', debug=True)
