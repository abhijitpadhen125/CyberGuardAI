import sqlite3
import re

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


DATABASE = "users.db"


# =========================================================
# INITIALIZE USER DATABASE
# =========================================================

def init_users_db():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()

    conn.close()


# =========================================================
# PASSWORD VALIDATION
# =========================================================

def validate_password(password):

    if len(password) < 8:

        return False, (
            "Password must contain at least 8 characters."
        )


    if not re.search(
        r"[A-Z]",
        password
    ):

        return False, (
            "Password must contain at least one uppercase letter."
        )


    if not re.search(
        r"[a-z]",
        password
    ):

        return False, (
            "Password must contain at least one lowercase letter."
        )


    if not re.search(
        r"[0-9]",
        password
    ):

        return False, (
            "Password must contain at least one number."
        )


    if not re.search(
        r"[^A-Za-z0-9]",
        password
    ):

        return False, (
            "Password must contain at least one special character."
        )


    return True, "Password is valid."


# =========================================================
# USERNAME VALIDATION
# =========================================================

def validate_username(username):

    if len(username) < 3:

        return False, (
            "Username must contain at least 3 characters."
        )


    if len(username) > 30:

        return False, (
            "Username must not exceed 30 characters."
        )


    if not re.match(
        r"^[A-Za-z0-9_]+$",
        username
    ):

        return False, (
            "Username can contain only letters, numbers and underscore."
        )


    return True, "Username is valid."


# =========================================================
# CREATE USER
# =========================================================

def create_user(
    username,
    password
):

    username_valid, username_message = (
        validate_username(username)
    )

    if not username_valid:

        return False, username_message


    password_valid, password_message = (
        validate_password(password)
    )

    if not password_valid:

        return False, password_message


    conn = sqlite3.connect(
        DATABASE
    )

    cursor = conn.cursor()


    try:

        password_hash = generate_password_hash(
            password
        )


        cursor.execute(
            """
            INSERT INTO users (
                username,
                password
            )
            VALUES (?, ?)
            """,
            (
                username,
                password_hash
            )
        )


        conn.commit()

        return True, "User created successfully."


    except sqlite3.IntegrityError:

        return False, (
            "Username already exists."
        )


    finally:

        conn.close()


# =========================================================
# VERIFY USER
# =========================================================

def verify_user(
    username,
    password
):

    conn = sqlite3.connect(
        DATABASE
    )

    cursor = conn.cursor()


    cursor.execute(
        """
        SELECT
            id,
            username,
            password
        FROM users
        WHERE username = ?
        """,
        (
            username,
        )
    )


    user = cursor.fetchone()

    conn.close()


    if user is None:

        return None


    if check_password_hash(
        user[2],
        password
    ):

        return user


    return None