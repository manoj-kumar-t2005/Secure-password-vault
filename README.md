# Secure-password-vault
import sqlite3
import hashlib
import secrets

# Create Database
conn = sqlite3.connect("password_vault.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL
)
""")
conn.commit()


# Function to Generate Salt
def generate_salt():
    return secrets.token_hex(16)


# Function to Hash Password
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


# Register User
def register():
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    try:
        cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?)",
            (username, salt, password_hash)
        )
        conn.commit()
        print("User Registered Successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists!")


# Login User
def login():
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    cursor.execute(
        "SELECT salt, password_hash FROM users WHERE username=?",
        (username,)
    )

    user = cursor.fetchone()

    if user:
        salt, stored_hash = user
        entered_hash = hash_password(password, salt)

        if entered_hash == stored_hash:
            print("Login Successful!")
        else:
            print("Invalid Password!")
    else:
        print("User Not Found!")


# Admin View
def admin_view():
    print("\n--- Database Records ---")
    cursor.execute("SELECT * FROM users")

    for row in cursor.fetchall():
        print(row)

    print("\nAdmin can only see SALT and HASH values.")
    print("Actual passwords are NOT stored in the database.")


# Menu
while True:
    print("\n1. Register")
    print("2. Login")
    print("3. Admin View")
    print("4. Exit")

    choice = input("Enter Choice: ")

    if choice == "1":
        register()
    elif choice == "2":
        login()
    elif choice == "3":
        admin_view()
    elif choice == "4":
        break
    else:
        print("Invalid Choice!")

conn.close()
