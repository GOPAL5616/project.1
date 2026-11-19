import sqlite3
import getpass
from werkzeug.security import generate_password_hash
from app import init_db, DB

init_db()
name = input("Super admin name: ").strip()
email = input("Super admin email: ").strip().lower()
password = getpass.getpass("Password (min 8 characters): ")

if not name or not email or len(password) < 8:
    print("Invalid details. Try again.")
else:
    db = sqlite3.connect(DB)
    try:
        db.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'superadmin')",
            (name, email, generate_password_hash(password)))
        db.commit()
        print("Super admin created.")
    except sqlite3.IntegrityError:
        print("This email already exists.")
    db.close()
