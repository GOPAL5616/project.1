import os
import smtplib
import secrets
import sqlite3
import time
import uuid
from email.message import EmailMessage
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import mail_config          # Gmail details for sending OTP (see mail_config.py)
except ImportError:
    mail_config = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-to-any-long-random-text"
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024  # 60 MB per request

ALLOWED_IMAGES = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_VIDEOS = {"mp4", "webm", "mov"}
MAX_IMAGES = 4
MAX_IMAGE_MB = 5
MAX_VIDEO_MB = 30
STATUSES = ["Pending", "In Progress", "Solved"]
STAFF_ROLES = ["faculty", "hod", "admin", "principal"]
ASSIGNABLE_ROLES = ["student", "faculty", "hod", "admin", "principal"]
ROLE_NEEDS_DEPT = ("student", "faculty", "hod")
ROLE_LABEL = {"student": "Student", "faculty": "Faculty", "hod": "HOD",
              "admin": "Admin", "principal": "Principal", "superadmin": "Super Admin"}
HANDLERS = ["hod", "admin", "principal"]

DEPARTMENTS = ["Computer Science", "Information Technology", "Mechanical",
               "Civil", "Electrical", "Electronics", "Management",
               "Pharmacy", "BBA"]

# problem type, kaun handle karega
PROBLEM_TYPES = [("Class", "hod"), ("College", "principal"), ("Bus", "admin"),
                 ("Canteen", "admin"), ("Library", "admin"),
                 ("Mess", "admin"), ("Hostel", "admin")]


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS problem_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        handled_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        department_id INTEGER,
        is_active INTEGER NOT NULL DEFAULT 1,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (department_id) REFERENCES departments(id)
    );
    CREATE TABLE IF NOT EXISTS problems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        problem_code TEXT UNIQUE,
        user_id INTEGER NOT NULL,
        type_id INTEGER NOT NULL,
        department_id INTEGER,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        visibility TEXT NOT NULL DEFAULT 'public',
        anonymous INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (type_id) REFERENCES problem_types(id),
        FOREIGN KEY (department_id) REFERENCES departments(id)
    );
    CREATE TABLE IF NOT EXISTS problem_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        problem_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        media_type TEXT NOT NULL,
        FOREIGN KEY (problem_id) REFERENCES problems(id)
    );
    CREATE TABLE IF NOT EXISTS problem_likes (
        problem_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (problem_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS problem_relatable (
        problem_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (problem_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS pending_registrations (
        email TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        department_id INTEGER NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at REAL NOT NULL,
        last_sent REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS staff_types (
        user_id INTEGER NOT NULL,
        type_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, type_id)
    );
    CREATE TABLE IF NOT EXISTS password_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        done INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        problem_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (problem_id) REFERENCES problems(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    cols = [r[1] for r in db.execute("PRAGMA table_info(problems)").fetchall()]
    if "status_updated_by" not in cols:
        db.execute("ALTER TABLE problems ADD COLUMN status_updated_by INTEGER")
    if "status_updated_at" not in cols:
        db.execute("ALTER TABLE problems ADD COLUMN status_updated_at TEXT")
    for d in DEPARTMENTS:
        db.execute("INSERT OR IGNORE INTO departments(name) VALUES (?)", (d,))
    for name, handler in PROBLEM_TYPES:
        db.execute("INSERT OR IGNORE INTO problem_types(name, handled_by) VALUES (?, ?)",
                   (name, handler))
    db.commit()
    db.close()


# ----------------------------------------------------------- access control
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        user = None
        if uid:
            user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not user or not user["is_active"]:
            session.clear()
            flash("Please log in first.", "bad")
            return redirect(url_for("login"))
        g.user = user
        session["role"] = user["role"]
        if user["must_change_password"] and request.endpoint not in ("change_password", "logout"):
            return redirect(url_for("change_password"))
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:
                flash("You do not have permission to open that page.", "bad")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def type_staff(type_id):
    """IDs of ACTIVE staff who are assigned to a problem type by the Super Admin."""
    return [r["user_id"] for r in get_db().execute(
        "SELECT st.user_id FROM staff_types st JOIN users u ON u.id = st.user_id "
        "WHERE st.type_id = ? AND u.is_active = 1", (type_id,)).fetchall()]


def college_level_access(p, user):
    """For problems NOT handled by HOD (Bus, Canteen, Hostel...): is this Admin/Principal responsible?
    If someone is assigned to the type, ONLY the assigned people. Otherwise the role routing is used."""
    assigned = type_staff(p["type_id"])
    if assigned:
        return user["id"] in assigned
    if user["role"] == "admin":
        return p["handled_by"] == "admin"
    if user["role"] == "principal":
        return p["handled_by"] in ("admin", "principal")
    return False


def can_view(p, user):
    """Who can see a problem (and its photos/videos)."""
    if p["user_id"] == user["id"]:
        return True
    if p["visibility"] == "public":
        return True
    role = user["role"]
    if role in ("superadmin", "principal"):
        return True
    if p["handled_by"] != "hod":          # private Bus / Canteen / Hostel ... problem
        return role in ("admin", "principal") and college_level_access(p, user)
    if role in ("admin", "principal", "faculty"):
        return True
    if role == "hod":
        return (p["department_id"] is not None
                and p["department_id"] == user["department_id"])
    return False


def can_manage(p, user):
    """Who can change the status (Pending / In Progress / Solved) of a problem."""
    role = user["role"]
    if role == "superadmin":
        return True
    if p["handled_by"] != "hod":
        return role in ("admin", "principal") and college_level_access(p, user)
    if role in ("hod", "faculty"):
        return (p["department_id"] is not None
                and p["department_id"] == user["department_id"])
    return False


# ------------------------------------------------------------------ helpers
PROBLEM_SELECT = """
SELECT p.*, t.name AS type_name, t.handled_by AS handled_by, u.name AS author_name, d.name AS dept_name,
  (SELECT m.id FROM problem_media m
     WHERE m.problem_id = p.id AND m.media_type = 'image'
     ORDER BY m.id LIMIT 1) AS thumb_id,
  (SELECT COUNT(*) FROM problem_media m WHERE m.problem_id = p.id) AS media_count,
  (SELECT COUNT(*) FROM problem_likes l WHERE l.problem_id = p.id) AS like_count,
  (SELECT COUNT(*) FROM problem_relatable r WHERE r.problem_id = p.id) AS relatable_count,
  (SELECT COUNT(*) FROM comments c WHERE c.problem_id = p.id) AS comment_count
FROM problems p
JOIN problem_types t ON t.id = p.type_id
JOIN users u ON u.id = p.user_id
LEFT JOIN departments d ON d.id = p.department_id
"""


def decorate(rows, user):
    out = []
    for r in rows:
        p = dict(r)
        real_name_visible = (not p["anonymous"]) or p["user_id"] == user["id"] \
            or user["role"] == "superadmin"
        if real_name_visible:
            p["author"] = p["author_name"] + (" (anonymous post)" if p["anonymous"] else "")
        else:
            p["author"] = "Anonymous"
        out.append(p)
    return out


def file_ext(f):
    name = f.filename or ""
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def file_size(f):
    f.stream.seek(0, os.SEEK_END)
    size = f.stream.tell()
    f.stream.seek(0)
    return size


def save_upload(f, problem_id, media_type):
    name = uuid.uuid4().hex + "." + file_ext(f)
    f.save(os.path.join(UPLOAD_FOLDER, name))
    get_db().execute(
        "INSERT INTO problem_media (problem_id, filename, media_type) VALUES (?, ?, ?)",
        (problem_id, name, media_type))


# ------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("home" if "user_id" in session else "login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user and not db.execute(
                "SELECT 1 FROM password_requests WHERE user_id = ? AND done = 0",
                (user["id"],)).fetchone():
            db.execute("INSERT INTO password_requests (user_id) VALUES (?)", (user["id"],))
            db.commit()
        flash("Request sent. The Super Admin will give you a temporary password. "
              "Then log in and set a new password.", "good")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


OTP_VALID_SECONDS = 600
OTP_RESEND_SECONDS = 60
OTP_MAX_TRIES = 5


def mail_configured():
    return bool(mail_config and getattr(mail_config, "EMAIL_ADDRESS", "")
                and getattr(mail_config, "EMAIL_APP_PASSWORD", ""))


def send_otp(email, otp):
    """Returns True if sent. Without mail_config the OTP is printed in the terminal (test mode)."""
    if not mail_configured():
        print(f"\n[TEST MODE] OTP for {email} is {otp}\n")
        return True
    msg = EmailMessage()
    msg["Subject"] = "College Complaint Portal - your verification code"
    msg["From"] = mail_config.EMAIL_ADDRESS
    msg["To"] = email
    msg.set_content(f"Your verification code is {otp}\n\nIt is valid for 10 minutes. "
                    "If you did not register, ignore this email.")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as server:
            server.login(mail_config.EMAIL_ADDRESS, mail_config.EMAIL_APP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print("Could not send email:", exc)
        return False


def issue_otp(db, email):
    """Make a new OTP for a pending registration, email it. Returns True if sent."""
    otp = f"{secrets.randbelow(1000000):06d}"
    if not send_otp(email, otp):
        return False
    now = time.time()
    db.execute("UPDATE pending_registrations SET otp_hash = ?, expires_at = ?, last_sent = ?, "
               "attempts = 0 WHERE email = ?",
               (generate_password_hash(otp), now + OTP_VALID_SECONDS, now, email))
    db.commit()
    return True


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    departments = db.execute("SELECT * FROM departments ORDER BY name").fetchall()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        dept_id = request.form.get("department", "")

        error = None
        if not name:
            error = "Enter your full name."
        elif not email.endswith("@gmail.com") or len(email) < 12:
            error = "Only a Gmail address (@gmail.com) is allowed."
        elif not dept_id:
            error = "Select your department."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            error = "This email is already registered. Please log in."

        if error:
            flash(error, "bad")
            return render_template("register.html", departments=departments)

        old = db.execute("SELECT last_sent FROM pending_registrations WHERE email = ?",
                         (email,)).fetchone()
        too_soon = old is not None and time.time() - old["last_sent"] < OTP_RESEND_SECONDS
        if too_soon:
            db.execute("UPDATE pending_registrations SET name = ?, password_hash = ?, "
                       "department_id = ? WHERE email = ?",
                       (name, generate_password_hash(password), dept_id, email))
            db.commit()
        else:
            db.execute("INSERT OR REPLACE INTO pending_registrations "
                       "(email, name, password_hash, department_id, otp_hash, expires_at, last_sent, attempts) "
                       "VALUES (?, ?, ?, ?, '', 0, 0, 0)",
                       (email, name, generate_password_hash(password), dept_id))
            db.commit()
            if not issue_otp(db, email):
                db.execute("DELETE FROM pending_registrations WHERE email = ?", (email,))
                db.commit()
                flash("Could not send the verification email. Check the email address and try again.", "bad")
                return render_template("register.html", departments=departments)
        session["pending_email"] = email
        flash("Verification code sent to your Gmail. Enter it below.", "good")
        return redirect(url_for("verify_email"))

    return render_template("register.html", departments=departments)


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email = session.get("pending_email")
    db = get_db()
    pending = db.execute("SELECT * FROM pending_registrations WHERE email = ?",
                         (email,)).fetchone() if email else None
    if not pending:
        flash("Please register first.", "bad")
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if time.time() > pending["expires_at"]:
            flash("This code has expired. Click 'Send new code'.", "bad")
        elif pending["attempts"] >= OTP_MAX_TRIES:
            db.execute("DELETE FROM pending_registrations WHERE email = ?", (email,))
            db.commit()
            session.pop("pending_email", None)
            flash("Too many wrong attempts. Please register again.", "bad")
            return redirect(url_for("register"))
        elif not check_password_hash(pending["otp_hash"], code):
            db.execute("UPDATE pending_registrations SET attempts = attempts + 1 WHERE email = ?",
                       (email,))
            db.commit()
            flash("Wrong code. Try again.", "bad")
        else:
            if not db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                db.execute("INSERT INTO users (name, email, password_hash, role, department_id) "
                           "VALUES (?, ?, ?, 'student', ?)",
                           (pending["name"], email, pending["password_hash"],
                            pending["department_id"]))
            db.execute("DELETE FROM pending_registrations WHERE email = ?", (email,))
            db.commit()
            session.pop("pending_email", None)
            flash("Email verified. Account created. You can log in now.", "good")
            return redirect(url_for("login"))
    return render_template("verify_email.html", email=email, test_mode=not mail_configured())


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("pending_email")
    db = get_db()
    pending = db.execute("SELECT last_sent FROM pending_registrations WHERE email = ?",
                         (email,)).fetchone() if email else None
    if not pending:
        return redirect(url_for("register"))
    wait = int(OTP_RESEND_SECONDS - (time.time() - pending["last_sent"]))
    if wait > 0:
        flash(f"Please wait {wait} seconds before asking for a new code.", "bad")
    elif issue_otp(db, email):
        flash("A new code has been sent.", "good")
    else:
        flash("Could not send the email. Try again later.", "bad")
    return redirect(url_for("verify_email"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect.", "bad")
        elif not user["is_active"]:
            flash("This account is deactivated. Contact the admin.", "bad")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "good")
    return redirect(url_for("login"))


@app.route("/home")
@login_required
def home():
    return render_template("home.html")


@app.route("/post", methods=["GET", "POST"])
@login_required
@role_required("student")
def post_problem():
    db = get_db()
    types = db.execute("SELECT * FROM problem_types ORDER BY id").fetchall()

    if request.method == "POST":
        type_id = request.form.get("type_id", "")
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        visibility = request.form.get("visibility", "public")
        anonymous = 1 if request.form.get("anonymous") else 0

        images = [f for f in request.files.getlist("images") if f and f.filename]
        video = request.files.get("video")
        if video is not None and not video.filename:
            video = None

        error = None
        if not db.execute("SELECT 1 FROM problem_types WHERE id = ?", (type_id,)).fetchone():
            error = "Select a problem type."
        elif not (5 <= len(title) <= 100):
            error = "Title must be 5 to 100 characters."
        elif not (20 <= len(description) <= 1000):
            error = "Describe the problem in 20 to 1000 characters."
        elif visibility not in ("public", "private"):
            error = "Choose Public or Private."
        elif len(images) > MAX_IMAGES:
            error = f"You can upload at most {MAX_IMAGES} photos."
        else:
            for f in images:
                if file_ext(f) not in ALLOWED_IMAGES:
                    error = "Photos must be JPG, PNG, GIF or WEBP."
                    break
                if file_size(f) > MAX_IMAGE_MB * 1024 * 1024:
                    error = f"Each photo must be under {MAX_IMAGE_MB} MB."
                    break
            if not error and video is not None:
                if file_ext(video) not in ALLOWED_VIDEOS:
                    error = "Video must be MP4, WEBM or MOV."
                elif file_size(video) > MAX_VIDEO_MB * 1024 * 1024:
                    error = f"Video must be under {MAX_VIDEO_MB} MB."

        if error:
            flash(error, "bad")
            return render_template("post.html", types=types, form=request.form,
                                   max_images=MAX_IMAGES, max_image_mb=MAX_IMAGE_MB,
                                   max_video_mb=MAX_VIDEO_MB)

        cur = db.execute(
            "INSERT INTO problems (user_id, type_id, department_id, title, description, "
            "visibility, anonymous) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (g.user["id"], type_id, g.user["department_id"], title, description,
             visibility, anonymous))
        pid = cur.lastrowid
        code = f"PRB-{1000 + pid}"
        db.execute("UPDATE problems SET problem_code = ? WHERE id = ?", (code, pid))
        for f in images:
            save_upload(f, pid, "image")
        if video is not None:
            save_upload(video, pid, "video")
        db.commit()

        flash(f"Problem posted. Your Problem ID is {code}.", "good")
        return redirect(url_for("problem_detail", code=code))

    return render_template("post.html", types=types, form={},
                           max_images=MAX_IMAGES, max_image_mb=MAX_IMAGE_MB,
                           max_video_mb=MAX_VIDEO_MB)


@app.route("/feed")
@login_required
def feed():
    db = get_db()
    types = db.execute("SELECT * FROM problem_types ORDER BY id").fetchall()
    selected = request.args.get("type", "").strip()

    sql = PROBLEM_SELECT + " WHERE p.visibility = 'public'"
    params = []
    if selected:
        sql += " AND t.name = ?"
        params.append(selected)
    sql += " ORDER BY p.id DESC LIMIT 100"

    problems = decorate(db.execute(sql, params).fetchall(), g.user)
    return render_template("feed.html", problems=problems, types=types, selected=selected)


@app.route("/my-problems")
@login_required
@role_required("student")
def my_problems():
    rows = get_db().execute(
        PROBLEM_SELECT + " WHERE p.user_id = ? ORDER BY p.id DESC", (g.user["id"],)).fetchall()
    return render_template("my_problems.html", problems=decorate(rows, g.user))


def get_visible_problem(code):
    row = get_db().execute(PROBLEM_SELECT + " WHERE p.problem_code = ?", (code,)).fetchone()
    if row is None or not can_view(row, g.user):
        abort(404)
    return row


@app.route("/problem/<code>")
@login_required
def problem_detail(code):
    db = get_db()
    row = get_visible_problem(code)
    p = decorate([row], g.user)[0]
    media = db.execute(
        "SELECT * FROM problem_media WHERE problem_id = ? ORDER BY id", (row["id"],)).fetchall()
    uid = g.user["id"]
    liked = db.execute("SELECT 1 FROM problem_likes WHERE problem_id = ? AND user_id = ?",
                       (row["id"], uid)).fetchone() is not None
    relatable = db.execute("SELECT 1 FROM problem_relatable WHERE problem_id = ? AND user_id = ?",
                           (row["id"], uid)).fetchone() is not None

    comments = []
    for c in db.execute(
            "SELECT c.*, u.name AS user_name, u.role AS user_role FROM comments c "
            "JOIN users u ON u.id = c.user_id WHERE c.problem_id = ? ORDER BY c.id",
            (row["id"],)).fetchall():
        c = dict(c)
        is_owner = c["user_id"] == row["user_id"]
        if is_owner and row["anonymous"] and uid != row["user_id"] \
                and g.user["role"] != "superadmin":
            c["who"] = "Anonymous (post author)"
        else:
            c["who"] = c["user_name"] + (" (post author)" if is_owner else "")
        c["staff"] = c["user_role"] != "student"
        comments.append(c)

    updater = None
    if row["status_updated_by"]:
        u = db.execute("SELECT name FROM users WHERE id = ?", (row["status_updated_by"],)).fetchone()
        updater = u["name"] if u else None
    return render_template("problem.html", p=p, media=media, liked=liked,
                           relatable=relatable, comments=comments, updater=updater,
                           can_manage=can_manage(row, g.user), statuses=STATUSES)


def toggle_reaction(table, code):
    db = get_db()
    row = get_visible_problem(code)
    uid = g.user["id"]
    exists = db.execute(f"SELECT 1 FROM {table} WHERE problem_id = ? AND user_id = ?",
                        (row["id"], uid)).fetchone()
    if exists:
        db.execute(f"DELETE FROM {table} WHERE problem_id = ? AND user_id = ?", (row["id"], uid))
    else:
        db.execute(f"INSERT INTO {table} (problem_id, user_id) VALUES (?, ?)", (row["id"], uid))
    db.commit()
    return redirect(url_for("problem_detail", code=code) + "#react")


@app.route("/problem/<code>/like", methods=["POST"])
@login_required
def like_problem(code):
    return toggle_reaction("problem_likes", code)


@app.route("/problem/<code>/relatable", methods=["POST"])
@login_required
def relatable_problem(code):
    return toggle_reaction("problem_relatable", code)


@app.route("/problem/<code>/comment", methods=["POST"])
@login_required
def add_comment(code):
    row = get_visible_problem(code)
    body = request.form.get("body", "").strip()
    if not (1 <= len(body) <= 500):
        flash("Comment must be 1 to 500 characters.", "bad")
    else:
        db = get_db()
        db.execute("INSERT INTO comments (problem_id, user_id, body) VALUES (?, ?, ?)",
                   (row["id"], g.user["id"], body))
        db.commit()
    return redirect(url_for("problem_detail", code=code) + "#comments")


@app.route("/media/<int:media_id>")
@login_required
def media(media_id):
    m = get_db().execute(
        "SELECT m.*, p.user_id, p.visibility, p.department_id, p.type_id, t.handled_by "
        "FROM problem_media m JOIN problems p ON p.id = m.problem_id "
        "JOIN problem_types t ON t.id = p.type_id WHERE m.id = ?",
        (media_id,)).fetchone()
    if m is None or not can_view(m, g.user):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, m["filename"])



# ------------------------------------------------------- staff: dashboard
def staff_scope(user):
    """SQL filter: which problems this staff member is responsible for."""
    role = user["role"]
    if role in ("superadmin", "principal"):
        return "", []
    if role == "admin":
        fallback = "('admin')"
        return (" AND t.handled_by != 'hod' AND ("
                "p.type_id IN (SELECT type_id FROM staff_types WHERE user_id = ?) "
                "OR (NOT EXISTS (SELECT 1 FROM staff_types st JOIN users su ON su.id = st.user_id "
                "WHERE st.type_id = p.type_id AND su.is_active = 1) "
                "AND t.handled_by IN " + fallback + "))", [user["id"]])
    if user["department_id"] is None:
        return " AND 1 = 0", []
    if role == "hod":
        # every PUBLIC problem of the HOD's department, plus the department's Class problems
        return (" AND p.department_id = ? AND (t.handled_by = 'hod' OR p.visibility = 'public')",
                [user["department_id"]])
    return " AND t.handled_by = 'hod' AND p.department_id = ?", [user["department_id"]]


@app.route("/dashboard")
@login_required
@role_required("faculty", "hod", "admin", "principal", "superadmin")
def dashboard():
    db = get_db()
    scope, params = staff_scope(g.user)
    selected = request.args.get("status", "open")

    counts = {s_: 0 for s_ in STATUSES}
    for r in db.execute(
            "SELECT p.status AS st, COUNT(*) AS n FROM problems p "
            "JOIN problem_types t ON t.id = p.type_id WHERE 1 = 1" + scope + " GROUP BY p.status",
            params).fetchall():
        counts[r["st"]] = r["n"]

    sql = PROBLEM_SELECT + " WHERE 1 = 1" + scope
    qparams = list(params)
    if selected == "open":
        sql += " AND p.status != 'Solved'"
    elif selected in STATUSES:
        sql += " AND p.status = ?"
        qparams.append(selected)
    else:
        selected = "all"
    sql += " ORDER BY p.id DESC LIMIT 200"
    rows = db.execute(sql, qparams).fetchall()
    problems = decorate(rows, g.user)
    for row, p in zip(rows, problems):
        p["view_only"] = not can_manage(row, g.user)

    if g.user["role"] in ("admin", "principal"):
        mine = [r["name"] for r in db.execute(
            "SELECT t.name FROM staff_types st JOIN problem_types t ON t.id = st.type_id "
            "WHERE st.user_id = ? ORDER BY t.id", (g.user["id"],)).fetchall()]
        if g.user["role"] == "principal":
            scope_text = "You can see ALL problems of all departments."
            if mine:
                scope_text += " Problem types given to you to solve: " + ", ".join(mine) + "."
        elif mine:
            scope_text = "Problem types given to you: " + ", ".join(mine) + "."
        else:
            scope_text = ("No problem type is given to you yet. You see only the types that "
                          "nobody is assigned to.")
    elif g.user["role"] == "superadmin":
        scope_text = "All problems of all departments."
    elif g.user["role"] == "hod":
        dept = db.execute("SELECT name FROM departments WHERE id = ?",
                          (g.user["department_id"],)).fetchone()
        scope_text = ("All public problems and Class problems of " +
                      (dept["name"] if dept else "your department") +
                      ". You can solve the Class problems; the rest are view only.")
    else:
        dept = db.execute("SELECT name FROM departments WHERE id = ?",
                          (g.user["department_id"],)).fetchone()
        scope_text = "Class problems of " + (dept["name"] if dept else "your department") + "."
    return render_template("dashboard.html", problems=problems, counts=counts,
                           selected=selected, scope_text=scope_text, statuses=STATUSES)


@app.route("/problem/<code>/status", methods=["POST"])
@login_required
def update_status(code):
    row = get_visible_problem(code)
    if not can_manage(row, g.user):
        flash("You cannot change the status of this problem.", "bad")
        return redirect(url_for("problem_detail", code=code))
    status = request.form.get("status", "")
    remark = request.form.get("remark", "").strip()
    if status not in STATUSES:
        flash("Invalid status.", "bad")
        return redirect(url_for("problem_detail", code=code))
    if len(remark) > 500:
        flash("Remark can be at most 500 characters.", "bad")
        return redirect(url_for("problem_detail", code=code))
    db = get_db()
    db.execute("UPDATE problems SET status = ?, status_updated_by = ?, "
               "status_updated_at = CURRENT_TIMESTAMP WHERE id = ?",
               (status, g.user["id"], row["id"]))
    if remark:
        db.execute("INSERT INTO comments (problem_id, user_id, body) VALUES (?, ?, ?)",
                   (row["id"], g.user["id"], remark))
    db.commit()
    flash(f"Status changed to {status}.", "good")
    return redirect(url_for("problem_detail", code=code))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(new) < 6:
            flash("Password must be at least 6 characters.", "bad")
        elif new != confirm:
            flash("Passwords do not match.", "bad")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                       (generate_password_hash(new), g.user["id"]))
            db.commit()
            flash("Password changed.", "good")
            return redirect(url_for("home"))
    return render_template("change_password.html")


# ------------------------------------------------------ super admin panel
def get_departments():
    return get_db().execute("SELECT * FROM departments ORDER BY name").fetchall()


@app.route("/admin/users")
@login_required
@role_required("superadmin")
def admin_users():
    db = get_db()
    selected = request.args.get("role", "staff")
    sql = ("SELECT u.*, d.name AS dept_name FROM users u "
           "LEFT JOIN departments d ON d.id = u.department_id")
    params = []
    if selected == "staff":
        sql += " WHERE u.role != 'student'"
    elif selected in ROLE_LABEL:
        sql += " WHERE u.role = ?"
        params.append(selected)
    else:
        selected = "all"
    sql += " ORDER BY u.role, u.name LIMIT 300"
    reqs = db.execute(
        "SELECT r.created_at, u.id AS uid, u.name, u.email, u.role FROM password_requests r "
        "JOIN users u ON u.id = r.user_id WHERE r.done = 0 ORDER BY r.id").fetchall()
    assigned_ids, assigned_names = {}, {}
    for r in db.execute("SELECT st.user_id AS uid, t.id AS tid, t.name FROM staff_types st "
                        "JOIN problem_types t ON t.id = st.type_id ORDER BY t.id").fetchall():
        assigned_ids.setdefault(r["uid"], []).append(r["tid"])
        assigned_names.setdefault(r["uid"], []).append(r["name"])
    college_types = db.execute(
        "SELECT * FROM problem_types WHERE handled_by != 'hod' ORDER BY id").fetchall()
    return render_template("admin_users.html", users=db.execute(sql, params).fetchall(),
                           reqs=reqs, college_types=college_types,
                           assigned_ids=assigned_ids, assigned_names=assigned_names,
                           departments=get_departments(), selected=selected,
                           roles=ASSIGNABLE_ROLES, labels=ROLE_LABEL)


@app.route("/admin/users/add", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_add_user():
    db = get_db()
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "")
    dept_id = request.form.get("department", "") or None
    password = request.form.get("password", "")
    error = None
    if not name:
        error = "Enter the staff name."
    elif "@" not in email or len(email) < 6:
        error = "Enter a valid email."
    elif role not in STAFF_ROLES:
        error = "Select a role."
    elif role in ROLE_NEEDS_DEPT and not dept_id:
        error = "Select a department for Faculty / HOD."
    elif len(password) < 6:
        error = "Temporary password must be at least 6 characters."
    elif db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        error = "This email is already registered."
    if error:
        flash(error, "bad")
    else:
        db.execute("INSERT INTO users (name, email, password_hash, role, department_id, "
                   "must_change_password) VALUES (?, ?, ?, ?, ?, 1)",
                   (name, email, generate_password_hash(password), role,
                    dept_id if role in ROLE_NEEDS_DEPT else None))
        db.commit()
        flash(f"{ROLE_LABEL[role]} account created for {name}. They must change the "
              "temporary password at first login.", "good")
    return redirect(url_for("admin_users"))


def target_user(uid):
    u = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if u is None:
        abort(404)
    return u


@app.route("/admin/users/<int:uid>/update", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_update_user(uid):
    u = target_user(uid)
    if u["id"] == g.user["id"] or u["role"] == "superadmin":
        flash("You cannot change a Super Admin account here.", "bad")
        return redirect(url_for("admin_users"))
    role = request.form.get("role", "")
    dept_id = request.form.get("department", "") or None
    if role not in ASSIGNABLE_ROLES:
        flash("Invalid role.", "bad")
    elif role in ROLE_NEEDS_DEPT and not dept_id:
        flash("Select a department for this role.", "bad")
    else:
        db = get_db()
        db.execute("UPDATE users SET role = ?, department_id = ? WHERE id = ?",
                   (role, dept_id if role in ROLE_NEEDS_DEPT else None, uid))
        if role not in ("admin", "principal"):
            db.execute("DELETE FROM staff_types WHERE user_id = ?", (uid,))
        db.commit()
        flash(f"{u['name']} is now {ROLE_LABEL[role]}.", "good")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/users/<int:uid>/types", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_set_user_types(uid):
    u = target_user(uid)
    if u["role"] not in ("admin", "principal"):
        flash("Problem types can be given only to Admin or Principal accounts.", "bad")
        return redirect(request.referrer or url_for("admin_users"))
    db = get_db()
    valid = {r["id"] for r in db.execute(
        "SELECT id FROM problem_types WHERE handled_by != 'hod'").fetchall()}
    chosen = {int(i) for i in request.form.getlist("type_ids") if i.isdigit() and int(i) in valid}
    db.execute("DELETE FROM staff_types WHERE user_id = ?", (uid,))
    for tid in chosen:
        db.execute("INSERT INTO staff_types (user_id, type_id) VALUES (?, ?)", (uid, tid))
    db.commit()
    flash(f"Problem types saved for {u['name']}.", "good")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_toggle_user(uid):
    u = target_user(uid)
    if u["id"] == g.user["id"] or u["role"] == "superadmin":
        flash("You cannot deactivate a Super Admin account.", "bad")
    else:
        db = get_db()
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (0 if u["is_active"] else 1, uid))
        db.commit()
        flash(f"{u['name']} is now {'deactivated' if u['is_active'] else 'active'}.", "good")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/users/<int:uid>/reset", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_reset_password(uid):
    u = target_user(uid)
    password = request.form.get("password", "")
    if u["role"] == "superadmin":
        flash("Super Admin password cannot be reset here.", "bad")
    elif len(password) < 6:
        flash("Temporary password must be at least 6 characters.", "bad")
    else:
        db = get_db()
        db.execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                   (generate_password_hash(password), uid))
        db.execute("UPDATE password_requests SET done = 1 WHERE user_id = ?", (uid,))
        db.commit()
        flash(f"Temporary password set for {u['name']}. They must change it at next login.", "good")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/admin/settings")
@login_required
@role_required("superadmin")
def admin_settings():
    types = get_db().execute(
        "SELECT t.*, (SELECT COUNT(*) FROM problems p WHERE p.type_id = t.id) AS used "
        "FROM problem_types t ORDER BY t.id").fetchall()
    names = {}
    for r in get_db().execute(
            "SELECT st.type_id AS tid, u.name FROM staff_types st JOIN users u ON u.id = st.user_id "
            "WHERE u.is_active = 1 ORDER BY u.name").fetchall():
        names.setdefault(r["tid"], []).append(r["name"])
    return render_template("admin_settings.html", types=types, departments=get_departments(),
                           names=names)


@app.route("/admin/types/add", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_add_type():
    name = request.form.get("name", "").strip()
    handled_by = request.form.get("handled_by", "")
    if not (2 <= len(name) <= 30) or handled_by not in HANDLERS:
        flash("Enter a type name (2 to 30 letters) and choose who handles it.", "bad")
    else:
        try:
            db = get_db()
            db.execute("INSERT INTO problem_types (name, handled_by) VALUES (?, ?)", (name, handled_by))
            db.commit()
            flash(f"Problem type '{name}' added.", "good")
        except sqlite3.IntegrityError:
            flash("This problem type already exists.", "bad")
    return redirect(url_for("admin_settings"))


@app.route("/admin/types/<int:tid>/route", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_route_type(tid):
    handled_by = request.form.get("handled_by", "")
    if handled_by not in HANDLERS:
        flash("Invalid choice.", "bad")
    else:
        db = get_db()
        db.execute("UPDATE problem_types SET handled_by = ? WHERE id = ?", (handled_by, tid))
        db.commit()
        flash("Routing updated. It applies to old and new problems of this type.", "good")
    return redirect(url_for("admin_settings"))


@app.route("/admin/types/<int:tid>/delete", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_delete_type(tid):
    db = get_db()
    if db.execute("SELECT 1 FROM problems WHERE type_id = ?", (tid,)).fetchone():
        flash("This type already has problems, so it cannot be deleted.", "bad")
    else:
        db.execute("DELETE FROM problem_types WHERE id = ?", (tid,))
        db.commit()
        flash("Problem type deleted.", "good")
    return redirect(url_for("admin_settings"))


@app.route("/admin/departments/add", methods=["POST"])
@login_required
@role_required("superadmin")
def admin_add_department():
    name = request.form.get("name", "").strip()
    if not (2 <= len(name) <= 60):
        flash("Enter a department name (2 to 60 characters).", "bad")
    else:
        try:
            db = get_db()
            db.execute("INSERT INTO departments (name) VALUES (?)", (name,))
            db.commit()
            flash(f"Department '{name}' added.", "good")
        except sqlite3.IntegrityError:
            flash("This department already exists.", "bad")
    return redirect(url_for("admin_settings"))


# ----------------------------------------------------------- error handlers
@app.errorhandler(404)
def not_found(e):
    return ("<p style='font-family:sans-serif;padding:24px'>Page not found or you do not "
            "have access. <a href='/'>Go home</a></p>"), 404


@app.errorhandler(413)
def too_large(e):
    flash(f"Upload too large. Photos max {MAX_IMAGE_MB} MB each, video max {MAX_VIDEO_MB} MB.",
          "bad")
    return redirect(url_for("post_problem"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
