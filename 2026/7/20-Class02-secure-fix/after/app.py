import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("APP_DATABASE"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_FAILED_ATTEMPTS=5,
        LOCKOUT_SECONDS=60,
    )
    if test_config:
        app.config.update(test_config)

    if not app.config["DATABASE"]:
        os.makedirs(app.instance_path, exist_ok=True)
        app.config["DATABASE"] = os.path.join(app.instance_path, "users.db")

    failed_logins = {}

    def get_db():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        conn = get_db()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    phone TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    balance INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                )
                """
            )
            admin_password = os.environ.get("ADMIN_PASSWORD")
            if admin_password:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users
                    (username, password_hash, email, phone, role, balance, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "admin",
                        generate_password_hash(admin_password),
                        os.environ.get("ADMIN_EMAIL", "admin@example.com"),
                        os.environ.get("ADMIN_PHONE", "13800138000"),
                        "admin",
                        int(os.environ.get("ADMIN_BALANCE", "0")),
                        int(time.time()),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def generate_csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def validate_csrf_token():
        expected = session.get("csrf_token")
        actual = request.form.get("csrf_token", "")
        return expected and secrets.compare_digest(expected, actual)

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        conn = get_db()
        try:
            return conn.execute(
                "SELECT id, username, email, phone, role, balance FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        finally:
            conn.close()

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def is_locked(username, ip_address):
        key = (ip_address, username.lower())
        attempts = failed_logins.get(key, [])
        now = time.time()
        attempts = [ts for ts in attempts if now - ts < app.config["LOCKOUT_SECONDS"]]
        failed_logins[key] = attempts
        return len(attempts) >= app.config["MAX_FAILED_ATTEMPTS"]

    def record_login_failure(username, ip_address):
        key = (ip_address, username.lower())
        failed_logins.setdefault(key, []).append(time.time())

    def clear_login_failures(username, ip_address):
        failed_logins.pop((ip_address, username.lower()), None)

    def validate_registration(username, password, email, phone):
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            return "用户名只能包含字母、数字和下划线，长度为 3-32 位"
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            return "密码至少 8 位，并同时包含字母和数字"
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return "邮箱格式不正确"
        if not re.fullmatch(r"1[3-9]\d{9}", phone):
            return "手机号格式不正确"
        return None

    @app.after_request
    def set_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    @app.context_processor
    def inject_globals():
        return {"csrf_token": generate_csrf_token, "current_user": current_user()}

    @app.route("/")
    def index():
        return render_template("index.html", user=current_user(), keyword="", search_results=None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            if not validate_csrf_token():
                abort(400)

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip_address = request.remote_addr or "unknown"

            if is_locked(username, ip_address):
                error = "登录失败次数过多，请稍后再试"
            else:
                conn = get_db()
                try:
                    row = conn.execute(
                        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                        (username,),
                    ).fetchone()
                finally:
                    conn.close()
                if row and check_password_hash(row["password_hash"], password):
                    clear_login_failures(username, ip_address)
                    session.clear()
                    session.permanent = True
                    session["user_id"] = row["id"]
                    session["username"] = row["username"]
                    session["role"] = row["role"]
                    generate_csrf_token()
                    return redirect(url_for("index"))

                record_login_failure(username, ip_address)
                error = "用户名或密码错误，请重试"

        return render_template("login.html", error=error, msg=request.args.get("msg", ""))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        error = None
        if request.method == "POST":
            if not validate_csrf_token():
                abort(400)

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()

            error = validate_registration(username, password, email, phone)
            if not error:
                try:
                    conn = get_db()
                    try:
                        conn.execute(
                            """
                            INSERT INTO users
                            (username, password_hash, email, phone, role, balance, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                username,
                                generate_password_hash(password),
                                email,
                                phone,
                                "user",
                                0,
                                int(time.time()),
                            ),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    return redirect(url_for("login", msg="注册成功，请登录"))
                except sqlite3.IntegrityError:
                    error = "用户名或邮箱已存在"

        return render_template("register.html", error=error)

    @app.route("/search")
    @login_required
    def search():
        user = current_user()
        if user["role"] != "admin":
            abort(403)

        keyword = request.args.get("keyword", "").strip()
        search_results = []
        if keyword:
            like_keyword = f"%{keyword[:64]}%"
            conn = get_db()
            try:
                search_results = conn.execute(
                    """
                    SELECT id, username, email, phone
                    FROM users
                    WHERE username LIKE ? OR email LIKE ?
                    ORDER BY id
                    LIMIT 20
                    """,
                    (like_keyword, like_keyword),
                ).fetchall()
            finally:
                conn.close()

        return render_template("index.html", user=user, keyword=keyword, search_results=search_results)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        if not validate_csrf_token():
            abort(400)
        session.clear()
        return redirect(url_for("index"))

    @app.route("/logout", methods=["GET"])
    def logout_get_not_allowed():
        abort(405)

    app.init_db = init_db
    return app


app = create_app()


if __name__ == "__main__":
    app.init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
