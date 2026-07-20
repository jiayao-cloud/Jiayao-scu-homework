import hmac
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler


app = Flask(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[0-9+\-\s]{5,20}$")


def _load_secret_key():
    """Load a deployment secret; never fall back to a predictable key."""
    configured = os.environ.get("FLASK_SECRET_KEY")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 characters")
        return configured

    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("FLASK_SECRET_KEY must be configured in production")

    return secrets.token_urlsafe(32)


def _required_password(name):
    password = os.environ.get(name)
    if not password or len(password) < 12:
        raise RuntimeError(f"{name} must be set and contain at least 12 characters")
    return password


def _database_path():
    return Path(os.environ.get("DATABASE_PATH", "data/users.db"))


app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get(
        "SESSION_COOKIE_SECURE", "1" if os.environ.get("FLASK_ENV") == "production" else "0"
    )
    == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


def _connect():
    db_path = _database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    default_users = (
        ("admin", _required_password("ADMIN_PASSWORD"), "admin", "admin@example.com", "13800138000", 99999),
        ("alice", _required_password("ALICE_PASSWORD"), "user", "alice@example.com", "13900139001", 100),
    )
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                balance INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        for username, password, role, email, phone, balance in default_users:
            conn.execute(
                """
                INSERT OR IGNORE INTO users
                    (username, password_hash, role, email, phone, balance)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, generate_password_hash(password, method="scrypt"), role, email, phone, balance),
            )
        conn.commit()
    finally:
        conn.close()


init_db()

# Compatibility symbol for tests and readers: users now live in SQLite.
USERS = "sqlite:data/users.db"

# This in-memory limiter is suitable for the teaching sample. Production should
# back it with a shared store such as Redis so multiple workers share limits.
MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60
_failed_attempts = defaultdict(deque)


def _rate_limit_key(username):
    ip = request.remote_addr or "unknown"
    return f"{ip}:{username[:64]}"


def _purge_old_attempts(attempts, now):
    while attempts and now - attempts[0] >= RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()


def _is_rate_limited(username):
    attempts = _failed_attempts[_rate_limit_key(username)]
    _purge_old_attempts(attempts, time.monotonic())
    return len(attempts) >= MAX_FAILED_ATTEMPTS


def _record_failed_attempt(username):
    attempts = _failed_attempts[_rate_limit_key(username)]
    now = time.monotonic()
    _purge_old_attempts(attempts, now)
    attempts.append(now)


def _clear_failed_attempts(username):
    _failed_attempts.pop(_rate_limit_key(username), None)


def _mask_email(email):
    local, separator, domain = email.partition("@")
    if not separator:
        return "***"
    return f"{local[:1]}***@{domain}"


def _mask_phone(phone):
    return f"{phone[:3]}****{phone[-4:]}" if len(phone) >= 7 else "***"


def _get_user(username):
    conn = _connect()
    try:
        return conn.execute(
            """
            SELECT id, username, password_hash, role, email, phone, balance
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        conn.close()


def _public_profile(user):
    """Return only fields appropriate for the authenticated profile page."""
    return {
        "username": user["username"],
        "email": _mask_email(user["email"]),
        "phone": _mask_phone(user["phone"]),
        "role": user["role"],
    }


def _escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_users(keyword):
    keyword = keyword.strip()
    if not keyword or len(keyword) > 64:
        return []

    like_pattern = f"%{_escape_like(keyword)}%"
    conn = _connect()
    try:
        return conn.execute(
            """
            SELECT id, username, email, phone
            FROM users
            WHERE username LIKE ? ESCAPE '\\'
               OR email LIKE ? ESCAPE '\\'
            ORDER BY id
            LIMIT 20
            """,
            (like_pattern, like_pattern),
        ).fetchall()
    finally:
        conn.close()


def _csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _valid_csrf_token():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def _registration_error(username, password, email, phone):
    if not USERNAME_RE.fullmatch(username):
        return "用户名只能包含字母、数字和下划线，长度为 3-64 位"
    if len(password) < 12 or len(password) > 256:
        return "密码长度至少 12 位"
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return "邮箱格式不正确"
    if not PHONE_RE.fullmatch(phone):
        return "手机号格式不正确"
    return None


@app.context_processor
def inject_security_context():
    return {"csrf_token": _csrf_token()}


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'",
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.endpoint in {"index", "login", "logout", "register", "search"}:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _render_index(keyword=""):
    username = session.get("username")
    user = _get_user(username) if username else None
    if username and not user:
        session.clear()
        return render_template("index.html", username=None, user=None, keyword="", search_results=None)

    search_results = _search_users(keyword) if username and keyword else None
    return render_template(
        "index.html",
        username=username if user else None,
        user=_public_profile(user) if user else None,
        keyword=keyword,
        search_results=search_results,
    )


@app.route("/")
def index():
    return _render_index(request.args.get("keyword", ""))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _valid_csrf_token():
            abort(400, description="Invalid CSRF token")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) > 64 or len(password) > 256:
            return render_template("login.html", error="用户名或密码错误，请重试", msg=""), 401

        if _is_rate_limited(username):
            return (
                render_template("login.html", error="登录尝试过于频繁，请稍后再试", msg=""),
                429,
                {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        user = _get_user(username)
        if not user or not check_password_hash(user["password_hash"], password):
            _record_failed_attempt(username)
            return render_template("login.html", error="用户名或密码错误，请重试", msg=""), 401

        _clear_failed_attempts(username)
        # Rotate the session on authentication to prevent session fixation.
        session.clear()
        session.permanent = True
        session["username"] = username
        session["_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))

    return render_template("login.html", error=None, msg=request.args.get("msg", ""))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not _valid_csrf_token():
            abort(400, description="Invalid CSRF token")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        error = _registration_error(username, password, email, phone)
        if error:
            return render_template("register.html", error=error), 400

        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, email, phone, balance)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, generate_password_hash(password, method="scrypt"), "user", email, phone, 0),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在"), 409
        finally:
            conn.close()

        return redirect(url_for("login", msg="注册成功，请登录"))

    return render_template("register.html", error=None)


@app.route("/search")
def search():
    return _render_index(request.args.get("keyword", ""))


@app.post("/logout")
def logout():
    if not _valid_csrf_token():
        abort(400, description="Invalid CSRF token")
    session.clear()
    return redirect(url_for("index"))


class QuietRequestHandler(WSGIRequestHandler):
    """Avoid exposing Werkzeug/Python versions in the local fallback server."""

    server_version = "SecureApp"
    sys_version = ""


if __name__ == "__main__":
    # Never enable Werkzeug's interactive debugger in a deployed service.
    app.run(host="0.0.0.0", port=5000, debug=False, request_handler=QuietRequestHandler)
