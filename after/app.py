import hmac
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from flask import Flask, abort, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler
from werkzeug.utils import secure_filename


app = Flask(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[0-9+\-\s]{5,20}$")
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 256
AVATAR_FILENAME_RE = re.compile(r"^[a-f0-9]{32}\.(?:jpg|jpeg|png|gif|webp)$")
ALLOWED_AVATAR_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
AVATAR_MIME_TYPES = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "webp": "image/webp",
}
PAGES_DIR = Path(__file__).resolve().parent / "pages"
ALLOWED_PAGES = {"help": "help.html"}


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


def _upload_dir():
    return Path(os.environ.get("AVATAR_UPLOAD_DIR", Path(app.instance_path) / "avatars"))


def _avatar_extension(filename):
    cleaned_name = secure_filename(filename)
    if "." not in cleaned_name:
        return None
    extension = cleaned_name.rsplit(".", 1)[1].lower()
    return extension if extension in ALLOWED_AVATAR_EXTENSIONS else None


def _detect_image_extension(header):
    if header.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    return None


def _validate_avatar(uploaded_file):
    requested_extension = _avatar_extension(uploaded_file.filename)
    if not requested_extension:
        return None, "只允许上传 jpg、jpeg、png、gif 或 webp 图片"

    uploaded_file.stream.seek(0)
    header = uploaded_file.stream.read(512)
    uploaded_file.stream.seek(0)
    detected_extension = _detect_image_extension(header)
    if not detected_extension:
        return None, "上传文件不是有效的图片"
    if requested_extension in {"jpg", "jpeg"} and detected_extension == "jpg":
        return requested_extension, None
    if requested_extension != detected_extension:
        return None, "文件扩展名与图片内容不一致"
    return requested_extension, None


app.secret_key = _load_secret_key()
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
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


def _get_user_by_id(user_id):
    conn = _connect()
    try:
        return conn.execute(
            """
            SELECT id, username, password_hash, role, email, phone, balance
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    finally:
        conn.close()


def _current_user():
    username = session.get("username")
    return _get_user(username) if username else None


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
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
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
    if request.endpoint in {
        "index",
        "page",
        "login",
        "logout",
        "register",
        "search",
        "upload",
        "avatar_file",
        "profile",
        "recharge",
        "change_password",
    }:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _render_index(keyword="", page_content=None):
    username = session.get("username")
    user = _get_user(username) if username else None
    if username and not user:
        session.clear()
        return render_template(
            "index.html",
            username=None,
            user=None,
            keyword="",
            search_results=None,
            page_content=page_content,
        )

    search_results = _search_users(keyword) if username and keyword else None
    return render_template(
        "index.html",
        username=username if user else None,
        user=_public_profile(user) if user else None,
        keyword=keyword,
        search_results=search_results,
        page_content=page_content,
    )


@app.route("/")
def index():
    return _render_index(request.args.get("keyword", ""))


@app.route("/page")
def page():
    requested_name = request.args.get("name", "").strip()
    page_key = requested_name[:-5] if requested_name.endswith(".html") else requested_name
    filename = ALLOWED_PAGES.get(page_key)
    if not filename:
        return _render_index(page_content="页面不存在"), 404

    page_path = PAGES_DIR / filename
    try:
        page_content = page_path.read_text(encoding="utf-8")
    except OSError:
        return _render_index(page_content="页面不存在"), 404
    return _render_index(page_content=page_content)


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


@app.route("/profile")
def profile():
    current_user = _current_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "").strip()
    if not user_id:
        requested_user = current_user
    elif not user_id.isdigit():
        abort(400, description="Invalid user_id")
    else:
        target_id = int(user_id)
        if target_id != current_user["id"] and current_user["role"] != "admin":
            abort(403)
        requested_user = _get_user_by_id(target_id)
    if not requested_user:
        abort(404)

    return render_template(
        "profile.html",
        user=requested_user,
        can_change_password=requested_user["id"] == current_user["id"],
        error=request.args.get("error", ""),
        msg=request.args.get("msg", ""),
    )


@app.post("/recharge")
def recharge():
    current_user = _current_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))
    if not _valid_csrf_token():
        abort(400, description="Invalid CSRF token")

    user_id = request.form.get("user_id", "").strip()
    amount = request.form.get("amount", "").strip()
    if not user_id.isdigit():
        abort(400, description="Invalid user_id")
    target_id = int(user_id)
    if target_id != current_user["id"] and current_user["role"] != "admin":
        abort(403)
    try:
        parsed_amount = int(amount)
    except ValueError:
        abort(400, description="Invalid amount")
    if parsed_amount <= 0 or parsed_amount > 100000:
        abort(400, description="Invalid amount")

    conn = _connect()
    try:
        result = conn.execute(
            """
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
            """,
            (parsed_amount, target_id),
        )
        if result.rowcount != 1:
            abort(404)
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("profile", user_id=target_id))


@app.post("/change-password")
def change_password():
    current_user = _current_user()
    if not current_user:
        session.clear()
        return redirect(url_for("login"))
    if not _valid_csrf_token():
        abort(400, description="Invalid CSRF token")

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not check_password_hash(current_user["password_hash"], current_password):
        return redirect(url_for("profile", error="当前密码不正确"))
    if new_password != confirm_password:
        return redirect(url_for("profile", error="两次输入的新密码不一致"))
    if not PASSWORD_MIN_LENGTH <= len(new_password) <= PASSWORD_MAX_LENGTH:
        return redirect(url_for("profile", error="新密码长度不符合要求"))

    conn = _connect()
    try:
        result = conn.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (generate_password_hash(new_password, method="scrypt"), current_user["id"]),
        )
        if result.rowcount != 1:
            abort(404)
        conn.commit()
    finally:
        conn.close()

    # Keep the user signed in while rotating credentials and CSRF state.
    session.clear()
    session.permanent = True
    session["username"] = current_user["username"]
    session["_csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("profile", msg="密码修改成功"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect(url_for("login"))

    error = None
    file_url = None

    if request.method == "POST":
        if not _valid_csrf_token():
            abort(400, description="Invalid CSRF token")

        uploaded_file = request.files.get("avatar")
        if not uploaded_file or not uploaded_file.filename:
            error = "请选择要上传的文件"
        else:
            extension, error = _validate_avatar(uploaded_file)
            if not error:
                upload_dir = _upload_dir()
                upload_dir.mkdir(parents=True, exist_ok=True)
                filename = f"{uuid4().hex}.{extension}"
                uploaded_file.save(upload_dir / filename)
                file_url = url_for("avatar_file", filename=filename)

    return render_template("upload.html", error=error, file_url=file_url)


@app.route("/avatars/<path:filename>")
def avatar_file(filename):
    if not session.get("username"):
        return redirect(url_for("login"))
    if not AVATAR_FILENAME_RE.fullmatch(filename):
        abort(404)
    extension = filename.rsplit(".", 1)[1].lower()
    return send_from_directory(_upload_dir(), filename, mimetype=AVATAR_MIME_TYPES[extension])


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
