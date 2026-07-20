import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import WSGIRequestHandler


app = Flask(__name__)


def _load_secret_key():
    """Load a deployment secret; never fall back to a predictable key."""
    configured = os.environ.get("FLASK_SECRET_KEY")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 characters")
        return configured

    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("FLASK_SECRET_KEY must be configured in production")

    # Local development remains runnable, but every process gets a new secret.
    return secrets.token_urlsafe(32)


def _required_password(name):
    password = os.environ.get(name)
    if not password or len(password) < 12:
        raise RuntimeError(f"{name} must be set and contain at least 12 characters")
    return password


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


def _build_users():
    return {
        "admin": {
            "username": "admin",
            "password_hash": generate_password_hash(_required_password("ADMIN_PASSWORD"), method="scrypt"),
            "role": "admin",
            "email": "admin@example.com",
            "phone": "13800138000",
            "balance": 99999,
        },
        "alice": {
            "username": "alice",
            "password_hash": generate_password_hash(_required_password("ALICE_PASSWORD"), method="scrypt"),
            "role": "user",
            "email": "alice@example.com",
            "phone": "13900139001",
            "balance": 100,
        },
    }


USERS = _build_users()

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


def _public_profile(user):
    """Return only fields appropriate for the authenticated profile page."""
    return {
        "username": user["username"],
        "email": _mask_email(user["email"]),
        "phone": _mask_phone(user["phone"]),
        "role": user["role"],
    }


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
    if request.endpoint in {"index", "login", "logout"}:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.route("/")
def index():
    username = session.get("username")
    if username not in USERS:
        if username:
            session.clear()
        return render_template("index.html", username=None, user=None)
    return render_template("index.html", username=username, user=_public_profile(USERS[username]))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not _valid_csrf_token():
            abort(400, description="Invalid CSRF token")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) > 64 or len(password) > 256:
            return render_template("login.html", error="用户名或密码错误，请重试"), 401

        if _is_rate_limited(username):
            return (
                render_template("login.html", error="登录尝试过于频繁，请稍后再试"),
                429,
                {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        user = USERS.get(username)
        if not user or not check_password_hash(user["password_hash"], password):
            _record_failed_attempt(username)
            return render_template("login.html", error="用户名或密码错误，请重试"), 401

        _clear_failed_attempts(username)
        # Rotate the session on authentication to prevent session fixation.
        session.clear()
        session.permanent = True
        session["username"] = username
        session["_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("index"))

    return render_template("login.html", error=None)


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
