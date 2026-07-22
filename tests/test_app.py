import os
import re
import sys
import unittest
from io import BytesIO
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "after"
TEST_DB = ROOT_DIR / ".test-security.db"
TEST_AVATAR_DIR = ROOT_DIR / ".test-avatars"
sys.path.insert(0, str(APP_DIR))

os.environ["FLASK_ENV"] = "testing"
os.environ["FLASK_SECRET_KEY"] = "test-only-secret-key-with-more-than-32-characters"
os.environ["ADMIN_PASSWORD"] = "TestOnly-Admin-Password-2026!"
os.environ["ALICE_PASSWORD"] = "TestOnly-Alice-Password-2026!"
os.environ["SESSION_COOKIE_SECURE"] = "1"
os.environ["DATABASE_PATH"] = str(TEST_DB)
os.environ["AVATAR_UPLOAD_DIR"] = str(TEST_AVATAR_DIR)

if TEST_DB.exists():
    TEST_DB.unlink()
if TEST_AVATAR_DIR.exists():
    for child in TEST_AVATAR_DIR.iterdir():
        if child.is_file():
            child.unlink()

from app import _connect, _failed_attempts, app, check_password_hash  # noqa: E402


class SecureClass04AppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        _failed_attempts.clear()
        self.client = app.test_client()
        TEST_AVATAR_DIR.mkdir(exist_ok=True)
        for child in TEST_AVATAR_DIR.iterdir():
            if child.is_file():
                child.unlink()

    @staticmethod
    def csrf_token(response):
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        if not match:
            raise AssertionError("CSRF token missing from response")
        return match.group(1)

    def login(self, username="admin", password=None):
        password = password or os.environ["ADMIN_PASSWORD"]
        login_page = self.client.get("/login")
        token = self.csrf_token(login_page)
        return self.client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": token},
        )

    def test_default_passwords_are_hashed_in_sqlite(self):
        conn = _connect()
        try:
            user = conn.execute("SELECT username, password_hash FROM users WHERE username = ?", ("admin",)).fetchone()
        finally:
            conn.close()

        self.assertEqual(user["username"], "admin")
        self.assertNotEqual(user["password_hash"], os.environ["ADMIN_PASSWORD"])
        self.assertTrue(check_password_hash(user["password_hash"], os.environ["ADMIN_PASSWORD"]))

    def test_login_page_has_no_debug_credentials_and_has_csrf(self):
        response = self.client.get("/login")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("调试信息", body)
        self.assertNotIn(os.environ["ADMIN_PASSWORD"], body)
        self.assertIn('name="csrf_token"', body)

    def test_login_requires_csrf_and_hides_sensitive_fields(self):
        missing_csrf = self.client.post(
            "/login",
            data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        )
        self.assertEqual(missing_csrf.status_code, 400)

        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)

        profile = self.client.get("/")
        body = profile.get_data(as_text=True)
        self.assertNotIn(os.environ["ADMIN_PASSWORD"], body)
        self.assertNotIn("password_hash", body)
        self.assertNotIn(">余额<", body)
        self.assertIn("a***@example.com", body)
        self.assertIn("138****8000", body)
        self.assertEqual(profile.headers["Cache-Control"], "no-store")

    def test_search_uses_bound_parameters_and_blocks_union_dump(self):
        self.login()

        normal = self.client.get("/search?keyword=admin")
        normal_body = normal.get_data(as_text=True)
        self.assertEqual(normal.status_code, 200)
        self.assertIn("admin@example.com", normal_body)
        self.assertNotIn("password_hash", normal_body)

        payload = "x' union select 1,username||':'||password_hash,3,email from users--+"
        injected = self.client.get("/search", query_string={"keyword": payload})
        injected_body = injected.get_data(as_text=True)
        self.assertEqual(injected.status_code, 200)
        self.assertIn("没有匹配的用户", injected_body)
        self.assertNotIn("admin:", injected_body)
        self.assertNotIn("alice:", injected_body)
        self.assertNotIn(os.environ["ADMIN_PASSWORD"], injected_body)

    def test_register_requires_csrf_and_preserves_users_table(self):
        missing_csrf = self.client.post(
            "/register",
            data={
                "username": "new_user",
                "password": "LongEnoughPassword2026!",
                "email": "new@example.com",
                "phone": "13000000000",
            },
        )
        self.assertEqual(missing_csrf.status_code, 400)

        register_page = self.client.get("/register")
        token = self.csrf_token(register_page)
        response = self.client.post(
            "/register",
            data={
                "username": "new_user",
                "password": "LongEnoughPassword2026!",
                "email": "new@example.com",
                "phone": "13000000000",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)

        conn = _connect()
        try:
            rows = conn.execute("SELECT username FROM users ORDER BY id").fetchall()
        finally:
            conn.close()
        self.assertIn("new_user", {row["username"] for row in rows})

    def test_logout_is_post_and_requires_csrf(self):
        self.assertEqual(self.client.get("/logout").status_code, 405)

        self.login("alice", os.environ["ALICE_PASSWORD"])
        self.assertEqual(self.client.post("/logout").status_code, 400)

        profile = self.client.get("/")
        logout_token = self.csrf_token(profile)
        response = self.client.post("/logout", data={"csrf_token": logout_token})
        self.assertEqual(response.status_code, 302)
        self.assertIn("请先登录", self.client.get("/").get_data(as_text=True))

    def test_login_rate_limit(self):
        login_page = self.client.get("/login")
        token = self.csrf_token(login_page)
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={"username": "unknown_test_user", "password": "wrong", "csrf_token": token},
            )
            self.assertEqual(response.status_code, 401)
        limited = self.client.post(
            "/login",
            data={"username": "unknown_test_user", "password": "wrong", "csrf_token": token},
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers["Retry-After"], "60")

    def test_security_headers(self):
        response = self.client.get("/login")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "same-origin")

    def test_profile_blocks_horizontal_authorization_and_defaults_to_current_user(self):
        self.login("alice", os.environ["ALICE_PASSWORD"])

        blocked = self.client.get("/profile", query_string={"user_id": "1"})
        self.assertEqual(blocked.status_code, 403)

        own_profile = self.client.get("/profile")
        own_body = own_profile.get_data(as_text=True)
        self.assertEqual(own_profile.status_code, 200)
        self.assertIn("alice", own_body)
        self.assertIn("alice@example.com", own_body)
        self.assertNotIn("admin@example.com", own_body)

    def test_admin_can_view_other_user_profile(self):
        self.login("admin", os.environ["ADMIN_PASSWORD"])

        response = self.client.get("/profile", query_string={"user_id": "2"})
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice", body)
        self.assertIn("alice@example.com", body)

    def test_recharge_requires_csrf_owner_and_positive_amount(self):
        self.login("alice", os.environ["ALICE_PASSWORD"])

        missing_csrf = self.client.post("/recharge", data={"user_id": "2", "amount": "50"})
        self.assertEqual(missing_csrf.status_code, 400)

        profile_page = self.client.get("/profile")
        token = self.csrf_token(profile_page)

        blocked_user = self.client.post(
            "/recharge",
            data={"csrf_token": token, "user_id": "1", "amount": "50"},
        )
        self.assertEqual(blocked_user.status_code, 403)

        blocked_negative = self.client.post(
            "/recharge",
            data={"csrf_token": token, "user_id": "2", "amount": "-50"},
        )
        self.assertEqual(blocked_negative.status_code, 400)

        response = self.client.post(
            "/recharge",
            data={"csrf_token": token, "user_id": "2", "amount": "50"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/profile?user_id=2")

        conn = _connect()
        try:
            alice_balance = conn.execute("SELECT balance FROM users WHERE id = ?", (2,)).fetchone()["balance"]
            admin_balance = conn.execute("SELECT balance FROM users WHERE id = ?", (1,)).fetchone()["balance"]
        finally:
            conn.close()
        self.assertEqual(alice_balance, 150)
        self.assertEqual(admin_balance, 99999)

    def test_upload_requires_login_and_csrf(self):
        anonymous = self.client.get("/upload")
        self.assertEqual(anonymous.status_code, 302)
        self.assertEqual(anonymous.headers["Location"], "/login")

        self.login()
        missing_csrf = self.client.post(
            "/upload",
            data={"avatar": (BytesIO(b"\x89PNG\r\n\x1a\nnot-a-real-image-body"), "avatar.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(missing_csrf.status_code, 400)

    def test_upload_rejects_script_php_svg_and_mismatched_content(self):
        self.login()
        upload_page = self.client.get("/upload")
        token = self.csrf_token(upload_page)

        samples = (
            (b"<html><script src='/static/uploads/poc.js'></script></html>", "avatar.html"),
            (b"<" + b"?php echo 'not executed'; ?" + b">", "avatar.php"),
            (b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "avatar.svg"),
            (b"<script>alert(1)</script>", "avatar.png"),
        )

        for payload, filename in samples:
            response = self.client.post(
                "/upload",
                data={"csrf_token": token, "avatar": (BytesIO(payload), filename)},
                content_type="multipart/form-data",
            )
            body = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("alert-error", body)
            self.assertNotIn("/avatars/", body)

        self.assertEqual(list(TEST_AVATAR_DIR.iterdir()), [])

    def test_upload_accepts_image_with_random_private_filename(self):
        self.login()
        upload_page = self.client.get("/upload")
        token = self.csrf_token(upload_page)

        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        response = self.client.post(
            "/upload",
            data={"csrf_token": token, "avatar": (BytesIO(png_header), "avatar.png")},
            content_type="multipart/form-data",
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        match = re.search(r"/avatars/([a-f0-9]{32}\.png)", body)
        self.assertIsNotNone(match)
        stored_name = match.group(1)
        self.assertNotIn("/static/uploads/avatar.png", body)
        self.assertTrue((TEST_AVATAR_DIR / stored_name).exists())

        public_static = self.client.get("/static/uploads/avatar.png")
        self.assertEqual(public_static.status_code, 404)

        fetched = self.client.get(f"/avatars/{stored_name}")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.mimetype, "image/png")
        fetched.close()

    def test_avatar_route_requires_login_and_rejects_untrusted_names(self):
        self.assertEqual(self.client.get("/avatars/abc.png").status_code, 302)
        self.login()
        self.assertEqual(self.client.get("/avatars/avatar.png").status_code, 404)
        self.assertEqual(self.client.get("/avatars/../app.py").status_code, 404)

    def test_source_has_no_legacy_sql_string_concatenation(self):
        source = (APP_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("LIKE '%{keyword}%'", source)
        self.assertNotIn("execute(sql)", source)
        self.assertNotIn("INSERT INTO users (username, password, email, phone) VALUES ('{username}'", source)
        self.assertNotIn("filename = uploaded_file.filename", source)
        self.assertNotIn('url_for("static", filename=f"uploads/{filename}")', source)
        self.assertIn("secure_filename", source)
        self.assertIn("uuid4", source)


if __name__ == "__main__":
    unittest.main()
