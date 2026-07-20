import os
import re
import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "after"
TEST_DB = ROOT_DIR / ".test-security.db"
sys.path.insert(0, str(APP_DIR))

os.environ["FLASK_ENV"] = "testing"
os.environ["FLASK_SECRET_KEY"] = "test-only-secret-key-with-more-than-32-characters"
os.environ["ADMIN_PASSWORD"] = "TestOnly-Admin-Password-2026!"
os.environ["ALICE_PASSWORD"] = "TestOnly-Alice-Password-2026!"
os.environ["SESSION_COOKIE_SECURE"] = "1"
os.environ["DATABASE_PATH"] = str(TEST_DB)

if TEST_DB.exists():
    TEST_DB.unlink()

from app import _connect, _failed_attempts, app, check_password_hash  # noqa: E402


class SecureClass02AppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        _failed_attempts.clear()
        self.client = app.test_client()

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

    def test_source_has_no_legacy_sql_string_concatenation(self):
        source = (APP_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("LIKE '%{keyword}%'", source)
        self.assertNotIn("execute(sql)", source)
        self.assertNotIn("INSERT INTO users (username, password, email, phone) VALUES ('{username}'", source)


if __name__ == "__main__":
    unittest.main()
