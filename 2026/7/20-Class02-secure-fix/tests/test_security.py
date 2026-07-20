import os
import re
import sqlite3
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AFTER_ROOT = PROJECT_ROOT / "after"
TEST_DB = PROJECT_ROOT / ".test-security.db"
sys.path.insert(0, str(AFTER_ROOT))

from app import create_app  # noqa: E402


def csrf_from(response):
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.data.decode("utf-8", errors="ignore")
    return match.group(1).decode("utf-8")


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        if TEST_DB.exists():
            TEST_DB.unlink()
        os.environ["ADMIN_PASSWORD"] = "Admin12345"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(TEST_DB),
                "SECRET_KEY": "test-only-secret-key",
                "WTF_CSRF_ENABLED": True,
            }
        )
        self.app.init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("ADMIN_PASSWORD", None)
        if TEST_DB.exists():
            TEST_DB.unlink()

    def post_with_csrf(self, path, data):
        page = self.client.get(path)
        data = dict(data)
        data["csrf_token"] = csrf_from(page)
        return self.client.post(path, data=data, follow_redirects=True)

    def login_admin(self):
        return self.post_with_csrf("/login", {"username": "admin", "password": "Admin12345"})

    def test_login_page_has_no_default_credential_comment(self):
        response = self.client.get("/login")
        body = response.data.decode("utf-8")
        self.assertNotIn("默认管理员账号", body)

    def test_register_requires_csrf_and_validates_fields(self):
        response = self.client.post(
            "/register",
            data={"username": "u1", "password": "1", "email": "bad", "phone": "abc"},
        )
        self.assertEqual(response.status_code, 400)

        response = self.post_with_csrf(
            "/register",
            {"username": "u1", "password": "1", "email": "bad", "phone": "abc"},
        )
        self.assertIn("用户名只能包含", response.data.decode("utf-8"))

    def test_password_is_hashed_and_not_rendered(self):
        response = self.post_with_csrf(
            "/register",
            {
                "username": "normal_user",
                "password": "SafePass123",
                "email": "normal@example.com",
                "phone": "13900139001",
            },
        )
        self.assertIn("注册成功", response.data.decode("utf-8"))

        response = self.post_with_csrf("/login", {"username": "normal_user", "password": "SafePass123"})
        body = response.data.decode("utf-8")
        self.assertIn("normal_user", body)
        self.assertNotIn("SafePass123", body)

        conn = sqlite3.connect(TEST_DB)
        try:
            password_hash = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                ("normal_user",),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertNotEqual(password_hash, "SafePass123")
        self.assertTrue(password_hash.startswith(("scrypt:", "pbkdf2:", "argon2:")))

    def test_search_uses_parameterized_query(self):
        self.post_with_csrf(
            "/register",
            {
                "username": "alice_safe",
                "password": "AlicePass123",
                "email": "alice.safe@example.com",
                "phone": "13900139002",
            },
        )
        self.login_admin()

        normal = self.client.get("/search?keyword=admin")
        self.assertIn("admin@example.com", normal.data.decode("utf-8"))

        injected = self.client.get("/search?keyword=%27%20OR%20%271%27%3D%271")
        body = injected.data.decode("utf-8")
        self.assertNotIn("alice.safe@example.com", body)
        self.assertNotIn("sqlite3.OperationalError", body)
        self.assertNotIn("Werkzeug Debugger", body)

    def test_logout_requires_post_and_csrf(self):
        self.login_admin()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 400)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
