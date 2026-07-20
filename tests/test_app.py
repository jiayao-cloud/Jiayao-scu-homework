import os
import re
import sys
import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1] / "after"
sys.path.insert(0, str(APP_DIR))

os.environ["FLASK_ENV"] = "testing"
os.environ["FLASK_SECRET_KEY"] = "test-only-secret-key-with-more-than-32-characters"
os.environ["ADMIN_PASSWORD"] = "TestOnly-Admin-Password-2026!"
os.environ["ALICE_PASSWORD"] = "TestOnly-Alice-Password-2026!"
os.environ["SESSION_COOKIE_SECURE"] = "1"

from app import USERS, app, check_password_hash  # noqa: E402


class SecureAppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    @staticmethod
    def csrf_token(response):
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        if not match:
            raise AssertionError("CSRF token missing from response")
        return match.group(1)

    def test_passwords_are_hashed_and_not_stored_as_plaintext(self):
        self.assertNotIn("password", USERS["admin"])
        self.assertIn("password_hash", USERS["admin"])
        self.assertTrue(check_password_hash(USERS["admin"]["password_hash"], os.environ["ADMIN_PASSWORD"]))

    def test_login_page_has_no_debug_credentials_and_has_csrf(self):
        response = self.client.get("/login")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("调试信息", body)
        self.assertNotIn(os.environ["ADMIN_PASSWORD"], body)
        self.assertIn('name="csrf_token"', body)

    def test_login_requires_csrf_and_hides_password(self):
        login_page = self.client.get("/login")
        token = self.csrf_token(login_page)

        missing_csrf = self.client.post("/login", data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]})
        self.assertEqual(missing_csrf.status_code, 400)

        response = self.client.post(
            "/login",
            data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"], "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)

        profile = self.client.get("/")
        body = profile.get_data(as_text=True)
        self.assertNotIn(os.environ["ADMIN_PASSWORD"], body)
        self.assertNotIn('class="info-label">密码', body)
        self.assertIn("a***@example.com", body)
        self.assertIn("138****8000", body)
        self.assertEqual(profile.headers["Cache-Control"], "no-store")

    def test_logout_is_post_and_requires_csrf(self):
        self.assertEqual(self.client.get("/logout").status_code, 405)

        login_page = self.client.get("/login")
        token = self.csrf_token(login_page)
        self.client.post(
            "/login",
            data={"username": "alice", "password": os.environ["ALICE_PASSWORD"], "csrf_token": token},
        )
        self.assertEqual(self.client.post("/logout").status_code, 400)

        profile = self.client.get("/")
        logout_token = self.csrf_token(profile)
        response = self.client.post("/logout", data={"csrf_token": logout_token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertIn("请先登录", self.client.get("/").get_data(as_text=True))

    def test_login_rate_limit(self):
        login_page = self.client.get("/login")
        token = self.csrf_token(login_page)
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={"username": "unknown-test-user", "password": "wrong", "csrf_token": token},
            )
            self.assertEqual(response.status_code, 401)
        limited = self.client.post(
            "/login",
            data={"username": "unknown-test-user", "password": "wrong", "csrf_token": token},
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers["Retry-After"], "60")

    def test_security_headers(self):
        response = self.client.get("/login")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "same-origin")


if __name__ == "__main__":
    unittest.main()
