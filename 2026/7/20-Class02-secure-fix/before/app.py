from flask import Flask, render_template, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "REDACTED_DEV_SECRET_KEY"

USERS = {
    "admin": {
        "username": "admin",
        "password": "REDACTED_ADMIN_PASSWORD",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "REDACTED_USER_PASSWORD",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'REDACTED_ADMIN_PASSWORD', 'admin@example.com', '13800138000')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'REDACTED_USER_PASSWORD', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    keyword = request.args.get("keyword", "")
    search_results = None
    if keyword:
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[DEBUG] 执行的SQL语句: {sql}")
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        cursor.execute(sql)
        search_results = cursor.fetchall()
        conn.close()

    return render_template("index.html", username=username, user=user_info, keyword=keyword, search_results=search_results)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    user_info = None
    msg = request.args.get("msg", "")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", username=username, user=user_info)
        else:
            error = "用户名或密码错误，请重试"

    return render_template("login.html", error=error, msg=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[DEBUG] 执行的SQL语句: {sql}")

        try:
            conn = sqlite3.connect("data/users.db")
            cursor = conn.cursor()
            cursor.execute(sql)
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except Exception as e:
            error = f"注册失败: {str(e)}"

    return render_template("register.html", error=error)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    search_results = None
    if keyword:
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[DEBUG] 执行的SQL语句: {sql}")
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        cursor.execute(sql)
        search_results = cursor.fetchall()
        conn.close()

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    return render_template("index.html", username=username, user=user_info, keyword=keyword, search_results=search_results)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
