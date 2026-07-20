# Jiayao-scu-homework

本仓库是 Class02 用户管理网站的 SQL 注入漏洞修复迭代。根目录只保留一份全局 README，代码按修复前后拆分，便于对照审计和验收。

## 目录结构

```text
.
|-- before/   # Class02 原始源码快照，保留 SQL 注入问题结构，真实口令和固定密钥已脱敏
|-- after/    # 基于上一版安全修复继续迭代后的 Class02 可运行项目
|-- tests/    # 面向 after/ 的安全回归测试
|-- .gitignore
`-- README.md
```

## 漏洞范围

本次迭代只围绕 SQL 注入修复展开，同时保留上一版已完成的基础安全加固。`before/` 中的漏洞主要出现在搜索和注册两类数据库操作。

搜索接口把用户输入直接拼进 SQL：

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

因此攻击者可以通过联合查询改变原始查询语义。例如输入：

```text
x' union select 1,username||':'||password,3,email,phone from users--+
```

在修复前会把用户表中的账号和密码字段拼接到搜索结果中，造成敏感信息泄露。

注册接口同样直接拼接用户输入：

```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cursor.execute(sql)
```

该写法会让注册表单成为 SQL 注入入口，可能造成异常插入、语句结构破坏，甚至在更宽松的数据库配置下引发进一步数据篡改风险。

## 修复内容

`after/` 在原安全版本基础上补齐 Class02 的 SQLite 搜索和注册功能，并完成 SQL 注入修复：

1. 所有数据库读写改为 SQLite 占位符绑定参数，不再把用户输入拼接进 SQL 字符串。
2. 搜索接口使用 `LIKE ? ESCAPE '\\'`，并对 `%`、`_`、`\` 做转义，避免通配符被滥用扩大查询范围。
3. 搜索结果只查询并返回 `id`、`username`、`email`、`phone`，不再返回 `password`、`password_hash`、`balance` 等敏感字段。
4. 注册接口增加用户名、密码、邮箱、手机号格式校验，插入时使用参数绑定并捕获用户名重复错误。
5. 密码从明文存储改为 Werkzeug `scrypt` 哈希存储，默认账号密码通过环境变量注入。
6. 数据库路径支持 `DATABASE_PATH` 配置，默认使用 `data/users.db`，数据库文件不提交到仓库。
7. 保留上一版安全加固：CSRF 防护、POST 登出、会话 Cookie 安全属性、登录限速、安全响应头、生产环境禁止固定 Secret 和关闭调试模式。

## 运行修复版

需要 Python 3.11 或以上版本。

```powershell
cd after
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:FLASK_ENV = "development"
$env:FLASK_SECRET_KEY = "local-only-random-secret-at-least-32-characters"
$env:ADMIN_PASSWORD = "local-admin-password-at-least-12"
$env:ALICE_PASSWORD = "local-alice-password-at-least-12"
$env:SESSION_COOKIE_SECURE = "0"
$env:DATABASE_PATH = "data/users.db"

python app.py
```

## 测试

在仓库根目录执行：

```powershell
python -m unittest discover -s tests -v
```

当前测试覆盖：

1. 默认账号密码已哈希写入 SQLite。
2. 登录和注册必须携带 CSRF Token。
3. 搜索注入 payload 不会触发联合查询数据回显。
4. 页面不会暴露密码哈希、余额等敏感字段。
5. 登出只允许 POST。
6. 登录失败限速和安全响应头保持有效。
7. `after/app.py` 不再出现旧版 SQL 字符串拼接模式。

## 提交边界

`before/` 用于展示漏洞修复前的代码结构，但真实默认密码、固定 Flask Secret 等敏感值已替换为脱敏占位符。仓库不包含攻击辅助脚本、真实数据库文件、`.env` 文件、Cookie、Token 或任何可直接复用的私密凭据。
