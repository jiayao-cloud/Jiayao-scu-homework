# Jiayao-scu-homework

本仓库是 Class03 用户管理网站的漏洞修复迭代。项目保留上一版已经完成的登录、注册、搜索和 SQL 注入修复能力，在此基础上新增并修复“用户头像上传”功能中的任意文件上传漏洞。

## 目录结构

```text
.
|-- before/   # Class03 修复前源码：保留头像上传任意文件上传漏洞
|-- after/    # Class03 修复后源码：在原功能基础上完成安全加固
|-- tests/    # 面向 after/ 的安全回归测试
|-- 文件上传漏洞报告-贾耀.md
|-- .gitignore
`-- README.md
```

## 修复前问题

`before/` 中的 `/upload` 路由允许登录用户上传头像，但服务端存在以下问题：

1. 不检查文件后缀，HTML、JavaScript、SVG、PHP 等非图片文件均可上传。
2. 不检查文件真实内容，伪造后缀的脚本文件也会被保存。
3. 直接使用用户提交的原始文件名保存，存在覆盖、可预测 URL 和路径处理风险。
4. 文件保存到 `static/uploads/`，上传后自动成为同源公开静态资源。
5. 当前 CSP 虽然阻止内联脚本，但攻击者可以同时上传 HTML 和同源 JS 文件，实现同源 JavaScript 执行。

实测结论：在 Flask 环境下 PHP 文件只会作为静态内容返回，不会被解释执行；但“上传 HTML + 上传同源 JS + 访问上传 HTML”的链路可以真实触发浏览器脚本执行，因此漏洞有效。

## 修复内容

`after/` 在不破坏登录、注册、搜索功能的前提下完成以下修复：

1. 上传接口加入 CSRF 校验，防止第三方页面诱导已登录用户发起上传请求。
2. 仅允许 `jpg`、`jpeg`、`png`、`gif`、`webp` 头像格式。
3. 读取文件头魔数校验真实图片类型，拒绝 HTML、JS、SVG、PHP 以及伪装成图片的文本文件。
4. 使用 `secure_filename()` 提取并规范化原始文件名中的扩展名，不信任用户提交的文件路径。
5. 使用 `uuid4().hex` 生成随机文件名保存，避免用户控制最终 URL 或覆盖同名文件。
6. 上传文件默认保存到 `instance/avatars/`，不再进入 `static/uploads/` 公开静态目录。
7. 新增受控路由 `/avatars/<filename>` 读取头像，只允许匹配随机文件名格式的图片文件，并设置固定图片 MIME 类型。
8. `/avatars` 响应加入登录校验和 no-store 缓存控制。
9. `.gitignore` 忽略数据库、日志、实例上传目录和测试上传产物，避免把运行数据或 POC 文件提交到公开仓库。

## 运行 after

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
$env:AVATAR_UPLOAD_DIR = "instance/avatars"

python app.py
```

## 测试

在仓库根目录执行：

```powershell
python -m unittest discover -s tests -v
```

测试覆盖范围包括：

1. 默认账户密码使用哈希写入 SQLite。
2. 登录、注册、登出和上传接口的 CSRF 防护。
3. 搜索接口无法通过 UNION SQL 注入回显敏感字段。
4. 上传接口必须登录访问。
5. HTML、JavaScript、SVG、PHP 和伪装图片内容被拒绝。
6. 合法图片使用随机文件名保存到私有目录。
7. 上传内容不会出现在 `/static/uploads/原始文件名`。
8. `/avatars/<filename>` 只允许登录用户访问合法随机图片名。

## 提交边界

`before/` 用于展示漏洞修复前结构，真实默认口令、固定密钥、数据库、日志、Cookie、Token、上传 POC 文件和运行缓存均不提交到仓库。漏洞报告只记录验证结论和修复方法，不提供可直接复用的一句话木马或攻击脚本文件。
