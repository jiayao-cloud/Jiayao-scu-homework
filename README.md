# Jiayao-scu-homework

本仓库是 Class04 用户管理网站的安全修复迭代。项目保留上一版已经完成的登录、注册、搜索和头像上传功能，并在新增个人中心与充值功能后修复业务逻辑类漏洞。

## 目录结构

```text
.
|-- before/   # 修复前源码快照
|-- after/    # Class04 修复后源码：在原功能基础上完成安全加固
|-- tests/    # 面向 after/ 的安全回归测试
|-- file-upload-vulnerability-report-jiayao.md
|-- .gitignore
`-- README.md
```

## 已有修复内容

上一轮迭代已围绕头像上传完成加固：

1. 上传接口加入 CSRF 校验。
2. 仅允许 `jpg`、`jpeg`、`png`、`gif`、`webp` 头像格式。
3. 读取文件头魔数校验真实图片类型。
4. 使用随机文件名保存头像。
5. 上传文件默认保存到 `instance/avatars/`，不进入 `static/uploads/`。
6. 通过 `/avatars/<filename>` 受控路由读取头像文件。

## 本轮修复内容

本轮针对个人中心与充值功能修复以下业务逻辑漏洞：

1. `/profile` 默认只展示当前登录用户资料。
2. 普通用户访问 `/profile?user_id=其他用户ID` 时返回 `403`，阻止水平越权查看邮箱、手机和余额。
3. 管理员保留查看其他用户资料的管理能力。
4. `/recharge` 增加 CSRF 校验，拒绝跨站诱导提交。
5. `/recharge` 校验表单中的 `user_id`，普通用户只能为本人充值，不能修改他人余额。
6. `/recharge` 校验 `amount` 必须为 `1-100000` 的正整数，拒绝负数、零、非数字和异常大额输入。
7. 导航栏和首页“个人中心”入口不再硬编码 `user_id=1`，避免默认指向管理员资料。

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
9. 普通用户访问他人个人中心资料返回 `403`。
10. 充值接口缺失 CSRF、跨用户充值、负数金额充值均会被拒绝。

## 提交边界

`before/` 用于展示漏洞修复前结构，真实默认口令、固定密钥、数据库、日志、Cookie、Token、上传 POC 文件和运行缓存均不提交到仓库。漏洞报告只记录验证结论和修复方法，不提供可直接复用的一句话木马或攻击脚本文件。
