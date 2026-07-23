# Jiayao-scu-homework

本仓库是 Class04 用户管理网站的安全修复迭代。项目保留登录、注册、搜索、头像上传、个人中心、充值功能，并在本轮新增动态页面加载功能。

## 目录结构

```text
.
|-- before/   # 修复前代码快照，用于展示漏洞写法
|-- after/    # 修复后代码，保留功能并完成安全加固
|-- evidence/ # 本轮真实测试截图
|-- tests/    # 面向 after/ 的安全回归测试
|-- file-upload-vulnerability-report-jiayao.md
|-- local-file-inclusion-vulnerability-report-jiayao.md
|-- local-file-inclusion-vulnerability-report-jiayao.docx
|-- .gitignore
`-- README.md
```

## 本轮功能

新增 `/page?name=help` 动态页面加载入口，并在 `pages/help.html` 中放置帮助中心内容。首页会在 `page_content` 存在时展示动态页面内容，同时提供“帮助中心”快捷入口。

## 本轮漏洞与修复

本轮围绕动态页面加载中的本地文件包含漏洞进行迭代。

`before/app.py` 按作业要求保留不安全实现：直接从 URL 参数读取 `name`，使用 `os.path.join("pages", name)` 拼接路径，文件不存在时追加 `.html` 后缀再次读取，且不校验 `../`。这种写法会让攻击者尝试读取 `pages/` 目录外的本地文件。

`after/app.py` 保留 `/page` 功能，但不再把用户输入直接作为文件路径使用。修复方式是建立固定白名单 `ALLOWED_PAGES = {"help": "help.html"}`，只允许加载预期页面；非法页面名、文件包含 payload 和不存在页面统一返回“页面不存在”并返回 404。页面目录使用应用自身目录下的 `pages/`，避免受启动工作目录影响。

## 已有修复

`after/` 还保留之前迭代的安全修复：

1. SQL 注入：搜索、注册、登录等数据库操作使用参数化查询。
2. 头像上传：限制扩展名和文件头，使用随机文件名，上传文件保存到受控目录，并通过 `/avatars/<filename>` 访问。
3. 越权访问：普通用户不能通过修改 `user_id` 查看他人个人中心。
4. 充值绕过：充值接口校验 CSRF、用户权限和正整数金额范围。
5. 会话与响应头：启用 HttpOnly、SameSite、缓存控制、CSP、X-Frame-Options 等基础安全头。

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

测试覆盖登录、注册、搜索、上传、个人中心、充值、动态页面加载，以及 SQL 注入、文件上传、越权、负数充值、文件包含等历史漏洞的修复效果。

## 证据截图

本轮文件包含漏洞验证截图位于 `evidence/`：

1. `before-file-inclusion-source-disclosure.png`：`before/` 中通过 `/page?name=../app.py` 包含并回显源码。
2. `after-file-inclusion-blocked.png`：`after/` 中同一请求被拦截并显示“页面不存在”。
3. `after-file-inclusion-normal-help.png`：`after/` 中 `/page?name=help` 正常显示帮助中心。

中文 DOCX 报告为 `local-file-inclusion-vulnerability-report-jiayao.docx`，已插入以上真实测试截图。

## 提交边界

`before/` 仅用于课程作业中的修复前后对比；真实口令、固定密钥、数据库、日志、Cookie、Token、上传样本和运行缓存不提交到仓库。
