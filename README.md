# Jiayao-scu-homework

Class06 用户管理网站安全修复迭代。本项目保留登录、注册、搜索、头像上传、个人中心、充值、动态页面加载和密码修改功能，并以 `before` / `after` 展示课程作业中的修复前后差异。

## 目录结构

```text
.
|-- before/    # Class06 修复前代码：包含用于课程验证的密码修改 CSRF / 越权缺陷
|-- after/     # Class06 修复后代码：保留功能并完成安全加固
|-- evidence/  # 本轮实测证据图
|-- tests/     # 面向 after/ 的安全回归测试
|-- Class06-CSRF-password-change-vulnerability-report-jiayao.docx
`-- README.md
```

## Class06 功能

- 登录、注册、用户搜索
- 受控头像上传与私有头像访问
- 个人中心、余额充值
- 白名单动态帮助页面加载
- 密码修改

## 本轮漏洞与修复

`before/app.py` 的 `/change-password` 接口只检查会话是否存在，却信任客户端提交的 `username`，且未校验 CSRF Token、原密码和确认密码。低权限用户可以构造针对其他账户的请求，实测能够修改管理员密码。

`after/app.py` 完成以下修复：

1. 密码修改对象只从当前服务端会话获取，不读取或信任客户端的 `username`。
2. 所有密码修改请求必须通过 CSRF Token 的常量时间比较校验。
3. 必须验证当前密码、新密码确认值和 12-256 位长度规则。
4. 成功修改后轮换会话与 CSRF Token，降低会话固定和旧 Token 重放风险。
5. 管理员浏览其他用户资料时不展示密码修改表单。

## 既有安全加固

- SQL 注入：数据库读写使用参数化查询，搜索关键词转义 `LIKE` 通配符。
- 文件上传：限制图片扩展名和文件头，生成随机文件名，上传目录不直接暴露为静态资源。
- 越权访问：普通用户不能通过篡改 `user_id` 查看他人资料或操作他人余额。
- 充值逻辑：校验 CSRF、账户归属、金额类型和正数范围。
- 文件包含：动态页面使用固定白名单，不将 URL 参数直接作为文件路径。
- 会话防护：启用 HttpOnly、SameSite、缓存控制和基础安全响应头。

## 运行 after

需要 Python 3.11 或更高版本。

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

当前测试覆盖登录、注册、搜索、上传、个人中心、充值、动态页面加载与密码修改，同时验证 SQL 注入、文件上传、越权、负数充值、文件包含和 CSRF 密码重置等历史漏洞的修复效果。

## 课程边界

`before/` 仅用于本地课程作业中展示漏洞与修复对比，不应部署或暴露到真实网络环境。真实口令、密钥、数据库、日志、Cookie、Token 和上传样本不应提交到仓库。
