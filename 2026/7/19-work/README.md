# Web 靶场安全修复：2026/7/19

本目录保存 `class01.zip` 的漏洞修复前后对比、修复后的可运行源码和自动化回归测试。修复范围依据本地靶场的黑盒验证结果，并针对源码逐项落地。

## 目录结构

```text
2026/7/19-work/
├── README.md                 # 本说明
├── before/                   # 修复前应用快照（保留漏洞复现所需源码）
│   ├── app.py
│   ├── templates/
│   └── static/css/
├── after/                    # 修复后应用源码
│   ├── .env.example
│   ├── app.py
│   ├── requirements.txt
│   ├── templates/
│   └── static/css/
└── tests/test_app.py         # 自动化安全回归测试
```

原压缩包中的 `brute_secret.py` 与 `forge_session.py` 是攻击辅助脚本，不属于业务运行必需文件；为避免把可直接用于攻击的脚本继续扩散，本次前后对比目录未上传这两个脚本。原始压缩包仍保留在用户本地工作区。

`before/` 快照中的真实密码和固定 Secret 也已脱敏；这样既保留了漏洞结构和修复前后对比，又不会把靶场凭据公开到仓库。

## 修复前确认的问题

1. 登录页 HTML 注释泄露默认管理员凭据。
2. `app.secret_key` 使用源码中的可预测固定值。
3. 用户密码以明文保存，并在首页 HTML 中回显。
4. 登出使用 GET，登录/登出没有 CSRF Token。
5. 登录失败没有速率限制或临时锁定。
6. Session Cookie 缺少 `Secure` 和显式 `SameSite`，应用使用 HTTP。
7. 缺少 CSP、点击劫持防护、MIME 嗅探防护和缓存控制。

## 修复内容

| 安全问题 | 修复方案 |
|---|---|
| 默认凭据/调试注释 | 删除所有客户端可见凭据；密码从环境变量注入，禁止可预测默认值 |
| 明文密码 | 使用 Werkzeug `scrypt` 哈希，仅保留 `password_hash`，模板永不渲染密码 |
| 固定 Flask Secret | 使用 `FLASK_SECRET_KEY`，生产环境未配置时启动失败；开发环境使用每进程随机值 |
| 会话固定 | 成功认证前清空旧会话并生成新的 CSRF Token |
| CSRF | 登录和 POST 登出都要求会话绑定的随机 Token；GET `/logout` 不再存在 |
| 暴力破解 | 按 IP+账号限制失败次数，5 次/60 秒后返回 429 和 `Retry-After` |
| Cookie/传输安全 | `HttpOnly`、`SameSite=Lax`，生产环境通过 `SESSION_COOKIE_SECURE=1` 启用 Secure |
| 敏感数据暴露 | 个人联系方式掩码，不再显示密码和余额；敏感响应使用 `no-store` |
| 浏览器安全基线 | 增加 CSP、`X-Frame-Options`、`X-Content-Type-Options`、Referrer/Permissions Policy |
| 调试服务器 | `debug=False`，不启用交互式 Werkzeug 调试器 |

## 本地运行

需要 Python 3.11+ 与 Flask 3.1+。不要把真实环境变量写入仓库。

### PowerShell 示例

```powershell
cd after
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:FLASK_ENV = "development"
$env:FLASK_SECRET_KEY = "local-only-random-secret-at-least-32-characters"
$env:ADMIN_PASSWORD = "local-admin-password-at-least-12"
$env:ALICE_PASSWORD = "local-alice-password-at-least-12"
$env:SESSION_COOKIE_SECURE = "0"  # 本地 HTTP；生产环境必须设为 1 并启用 HTTPS
python app.py
```

生产部署必须设置 `FLASK_ENV=production`、长度至少 32 的随机 `FLASK_SECRET_KEY`、两个长度至少 12 的唯一密码，并通过 HTTPS 运行；生产环境不要使用 Flask 内置开发服务器。

## 自动化验证

在目录 `2026/7/19-work` 下执行：

```bash
python -m unittest discover -s tests -v
```

当前验证结果：**6 项测试全部通过**，覆盖以下安全要求：

- 登录页不再泄露调试凭据；
- 密码只以哈希形式存在；
- 登录必须携带 CSRF Token；
- 认证页面不返回密码并掩码联系方式；
- Cookie 含 `Secure`、`HttpOnly`、`SameSite=Lax`；
- GET 登出被拒绝，POST 登出需要 CSRF；
- 连续失败触发 429 限速；
- 安全响应头和 `Cache-Control: no-store` 生效。

## 变更边界

本次修复保持原靶场的内存用户模型和页面用途，不引入外部数据库或复杂依赖；生产环境仍应进一步接入服务端会话存储、集中式限速、MFA、审计日志和密钥管理系统。
