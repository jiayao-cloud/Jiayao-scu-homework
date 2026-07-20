# Jiayao-scu-homework

本仓库保存一个 Flask 用户管理示例的安全修复作业。项目已整理到仓库根目录，原 `2026/7/19` 分层目录已移除，根目录只保留这一份全局 README。

## 目录结构

```text
.
├── before/                  # 修复前代码快照，敏感值已脱敏
├── after/                   # 修复后的可运行 Flask 项目
├── tests/                   # 针对修复后项目的安全回归测试
├── .gitignore
└── README.md
```

`before/` 用于对比漏洞修复前的实现方式，保留了固定 Secret、明文密码、GET 登出、缺少 CSRF、调试模式等问题的代码结构，但真实密码和固定密钥均已替换为脱敏占位符。`after/` 是修复后的版本，`tests/` 用于验证主要安全要求。

## 修复内容

本项目主要完成以下安全加固：

1. 移除页面中的调试凭据提示，密码改为从环境变量读取。
2. 使用 Werkzeug `scrypt` 哈希保存密码，不再在内存用户表或页面中暴露明文密码。
3. Flask `SECRET_KEY` 改为环境变量配置，生产环境缺失时拒绝启动，开发环境使用随机值。
4. 登录和登出加入 CSRF Token，登出改为 POST 请求。
5. 登录成功后清空旧 Session 并重新生成 CSRF Token，降低会话固定风险。
6. 登录失败加入基于 IP 和用户名的简单速率限制。
7. Cookie 显式启用 `HttpOnly`、`SameSite=Lax`，生产环境启用 `Secure`。
8. 首页只展示脱敏邮箱和手机号，不展示密码、余额等敏感字段。
9. 增加 CSP、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy` 等响应头。
10. 关闭 Flask/Werkzeug 调试模式，避免交互式调试器暴露。

## 本地运行修复版

需要 Python 3.11+。

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
python app.py
```

生产环境必须设置足够长且随机的 `FLASK_SECRET_KEY`，为每个用户配置独立强密码，并通过 HTTPS 部署。不要把真实环境变量写入仓库。

## 自动化测试

在仓库根目录执行：

```powershell
python -m unittest discover -s tests -v
```

测试覆盖密码哈希、登录 CSRF、登出方式、Cookie 安全属性、敏感信息隐藏、登录限速和安全响应头等修复点。

## 提交边界

本仓库只保留课程作业需要的修复前后对比代码、修复后项目和测试代码。原始压缩包中的攻击辅助脚本未纳入仓库，修复前快照中的真实凭据也已脱敏，避免把可直接复用的敏感信息公开。
