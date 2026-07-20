# Class02 Web 安全修复项目

本目录包含 Class02 用户管理系统的漏洞修复前后对照代码。

## 目录结构

```text
2026/7/20-Class02-secure-fix/
├── before/   # 修复前代码快照，保留漏洞结构，敏感口令和密钥已脱敏
├── after/    # 修复后的可运行 Flask 项目
└── tests/    # 修复版安全回归测试
```

说明：原压缩包中的 `brute_secret.py` 和 `forge_session.py` 是攻击辅助脚本，不属于修复后网页项目，也不适合放入公开仓库，因此没有纳入本次上传目录。

## 修复前主要问题

修复前代码存在以下安全问题：

1. `app.secret_key` 写死在源码中，容易被猜解后伪造 Flask Session。
2. 登录页 HTML 注释泄露默认管理员账号和密码。
3. 用户密码以明文形式写在内存字典和 SQLite 数据库中。
4. 登录成功后页面直接回显密码字段。
5. `/` 和 `/search` 的搜索 SQL 使用字符串拼接，存在 SQL 注入。
6. `/register` 的插入 SQL 使用字符串拼接，存在 SQL 注入。
7. 注册接口缺少服务端校验，可写入弱密码、非法邮箱和非法手机号。
8. `debug=True` 暴露 Werkzeug 调试错误页和内部调用栈。
9. `/logout` 使用 GET 改变登录状态，缺少 CSRF 防护。
10. 缺少安全响应头、缓存控制和基础登录失败限制。

## 修复方式

修复后的 `after/` 版本做了以下处理：

| 问题 | 修复方式 |
|---|---|
| 硬编码 Flask 密钥 | 使用 `SECRET_KEY` 环境变量；未设置时仅为本地开发生成运行时随机密钥 |
| 默认凭据泄露 | 删除登录页调试注释；管理员初始密码只允许通过 `ADMIN_PASSWORD` 环境变量注入 |
| 明文密码 | 使用 `werkzeug.security.generate_password_hash` 存储哈希，登录用 `check_password_hash` 校验 |
| 密码回显 | 首页不再展示密码字段，手机号做掩码展示 |
| SQL 注入 | 所有 SQLite 查询和插入改为 `?` 参数化查询 |
| 注册脏数据 | 服务端校验用户名、密码强度、邮箱格式、手机号格式和唯一性 |
| Debug 暴露 | 运行入口改为 `debug=False`，默认监听 `127.0.0.1` |
| GET 登出 / CSRF | 登出改为 POST，登录、注册、登出表单都校验 CSRF Token |
| 越权搜索 | 搜索功能仅管理员可用，并限制返回字段和最大结果数 |
| 暴力尝试 | 增加基于 IP + 用户名的内存失败次数限制 |
| 安全响应头 | 添加 `Cache-Control`、CSP、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy` |

## 运行修复后项目

进入修复版目录：

```bash
cd after
python -m pip install -r requirements.txt
```

首次创建管理员时，通过环境变量提供管理员密码：

```bash
# PowerShell
$env:SECRET_KEY = "请替换为至少32字节的随机密钥"
$env:ADMIN_PASSWORD = "请替换为强管理员密码"
python app.py
```

生产环境还应启用 HTTPS，并设置：

```bash
$env:SESSION_COOKIE_SECURE = "1"
```

## 运行测试

在 `2026/7/20-Class02-secure-fix` 目录下执行：

```bash
python -m unittest discover -s tests -v
```

测试覆盖：

- 登录页不再泄露默认凭据。
- 注册接口要求 CSRF 并拒绝非法字段。
- 密码入库为哈希，页面不回显明文密码。
- 搜索接口参数化后，`' OR '1'='1` 不再扩展返回结果。
- GET `/logout` 不再改变状态。
- 基础安全响应头存在。

## 安全边界

- `before/` 目录用于说明修复前问题，已将固定密钥和默认密码替换为 `REDACTED_*` 占位符。
- 不要把真实运行环境的 `SECRET_KEY`、管理员密码、数据库文件、Cookie 或日志提交到仓库。
- 修复版仍是课程作业级示例项目；若用于真实业务，还需要接入生产数据库、HTTPS 反向代理、集中日志、MFA、审计告警和更完整的权限模型。
