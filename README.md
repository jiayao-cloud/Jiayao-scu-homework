# Jiayao-scu-homework

Class08 用户管理网站安全修复迭代。本项目保留登录、注册、搜索、头像上传、个人中心、充值、动态页面加载、密码修改、欢迎页和反馈页，并新增 Ping 网络诊断功能，以 `before` / `after` 展示修复前后差异。

## 目录结构

```text
.
|-- before/    # Class08 原始目录：本轮 Ping 漏洞已完成修复
|-- after/     # Class08 修复后代码：保留功能并完成安全加固
|-- evidence/  # 本轮实测证据、截图和报告构建脚本
|-- tests/     # 面向 after/ 的回归测试
`-- README.md
```

## Class08 功能

- 登录、注册、用户搜索
- 头像上传与私有头像访问
- 个人中心、余额充值
- 密码修改
- 动态页面加载
- 欢迎页和反馈页
- 登录后 Ping 网络诊断

## 漏洞修复

`before/app.py` 中新增的 `/welcome` 和 `/feedback` 页面曾使用字符串拼接把用户输入直接写入 `render_template_string` 模板源码，导致 SSTI。
`after/app.py` 已修复为安全模板渲染：用户输入只作为模板变量传入，不再参与模板源码拼接。

此前 Ping 功能把用户输入拼接进 `shell=True` 命令，存在 CWE-78 命令注入风险。当前 `before` 和 `after` 均使用 IP 地址校验、参数列表和 `shell=False` 调用系统命令。

## 既有安全加固

- SQL 注入：数据库读写使用参数化查询，搜索关键字会转义 `LIKE` 通配符。
- 文件上传：限制图片扩展名和文件头，生成随机文件名，上传目录不直接暴露为静态资源。
- 越权访问：普通用户不能通过篡改 `user_id` 查看他人资料或操作他人余额。
- 充值逻辑：校验 CSRF、账户归属、金额类型和正数范围。
- 口令与会话：启用 HttpOnly、SameSite、缓存控制和基础安全响应头。

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

本轮还补充了 `/ping` 命令注入实测验证；相关报告文档保留在本地，不纳入本次提交。

## 课程边界

`before/` 和 `after/` 均为课程实训代码，不应直接部署到真实网络环境。真实口令、数据库、日志、Cookie、Token 和上传样本不应提交到仓库。
