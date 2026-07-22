# Class03 用户头像上传任意文件上传漏洞报告

## 一、漏洞结论

Class03 修复前版本 `before/` 的用户头像上传功能存在任意文件上传漏洞。登录用户访问 `/upload` 后，可以上传 HTML、JavaScript、SVG、PHP 等非头像文件；服务端使用用户提供的原始文件名保存到 `static/uploads/`，上传后的文件可通过 `/static/uploads/文件名` 直接访问。

经本地验证，当前 Flask 环境不会解释执行 PHP 文件，PHP 只能作为静态内容返回；但攻击者可以通过“上传 HTML 文件 + 上传同源 JavaScript 文件”的方式，让浏览器在当前站点同源路径下执行上传的 JavaScript。因此该漏洞不是单纯的“可上传非图片文件”，而是具备真实可验证影响的任意文件上传漏洞。

## 二、风险等级

高危。

评级依据：

1. 普通登录用户即可触发。
2. 服务端不校验后缀、MIME 类型和文件真实内容。
3. 文件名完全由用户控制。
4. 文件保存到 Flask 公开静态目录。
5. 上传后的 HTML 和 JavaScript 可被浏览器以同源资源访问。
6. 可造成同源脚本执行、钓鱼页面托管、恶意静态资源投放和同名文件覆盖。

## 三、漏洞位置

漏洞代码位于修复前项目：

```text
before/app.py
```

核心问题代码：

```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect(url_for("login"))

    error = None
    file_url = None

    if request.method == "POST":
        uploaded_file = request.files.get("avatar")
        if not uploaded_file or not uploaded_file.filename:
            error = "请选择要上传的文件"
        else:
            upload_dir = _upload_dir()
            upload_dir.mkdir(parents=True, exist_ok=True)
            filename = uploaded_file.filename
            uploaded_file.save(upload_dir / filename)
            file_url = url_for("static", filename=f"uploads/{filename}")

    return render_template("upload.html", error=error, file_url=file_url)
```

上传目录函数：

```python
def _upload_dir():
    return Path(app.static_folder) / "uploads"
```

该实现把不可信文件直接放入公开静态资源目录，并返回可访问 URL。

## 四、成因分析

### 1. 未限制文件后缀

头像上传业务应只允许图片格式，但修复前代码没有任何扩展名白名单，导致 `.html`、`.js`、`.svg`、`.php` 等文件均可上传。

### 2. 未校验文件真实内容

服务端没有读取文件头，也没有判断文件是否为真实图片。攻击者可以把脚本内容伪装成 `.png`、`.jpg` 等图片后缀上传。

### 3. 使用原始文件名保存

修复前代码直接使用：

```python
filename = uploaded_file.filename
uploaded_file.save(upload_dir / filename)
```

这会导致最终文件名和访问路径由用户控制，并可能造成同名文件覆盖。

### 4. 上传目录位于 static

`static/uploads/` 是 Flask 默认可访问静态目录的一部分，文件保存后立即暴露为同源公开资源。浏览器访问 HTML 文件时会按 `text/html` 处理，访问 JS 文件时会按 `application/javascript` 处理。

### 5. CSP 无法单独兜底

当前站点 CSP 可阻止内联脚本，但允许同源脚本加载。由于攻击者能把 JavaScript 上传到同源路径，HTML 文件可以引用该同源 JS，从而绕过“禁止内联脚本”的防护效果。

## 五、验证结果

本地验证日期：2026-07-21。

测试目标：

```text
http://127.0.0.1:5000/upload
```

验证结果：

1. 上传 HTML 文件成功，访问路径返回 `text/html`。
2. 上传 JavaScript 文件成功，访问路径返回 `application/javascript`。
3. 上传 SVG 文件成功，访问路径返回 `image/svg+xml`。
4. 上传 PHP 文件成功，访问路径返回静态内容，但 Flask 不解释执行。
5. 使用真实 Chrome 访问上传的 HTML 文件时，该 HTML 可加载同目录下上传的同源 JS，浏览器成功触发脚本执行。

因此，当前有效攻击链为：

```text
登录普通用户
访问 /upload
上传 JavaScript 文件到 /static/uploads/
上传引用该 JavaScript 的 HTML 文件到 /static/uploads/
诱导用户访问上传后的 HTML URL
浏览器以当前站点同源身份加载并执行上传的 JavaScript
```

## 六、影响分析

### 同源脚本执行

攻击者可以在站点同源路径下托管并执行 JavaScript。若页面或接口存在可被脚本读取、提交或诱导点击的敏感操作，风险会进一步扩大。

### 钓鱼页面托管

攻击者可上传伪造登录页、通知页或作业提交页。由于 URL 属于当前站点，用户更容易信任页面内容。

### 恶意静态资源投放

攻击者可利用网站作为恶意 HTML、JS、SVG 文件的托管点，影响站点信誉并扩大攻击面。

### 文件覆盖

由于保存时使用原始文件名，重复上传同名文件会覆盖旧内容，可能破坏其他用户已上传的文件或替换历史文件。

### 部署环境升级风险

当前 Flask 开发环境不执行 PHP，但如果未来部署到支持 PHP 解析的 Web 服务器，并且上传目录未禁止脚本执行，该漏洞可能升级为服务端代码执行风险。

## 七、修复方案

修复后项目位于：

```text
after/
```

修复措施如下：

1. `/upload` POST 请求增加 CSRF Token 校验。
2. 使用白名单限制头像格式，仅允许 `jpg`、`jpeg`、`png`、`gif`、`webp`。
3. 读取文件头魔数校验真实图片类型，拒绝脚本文件和伪装图片。
4. 使用 `secure_filename()` 规范化原始文件名，只提取可信扩展名。
5. 使用 `uuid4().hex` 生成随机文件名，禁止用户控制最终文件名。
6. 将上传文件保存到 `instance/avatars/`，不再保存到 `static/uploads/`。
7. 通过 `/avatars/<filename>` 受控路由读取头像文件，只允许合法随机文件名。
8. 返回头像时设置固定图片 MIME 类型，避免浏览器把上传内容当作 HTML 或 JS 执行。
9. `.gitignore` 忽略实例上传目录、日志、数据库和测试产物，避免敏感运行文件进入公开仓库。

## 八、修复后预期

修复后应满足：

1. HTML、JS、SVG、PHP 文件无法作为头像上传。
2. 伪装成图片后缀的脚本文件无法上传。
3. 上传成功的图片文件名不可由用户控制。
4. 上传文件不再暴露于 `/static/uploads/原始文件名`。
5. 同名文件上传不会覆盖历史文件。
6. 未登录用户无法访问上传页和头像读取路由。
7. 自动化测试可持续验证上述安全要求。

## 九、结论

Class03 修复前版本存在真实有效的任意文件上传漏洞。漏洞根因是缺少类型校验、内容校验、文件名随机化和上传目录隔离。修复后版本通过白名单、魔数校验、随机命名、私有目录保存、受控读取路由和 CSRF 防护完成了高质量加固，同时保持登录、注册、搜索和头像上传业务功能不变。
