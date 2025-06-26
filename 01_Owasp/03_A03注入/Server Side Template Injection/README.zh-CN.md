# 服务器端模板注入 (SSTI)

> 模板注入允许攻击者将模板代码注入到现有（或新建）的模板中。模板引擎通过使用静态模板文件，在运行时将变量/占位符替换为 HTML 页面中的实际值，从而简化了 HTML 页面的设计。

## 模板注入原理

服务器端模板注入（SSTI）是一种安全漏洞，当应用程序在未经验证或转义的情况下，将用户输入直接拼接到服务器端模板中时出现。攻击者可以利用此漏洞注入恶意模板代码，导致服务器执行非预期的操作。

### 漏洞成因

1. **不安全的用户输入处理**：应用程序直接将用户输入拼接到模板中
2. **缺乏输入验证**：未对用户输入进行适当的验证和过滤
3. **模板引擎配置不当**：模板引擎配置允许执行危险操作

### 攻击面

- **用户输入点**：搜索框、表单字段、URL 参数、HTTP 头等
- **模板上下文**：网页渲染、PDF 生成、邮件模板、报告生成等
- **模板引擎**：Jinja2 (Python)、Twig (PHP)、FreeMarker (Java) 等

### 影响

- 任意文件读取
- 远程代码执行 (RCE)
- 敏感信息泄露
- 服务器端请求伪造 (SSRF)
- 拒绝服务 (DoS)

## 目录

- [工具](#工具)
- [方法学](#方法学)
    - [识别易受攻击的输入字段](#识别易受攻击的输入字段)
    - [注入模板语法](#注入模板语法)
    - [枚举模板引擎](#枚举模板引擎)
    - [提升至代码执行](#提升至代码执行)
- [实验](#实验)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 工具

- [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - 一个高效的 SSTI + CSTI 扫描器，利用新型多语言有效载荷

  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

- [epinna/tplmap](https://github.com/epinna/tplmap) - 服务器端模板注入和代码注入检测与利用工具

  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - 基于 [epinna/tplmap](https://github.com/epinna/tplmap) 的自动 SSTI 检测工具，具有交互式界面

  ```powershell
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## 方法学

### 识别易受攻击的输入字段

攻击者首先定位输入字段、URL 参数或应用程序中任何用户可控制的部分，这些部分在未经适当清理或转义的情况下传递到服务器端模板中。

例如，攻击者可能会识别一个 Web 表单、搜索栏或模板预览功能，这些功能似乎基于动态用户输入返回结果。

**提示**：生成的 PDF 文件、发票和电子邮件通常使用模板。

### 注入模板语法

攻击者通过注入特定于所使用的模板引擎的模板语法来测试已识别的输入字段。不同的 Web 框架使用不同的模板引擎（例如，Python 的 Jinja2、PHP 的 Twig 或 Java 的 FreeMarker）。

常见的模板表达式：

- `{{7*7}}` 用于 Jinja2 (Python)
- `#{7*7}` 用于 Thymeleaf (Java)

在相关技术（PHP、Python 等）的专用页面中查找更多模板表达式。

![SSTI 速查表工作流程](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

在大多数情况下，这个多语言有效载荷会在存在 SSTI 漏洞时触发错误：

```
${{<%[%'"}}\%.
```

[Hackmanit/Template Injection Table](https://github.com/Hackmanit/template-injection-table) 是一个交互式表格，包含最高效的模板注入多语言有效载荷以及 44 种最重要模板引擎的预期响应。

### 枚举模板引擎

根据成功的响应，攻击者确定正在使用哪个模板引擎。此步骤至关重要，因为不同的模板引擎具有不同的语法、功能和利用潜力。攻击者可能会尝试不同的有效载荷来查看哪个有效，从而识别引擎。

- **Python**: Django, Jinja2, Mako, ...
- **Java**: Freemarker, Jinjava, Velocity, ...
- **Ruby**: ERB, Slim, ...

[@0xAwali 的文章 "template-engines-injection-101"](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) 总结了 JavaScript、Python、Ruby、Java 和 PHP 的大多数模板引擎的语法和检测方法，以及如何区分使用相同语法的引擎。

### 提升至代码执行

一旦识别出模板引擎，攻击者会注入更复杂的表达式，目标是执行服务器端命令或任意代码。

## 实验

- [Root Me - Java - 服务器端模板注入](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection)
- [Root Me - Python - 服务器端模板注入简介](https://www.root-me.org/en/Challenges/Web-Server/Python-Server-side-Template-Injection-Introduction)
- [Root Me - Python - 盲注 SSTI 过滤器绕过](https://www.root-me.org/en/Challenges/Web-Server/Python-Blind-SSTI-Filters-Bypass)

## 防御措施

### 输入验证
- 对所有用户输入进行严格验证
- 使用白名单验证允许的字符和格式
- 拒绝包含模板语法的输入

### 输出编码
- 在将用户输入输出到页面之前进行适当的 HTML 编码
- 使用上下文相关的编码函数

### 沙箱环境
- 在受限环境中执行模板渲染
- 限制模板引擎的功能
- 禁用危险函数和操作

### 安全配置
- 使用最新版本的模板引擎
- 应用安全补丁
- 配置模板引擎以限制潜在的危险操作

### 安全开发实践
- 避免将用户输入直接嵌入到模板中
- 使用模板引擎的安全功能
- 实施内容安全策略 (CSP)

## 参考资料

- [渗透测试人员指南：服务器端模板注入 (SSTI) - Busra Demir - 2020年12月24日](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- [使用服务器端模板注入 (SSTI) 获取 Shell - David Valles - 2018年8月22日](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
- [模板引擎注入 101 - Mahmoud M. Awali - 2024年11月1日](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [强化目标上的模板注入 - Lucas 'BitK' Philippe - 2022年9月28日](https://youtu.be/M0b_KA0OMFw)
