# 文件上传漏洞集合

> 本目录包含多个文件上传漏洞的检测模板，这些漏洞可能导致远程代码执行(RCE)、系统入侵等严重后果。

## 目录

- [漏洞概述](#漏洞概述)
- [漏洞分类](#漏洞分类)
- [高危漏洞列表](#高危漏洞列表)
- [检测方法](#检测方法)
- [防御措施](#防御措施)
- [参考资源](#参考资源)
- [免责声明](#免责声明)

## 漏洞概述

文件上传漏洞是指由于Web应用程序未对用户上传的文件进行充分验证，导致攻击者可以上传恶意文件（如Webshell）到服务器，从而获取系统控制权。

### 常见攻击方式

1. **绕过文件类型检测**
   - 修改Content-Type
   - 修改文件扩展名
   - 双扩展名绕过
   - 空字节截断

2. **目录遍历**
   - 使用`../`跳转目录
   - 绝对路径上传

3. **文件内容检测绕过**
   - 添加文件头
   - 使用短标签
   - 编码混淆

## 漏洞分类

### 按漏洞类型

1. **未授权上传**
   - 无需认证即可上传文件
   - 示例：`CVE-2022-29464` WSO2 未授权文件上传

2. **认证绕过**
   - 认证机制存在缺陷
   - 示例：`CVE-2021-22005` vCenter Server 文件上传漏洞

3. **目录遍历**
   - 可上传到任意目录
   - 示例：`CVE-2021-21972` vSphere Client 目录遍历

4. **文件解析漏洞**
   - 服务器错误解析文件
   - 示例：`CVE-2021-41773` Apache HTTP Server 路径遍历

### 按影响系统

- **Web应用框架**：WordPress, vBulletin 等
- **企业应用**：WSO2, vCenter, 用友, 致远等
- **网络设备**：Cisco, H3C, Ruijie 等
- **CMS系统**：Drupal, Joomla 等

## 高危漏洞列表

| CVE ID | 漏洞名称 | 影响系统 | 严重程度 | 利用难度 |
|--------|---------|---------|---------|---------|
| [CVE-2024-55956](CVE-2024-55956.yaml) | Cleo Harmony 文件上传漏洞 | Cleo Harmony < 5.8.0.24 | 严重 (9.8) | 低 |
| [CVE-2022-29464](CVE-2022-29464.yaml) | WSO2 未授权文件上传 | WSO2 API Manager 2.2.0-4.0.0 等 | 严重 (9.8) | 中 |
| [CVE-2021-22005](CVE-2021-22005.yaml) | vCenter Server 文件上传 | vCenter Server 6.5-7.0 | 严重 (9.8) | 中 |
| [CVE-2021-21972](CVE-2021-21972.yaml) | vSphere Client 目录遍历 | vCenter Server 6.5-7.0 | 严重 (9.8) | 中 |
| [CVE-2020-10189](CVE-2020-10189.yaml) | Zoho ManageEngine 文件上传 | ManageEngine Desktop Central < 10.0.474 | 严重 (9.8) | 低 |
| [CVE-2019-17558](CVE-2019-17558.yaml) | Apache Solr 文件上传 | Apache Solr 5.0.0-8.3.1 | 严重 (9.8) | 中 |
| [CVE-2018-15961](CVE-2018-15961.yaml) | Adobe ColdFusion 反序列化 | Adobe ColdFusion 2016/2018 | 严重 (9.8) | 中 |
| [CVE-2016-10033](CVE-2016-10033.yaml) | WordPress PHPMailer RCE | WordPress with PHPMailer < 5.2.18 | 严重 (9.8) | 中 |

> 完整漏洞列表请查看目录中的YAML文件

## 检测方法

### 自动检测

使用 Nuclei 工具进行批量检测：

```bash
# 检测单个漏洞
nuclei -t CVE-2022-29464.yaml -u https://target.com

# 批量检测目标
nuclei -l targets.txt -t ./

# 按标签筛选
nuclei -t . -tags file-upload -u https://target.com
```

### 手动验证

1. **文件上传功能测试**
   - 尝试上传常见Webshell
   - 测试文件类型绕过
   - 检查目录遍历

2. **权限验证**
   - 测试未授权上传
   - 检查权限提升

3. **日志分析**
   - 检查访问日志
   - 监控文件系统变化

## 防御措施

### 通用防护

1. **输入验证**
   - 白名单验证文件类型
   - 验证文件内容
   - 重命名上传文件

2. **存储安全**
   - 上传目录禁止执行
   - 使用CDN存储静态文件
   - 设置适当权限

3. **安全配置**
   - 禁用危险函数
   - 配置WAF规则
   - 定期安全审计

### 特定防护

- **WSO2**：升级到最新版本，配置访问控制
- **vCenter**：应用VMware安全公告中的补丁
- **WordPress**：更新插件和主题，使用安全插件

## 参考资源

### 工具

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 快速、可定制的漏洞扫描器
- [Burp Suite](https://portswigger.net/burp) - Web应用安全测试平台
- [OWASP ZAP](https://www.zaproxy.org/) - Web应用安全扫描器
- [Upload Scanner](https://github.com/almandin/uxss) - 文件上传漏洞扫描器

### 学习资源

- [OWASP 文件上传防护指南](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PortSwigger 文件上传漏洞](https://portswigger.net/web-security/file-upload)
- [CWE-434: 不受限制上传危险类型文件](https://cwe.mitre.org/data/definitions/434.html)

## 八、典型漏洞 YAML 文件分析

本目录收录了多种场景下的文件上传漏洞模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2021-21978.yaml (VMware View Planner RCE)
- **漏洞类型**：未授权任意文件上传
- **漏洞原理**：
  VMware View Planner 的 `logupload` 功能存在输入验证不当和权限控制缺失的问题。攻击者无需认证，即可通过构造恶意的 `logMetaData` 参数（包含目录遍历 `../`）来指定任意上传路径和文件名，从而将恶意文件（如 Webshell）写入到 Web 服务器的任意位置，导致远程代码执行。
- **探测原理**：
  该 YAML 模板向 `/logupload` 接口发送一个 POST 请求。请求的 `logMetaData` 参数被构造成 `"..\\..\\..\\..\\..\\..\\..\\etc\\httpd\\html\\wsgi_log_upload"`，试图将一个名为 `log_upload_wsgi.py` 的测试文件上传到服务器的 Web 目录下。如果上传成功并返回特定成功信息，则判定漏洞存在。
- **修复建议**：升级 VMware View Planner 至 4.6 SP1 或更高版本，并对所有上传接口做严格的路径和权限校验。

### 2. wanhu-oa-fileupload-controller-arbitrary-file-upload.yaml (万户 OA 任意文件上传)
- **漏洞类型**：任意文件上传
- **漏洞原理**：
  万户 OA 的 `fileUpload.controller` 接口在处理文件上传时，未对上传的文件类型和内容进行有效过滤。攻击者可以直接上传 JSP Webshell 到服务器，并获得服务器的执行权限。
- **探测原理**：
  该模板首先向 `/defaultroot/upload/fileUpload.controller` 接口 POST 一个随机命名的 JSP 文件，文件内容为一个简单的 JSP 表达式（用于计算乘法）和自删除代码。上传成功后，模板会记录返回的文件路径。接着，模板会向该路径发送 GET 请求，如果响应中包含了预期的计算结果，则证明 JSP 文件被成功解析执行，漏洞得到确认。
- **修复建议**：对 `/defaultroot/upload/fileUpload.controller` 接口增加严格的认证和文件类型白名单校验，禁止上传可执行脚本文件。

---

#### 总结
文件上传漏洞是最高危的漏洞之一，其核心问题在于信任了用户的输入。防御的关键在于"不信任"原则：
- **严格校验**：对文件名、扩展名、路径、内容进行多维度、服务端的严格校验。
- **权限最小化**：Web 容器应对上传目录不授予执行权限，上传文件应与 Web 服务隔离。
- **安全重命名**：使用随机或哈希值重命名上传的文件，避免解析漏洞。


