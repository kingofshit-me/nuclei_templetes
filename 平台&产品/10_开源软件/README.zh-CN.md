# 开源软件安全模板分类说明

本目录聚焦于各类主流开源软件的安全风险，涵盖远程代码执行、未授权访问、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 典型漏洞模板举例

### GLPI 任意文件上传导致远程代码执行漏洞（CVE-2021-32853）

**模板文件**：`CVE-2021-32853.yaml`

#### 漏洞简介

GLPI 是一款流行的开源 IT 资产管理和服务台系统。其部分版本存在任意文件上传漏洞，攻击者可上传恶意脚本文件（如 webshell），进而远程执行任意代码，危害极大。

#### 漏洞原理

该漏洞源于 GLPI 文件上传功能对文件类型、后缀及内容校验不严，未对上传用户进行严格权限验证。攻击者可构造特殊请求上传 `.php` 等可执行脚本文件，随后直接访问该文件实现远程命令执行。

#### 检测逻辑（YAML内容解析）

```yaml
id: CVE-2021-32853

http:
  - method: POST
    path:
      - "/front/document.send.php"
    headers:
      Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
    body: |
      ------WebKitFormBoundary
      Content-Disposition: form-data; name="upload"; filename="test.php"
      Content-Type: application/x-php

      <?php echo "glpi_upload_test"; ?>
      ------WebKitFormBoundary--
    matchers:
      - type: word
        part: body
        words:
          - "glpi_upload_test"
```

- 发送包含恶意 PHP 文件的 POST 请求到上传接口。
- 上传后访问该文件，若响应体中出现特定字符串，则判定存在任意文件上传漏洞。

#### 防护建议

- 升级 GLPI 至官方修复版本。
- 对上传接口进行严格的文件类型、后缀和内容校验，禁止上传可执行脚本文件。
- 增加权限校验，限制未授权用户访问上传接口。

---