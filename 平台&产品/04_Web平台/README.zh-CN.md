# Web平台安全模板分类说明

本目录聚焦于各类 Web 管理平台、控制面板等常见的安全风险，涵盖未授权访问、远程命令执行、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 分类说明

- **主流 Web 面板**：如 mCloud、宝塔、WDCP、cPanel 等，常见风险包括默认口令、未授权访问、命令执行、敏感信息泄露等。
- **自研/定制平台**：企业自研的 Web 管理后台，风险点多为认证绕过、权限提升、接口未授权等。

---

## 典型漏洞模板举例

### mCloud Installer 未授权远程命令执行漏洞

**模板文件**：`面板/mcloud-installer.yaml`

#### 漏洞简介

mCloud Installer 某些版本存在未授权远程命令执行漏洞。攻击者可直接访问安装接口并传入恶意参数，无需认证即可在服务器上执行任意命令，导致系统被完全控制。

#### 漏洞原理

该漏洞源于安装接口对用户输入缺乏有效校验，未对敏感操作做权限限制。攻击者可构造特定请求，将命令注入到参数中，服务端直接执行，造成严重危害。

#### 检测逻辑（YAML内容解析）

```yaml
id: mcloud-installer-rce

http:
  - method: POST
    path:
      - "/install"
    body: "cmd=whoami"
    matchers:
      - type: word
        part: body
        words:
          - "root"
          - "www-data"
```

- 发送包含命令的 POST 请求到 `/install` 接口。
- 若响应体中出现系统用户名（如 root、www-data），则判定存在命令执行漏洞。

#### 防护建议

- 升级 mCloud Installer 至官方修复版本。
- 对敏感接口添加认证和权限校验，禁止未授权访问。
- 对用户输入进行严格校验，避免命令注入。

---