# 漏洞利用框架 (Exploitation Frameworks)

> 漏洞利用框架是安全专业人员和渗透测试人员用于开发、测试和执行漏洞利用代码的集成工具集。这些框架提供了预构建的漏洞利用模块、有效载荷生成器和其他实用工具，使安全评估过程更加高效和系统化。

## 目录

* [Metasploit 框架](#metasploit-框架)
* [Cobalt Strike](#cobalt-strike)
* [Empire](#empire)
* [PowerSploit](#powersploit)
* [Mimikatz](#mimikatz)
* [Impacket](#impacket)
* [参考资料](#参考资料)

## Metasploit 框架

[Metasploit](https://www.metasploit.com/) 是最流行的渗透测试框架之一，提供大量漏洞利用模块、有效载荷、编码器和后渗透工具。

**主要特点**:
- 超过2000个漏洞利用模块
- 500多个有效载荷
- 支持多种操作系统和架构
- 与Nessus、Nexpose等工具集成

**基本命令**:
```bash
# 启动Metasploit控制台
msfconsole

# 搜索漏洞利用
search exploit_name

# 使用漏洞利用
use exploit/path/to/exploit

# 显示选项
show options

# 设置参数
set RHOSTS target_ip
set LHOST your_ip

# 执行利用
exploit
```

## Cobalt Strike

[Cobalt Strike](https://www.cobaltstrike.com/) 是一个商业渗透测试工具，专注于对抗性攻击模拟和红队行动。

**主要特点**:
- 高级命令与控制(C2)功能
- 社会工程学工具包
- 后渗透功能
- 团队协作功能

## Empire

[Empire](https://github.com/BC-SECURITY/Empire) 是一个后漏洞利用代理框架，专注于Windows操作系统的利用。

**主要特点**:
- 模块化设计
- 加密通信
- 支持多个监听器
- 与PowerShell集成

## PowerSploit

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit) 是一个PowerShell模块集合，用于渗透测试和红队操作。

**主要模块**:
- **CodeExecution**: 执行代码
- **Exfiltration**: 数据外泄
- **Recon**: 侦察
- **ScriptModification**: 脚本修改

## Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) 是一个后渗透工具，用于从Windows系统中提取凭证。

**主要功能**:
- 提取明文密码
- 哈希转储
- 票据操作
- 黄金票据/白银票据攻击

## Impacket

[Impacket](https://github.com/SecureAuthCorp/impacket) 是一个Python类集合，用于处理网络协议。

**主要工具**:
- **psexec.py**: 类似PsExec的工具
- **secretsdump.py**: 转储SAM数据库
- **ntlmrelayx.py**: NTLM中继攻击
- **wmiexec.py**: 通过WMI执行命令

## 参考资料

* [Metasploit Unleashed - 免费Metasploit培训](https://www.offensive-security.com/metasploit-unleashed/)
* [Cobalt Strike 官方文档](https://www.cobaltstrike.com/help-master)
* [Empire Wiki](https://www.powershellempire.com/)
* [PowerSploit Wiki](https://github.com/PowerShellMafia/PowerSploit/wiki)
* [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
* [Imacket 示例](https://www.secureauth.com/labs/open-source-tools/impacket/)

## 使用注意事项

1. **法律合规**: 仅在对您拥有合法授权的系统上使用这些工具
2. **责任**: 未经授权使用这些工具可能违反法律
3. **道德准则**: 始终遵循负责任的披露政策
4. **更新**: 定期更新工具以获取最新的漏洞利用和修复

## 学习资源

* [Offensive Security 培训](https://www.offensive-security.com/)
* [Hack The Box](https://www.hackthebox.com/)
* [TryHackMe](https://tryhackme.com/)
* [VulnHub](https://www.vulnhub.com/)

---

## 八、典型漏洞 YAML 文件分析

本目录中的 YAML 文件多与知名漏洞利用框架（如 Metasploit）中收录的漏洞相关，以下对部分典型文件进行解读。

### 1. CVE-2014-6287.yaml (HFS 远程命令执行)
- **漏洞类型**：远程代码执行 (RCE)
- **漏洞原理**：
  HTTP File Server (HFS) 2.3c 之前的版本中，其内置的 `parserLib.pas` 脚本的 `findMacroMarker` 函数存在一个漏洞。攻击者可以在搜索参数中通过空字节（`%00`）截断输入，并将宏命令注入到服务器的脚本解析引擎中。这使得攻击者可以执行任意系统命令。
- **探测原理**：
  该 YAML 模板利用此漏洞，在 `search` 参数中注入一个 payload：`%00{.cookie|{{str1}}|value%3d{{str2}}.}`。这个 payload 的意图是利用 HFS 的宏功能设置一个 Cookie。模板会检查服务器的响应头中是否包含了 `Set-Cookie` 并且其值与 payload 中设置的随机字符串相匹配。如果匹配成功，则证明服务器执行了注入的宏命令，漏洞存在。
- **修复建议**：升级 HFS 至 2.3c 或更高版本。

### 2. hadoop-unauth-rce.yaml (Hadoop YARN 未授权访问 RCE)
- **漏洞类型**：未授权访问 & 远程代码执行
- **漏洞原理**：
  Apache Hadoop YARN 的 ResourceManager 默认在 8088 端口开放 REST API，用于集群管理。在未启用 Kerberos 认证的情况下，此接口允许任何用户在无需认证的情况下提交应用程序。攻击者可以构造一个恶意的应用程序提交请求，请求中包含的命令将在集群的某个节点上执行，从而导致远程代码执行。
- **探测原理**：
  该模板向 `/ws/v1/cluster/apps/new-application` API 端点发送一个 POST 请求。这是一个用于创建新应用程序的合法接口。如果服务器响应成功（HTTP 200）并且返回的内容中包含 `"application-id"`，则表明该接口允许未经认证的访问，存在未授权访问和潜在的 RCE 风险。
- **修复建议**：在 Hadoop 集群中启用并强制配置 Kerberos 安全认证。

---

#### 总结
漏洞利用框架中收录的漏洞通常具有以下特点：
- **影响广泛**：影响流行的软件和服务，如 HFS、Hadoop。
- **利用稳定**：通常有公开且可靠的漏洞利用代码（Exploit）。
- **危害严重**：多为远程代码执行、权限提升等高危漏洞。

使用这些模板进行扫描时，可以快速发现那些已经被广泛利用的、构成严重威胁的已知漏洞。
