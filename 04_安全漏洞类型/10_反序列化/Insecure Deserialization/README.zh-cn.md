# 不安全的反序列化漏洞

> 序列化是将对象转换为可以稍后恢复的数据格式的过程。人们通常将对象序列化以保存到存储中，或作为通信的一部分发送。反序列化则是相反的过程——从某种格式的结构化数据重建为对象。 — OWASP

## 目录

- [漏洞概述](#漏洞概述)
- [序列化标识符](#序列化标识符)
- [POP链利用](#pop链利用)
- [各语言反序列化漏洞](#各语言反序列化漏洞)
- [漏洞检测与利用](#漏洞检测与利用)
- [防御措施](#防御措施)
- [实验环境](#实验环境)
- [参考资源](#参考资源)

## 漏洞概述

不安全的反序列化漏洞（Insecure Deserialization）是OWASP Top 10中的严重安全风险之一。当应用程序反序列化不可信的输入数据时，攻击者可能通过构造恶意序列化数据来执行任意代码、绕过安全控制或导致拒绝服务。

### 常见攻击场景

1. 修改序列化对象中的属性值
2. 注入任意类型的对象
3. 利用应用程序中的POP链（Property-Oriented Programming）执行任意代码
4. 通过反序列化触发远程代码执行（RCE）

## 序列化标识符

不同编程语言和框架使用不同的序列化格式，可以通过以下标识符进行识别：

| 对象类型 | 十六进制头部 | Base64头部 | 文件扩展名 |
|---------|------------|------------|-----------|
| Java序列化 | AC ED | rO | .ser |
| .NET ViewState | FF 01 | /w | .aspx |
| Python Pickle | 80 04 95 | gASV | .pkl |
| PHP序列化 | 4F 3A | Tz: | .php |
| Ruby Marshal | 04 08 | BAo= | .marshal |
| Node.js (node-serialize) | - | - | .json |

## POP链利用

POP（Property-Oriented Programming）链是一种利用反序列化漏洞的技术，通过组合应用程序中的类和方法来构造恶意对象。

### POP链特点

- 可被序列化
- 具有公共/可访问的属性
- 实现了特定的危险方法
- 可以访问其他"可调用"的类

### 常见POP链模式

1. **Java**：利用Apache Commons Collections、JDK等库中的危险方法
2. **.NET**：利用ObjectDataProvider、WindowsIdentity等类
3. **PHP**：利用魔术方法如`__wakeup`、`__destruct`等
4. **Python**：利用`__reduce__`方法执行任意命令

## 各语言反序列化漏洞

### [Java反序列化](Java.md)
- 工具：ysoserial、marshalsec
- 常见库：Apache Commons Collections、JDK、Groovy、Spring
- 利用链：CommonsCollections、JNDI注入、RMI等

### [PHP反序列化](PHP.md)
- 工具：phpggc、PHPGGC
- 魔术方法：`__wakeup`、`__destruct`、`__toString`
- 利用链：Laravel、Symfony、Monolog等

### [Python反序列化](Python.md)
- 模块：pickle、PyYAML、jsonpickle
- 危险方法：`__reduce__`、`__setstate__`
- 利用方式：代码执行、文件操作等

### [.NET反序列化](DotNET.md)
- 工具：ysoserial.net
- 危险类：ObjectDataProvider、WindowsIdentity、LosFormatter
- 利用链：ViewState、BinaryFormatter等

### [Ruby反序列化](Ruby.md)
- 工具：universal_rce_gadget
- 利用方式：Marshal.load、YAML.load
- 常见漏洞：Ruby on Rails、Rack等

### [Node.js反序列化](Node.md)
- 模块：node-serialize、serialize-javascript
- 利用方式：IIFE（立即调用函数表达式）
- 防护措施：避免使用不安全的反序列化方法

## 漏洞检测与利用

### 检测方法

1. **静态分析**：
   - 查找反序列化函数调用
   - 检查输入验证和过滤
   - 识别危险的反序列化配置

2. **动态测试**：
   - 修改序列化数据
   - 测试异常处理
   - 监控反序列化过程

### 利用步骤

1. 识别反序列化入口点
2. 分析应用程序依赖
3. 构造恶意序列化数据
4. 发送并触发反序列化
5. 验证漏洞利用结果

## 防御措施

1. **避免反序列化不可信数据**
   - 使用安全的替代方案（如JSON）
   - 实现完整性检查

2. **实施严格的输入验证**
   - 白名单验证
   - 类型检查
   - 数据签名

3. **安全配置**
   - 限制反序列化类
   - 使用最低权限运行
   - 启用安全管理器

4. **代码审查**
   - 检查反序列化使用
   - 更新依赖库
   - 实施安全编码规范

## 实验环境

### 在线实验室

- [PortSwigger 实验室](https://portswigger.net/web-security/deserialization)
  - 修改序列化对象
  - 利用PHP反序列化
  - Java反序列化利用
  - 构建自定义Gadget链

- [DeserLab](https://github.com/NickstaDB/DeserLab)
  - Java反序列化实验环境
  - 多种Gadget链示例

## 参考资源

### 文档与教程
- [OWASP反序列化防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Java反序列化漏洞详解](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [PHP反序列化漏洞利用](https://www.owasp.org/images/9/9e/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)

### 工具
- [ysoserial - Java反序列化利用工具](https://github.com/frohoff/ysoserial)
- [phpggc - PHP反序列化利用工具](https://github.com/ambionics/phpggc)
- [ysoserial.net - .NET反序列化利用工具](https://github.com/pwntester/ysoserial.net)
- [GadgetProbe - Java反序列化类检测](https://github.com/BishopFox/GadgetProbe)

### 研究论文
- [ExploitDB - 反序列化漏洞介绍](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
- [PortSwigger - 反序列化漏洞利用](https://portswigger.net/web-security/deserialization/exploiting)
- [Instagram百万美元漏洞分析](http://www.exfiltrated.com/research-Instagram-RCE.php)

* [不安全的反序列化漏洞 - ExploitDB](https://www.exploit-db.com/docs/44756)
* [利用不安全的反序列化漏洞 - PortSwigger](https://portswigger.net/web-security/deserialization/exploiting)
* [Instagram的百万美元漏洞 - Wesley Wineberg](http://www.exfiltrated.com/research-Instagram-RCE.php)

---

## 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了大量与不安全反序列化相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读。

### 1. fastjson-1-2-47-rce.yaml (Fastjson 1.2.47 反序列化 RCE)
- **漏洞类型**：不安全的反序列化
- **漏洞原理**：
  Fastjson 在 1.2.47 及以前的版本中，由于其 `autoType` 功能的黑名单机制不完善，攻击者可以构造一个恶意的 JSON 数据来指定反序列化的类。通过利用 `com.sun.rowset.JdbcRowSetImpl` 这个 "gadget"（利用链），攻击者可以设置一个恶意的 RMI 或 LDAP 服务地址作为数据源。当 Fastjson 解析这段 JSON 时，会实例化 `JdbcRowSetImpl` 类并尝试连接该恶意地址，从而触发 JNDI 注入，加载并执行远程服务器上的恶意代码。
- **探测原理**：
  该模板向目标发送一个包含 `JdbcRowSetImpl` gadget 的 JSON 请求。JSON 中的 `dataSourceName` 字段被设置为一个指向攻击者控制的 `interactsh` 服务器的 RMI 地址。如果目标服务器的 Fastjson 组件解析了这段 JSON 并尝试连接该 RMI 地址，`interactsh` 就会收到一个 DNS 请求，从而验证漏洞的存在。
- **修复建议**：升级 Fastjson 至最新版本，并尽可能关闭 `autoType` 功能。如果必须使用，应配置严格的 `autoType` 白名单，而不是依赖黑名单。

### 2. CVE-2023-49070.yaml (Apache OFBiz 反序列化 RCE)
- **漏洞类型**：反序列化远程代码执行
- **漏洞原理**：
  由于 Apache OFBiz 的一个旧的、未被良好维护的 XML-RPC 端点依然存在，攻击者可以发送特制的 XML 请求。该请求包含一个可序列化的 Java 对象。当服务器端处理此 XML 时，会触发不安全的反序列化过程，从而执行攻击者预设的恶意代码（通常通过 Common-Collections 等库的 gadget chain）。
- **探测原理**：
  该 YAML 模板向 `/webtools/control/xmlrpc` 发送一个包含 `generate_java_gadget` 函数生成的 Java Payload 的 POST 请求。该 Payload 会在反序列化时向攻击者控制的 `interactsh` 服务器发起 DNS 请求。如果 `interactsh` 收到了相应的请求，即可确认漏洞存在。
- **修复建议**：升级 Apache OFBiz 至 18.12.10 或更高版本，并移除或通过防火墙策略禁用不再使用的 XML-RPC 端点。

---

#### 总结
不安全的反序列化漏洞的本质在于，应用程序盲目地信任并处理了来自不可信来源的序列化数据。攻击者通过构造恶意的数据流，可以在反序列化过程中控制程序的执行流程，最终导致任意代码执行。防御此类漏洞的关键在于：
- **禁止来自不可信源的反序列化**：这是最根本的解决办法。
- **使用更安全的数据格式**：如果需要数据交换，优先选用如 JSON (不带类型转换) 等不易导致代码执行的纯数据格式。
- **增强反序列化过程的安全性**：对即将反序列化的类进行白名单校验，只允许预期的、安全的类被反序列化。
- **保持依赖库更新**：及时更新常用的序列化/反序列化库以及可能包含 "gadget" 的第三方库。

