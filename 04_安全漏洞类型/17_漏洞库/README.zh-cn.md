# 漏洞库 (Vulnerability Database)

> 本目录包含各种已知漏洞的YAML模板文件，用于安全测试和漏洞验证。这些模板遵循标准格式，便于在安全评估和渗透测试中使用。

## 目录

* [包含的漏洞](#包含的漏洞)
* [YAML模板结构](#yaml模板结构)
* [使用方法](#使用方法)
* [贡献指南](#贡献指南)
* [参考资料](#参考资料)
* [VulnDB](https://vulndb.cyberriskanalytics.com/)
* [Snyk Vulnerability DB](https://snyk.io/vulnerability-database/)

## 包含的漏洞

本目录包含以下漏洞的YAML模板：

| CVE/标识符 | 描述 | 严重性 |
|------------|------|--------|
| CVE-2016-10134 | PHPMailer 远程代码执行 | 高危 |
| CVE-2017-12149 | JBoss AS 6.x 反序列化漏洞 | 严重 |
| CVE-2017-12629 | Apache Solr 远程代码执行 | 严重 |
| CVE-2018-1000533 | Ruby on Rails 任意文件读取 | 中危 |
| CVE-2018-1000861 | Jenkins 远程代码执行 | 严重 |
| CVE-2018-17246 | Kibana 原型污染 | 高危 |
| CVE-2018-18925 | Node.js 目录遍历 | 中危 |
| CVE-2018-2894 | WebLogic 反序列化漏洞 | 严重 |
| CVE-2018-7600 | Drupal 远程代码执行 (Drupalgeddon2) | 严重 |
| CVE-2018-7602 | Drupal 远程代码执行 | 严重 |
| CVE-2019-10758 | MongoDB 注入漏洞 | 中危 |
| CVE-2020-16846 | SaltStack 命令注入 | 严重 |
| CVE-2021-21351 | Node.js 命令注入 | 高危 |
| CVE-2021-22911 | F5 BIG-IP 远程代码执行 | 严重 |
| CVE-2021-3129 | Laravel 远程代码执行 | 严重 |
| CVE-2022-22963 | Spring Cloud 远程代码执行 | 严重 |
| apache-solr-log4j-rce | Apache Solr Log4j 远程代码执行 | 严重 |
| fastjson-1-2-24-rce | Fastjson 1.2.24 反序列化漏洞 | 严重 |
| fastjson-1-2-47-rce | Fastjson 1.2.47 反序列化漏洞 | 严重 |
| hadoop-unauth-rce | Hadoop 未授权访问导致RCE | 严重 |
| thinkphp-509-information-disclosure | ThinkPHP 5.0.9 信息泄露 | 中危 |

## YAML模板结构

每个YAML文件通常包含以下部分：

```yaml
id: CVE-YYYY-XXXXX  # 漏洞标识符
info:
  name: 漏洞名称
  author: 发现者
  severity: 严重性 (critical/high/medium/low)
  description: 漏洞描述
  reference:
    - 参考链接1
    - 参考链接2
  tags: 标签1,标签2

requests:
  - method: 请求方法 (GET/POST等)
    path: 请求路径
    headers:
      Header1: 值1
    body: 请求体
    matchers:
      - type: 匹配器类型
        part: 匹配部分 (headers/body)
        words:
          - 匹配关键词1
          - 匹配关键词2
```

## 使用方法

1. **使用Nuclei扫描**
   ```bash
   nuclei -t CVE-2021-3129.yaml -u https://target.com
   ```

2. **手动测试**
   - 使用curl或Burp Suite发送请求
   - 根据响应判断漏洞是否存在

3. **批量扫描**
   ```bash
   nuclei -t ./ -l targets.txt
   ```

## 八、典型漏洞 YAML 文件分析

本漏洞库涵盖了各类常见的高危漏洞，以下对部分典型 YAML 文件进行详细解读，以展示不同漏洞的利用和检测原理。

### 1. CVE-2022-22963.yaml (Spring Cloud Function SpEL RCE)
- **漏洞类型**：表达式注入远程代码执行
- **漏洞原理**：
  Spring Cloud Function 在处理路由表达式时，使用了 Spring Expression Language (SpEL)。由于对用户提供的路由表达式 `spring.cloud.function.routing-expression` 未做严格过滤，攻击者可以构造恶意的 SpEL 表达式，该表达式会被后端执行，从而造成远程代码执行。
- **探测原理**：
  该 YAML 模板向 `/functionRouter` 接口发送一个 POST 请求，并在请求头中注入一个恶意的 SpEL 表达式：`T(java.net.InetAddress).getByName("{{interactsh-url}}")`。这个表达式会调用 Java 的 `InetAddress` 类来解析一个攻击者控制的 `interactsh-url`。如果 `interactsh` 服务器收到了来自目标服务器的 DNS 或 HTTP 请求，即可确认 SpEL 表达式被成功执行，漏洞存在。
- **修复建议**：升级 Spring Cloud Function 至 3.1.7 或 3.2.3 以上版本。

### 2. fastjson-1-2-47-rce.yaml (Fastjson 1.2.47 反序列化 RCE)
- **漏洞类型**：不安全的反序列化
- **漏洞原理**：
  Fastjson 在 1.2.47 及以前的版本中，由于开启了 `autoType` 功能且黑名单不完善，攻击者可以通过构造恶意的 JSON 数据来反序列化任意类。通过利用 `com.sun.rowset.JdbcRowSetImpl` 这个 "gadget"（利用链），攻击者可以指定一个恶意的 RMI 或 LDAP 服务地址。当 Fastjson 解析这段 JSON 时，会去连接该地址，从而触发 JNDI 注入，加载并执行远程服务器上的恶意代码。
- **探测原理**：
  该模板向目标发送一个包含 `JdbcRowSetImpl` gadget 的 JSON 请求。JSON 中的 `dataSourceName` 字段被设置为一个指向攻击者控制的 `interactsh` 服务器的 RMI 地址。如果目标服务器的 Fastjson 组件解析了这段 JSON 并尝试连接该 RMI 地址，`interactsh` 就会收到一个 DNS 请求，从而验证漏洞的存在。
- **修复建议**：升级 Fastjson 至最新版本，并关闭 `autoType` 功能，或配置安全的 `autoType` 白名单。

#### 总结
漏洞库中的模板是安全研究成果的结晶，它们揭示了各种软件和框架中存在的真实风险。分析这些模板有助于我们理解：
- **漏洞模式**：识别反复出现的漏洞类型，如反序列化、表达式注入等。
- **攻击向量**：了解攻击者如何通过 HTTP 请求头、请求体等不同位置注入恶意数据。
- **检测技术**：学习如何通过带外交互（OAST，如 `interactsh`）来探测那些没有明显回显的"盲"漏洞。


