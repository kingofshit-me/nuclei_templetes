# DNS 重绑定攻击 (DNS Rebinding)

> DNS重绑定是一种攻击技术，攻击者通过控制恶意域名的DNS解析，将其IP地址从攻击者控制的服务器更改为目标应用程序的IP地址，从而绕过浏览器的[同源策略](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)，使浏览器能够向目标应用程序发起任意请求并读取响应。

## DNS 重绑定攻击原理

DNS重绑定攻击是一种客户端攻击技术，它利用DNS解析机制和浏览器同源策略的特性，使恶意网站能够绕过安全限制，访问内部网络资源或本地服务。

### 漏洞成因

1. **DNS TTL 滥用**：
   - 攻击者设置极短的DNS TTL（生存时间）
   - 强制浏览器频繁重新解析域名
   - 在初始请求后更改IP地址解析

2. **同源策略绕过**：
   - 浏览器基于域名而非IP实施同源策略
   - 允许来自同一域名的脚本继续执行
   - 即使底层IP地址已更改

3. **内部服务暴露**：
   - 内部服务通常缺乏身份验证
   - 默认配置不安全
   - 通常监听在本地或内部网络

### 攻击面

- **内部网络服务**：路由器管理界面、内部API、数据库管理界面
- **本地服务**：本地开发服务器、管理控制台、IoT设备界面
- **云服务元数据**：云平台元数据服务(如AWS/Azure/GCP)
- **企业内网**：内部应用、管理接口、监控系统

### 影响

- 未授权访问内部服务
- 敏感信息泄露
- 内部网络探测
- 内部系统漏洞利用
- 横向移动攻击

## 目录

- [工具](#工具)
- [攻击方法](#攻击方法)
- [防护绕过技术](#防护绕过技术)
    - [0.0.0.0 绕过](#0000-绕过)
    - [CNAME 记录绕过](#cname-记录绕过)
    - [localhost 绕过](#localhost-绕过)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 工具

* [nccgroup/singularity](https://github.com/nccgroup/singularity) - DNS重绑定攻击框架
* [rebind.it](http://rebind.it/) - Singularity of Origin Web客户端
* [taviso/rbndr](https://github.com/taviso/rbndr) - 简单的DNS重绑定服务
* [taviso/rebinder](https://lock.cmpxchg8b.com/rebinder.html) - rbndr工具助手

## 攻击方法

**准备阶段**:

* 注册恶意域名（例如`malicious.com`）
* 配置自定义DNS服务器，能够将`malicious.com`解析为不同的IP地址

**初始受害者交互**:

* 在`malicious.com`上创建包含恶意JavaScript的网页
* 诱使受害者访问该恶意网页（例如通过钓鱼、社会工程或广告）

**初始DNS解析**:

* 当受害者的浏览器访问`malicious.com`时，会向攻击者的DNS服务器查询IP地址
* DNS服务器将`malicious.com`解析为一个初始的、看似合法的IP地址（例如203.0.113.1）

**重绑定到内部IP**:

* 在浏览器的初始请求后，攻击者的DNS服务器将`malicious.com`的解析更新为私有或内部IP地址（例如192.168.1.1，对应受害者的路由器或其他内部设备）

这通常通过为初始DNS响应设置非常短的TTL（生存时间）来实现，强制浏览器重新解析域名。

**同源利用**:

浏览器将后续响应视为来自同一来源（`malicious.com`）。

在受害者浏览器中运行的恶意JavaScript现在可以向内部IP地址或本地服务（例如192.168.1.1或127.0.0.1）发出请求，绕过同源策略限制。

**示例:**

1. 注册一个域名
2. [设置Singularity of Origin](https://github.com/nccgroup/singularity/wiki/Setup-and-Installation)
3. 根据需求编辑[autoattack HTML页面](https://github.com/nccgroup/singularity/blob/master/html/autoattack.html)
4. 访问`http://rebinder.your.domain:8080/autoattack.html`
5. 等待攻击完成（可能需要几秒到几分钟）

## 防护绕过技术

> 大多数DNS保护措施以在边界阻止包含不需要的IP地址的DNS响应的形式实现，当DNS响应进入内部网络时。最常见的保护形式是阻止RFC 1918中定义的私有IP地址（即10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）。一些工具还允许额外阻止本地主机（127.0.0.0/8）、本地（内部）网络或0.0.0.0/0网络范围。

在启用DNS保护的情况下（默认通常禁用），NCC Group记录了多种可以使用的[DNS保护绕过](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses)技术。

### 0.0.0.0 绕过

我们可以使用IP地址0.0.0.0来访问本地主机（127.0.0.1），以绕过阻止包含127.0.0.1或127.0.0.0/8的DNS响应的过滤器。

### CNAME 记录绕过

我们可以使用DNS CNAME记录来绕过阻止所有内部IP地址的DNS保护解决方案。
由于我们的响应只会返回内部服务器的CNAME，
过滤内部IP地址的规则将不会应用。
然后，本地内部DNS服务器将解析CNAME。

```bash
$ dig cname.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
cname.example.com.            381     IN      CNAME   target.local.
```

### localhost 绕过

我们可以使用"localhost"作为DNS CNAME记录来绕过阻止包含127.0.0.1的DNS响应的过滤器。

```bash
$ dig www.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
localhost.example.com.            381     IN      CNAME   localhost.
```

## 防御措施

1. **DNS层防护**：
   - 在边界防火墙阻止外部DNS响应包含内部IP地址
   - 强制使用内部DNS服务器
   - 限制DNS响应中的私有IP范围

2. **应用层防护**：
   - 实现适当的身份验证和授权
   - 使用CSRF令牌
   - 设置适当的CORS策略
   - 验证Host和Origin头

3. **网络隔离**：
   - 将敏感服务隔离到专用网络
   - 实施网络分段
   - 使用VPN访问内部资源

4. **浏览器安全**：
   - 使用现代浏览器（已实现DNS缓存锁定）
   - 考虑使用DNS-over-HTTPS (DoH) 或 DNS-over-TLS (DoT)
   - 禁用不必要的浏览器功能

5. **监控与日志**：
   - 监控异常的DNS查询模式
   - 记录和审查DNS查询日志
   - 设置入侵检测系统(IDS)规则

## 参考资料

* [DNS重绑定攻击如何工作？- nccgroup - 2019年4月9日](https://github.com/nccgroup/singularity/wiki/How-Do-DNS-Rebinding-Attacks-Work%3F)
* [OWASP: DNS重绑定](https://owasp.org/www-community/attacks/DNS_Rebinding)
* [PortSwigger: 绕过同源策略](https://portswigger.net/web-security/cors/same-origin-policy)
* [Cloudflare: 什么是DNS重绑定攻击](https://www.cloudflare.com/learning/dns/dns-rebinding/)
* [MITRE ATT&CK: T1071.004 - DNS](https://attack.mitre.org/techniques/T1071/004/)
