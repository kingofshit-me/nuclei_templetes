# HTTP 参数污染 (HTTP Parameter Pollution)

> HTTP 参数污染 (HPP) 是一种 Web 攻击规避技术，攻击者可以通过构造 HTTP 请求来操纵 Web 逻辑或获取隐藏信息。这种规避技术基于在多个同名参数之间分割攻击向量（?param1=value&param1=value）。由于没有统一的 HTTP 参数解析标准，不同的 Web 技术对同名 URL 参数的解析和读取方式各不相同。有些采用第一个出现的值，有些采用最后一个出现的值，还有一些将其作为数组读取。攻击者利用这种行为来绕过基于模式的安全机制。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [参数污染表](#参数污染表)
    * [参数污染有效载荷](#参数污染有效载荷)
* [参考资料](#参考资料)

## 工具

* **Burp Suite**：手动修改请求以测试重复参数。
* **OWASP ZAP**：拦截和操作 HTTP 参数。

## 方法学

HTTP 参数污染 (HPP) 是一种 Web 安全漏洞，攻击者在请求中注入多个相同 HTTP 参数的实例。服务器处理重复参数时的行为可能各不相同，可能导致意外或可利用的行为。

HPP 可以针对两个层面：

* 客户端 HPP：利用在客户端（浏览器）运行的 JavaScript 代码。
* 服务器端 HPP：利用服务器处理同名多个参数的方式。

**示例**：

```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```

### 参数污染表

当 ?par1=a&par1=b 时

| 技术/框架                                      | 解析结果                | 结果 (par1=)     |
| --------------------------------------------- | ----------------------- | ---------------- |
| ASP.NET/IIS                                   | 所有出现的值            | a,b              |
| ASP/IIS                                       | 所有出现的值            | a,b              |
| Golang net/http - `r.URL.Query().Get("param")` | 第一个出现的值          | a                |
| Golang net/http - `r.URL.Query()["param"]`     | 所有值作为数组          | ['a','b']        |
| IBM HTTP Server                               | 第一个出现的值          | a                |
| IBM Lotus Domino                              | 第一个出现的值          | a                |
| JSP, Servlet/Tomcat                           | 第一个出现的值          | a                |
| mod_wsgi (Python)/Apache                      | 第一个出现的值          | a                |
| Nodejs                                        | 所有出现的值            | a,b              |
| Perl CGI/Apache                               | 第一个出现的值          | a                |
| PHP/Apache                                    | 最后一个出现的值        | b                |
| PHP/Zeus                                      | 最后一个出现的值        | b                |
| Python Django                                 | 最后一个出现的值        | b                |
| Python Flask                                  | 第一个出现的值          | a                |
| Python/Zope                                   | 所有值作为数组          | ['a','b']        |
| Ruby on Rails                                 | 最后一个出现的值        | b                |

### 参数污染有效载荷

* 重复参数：

    ```ps1
    param=value1&param=value2
    ```

* 数组注入：

    ```ps1
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
    ```

* 编码注入：

    ```ps1
    param=value1%26other=value2
    ```

* 嵌套注入：

    ```ps1
    param[key1]=value1&param[key2]=value2
    ```

* JSON 注入：

    ```ps1
    {
        "test": "user",
        "test": "admin"
    }
    ```

## 参考资料

* [如何检测 HTTP 参数污染攻击 - Acunetix - 2024年1月9日](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
* [HTTP 参数污染 - Itamar Verta - 2023年12月20日](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
* [11分钟了解 HTTP 参数污染 - PwnFunction - 2019年1月28日](https://www.youtube.com/watch?v=QVZBl8yxVX0&ab_channel=PwnFunction)
