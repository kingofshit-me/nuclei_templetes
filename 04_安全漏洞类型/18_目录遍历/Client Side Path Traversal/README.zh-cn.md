# 客户端路径遍历 (Client Side Path Traversal)

> 客户端路径遍历（Client-Side Path Traversal，CSPT），有时也被称为"站内请求伪造"，是一种可被利用于CSRF或XSS攻击的漏洞。
> 它利用了客户端使用fetch函数向URL发起请求的能力，其中可以注入多个"../"字符。在规范化处理后，这些字符会将请求重定向到不同的URL，可能导致安全漏洞。
> 由于每个请求都是从应用程序的前端发起的，浏览器会自动包含cookie和其他认证机制，使得这些认证信息在攻击中可被利用。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [CSPT 转 XSS](#cspt-转-xss)
    * [CSPT 转 CSRF](#cspt-转-csrf)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [doyensec/CSPTBurpExtension](https://github.com/doyensec/CSPTBurpExtension) - 用于发现和利用客户端路径遍历的开源Burp Suite扩展。

## 方法学

### CSPT 转 XSS

![cspt-query-param](https://matanber.com/images/blog/cspt-query-param.png)

一个后置服务页面调用fetch函数，向一个URL发送请求，该URL的路径中包含攻击者可控的输入，但没有进行适当的编码，允许攻击者在路径中注入`../`序列，使请求被发送到任意端点。这种行为被称为CSPT漏洞。

**示例**:

* 页面 `https://example.com/static/cms/news.html` 接收一个 `newsitemid` 参数
* 然后获取 `https://example.com/newitems/<newsitemid>` 的内容
* 在 `https://example.com/pricing/default.js` 中通过 `cb` 参数发现文本注入漏洞
* 最终有效载荷为 `https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//`

### CSPT 转 CSRF

CSPT可以重定向合法的HTTP请求，允许前端为API调用添加必要的令牌，如认证令牌或CSRF令牌。这种能力可能被利用来绕过现有的CSRF防护措施。

|                                             | CSRF               | CSPT2CSRF          |
| ------------------------------------------- | -----------------  | ------------------ |
| 支持POST CSRF ?                             | :white_check_mark: | :white_check_mark: |
| 可以控制请求体 ?                            | :white_check_mark: | :x:                |
| 可以绕过反CSRF令牌 ?                        | :x:                | :white_check_mark: |
| 可以绕过Samesite=Lax ?                      | :x:                | :white_check_mark: |
| 支持GET/PATCH/PUT/DELETE CSRF ?             | :x:                | :white_check_mark: |
| 支持1-click CSRF ?                         | :x:                | :white_check_mark: |
| 影响是否取决于源和接收端 ?                 | :x:                | :white_check_mark: |

实际案例:

* Rocket.Chat中的1-click CSPT2CSRF
* CVE-2023-45316: Mattermost中的POST接收端CSPT2CSRF: `/<team>/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate`
* CVE-2023-6458: Mattermost中的GET接收端CSPT2CSRF
* [Client Side Path Manipulation - erasec.be](https://www.erasec.be/blog/client-side-path-manipulation/): CSPT2CSRF `https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=`
* [CVE-2023-5123 : Grafana JSON API插件中的CSPT2CSRF](https://medium.com/@maxime.escourbiac/grafana-cve-2023-5123-write-up-74e1be7ef652)

## 实验环境

* [doyensec/CSPTPlayground](https://github.com/doyensec/CSPTPlayground) - 用于发现和利用客户端路径遍历(CSPT)的开源实验环境。
* [Root Me - CSPT - The Ruler](https://www.root-me.org/en/Challenges/Web-Client/CSPT-The-Ruler)

## 参考资料

* [利用客户端路径遍历执行跨站请求伪造 - 引入CSPT2CSRF - Maxence Schmitt - 2024年7月2日](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)
* [利用客户端路径遍历 - CSRF已死，CSRF永存 - 白皮书 - Maxence Schmitt - 2024年7月2日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf)
* [利用客户端路径遍历 - CSRF已死，CSRF永存 - OWASP Global AppSec 2024 - Maxence Schmitt - 2024年6月24日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_OWASP_Appsec_Lisbon.pdf)
* [利用CVE-2023-39968、CVE-2024-22421和Chromium漏洞泄露Jupyter实例认证令牌 - Davwwwx - 2023年8月30日](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/)
* [站内请求伪造 - Dafydd Stuttard - 2007年5月3日](https://portswigger.net/blog/on-site-request-forgery)
* [使用编码级别绕过WAF利用CSPT - Matan Berson - 2024年5月10日](https://matanber.com/blog/cspt-levels)
* [自动化客户端路径遍历发现 - Vitor Falcao - 2024年10月3日](https://vitorfalcao.com/posts/automating-cspt-discovery/)
* [用Eval Villain方式实现CSPT! - Dennis Goodlett - 2024年12月3日](https://blog.doyensec.com/2024/12/03/cspt-with-eval-villain.html)
* [绕过文件上传限制利用客户端路径遍历 - Maxence Schmitt - 2025年1月9日](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)

---

*最后更新: 2025年6月*
