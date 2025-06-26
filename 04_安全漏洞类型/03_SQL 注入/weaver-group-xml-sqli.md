# 泛微OA E-Office group_xml.php SQL注入漏洞探测原理说明

## 1. 漏洞简介

泛微OA E-Office的group_xml.php文件存在SQL注入漏洞。攻击者可通过该漏洞写入Webshell，获取服务器权限。

## 2. 影响范围

- 受影响产品：泛微OA E-Office（具体版本以官方公告为准）
- 只要未修复该漏洞的系统均可能被利用

## 3. 漏洞原理

该漏洞源于group_xml.php文件对par参数未做有效过滤，攻击者可注入SQL语句，利用`into outfile`写入Webshell。

## 4. 利用方式与攻击流程

1. 攻击者构造带有SQL注入payload的GET请求，par参数为base64编码的注入语句。
2. 数据库执行恶意SQL，将Webshell写入服务器指定目录。
3. 攻击者访问Webshell，获取服务器权限。

## 5. 探测原理与流程（yaml 规则详细说明）

该yaml规则通过注入特征payload并检测Webshell回显进行无害化探测，流程如下：

### 5.1 探测请求的构造

- 第一步：发送GET请求，par参数为base64编码的SQL注入payload，尝试写入Webshell。
- 第二步：访问写入的Webshell文件，检测特征内容。

  ```
  GET /inc/group_user_list/group_xml.php?par=<base64_payload> HTTP/1.1
  Host: <目标主机>
  Content-Type: application/x-www-form-urlencoded

  GET /<filename>.php HTTP/1.1
  Host: <目标主机>
  ```
  - <filename>为随机生成，payload内容会写入特征字符串的Webshell。

### 5.2 预期响应与交互

- **HTTP响应内容**：
  - 第二步响应体需包含Webshell特征内容（如md5(string)值）。
  - HTTP状态码为200。

### 5.3 判定逻辑

- 只有当：
  1. 第二步响应体中包含md5(string)值，
  2. 状态码为200，
  才判定目标存在SQL注入漏洞。

- **判定流程伪代码**：
  ```pseudo
  payload = base64("[group]:[1]|[groupid]:[1 union select '<?php echo md5(\"string\");unlink(__FILE__);?>',... into outfile '../webroot/filename.php']")
  发送GET /inc/group_user_list/group_xml.php?par=payload
  发送GET /filename.php
  若响应体含md5(string)，且状态码为200：
      判定目标存在SQL注入漏洞
  ```

- **流程图**：
  ```mermaid
  graph TD
      A[发送带payload的GET请求到group_xml.php] --> B[访问写入的Webshell]
      B --> C{响应体含md5(string)?}
      C -- 否 --> F[无漏洞或未触发]
      C -- 是 --> D{状态码为200?}
      D -- 否 --> F
      D -- 是 --> E[判定目标存在SQL注入漏洞]
  ```

通过上述流程，既保证了探测的准确性，也避免了对目标系统的实际危害。

## 6. 参考链接

- [PeiQi-WIKI漏洞分析](http://wiki.peiqi.tech/wiki/oa/泛微OA/泛微OA%20E-Office%20group_xml.php%20SQL注入漏洞.html)
- [PeiQi-WIKI-Book](https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Office%20group_xml.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md) 