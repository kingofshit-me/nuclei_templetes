# 不安全的直接对象引用 (IDOR)

> 不安全的直接对象引用(IDOR)是一种安全漏洞，当应用程序允许用户基于用户提供的输入直接访问或修改对象（如文件、数据库记录或URL）时出现，且没有足够的访问控制。这意味着如果用户在URL或API请求中更改参数值（如ID），他们可能能够访问或修改他们未被授权查看或操作的数据。

## 目录

* [工具](#工具)
* [方法学](#方法学)
    * [数字值参数](#数字值参数)
    * [常见标识符参数](#常见标识符参数)
    * [弱伪随机数生成器](#弱伪随机数生成器)
    * [哈希参数](#哈希参数)
    * [通配符参数](#通配符参数)
    * [IDOR技巧](#idor技巧)
* [实验环境](#实验环境)
* [参考资料](#参考资料)

## 工具

* [PortSwigger/BApp 商店 > Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
* [PortSwigger/BApp 商店 > AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e)
* [PortSwigger/BApp 商店 > Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)

## 方法学

IDOR代表不安全的直接对象引用。当应用程序基于用户提供的输入直接提供对对象的访问时，就会出现这种类型的安全漏洞。因此，攻击者可以绕过授权直接访问系统中的资源，可能导致未经授权的信息泄露、修改或删除。

**IDOR示例**:

想象一个允许用户通过点击链接`https://example.com/profile?user_id=123`查看个人资料的Web应用程序：

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```

在这里，`user_id=123`是对特定用户个人资料的直接引用。如果应用程序没有正确检查登录用户是否有权查看与`user_id=123`关联的个人资料，攻击者可以简单地更改`user_id`参数来查看其他用户的个人资料：

```ps1
https://example.com/profile?user_id=124
```

![IDOR示意图](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/Images/idor.png)

### 数字值参数

递增和递减这些值以访问敏感信息。

* 十进制值: `287789`, `287790`, `287791`, ...
* 十六进制: `0x4642d`, `0x4642e`, `0x4642f`, ...
* Unix时间戳: `1695574808`, `1695575098`, ...

**示例**:

* [HackerOne - 通过IDOR查看用户订单信息 - meals](https://hackerone.com/reports/287789)
* [HackerOne - 通过IDOR删除消息 - naaash](https://hackerone.com/reports/697412)

### 常见标识符参数

一些标识符可以被猜测，如姓名和电子邮件，它们可能会让您访问客户数据。

* 姓名: `john`, `doe`, `john.doe`, ...
* 电子邮件: `john.doe@mail.com`
* Base64编码值: `am9obi5kb2VAbWFpbC5jb20=`

**示例**:

* [HackerOne - 不安全的直接对象引用(IDOR) - 删除活动 - datph4m](https://hackerone.com/reports/1969141)

### 弱伪随机数生成器

* 如果知道创建时间，可以预测UUID/GUID v1: `95f6e264-bb00-11ec-8833-00155d01ef00`
* MongoDB对象ID以可预测的方式生成: `5ae9b90a2c144b9def01ec37`
    * 4字节值，表示自Unix纪元以来的秒数
    * 3字节机器标识符
    * 2字节进程ID
    * 3字节计数器，从随机值开始

**示例**:

* [HackerOne - 允许通过IDOR读取社交媒体广告服务中另一个用户令牌的漏洞 - a_d_a_m](https://hackerone.com/reports/1464168)
* [通过MongoDB对象ID预测实现IDOR](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)

### 哈希参数

有时我们看到网站使用哈希值来生成随机用户ID或令牌，如`sha1(username)`、`md5(email)`等。

* MD5: `098f6bcd4621d373cade4e832627b4f6`
* SHA1: `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
* SHA2: `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**示例**:

* [具有可预测HMAC生成的IDOR - DiceCTF 2022 - CryptoCat](https://youtu.be/Og5_5tEg6M0)

### 通配符参数

发送通配符(`*`、`%`、`.`、`_`)而不是ID，某些后端可能会返回所有用户的数据。

* `GET /api/users/* HTTP/1.1`
* `GET /api/users/% HTTP/1.1`
* `GET /api/users/_ HTTP/1.1`
* `GET /api/users/. HTTP/1.1`

### IDOR技巧

* 更改HTTP请求方法: `POST → PUT`
* 更改内容类型: `XML → JSON`
* 将数值转换为数组: `{"id":19} → {"id":[19]}`
* 使用参数污染: `user_id=hacker_id&user_id=victim_id`

## 实验环境

* [PortSwigger - 不安全的直接对象引用](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

## 参考资料

* [从区块链中的圣诞礼物到巨额漏洞赏金 - Jesse Lakerveld - 2018年3月21日](http://web.archive.org/web/20180401130129/https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)
* [如何：寻找不安全的直接对象引用(IDOR)漏洞以获取高额赏金 - Sam Houton - 2017年11月9日](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
* [寻找不安全的直接对象引用漏洞的乐趣与收益（第1部分） - Mohammed Abdul Raheem - 2018年2月2日](https://codeburst.io/hunting-insecure-direct-object-reference-vulnerabilities-for-fun-and-profit-part-1-f338c6a52782)
* [IDOR - 如何预测标识符？漏洞赏金案例研究 - Bug Bounty Reports Explained - 2023年9月21日](https://youtu.be/wx5TwS0Dres)
* [不安全的直接对象引用防护速查表 - OWASP - 2023年7月31日](https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
* [不安全的直接对象引用(IDOR) - PortSwigger - 2019年12月25日](https://portswigger.net/web-security/access-control/idor)
* [测试IDOR - PortSwigger - 2024年10月29日](https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls/testing-for-idors)
* [测试不安全的直接对象引用(OTG-AUTHZ-004) - OWASP - 2014年8月8日](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [IDOR的兴起 - HackerOne - 2021年4月2日](https://www.hackerone.com/company-news/rise-idor)
* [从网页到应用手机通知的IDOR漏洞可查看所有人的Airbnb消息 - Brett Buerhaus - 2017年3月31日](http://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/)

---

*最后更新: 2025年6月*
