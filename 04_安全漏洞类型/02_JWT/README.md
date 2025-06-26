JWT（JSON Web Token）学习文档

一、什么是 JWT？

JWT，全称 JSON Web Token，是一种开放标准（RFC 7519），用于在网络应用环境中作为用户身份验证和信息交换的令牌。

JWT 由三部分组成：
	1.	Header（头部）
	2.	Payload（载荷）
	3.	Signature（签名）

通常结构为：xxxxx.yyyyy.zzzzz

⸻

二、JWT 的结构
	1.	Header（头部）

描述该 JWT 的元数据，一般包括类型（typ）和签名算法（alg）：
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
	2.	Payload（载荷）

包含实际传输的数据，可以是用户信息、自定义字段、权限等。

例如：
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 15162390ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo22
}
```
注意：不要在 Payload 中放置敏感信息，因为它是可以被解码查看的！
	3.	Signature（签名）

使用指定算法对 Header 和 Payload 进行签名，防止数据被篡改。

签名生成方式：
```json
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```
三、JWT 的使用场景
	1.	身份验证（Authentication）
	•	用户登录后，服务器生成 JWT 返回给客户端，客户端后续请求都携带 JWT。
	•	服务器通过验证 JWT 来判断请求身份。
	2.	授权（Authorization）
	•	根据 JWT 中的角色或权限字段控制访问权限。
	3.	信息交换
iui	双方之间以 JWT 的方式交换数据，可携带额外字段如 token 过期时间、签发方等。
四、JWT 的优点与缺点

优点：
	•	跨平台，基于标准，兼容性强
	•	无状态，服务器无需存储 session 数据
	•	传输高效，结构清晰，易于前后端分离

缺点：
	•	无法主动注销，无法轻易撤销已签发的 token
	•	长时间有效的 token 存在被窃取风险
	•	token 长度比传统 session ID 长，占带宽
五、JWT 安全注意事项
	1.	使用 HTTPS 传输，防止 token 被中间人攻击
	2.	设置合理的过期时间（exp）
	3.	不要在 Payload 中放敏感信息（如密码、身份证号）
	4.	使用强壮的签名密钥（secret）
	5.	对签名部分进行验证，避免算法绕过漏洞（如"alg: none"）
	6.	可引入 token 黑名单机制，用于强制注销
七、JWT 示例
	1.	登录阶段：

客户端发送账号密码
服务器验证通过后，返回 JWT：
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJ1c2VySWQiOiIxMjMiLCJpYXQiOjE2MjY1NzAzNDIsImV4cCI6MTYyNjU3Mzk0Mn0
.tF92dN-lUoKmBBT3GtrZlCxn4VZ5GQfXtYKRYixGBRM
```

```
Authorization: Bearer <token>
```
八、常见 JWT 攻击与防护
	1.	算法混淆攻击
如使用 alg: none 绕过签名校验（应禁用该算法）
	2.	暴力破解签名密钥
使用弱密钥易被爆破，应使用高强度 secret，并可考虑使用 RSA 公私钥机制
	3.	Replay 攻击
限制 JWT 有效期，并配合使用 CSRF Token 或 Token Rotation 技术

⸻

九、相关工具与库
	•	JWT.io（在线编码/解码工具）
https://jwt.io
	•	后端常用库：
	•	Java: jjwt、nimbus-jose-jwt
	•	Python: PyJWT
	•	Node.js: jsonwebtoken
	•	Go: golang-jwt

⸻

