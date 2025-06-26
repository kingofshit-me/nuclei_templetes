JWT（JSON Web Token）学习文档

一、什么是 JWT？

JWT，全称 JSON Web Token，是一种开放标准（RFC 7519），用于在网络应用环境中作为用户身份验证和信息交换的令牌。

JWT 由三部分组成：
	1.	Header（头部）
	2.	Payload（载荷）
	3.	Signature（签名）

二、JWT 的结构

1. Header（头部）
通常由两部分组成：
- 令牌的类型（即 JWT）
- 签名算法，如 HMAC SHA256 或 RSA

示例：
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

2. Payload（载荷）
包含声明（claims），即关于实体（通常是用户）和附加数据的声明。声明有三种类型：
- 注册声明（Registered claims）
- 公共声明（Public claims）
- 私有声明（Private claims）

示例：
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

3. Signature（签名）
使用编码后的 header、编码后的 payload、一个密钥（secret）和 header 中指定的算法来创建签名。

三、JWT 的工作流程

1. 用户使用凭据登录
2. 服务器验证凭据
3. 服务器创建一个 JWT 并发送给客户端
4. 客户端存储 JWT（通常在本地存储中）
5. 客户端在每个后续请求中包含 JWT
6. 服务器验证 JWT 并响应请求

四、JWT 的安全考虑

1. 敏感信息：不要在 JWT 中存储敏感信息
2. 令牌过期：始终设置合理的过期时间
3. HTTPS：始终使用 HTTPS 传输 JWT
4. 存储安全：安全地存储 JWT（HttpOnly, Secure, SameSite 标志）
5. 密钥管理：安全地管理签名密钥

五、JWT 的实现

以下是一个使用 Node.js 实现 JWT 的简单示例：

```javascript
const jwt = require('jsonwebtoken');

// 创建 token
const token = jwt.sign(
  { user_id: 12345 },
  'your-secret-key',
  { expiresIn: '24h' }
);

// 验证 token
try {
  const decoded = jwt.verify(token, 'your-secret-key');
  console.log(decoded);
} catch (err) {
  console.error('Token 验证失败:', err);
}
```

六、JWT 的优缺点

优点：
- 无状态，服务器不需要存储会话信息
- 跨域友好
- 可以包含自定义声明
- 适合分布式系统

缺点：
- 令牌一旦签发，在过期前无法撤销
- 如果被盗用，攻击者可以冒充用户
- 需要仔细处理密钥和签名

七、JWT 最佳实践

1. 使用强密钥
2. 设置合理的过期时间
3. 使用 HTTPS
4. 避免在 URL 中传递 JWT
5. 实现令牌刷新机制
6. 考虑使用短期访问令牌和长期刷新令牌

## 八、典型漏洞 YAML 文件分析

本目录下收录了与 JWT 相关的安全漏洞利用模板，以下对典型 YAML 文件进行详细解读：

### 1. nacos-authentication-bypass.yaml
- **漏洞类型**：JWT 认证绕过
- **漏洞原理**：
  Nacos < 2.2.0 版本中，JWT 密钥（secret）为默认值，攻击者可伪造合法的 JWT Token，绕过认证机制，获取敏感接口权限。
- **探测原理**：
  该 YAML 模板通过构造默认密钥签发的 JWT Token，访问 `/nacos/v1/auth/users` 等接口，若返回包含用户名和密码等敏感信息，且状态码为 200，则判定存在认证绕过漏洞。
- **修复建议**：修改配置文件中的 JWT secret，避免使用默认密钥。

---

#### 总结
JWT 相关漏洞常见于密钥管理不当、算法配置不安全等场景。攻击者可利用弱密钥、默认密钥或算法绕过等手段伪造 Token，进而绕过认证或提升权限。防御措施包括：
- 使用强随机密钥并定期更换
- 禁用不安全算法（如 none）
- 对 Token 进行有效期和黑名单管理
- 严格校验 Token 签名和载荷内容
