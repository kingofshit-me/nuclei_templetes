# 帐号劫持漏洞集合

> 本目录包含多个关键性的帐号劫持（Account Takeover）漏洞检测模板，这些漏洞可能允许攻击者未经授权访问用户账户，甚至完全控制系统。

## 目录

- [漏洞概述](#漏洞概述)
- [漏洞列表](#漏洞列表)
- [检测方法](#检测方法)
- [影响分析](#影响分析)
- [缓解措施](#缓解措施)
- [参考资源](#参考资源)
- [免责声明](#免责声明)

## 漏洞概述

帐号劫持（Account Takeover, ATO）是指攻击者未经授权获取对用户账户的访问权限。本目录收集了多个影响不同系统的关键帐号劫持漏洞，这些漏洞通常由以下原因导致：

- 密码重置机制缺陷
- 弱随机数生成
- 会话管理问题
- 认证绕过漏洞
- 不安全的直接对象引用(IDOR)

## 漏洞列表

### 1. [CVE-2024-20419](CVE-2024-20419.yaml) - Cisco SSM On-Prem 密码重置漏洞

**严重程度**：严重 (CVSS: 10.0)

**影响版本**：Cisco Smart Software Manager On-Prem (SSM On-Prem) ≤ 8-202206

**漏洞描述**：
Cisco SSM On-Prem 认证系统中的漏洞允许未经身份验证的远程攻击者重置任何用户（包括管理员）的密码。

**影响**：
- 攻击者可以获取对Web UI或API的完全访问权限
- 可能导致敏感信息泄露
- 可能完全控制系统

**参考**：
- [Cisco 安全公告](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy)
- [NVD 详情](https://nvd.nist.gov/vuln/detail/CVE-2024-20419)

### 2. [CVE-2024-23163](CVE-2024-23163.yaml) - GestSup 账户劫持漏洞

**严重程度**：严重 (CVSS: 9.8)

**影响版本**：所有版本（截至漏洞发现时）

**漏洞描述**：
GestSup 工单系统中的认证绕过漏洞，允许攻击者通过修改用户邮箱并请求密码重置来获取管理员权限。

**影响**：
- 未授权账户接管
- 敏感数据访问
- 系统配置修改

**参考**：
- [Synacktiv 安全公告](https://www.synacktiv.com/advisories/multiple-vulnerabilities-on-gestsup-3244)
- [CVE 详情](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-23163)

### 3. [CVE-2024-29868](CVE-2024-29868.yaml) - Apache StreamPipes 弱随机数生成漏洞

**严重程度**：严重 (CVSS: 待定)

**影响版本**：Apache StreamPipes 0.69.0 至 0.93.0

**漏洞描述**：
Apache StreamPipes 在恢复令牌生成机制中使用了密码学上不安全的伪随机数生成器(PRNG)，使得攻击者可以预测所有过去和未来的令牌。

**影响**：
- 账户接管
- 未授权数据访问
- 系统完整性破坏

**参考**：
- [Apache 邮件列表公告](https://lists.apache.org/thread/g7t7zctvq2fysrw1x17flnc12592nhx7)
- [NVD 详情](https://nvd.nist.gov/vuln/detail/CVE-2024-29868)

## 检测方法

### 自动检测

使用 Nuclei 工具进行批量检测：

```bash
# 检测单个目标
nuclei -t CVE-2024-20419.yaml -u https://target.com

# 批量检测目标列表
nuclei -l targets.txt -t ./
```

### 手动验证

1. **Cisco SSM On-Prem**
   - 检查目标是否运行受影响的版本
   - 尝试访问密码重置功能
   - 验证是否可以绕过认证

2. **GestSup**
   - 查找 GestSup 安装
   - 检查 `/ajax/ticket_user_db.php` 端点
   - 验证参数修改是否导致权限提升

3. **Apache StreamPipes**
   - 确认 StreamPipes 版本
   - 检查恢复令牌生成机制
   - 验证令牌是否可预测

## 影响分析

### 业务影响

- **数据泄露**：敏感业务数据可能被未授权访问
- **服务中断**：攻击者可能修改或删除关键数据
- **合规风险**：可能导致违反数据保护法规
- **声誉损害**：客户信任度下降

### 技术影响

- **权限提升**：普通用户可能获得管理员权限
- **持久访问**：攻击者可能建立持久后门
- **横向移动**：可能用于网络内部横向移动

## 缓解措施

### 通用建议

1. **及时更新**：应用供应商提供的最新安全补丁
2. **强化认证**：实施多因素认证(MFA)
3. **监控日志**：监控异常登录和密码重置活动
4. **最小权限**：遵循最小权限原则

### 特定修复

- **Cisco SSM On-Prem**：升级到最新版本并应用Cisco安全公告中的修复
- **GestSup**：应用供应商提供的最新补丁或临时缓解措施
- **Apache StreamPipes**：升级到0.95.0或更高版本

## 参考资源

### 工具

- [Nuclei](https://github.com/projectdiscovery/nuclei) - 漏洞扫描工具
- [Burp Suite](https://portswigger.net/burp) - Web应用安全测试工具
- [OWASP ZAP](https://www.zaproxy.org/) - 开源Web应用安全扫描器

### 学习资源

- [OWASP 帐号劫持防御指南](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK - 账户劫持](https://attack.mitre.org/techniques/T1199/)
- [CISA 账户劫持防护指南](https://www.cisa.gov/secure-our-digital-future/account-takeover)

