# CI/CD 与 DevOps 安全模板说明

本目录聚焦于 CI/CD、DevOps 及云原生基础设施的安全风险，涵盖 Jenkins、GitLab CI、TeamCity、Travis CI、Drone 及 Kubernetes 等主流平台。以下重点介绍 Kubernetes 相关的典型风险，其余平台仅做简要说明。

---

## 重点案例：Kubernetes Pods API 未授权访问

**模板文件**：`kubernetes-pods-api.yaml`

### 漏洞简介

Kubernetes 集群的 API Server 若未正确配置认证与授权，攻击者可直接访问 `/api/v1/pods` 等接口，获取集群中所有 Pod 的详细信息。这不仅泄露了容器部署、镜像、环境变量等敏感数据，还可能暴露凭据、密钥等核心资产，为进一步攻击（如横向移动、权限提升）提供条件。

### 漏洞原理

Kubernetes API Server 是集群的核心控制组件，负责所有资源的管理和调度。若 API Server 暴露在公网或内网且未启用认证/授权，任何人都可以通过 HTTP 请求访问其 RESTful API，读取、修改甚至删除集群资源。  
`/api/v1/pods` 接口返回所有命名空间下的 Pod 信息，包括容器镜像、挂载卷、环境变量、服务账户等，极易造成敏感信息泄露。

### 检测逻辑（YAML内容解析）

```yaml
id: kubernetes-pods-api

info:
  name: Kubernetes Pods API 未授权访问
  description: 检测 Kubernetes API Server 是否存在未授权访问 /api/v1/pods 接口的风险
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/pods"
    matchers:
      - type: word
        part: body
        words:
          - "kind"
          - "items"
          - "metadata"
```

- 直接向 `/api/v1/pods` 发起 GET 请求。
- 若响应体中包含 `kind`、`items`、`metadata` 等关键字段，说明接口未做访问控制，存在未授权访问风险。

### 修复建议

- 启用并强制 API Server 认证与授权，禁止匿名访问。
- 限制 API Server 的网络暴露，仅允许可信网络或 VPN 访问。
- 定期审计 RBAC 策略，最小化权限分配。

---

## 其他平台模板

- **Jenkins 未授权脚本执行**：检测 Jenkins `/script` 接口是否可直接执行 Groovy 脚本，建议启用认证与权限控制。
- **GitLab CI Runner 注册泄露**：检测 Runner 注册接口是否对外开放，建议关闭公开注册并定期更换 token。
- **TeamCity 未授权接口访问**：检测敏感 REST API 是否可匿名访问，建议关闭匿名访问并强化权限配置。

---
