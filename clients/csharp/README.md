# CardKey.Client C# 示例

这是一个只依赖现代 .NET BCL 的 CardKey API v1 客户端示例，目标框架为 `net8.0`。示例覆盖：

- `POST /api/v1/verify`
- `POST /api/v1/activate`
- `POST /api/v1/consume`
- `POST /api/v1/query`
- `POST /api/v1/unbind`
- HMAC-SHA256 v1 请求签名和响应验签
- RFC5869 HKDF-SHA256 + AES-256-GCM 卡密传输加密
- 统一响应模型、错误码和不泄露敏感信息的异常

## 目录

- `src/`：可复用客户端库源码。
- `sample/`：控制台入口和占位配置。
- `tests/`：无外部测试包的固定向量测试入口。

## 快速开始

```powershell
dotnet run --project .\CardKey.Client.csproj -- sample
# 只运行本地固定向量测试
dotnet run --project .\CardKey.Client.csproj -- vectors
```

当前示例项目的入口在 `sample/Program.cs`，因为它与库源码共用一个轻量项目，便于复制到已有 .NET 8 项目。生产集成时可只复制 `src/` 并按需引用 `CardKeyClient`。

## 配置

复制 `sample/appsettings.example.json` 到受保护的位置，通过环境变量或宿主机密钥存储注入：

- `BaseUrl`：例如 `https://example.invalid`，不要在生产环境使用 HTTP。
- `AppId`：占位值，不是真实 AppID。
- `AppSecret`：占位值；不要提交、打印、写入 URL、异常、崩溃报告或普通配置文件。

不要把真实卡密写在源码、固定向量或日志中。示例中的固定向量使用人工构造的非生产字符串，仅用于验证字节级协议兼容性。

## 协议要点

请求原始 body 必须先编码为 UTF-8，再把同一字节数组交给 `HttpContent`。请求签名 canonical string 为：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(raw_body)
```

签名是 ASCII AppSecret 作为 HMAC-SHA256 key 的小写十六进制摘要。路径不包含域名、查询字符串或 fragment。每次请求都生成新的 Unix 秒时间戳、密码学随机 nonce 和签名；超时后不要复用同一 nonce。

响应验签必须在 JSON 解析前使用 HTTP 返回的 raw body 字节，canonical string 为：

```text
X-Response-Timestamp\n原请求 nonce\nSHA256_HEX(raw_response_body)
```

中间件拒绝、参数校验和解密异常可能没有响应签名。`CardKeyClient` 对带有签名头的响应强制验签；缺少签名头时只返回未验签结果并在 `IsResponseSigned` 标识，调用方必须根据部署策略决定是否接受。若只允许已签名响应，请使用 `RequireSignedResponses = true`。

## 卡密传输加密

```text
key = HKDF-SHA256(IKM=AppSecret, salt=AppID,
                  info="cardkey-enc-v1", L=32)
AES-256-GCM(key, random 12-byte IV, AAD=AppID)
```

JSON 载荷为 `iv`、`data`、`tag` 的 Base64 字段。`.NET AesGcm` 的 `Encrypt`/`Decrypt` 使用分离的 16 字节 tag。绝不复用同一 key+IV；认证失败必须拒绝明文。

## API 入参

```csharp
await client.VerifyAsync(new VerifyRequest { CardKey = "...", DeviceId = "device-001" });
await client.ActivateAsync(new ActivateRequest { CardKey = "..." });
await client.ConsumeAsync(new ConsumeRequest { CardKey = "...", Count = 1 });
await client.QueryAsync(new QueryRequest { CardKey = "...", DeviceId = "device-001" });
await client.UnbindAsync(new UnbindRequest { CardKey = "...", DeviceId = "device-001", Force = false });
```

若服务端启用强制密文卡密，使用 `CardKeyTransportCrypto.EncryptCardKey` 的结果作为 `CardKey` 对象，而不是明文字符串。`JsonSerializer` 选项固定为 camelCase；序列化结果必须保持不变直到发送。

## 错误处理与日志

- 同时检查 HTTP 状态、响应 `code` 和 `success`；部分业务错误会以 HTTP 200 返回。
- `ApiException` 只携带状态码、业务码和服务端消息，不把 AppSecret、卡密、完整请求体或响应体放入异常文本。
- 默认日志只记录 endpoint、HTTP 状态、业务码和请求 nonce 的哈希前缀；不会记录 nonce 原文、签名、请求/响应 body 或凭据。
- `consume` 没有服务端幂等键。网络超时后不要盲目重试，否则可能重复扣次。

## 安全边界

这个 C# 示例适用于受控服务端、桌面工具或测试程序。若把 AppSecret 编译进公开客户端，它可以被提取，攻击者即可伪造请求；它不适合作为高信任客户端认证。公开客户端应改为调用受保护的后端代理，或为低信任场景设计短期、最小权限凭据。

## 验证限制

本目录的 `vectors` 测试不需要网络或真实凭据，只能证明客户端本地实现与协议固定向量一致。完整联调需要一个已启用的 CardKey API 应用、测试卡密和 HTTPS 服务端；不要使用仓库外的本地凭据填入示例文件。
