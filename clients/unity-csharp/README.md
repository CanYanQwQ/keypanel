# CardKey API v1 Unity C# 示例

这是一个不依赖第三方 JSON/HTTP 包的 Unity 客户端示例，使用：

- `UnityWebRequest` 发送五个 POST API 请求；
- `System.Security.Cryptography` 完成 HMAC-SHA256、HKDF-SHA256 和 AES-GCM；
- Unity Test Framework Editor 测试固定协议向量。

覆盖端点：`verify`、`activate`、`consume`、`query`、`unbind`。

## 目录

- `Runtime/`：运行时库和 `CardKey.Runtime.asmdef`；复制到 Unity 项目的 `Assets/CardKey/Runtime/`。
- `Tests/Editor/`：固定向量和请求模型测试、Editor asmdef；复制到 `Assets/CardKey/Tests/Editor/`，项目需启用 Test Framework。
- `Samples/`：最小 MonoBehaviour 使用入口和独立 asmdef。

## 兼容性和 AES-GCM 依赖

Unity 运行时是否可用 `AesGcm` 取决于 Unity 版本、目标平台和 IL2CPP/.NET 配置。此示例默认要求目标运行时提供现代 .NET 的 `System.Security.Cryptography.AesGcm` 与 `HKDF` API；在不提供这些 API 的旧 Unity/平台组合中，必须接入经过维护和审计的密码学插件（例如平台原生 CNG/CommonCrypto/Android Keystore 封装），不能自行补写“简化版 AES-GCM”。

请在目标平台上实际构建并运行 `CardKeyProtocolTests`，不要只依赖 Editor 通过。若平台不支持 API，构建应明确失败或由项目配置禁用该样例，而不是静默回退到明文或非认证加密。

## 配置和安全边界

`Samples/CardKeySampleConfig.cs` 只有占位配置。不要把真实 AppSecret 写入 `Resources`、StreamingAssets、PlayerPrefs、Inspector 资产、日志、崩溃报告或公开仓库。Unity 游戏包中的 AppSecret 可被提取，因此不适合作为高信任客户端：攻击者可以恢复 secret 并伪造请求。正式游戏应使用受保护的后端代理或低权限、短期凭据。

生产必须使用 HTTPS，并在平台层配置证书校验/合适的 TLS 策略。不要为了绕过开发证书问题全局关闭证书验证。

## 使用示例

```csharp
var config = new CardKeyClientOptions
{
    BaseUrl = new Uri("https://example.invalid"),
    AppId = "REPLACE_WITH_APP_ID",
    AppSecret = "REPLACE_WITH_APP_SECRET",
    RequireSignedResponses = true,
};

var client = new CardKeyClient(config);
var result = await client.VerifyAsync(new VerifyRequest
{
    CardKey = "CARD-EXAMPLE",
    DeviceId = "device-001",
});
```

如服务端要求密文卡密：

```csharp
var encrypted = CardTransportCrypto.EncryptCardKey("CARD-EXAMPLE", appSecret, appId);
await client.VerifyAsync(new VerifyRequest { CardKey = encrypted });
```

## 协议

请求 body 先固定为将要发送的 UTF-8 原始字节，canonical string：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(raw_body)
```

响应验签必须在 JSON 解析前使用 raw response body，canonical string：

```text
X-Response-Timestamp\n原请求 nonce\nSHA256_HEX(raw_response_body)
```

AES-GCM 使用 `HKDF-SHA256(IKM=AppSecret, salt=AppID, info=cardkey-enc-v1, L=32)`、随机 12 字节 IV、AAD=`AppID`、16 字节 tag；JSON 字段 `iv`、`data`、`tag` 均为 Base64。每次加密必须生成新的 IV。

## 错误、重试与日志

客户端同时检查 HTTP 状态、`code` 和 `success`；业务错误可能使用 HTTP 200。响应签名缺失或不完整时，在 `RequireSignedResponses` 下拒绝。网络超时后不要自动重试 `consume`，因为该接口没有服务端幂等键。日志只允许记录 endpoint、HTTP 状态、业务码和 nonce 哈希前缀，不记录 secret、卡密、签名、nonce 原文或 body。

## 测试

在 Unity Test Runner 中运行 `CardKeyProtocolTests`。测试覆盖：请求签名、响应签名、RFC5869 HKDF、AES-GCM 固定 IV 向量、JSON 字节和失败验签。它不需要服务端或真实凭据；完整联调仍需独立的测试应用、测试卡密和 HTTPS 环境。
