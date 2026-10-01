# CardKey API 客户端对接文档

本目录提供 CardKey API v1 的跨语言客户端模板。服务端 API 位于 `/api/v1`，所有请求必须使用 AppID/AppSecret 签名；生产环境必须使用 HTTPS。

## 端点

- `POST /api/v1/verify`
- `POST /api/v1/activate`
- `POST /api/v1/consume`
- `POST /api/v1/query`
- `POST /api/v1/unbind`

所有端点都需要以下请求头：

```text
X-App-Id: <AppID>
X-Timestamp: <Unix seconds>
X-Nonce: <unique cryptographic random value>
X-Signature-Version: v1
X-Signature: <lowercase hex HMAC-SHA256>
Content-Type: application/json
Accept: application/json
```

## 请求签名

先生成最终要发送的原始 JSON 字节，不要在签名后重新序列化：

```text
METHOD
PATH
TIMESTAMP
NONCE
SHA256_HEX(raw_body)
```

使用完整 ASCII AppSecret 作为 HMAC-SHA256 密钥，输出 64 位小写十六进制字符串。路径不包含域名、查询字符串或 fragment；请求体摘要使用 HTTP 实际发送的字节。

## 卡密传输加密

当应用或全局设置要求密文卡密时，`card_key` 必须是对象：

```json
{
  "iv": "base64(12-byte random IV)",
  "data": "base64(ciphertext)",
  "tag": "base64(16-byte GCM tag)"
}
```

密钥派生：

```text
HKDF-SHA256(IKM=AppSecret, salt=AppID, info=cardkey-enc-v1, length=32)
AES-256-GCM(key, random 12-byte IV, AAD=AppID)
```

每次加密必须生成新 IV；不能复用同一个 key+IV。GCM tag 校验失败时必须拒绝数据。

## 响应验签

正常经过控制器的响应可能包含：

```text
X-Response-Timestamp
X-Response-Signature
```

响应签名数据为：

```text
RESPONSE_TIMESTAMP
REQUEST_NONCE
SHA256_HEX(raw_response_body)
```

客户端必须先使用原始响应字节验证签名，再解析 JSON。中间件拒绝、参数验证和解密异常当前可能没有响应签名，不能将缺少签名当作成功。

## 响应和错误

响应通常包含：

```json
{
  "code": 0,
  "message": "操作成功",
  "success": true,
  "server_time": 1700000000,
  "data": {}
}
```

客户端必须同时检查 HTTP 状态、`code` 和 `success`。部分业务失败使用 HTTP 200，例如设备不匹配和卡密类型不支持。

完整错误码见 `app/Enums/ApiErrorCode.php` 和 `docs/templates/shared/error-codes.json`。

## 安全边界

- AppSecret 不能写入日志、URL、前端 bundle、崩溃报告或提交到仓库。
- Vue/React 浏览器代码不得持有 AppSecret；请使用受保护的后端代理。
- 请求超时重试必须生成新的 timestamp、nonce 和 signature。
- `consume` 没有服务端幂等键，网络超时后不要盲目重试，否则可能重复扣次。
- 示例配置只使用占位符，不能复制本地 Seeder、HANDOFF 或数据库中的真实凭据。
