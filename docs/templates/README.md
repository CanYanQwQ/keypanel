# CardKey 客户端模板总入口

本目录是 CardKey API v1 跨语言模板的总入口。模板默认面向“受保护后端代理”架构：真正的 AppID/AppSecret 签名、响应验签以及卡密传输加密只在可信后端完成。浏览器端模板只提交业务参数到同源代理，不直接访问 `/api/v1/*`，也不保存或读取 AppSecret。

> 本次只新增/维护 `docs/templates`、`clients/vue` 和 `clients/react`。Laravel `app`、`routes`、`config`、`tests` 未作为模板的一部分修改。

## 完整模板清单

| 目录 | 技术栈 | 说明 |
| --- | --- | --- |
| `clients/cpp-qt` | C++ / Qt | 桌面客户端扩展位 |
| `clients/csharp` | C# | .NET 客户端扩展位 |
| `clients/e-language` | 易语言 | Windows 客户端扩展位 |
| `clients/flutter` | Dart / Flutter | 移动端/桌面端扩展位 |
| `clients/go` | Go | 服务端或桌面客户端扩展位 |
| `clients/java` | Java | JVM 客户端扩展位 |
| `clients/javascript` | JavaScript | 通用 JavaScript 扩展位 |
| `clients/kotlin` | Kotlin | Android/JVM 客户端扩展位 |
| `clients/php` | PHP | 服务端 PHP 客户端扩展位 |
| `clients/python` | Python | 服务端或脚本客户端扩展位 |
| `clients/react` | React + TypeScript | 浏览器代理安全模板，本次完善 |
| `clients/rust` | Rust | 服务端或桌面客户端扩展位 |
| `clients/typescript` | TypeScript | 通用 TypeScript 扩展位 |
| `clients/unity-csharp` | Unity / C# | Unity 客户端扩展位 |
| `clients/vue` | Vue 3 + TypeScript | 浏览器代理安全模板，本次完善 |

各语言模板应遵守同一协议。错误码单一镜像位于 [`shared/error-codes.json`](./shared/error-codes.json)，字段含义和同步规则见 [`shared/README.md`](./shared/README.md)。

## API v1 协议

### 上游端点

服务端公开的上游 API 是以下五个 `POST` 端点：

- `/api/v1/verify`
- `/api/v1/activate`
- `/api/v1/consume`
- `/api/v1/query`
- `/api/v1/unbind`

请求通常包含 `card_key`、可选 `device_id`；`consume` 还接受 `count`，`unbind` 还接受 `force`。服务端可能要求 `card_key` 为 AES-256-GCM 密文对象。

### 请求头

直接调用上游 API 的可信后端必须提供：

```text
X-App-Id: <server-side AppID>
X-Timestamp: <Unix seconds>
X-Nonce: <new cryptographic random nonce>
X-Signature-Version: v1
X-Signature: <lowercase hex HMAC-SHA256>
Content-Type: application/json
Accept: application/json
```

浏览器 Vue/React 模板**不**生成这些认证头；浏览器请求只发给受保护代理。代理应从服务端密钥管理系统取得 AppID/AppSecret，并且禁止浏览器覆盖这些值。

### 签名 canonical string

必须先确定最终要发送的原始请求体字节，再计算 SHA-256。签名输入严格为：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(raw_body)
```

规则：

- `METHOD` 使用大写 HTTP 方法。
- `PATH` 是不含域名、查询字符串和 fragment 的路径，例如 `/api/v1/verify`。
- `TIMESTAMP` 是 Unix 秒级时间戳字符串。
- `NONCE` 每次请求都必须使用新的密码学安全随机值。
- `raw_body` 是 HTTP 实际发送的字节；签名后不得重新序列化 JSON。
- HMAC 密钥是完整 AppSecret，输出小写十六进制 HMAC-SHA256。

### 响应验签

业务响应可能带有：

```text
X-Response-Timestamp: <timestamp>
X-Response-Signature: <lowercase hex HMAC-SHA256>
```

响应签名 canonical string 为：

```text
RESPONSE_TIMESTAMP\nREQUEST_NONCE\nSHA256_HEX(raw_response_body)
```

可信后端必须先对收到的原始响应字节验签，再解析 JSON。中间件拒绝、限流或参数错误响应可能没有响应签名；缺少响应签名不能被当作成功。

### 卡密传输加密

当服务端启用密文卡密时，可信后端使用下列协议构造 `card_key`：

```text
key = HKDF-SHA256(
  IKM=AppSecret,
  salt=AppID,
  info="cardkey-enc-v1",
  length=32
)
AES-256-GCM(key, random 12-byte IV, AAD=AppID)
```

JSON 载荷格式为：

```json
{
  "iv": "base64(12-byte random IV)",
  "data": "base64(ciphertext)",
  "tag": "base64(16-byte authentication tag)"
}
```

每次加密必须生成新 IV；GCM tag 校验失败必须拒绝。Vue/React 浏览器代码不执行该流程，也不接触派生密钥。

### 响应 envelope

客户端必须同时检查 HTTP 状态、业务 `code` 和 `success`，不能只依据 HTTP 200：

```json
{
  "code": 0,
  "message": "操作成功",
  "success": true,
  "server_time": 1700000000,
  "data": {}
}
```

部分卡密业务失败会使用 HTTP 200 并在 `code` 中返回错误。完整错误码见 [`shared/error-codes.json`](./shared/error-codes.json)。

## 浏览器代理契约

Vue/React 模板约定由同源、受认证保护的后端提供：

```text
POST /api/cardkey-proxy
Content-Type: application/json
Accept: application/json
Cookie/Authorization: 由宿主应用的会话或短期访问令牌提供
X-CSRF-TOKEN: 按宿主应用的 CSRF 策略提供（如适用）
```

请求体只允许以下业务字段，不能让浏览器提交 AppID、AppSecret、签名、上游 URL 或任意 header：

```json
{
  "operation": "verify",
  "card_key": "ABCD-EFGH-JKMN-PQRS",
  "device_id": "browser-device-placeholder"
}
```

`operation` 只能是 `verify`、`activate`、`consume`、`query`、`unbind`；`consume` 可带正整数 `count`，`unbind` 可带布尔 `force`。代理应校验当前用户/会话权限、CSRF、请求体大小、字段白名单和速率，然后将请求映射到固定的上游 origin 与 `/api/v1/{operation}`。代理可以原样返回上游 envelope，但不应向浏览器暴露 AppID、签名头、AppSecret、内部 URL 或原始上游调试信息。

### Node/TypeScript 服务端适配伪代码

以下代码只用于说明边界，不能直接当作生产路由。`getSecretFromVault`、会话认证、CSRF、审计日志和上游 HTTP 客户端必须由宿主后端实现。`CARDKEY_APP_SECRET` 只能通过服务端密钥管理注入，不能通过 `VITE_*`、前端 bundle 或用户请求传入。

```ts
import {
  createCipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

type ProxyRequest = {
  operation: 'verify' | 'activate' | 'consume' | 'query' | 'unbind';
  card_key: string;
  device_id?: string;
  count?: number;
  force?: boolean;
};

function signRequest(
  appSecret: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  rawBody: string,
): string {
  // rawBody 必须就是 fetch/HTTP 客户端实际发送的 UTF-8 字节内容。
  const bodyHash = createHash('sha256').update(Buffer.from(rawBody, 'utf8')).digest('hex');
  const canonical = [method.toUpperCase(), path, timestamp, nonce, bodyHash].join('\n');
  return createHmac('sha256', appSecret).update(canonical, 'utf8').digest('hex');
}

function encryptCardKey(plainCardKey: string, appId: string, appSecret: string) {
  // 该函数只在可信后端运行。浏览器绝不能复制或调用它。
  const key = Buffer.from(hkdfSync(
    'sha256',
    Buffer.from(appSecret, 'utf8'),
    Buffer.from(appId, 'utf8'),
    'cardkey-enc-v1',
    32,
  ));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(appId, 'utf8'));
  const data = Buffer.concat([cipher.update(plainCardKey, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    data: data.toString('base64'),
    tag: tag.toString('base64'),
  };
}

async function cardKeyProxy(request: Request): Promise<Response> {
  await requireSameOriginSessionAndCsrf(request);

  const input = await readAndValidateAllowlistedJson<ProxyRequest>(request);
  // 不接受 input.app_secret、input.signature、input.url 等字段。
  const appId = getSecretFromVault('CARDKEY_APP_ID');
  const appSecret = getSecretFromVault('CARDKEY_APP_SECRET');
  const operation = input.operation;
  const upstreamPath = `/api/v1/${operation}`; // 固定 allowlist，禁止用户控制 URL。

  const upstreamPayload = {
    card_key: encryptCardKey(input.card_key, appId, appSecret),
    ...(input.device_id === undefined ? {} : { device_id: input.device_id }),
    ...(operation === 'consume' && input.count === undefined ? {} : { count: input.count }),
    ...(operation === 'unbind' && input.force === undefined ? {} : { force: input.force }),
  };
  const rawBody = JSON.stringify(upstreamPayload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString('hex');

  const upstream = await fetch(`${TRUSTED_API_ORIGIN}${upstreamPath}`, {
    method: 'POST',
    // 生产环境必须 HTTPS、校验证书，并限制固定的 TRUSTED_API_ORIGIN。
    headers: {
      'X-App-Id': appId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature-Version': 'v1',
      'X-Signature': signRequest(appSecret, 'POST', upstreamPath, timestamp, nonce, rawBody),
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: rawBody,
  });

  const rawResponseBody = await upstream.text();
  // 若存在 X-Response-Signature，必须先用 rawResponseBody 验签，再 JSON.parse。
  const envelope = JSON.parse(rawResponseBody);
  // 对浏览器只返回允许的 envelope；绝不透传 AppSecret、签名密钥、内部 URL 或完整调试异常。
  return json(envelope, upstream.status);
}
```

代理实际是否需要加密卡密取决于上游应用设置；若代理允许明文上游，也必须仅在受信任的服务器到服务器 TLS 通道中发送，并遵循服务端的密文要求。浏览器端始终不应持有 AppSecret。

## 运行方式

Vue 和 React 目录都是可独立安装的 TypeScript 模板：

```bash
cd clients/vue
npm install
npm run typecheck
npm test
npm run build

cd ../react
npm install
npm run typecheck
npm test
npm run build
```

模板使用浏览器原生 `fetch`，不要求把 AppSecret 配到前端。代理路径默认是 `/api/cardkey-proxy`，也可以通过代码运行时选项传入另一个**同源受保护代理路径**。不要把 Secret 放入 `VITE_*`、`NEXT_PUBLIC_*`、`REACT_APP_*` 或任何前端可见配置；公开的代理路径不是 Secret，但它仍必须在服务端做认证和 CSRF 防护。

生产部署必须：

1. 浏览器到宿主应用、宿主应用到 CardKey API 都使用 HTTPS，并校验证书；HMAC/AES-GCM 不能替代 TLS。
2. 通过密钥管理系统注入服务端 AppID/AppSecret，最小化读取权限并轮换密钥。
3. 固定上游 origin，禁止代理成为任意 URL 转发器。
4. 对代理执行会话/令牌认证、CSRF、防重放、请求体大小限制、速率限制和审计。
5. 日志只记录脱敏 AppID、操作、结果和内部关联 ID；不得记录 AppSecret、完整卡密、完整请求体/响应体、签名头或 AES-GCM 载荷。

## 占位配置

以下值仅用于示例，均不可作为真实凭据：

```text
CARDKEY_APP_ID=ak_example_replace_me
CARDKEY_APP_SECRET=sk_example_replace_me_on_trusted_backend_only
CARDKEY_API_ORIGIN=https://api.example.invalid
CARDKEY_PROXY_PATH=/api/cardkey-proxy
CARDKEY_EXAMPLE_CARD_KEY=ABCD-EFGH-JKMN-PQRS
```

`CARDKEY_APP_SECRET` 只能存在于可信后端的运行时秘密存储。示例中的 `CARDKEY_EXAMPLE_CARD_KEY` 也不应写入生产日志或测试输出。浏览器端代码不读取任何 `*_SECRET` 或 `VITE_*` Secret。

## 重试与业务副作用

- 每次上游重试都必须重新生成 timestamp、nonce、raw body 和 signature。
- `consume` 会扣减次数，服务端当前没有可由客户端自行假设的幂等键。网络超时或响应未知时，**不可盲目重试 `consume`**；应让用户或业务方确认状态，或由可信后端提供经过设计的幂等方案。
- `verify`、`query` 等操作是否可以重试也必须结合业务和错误类型判断，不能只看到 HTTP 5xx 就无条件重放。
- Vue/React 模板不内置自动重试，避免把副作用操作变成重复扣次。

## 验证范围

本次模板应至少验证：

- TypeScript 类型检查、单元测试和独立构建。
- 浏览器 client 只向 `/api/cardkey-proxy`（或显式的同源代理路径）发请求。
- 请求体字段使用代理契约的 snake_case，且不发送 `X-App-Id`、`X-Signature`、AppSecret 或上游 `/api/v1/*` URL。
- HTTP 非 2xx、业务 `success: false`、非法 JSON 和网络错误均可被调用方识别。
- 客户端对 `consume` 不做自动重试。
- 生产接入方另行验证代理的 TLS、CSRF、认证、上游签名、AES-GCM、响应验签和日志脱敏；这些不由浏览器包替代。

未在本次模板中修改或承诺验证 Laravel 路由、控制器、中间件、数据库、队列和生产部署配置。
