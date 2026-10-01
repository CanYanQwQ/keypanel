# React 18+ 代理安全客户端模板

这是一个独立的 React + TypeScript 浏览器客户端模板。它只调用宿主应用的同源受保护代理，默认路径为 `/api/cardkey-proxy`。它不会、也不应该读取 AppSecret、上游 AppID 或 `VITE_*` Secret。

## 安全模型

```text
React 浏览器代码 --(同源会话/CSRF, 仅业务字段)--> /api/cardkey-proxy
      代理服务端 --(可信 TLS + HMAC v1 + AES-256-GCM)--> /api/v1/{operation}
```

- 浏览器端不生成 `X-Signature`，不持有 AppSecret，不直接请求 `/api/v1/*`。
- 真正的 HMAC canonical string、响应验签和 AES-256-GCM 必须由可信 Node/PHP/其他后端完成。
- 代理必须固定上游 origin 和五个 operation allowlist，校验会话/令牌、CSRF、请求体大小和速率。
- 日志不能记录 AppSecret、完整卡密、完整请求/响应体、签名头或 AES-GCM 载荷。
- 浏览器到代理、代理到上游都必须使用 HTTPS 并校验证书；HMAC/AES-GCM 不能替代 TLS。

完整协议、代理契约、Node/TypeScript 适配伪代码和错误码见 [`../../docs/templates/README.md`](../../docs/templates/README.md) 与 [`../../docs/templates/shared/error-codes.json`](../../docs/templates/shared/error-codes.json)。

## 安装与运行

```bash
cd clients/react
npm install
npm run typecheck
npm test
npm run build
```

包是独立的，无需把根项目依赖复制进来。`react` 是 peer dependency，宿主 React 应用负责提供运行时；模板的开发依赖用于 JSX 类型检查和测试。

## 调用示例

```tsx
import { useCardKeyProxy, isSuccessfulResponse } from '@cardkey/react-proxy-client';

export function VerifyCard() {
  const { verify, consume, loading, response, error } = useCardKeyProxy({
    // 只能是同源路径，不可填上游绝对 URL。
    proxyPath: '/api/cardkey-proxy',
    // csrfToken: readFromHostMetaTag(),
  });

  async function onVerify(cardKey: string, deviceId?: string) {
    const result = await verify({
      card_key: cardKey,
      device_id: deviceId || undefined,
    });

    if (isSuccessfulResponse(result)) {
      console.log('业务成功', result.data);
    } else {
      // HTTP 200 也可能是业务失败，例如设备不匹配 code=2007。
      showUserMessage(result.code, result.message);
    }
  }

  // consume 没有自动重试。网络超时后的未知结果不能盲目再次扣次。
  void consume;
  void loading;
  void response;
  void error;
  return <button onClick={() => onVerify(form.cardKey, form.deviceId)}>Verify</button>;
}
```

`verify`、`activate`、`query`、`unbind` 同样接受类型化输入。`useCardKeyProxy` 的 `error` 用于网络错误、无效 JSON、无效 envelope 和非 2xx HTTP 错误；合法的 HTTP 200 业务失败通过返回值的 `success=false` 和 `code` 表示。

也可以直接使用非 React 的 client（例如在边界层注入 fetch）：

```ts
import { createCardKeyProxyClient } from '@cardkey/react-proxy-client';

const client = createCardKeyProxyClient({
  proxyPath: '/api/cardkey-proxy',
  fetch: globalThis.fetch,
  credentials: 'same-origin',
});
const response = await client.query({ card_key: userEnteredCardKey });
```

不要把下面这类配置写进 React：

```text
VITE_CARDKEY_APP_SECRET=...
```

Vite、CRA 等前端构建变量最终可能进入公开 bundle。AppSecret 只能由后端密钥管理系统注入可信代理。

## 代理请求契约

客户端只会发送：

```http
POST /api/cardkey-proxy
Content-Type: application/json
Accept: application/json
Cookie: <same-origin session, if used>
X-CSRF-TOKEN: <optional host-issued token>
```

```json
{
  "operation": "verify",
  "card_key": "ABCD-EFGH-JKMN-PQRS",
  "device_id": "browser-device-placeholder"
}
```

字段 allowlist：

- 所有 operation：`operation`、`card_key`、可选 `device_id`
- `consume`：可选正整数 `count`，范围 1–1000
- `unbind`：可选布尔 `force`

浏览器不会发送 AppID、AppSecret、签名、timestamp、nonce、上游 URL 或任意用户提供的 headers。服务端代理收到请求后才负责：

1. 校验宿主身份、CSRF、字段和 operation allowlist。
2. 从可信密钥存储读取 AppID/AppSecret，不接受请求体或浏览器环境变量中的 Secret。
3. 按原始 JSON 字节生成 v1 HMAC 签名。
4. 根据服务端策略用 HKDF-SHA256 + AES-256-GCM 加密 card key。
5. 用 HTTPS 调用固定的 `/api/v1/{operation}`，先以 raw response body 验证响应签名再解析 JSON。
6. 向浏览器只返回允许的业务 envelope，不透传内部凭据、上游 URL 和调试堆栈。

## 错误和重试

客户端不实现自动重试。调用方需要同时检查：

- 传输异常：`CardKeyTransportError`
- 无法解析或结构不合法：`CardKeyProtocolError`
- 非 2xx 且 envelope 合法：`CardKeyHttpError`（包含 `status` 和 `response`）
- HTTP 200 业务失败：返回值 `success === false`，结合 `code` 判断

`consume` 可能已经扣减卡密次数。网络超时、连接断开或响应未知时不得盲目重试；如果产品确实需要幂等能力，应由可信后端设计并验证，而不是依赖浏览器 `X-Request-Id`。

## 文件清单

- `src/index.ts`：公开入口。
- `src/types.ts`：代理请求、API envelope、各 operation 输入/输出类型。
- `src/client.ts`：只调用同源代理的 fetch client、错误类型和安全 allowlist。
- `src/useCardKeyProxy.ts`：React hook，提供 loading/response/error 状态。
- `src/example.tsx`：不读取 Secret 的表单组件示例。
- `test/client.test.mjs`：代理路径、字段 allowlist、错误分类和 consume 不重试测试。

## 测试范围

`npm test` 会先编译 TypeScript，再使用 Node 内置测试运行器验证：

- 浏览器请求只发送 `/api/cardkey-proxy` 和业务字段。
- 请求头没有 `X-App-Id` 或 `X-Signature`。
- HTTP 200 的业务失败不会被误判为成功。
- 非 2xx、非法 JSON、网络失败能被调用方识别。
- `consume` 传输失败只调用一次，不自动重试。

这些测试不替代服务端代理的 TLS、CSRF、认证、HMAC、AES-GCM、响应验签和日志脱敏测试。
