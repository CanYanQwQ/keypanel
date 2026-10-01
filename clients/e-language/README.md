# CardKey API v1 易语言 Windows 客户端示例

本目录提供易语言 Windows 工程的可靠集成边界和可复制模板。它**不伪造** HMAC-SHA256、HKDF 或 AES-GCM；密码学实现交给 Windows CNG (`bcrypt.dll`) 或经过审计、固定版本的原生 DLL。易语言工程只负责编排 HTTP、UTF-8 原始 JSON、签名头、响应验签和业务模型。

## 目录

- `README.md`：协议、安全边界、构建和联调说明。
- `config.example.json`：只含占位符的配置模板。
- `example/CardKeyClientDemo.e`：易语言伪代码级入口/调用顺序模板；其中所有密码学 DLL 调用均明确标记为外部依赖，不声称可直接运行。
- `example/CardKeyModels.e`：请求/响应字段和错误码映射模板。
- `example/Utf8Json.e`：UTF-8 body 约束和 JSON 组装注意事项。
- `cng/README.md`：Windows CNG 原语映射、DLL 搜索和可靠依赖说明。
- `cng/cardkey_cng.h`：可选桥接 DLL 的 C ABI 头文件；没有实现文件，避免提交未经审计的密码学代码。

## 推荐实现边界

### 方案 A：易语言调用 Windows CNG 桥接 DLL（推荐

使用一个由 C/C++/Rust 等受信代码构建、代码审查和单元测试的 DLL，内部使用 Windows CNG：

- HMAC-SHA256：`BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM, ...)` + `BCryptCreateHash`/`BCryptHashData`/`BCryptFinishHash`，或 `BCryptSignHash` 配合 HMAC provider。
- HKDF-SHA256：使用系统支持的 `BCRYPT_KDF_HKDF`/`BCryptKeyDerivation`，并明确设置 `BCRYPT_KDF_HKDF_SECRET`, `BCRYPT_KDF_HKDF_SALT`, `BCRYPT_KDF_HKDF_INFO`；若目标 Windows SDK/版本不支持该 provider，桥接层应使用经过测试的 RFC5869 实现，不在易语言源码中重写。
- AES-256-GCM：使用 CNG 支持的 GCM 模式，12-byte IV、16-byte tag、AAD=`AppID`；桥接 DLL 必须明确 tag 输出/输入方向，并用跨语言固定向量测试确认。
- 随机数：`BCryptGenRandom(NULL, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)`。
- 常量时间比较：桥接层使用 `BCrypt`/安全比较函数，易语言不得用普通字符串比较验证签名。

`cng/cardkey_cng.h` 只定义最小 C ABI。它不是 DLL 实现，也不能单独提供密码学能力。必须从受信源码构建与签名 DLL，并在部署机固定 DLL 路径、版本、哈希和架构（x64/x86）。

### 方案 B：调用经过审计的第三方 DLL

可使用组织批准的、固定版本且支持 AES-GCM/HKDF/HMAC-SHA256 的 DLL，但必须确认：

1. DLL 具有明确的 x64/x86 ABI 和调用约定；
2. 文档明确字节数组长度、输出缓冲区、错误码、tag/AAD 语义；
3. 依赖 DLL 与许可证可随产品分发；
4. 使用本目录固定向量做集成测试；
5. 不接受“只实现了 AES-CBC/ECB”或“只校验 Base64”的 DLL。

不要把 OpenSSL/CNG 的复杂结构体直接暴露给易语言；用长度明确、调用约定明确的 C ABI 包装层。

## HTTP 与五个接口

`POST` 请求路径固定为：

- `/api/v1/verify`
- `/api/v1/activate`
- `/api/v1/consume`
- `/api/v1/query`
- `/api/v1/unbind`

请求必须发送最终 UTF-8 `raw_body`，签名 canonical string 为：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256_HEX(raw_body)
```

请求头：`X-App-Id`、`X-Timestamp`、`X-Nonce`、`X-Signature-Version: v1`、`X-Signature`、`Content-Type: application/json`。签名是 AppSecret 作为字节 key 的 HMAC-SHA256 小写十六进制。nonce 必须使用 CNG 生成的至少 16 字节随机值；时间戳为 Unix 秒。

响应读取顺序必须是：

1. 读取 HTTP 返回的原始响应 body 字节，不进行转码或重新 JSON 序列化；
2. 读取 `X-Response-Timestamp` 和 `X-Response-Signature`；
3. 用原请求 nonce 验签：`RESPONSE_TIMESTAMP\nREQUEST_NONCE\nSHA256_HEX(raw_response_body)`；
4. 验签成功后再按 UTF-8 解析 JSON；
5. 同时检查 HTTP 状态、`code` 和 `success`。

服务端中间件拒绝、参数校验和解密异常可能没有响应签名；生产策略建议缺少签名时拒绝，而不是把它当作成功。

## 卡密传输加密

```text
key = HKDF-SHA256(IKM=AppSecret, salt=AppID,
                  info="cardkey-enc-v1", L=32)
AES-256-GCM(key, random 12-byte IV, AAD=AppID, tag=16 bytes)
```

JSON 字段为 `iv`、`data`、`tag`，均为 Base64；`data` 是密文。每次加密必须产生新 IV。GCM tag 校验失败必须拒绝明文。不要把 AppSecret 或明文卡密传给日志、调试窗口、异常文本或剪贴板。

## 错误码

`example/CardKeyModels.e` 镜像服务端 `ApiErrorCode`：0 成功；1001-1011 认证/请求类；2001-2011 卡密业务类；4004/4005/4013 HTTP 请求类；5000/5003 服务端类。业务失败可能返回 HTTP 200，必须以 `code`/`success` 为准。

## 构建与测试

本目录不包含未经验证的 `.e` 二进制工程或伪造 DLL。易语言 IDE/版本、系统位数、HTTP 组件和组织批准的密码学 DLL 会影响最终工程配置。建议按以下顺序验证：

1. 在 C/C++ 桥接项目中运行 RFC5869、HMAC、AES-GCM 固定向量；
2. 在易语言中验证 DLL 导出函数的调用约定、UTF-8 字节长度和错误码；
3. 用本目录固定向量比对签名、派生 key、密文和 tag；
4. 用测试 App 和测试卡密联调五个端点；
5. 在没有真实凭据的 CI/构建机上只运行固定向量和模型序列化检查。

当前工作区没有易语言编译器，也没有已批准的 CNG 桥接 DLL，因此不能声称已完成易语言二进制构建或真实网络联调。README 和模板故意保留这些边界。

## 客户端信任边界

易语言 Windows 客户端中的 AppSecret 同样可以被本机用户提取；它不适合作为高信任授权方案。公开分发程序应使用后端代理、短期凭据或服务端可撤销的低权限凭据。生产必须使用 HTTPS，并固定 DLL 的来源、签名和哈希。
