# 易语言入口模板（伪代码，不是可直接编译的密码学实现）

.版本 2

.子程序 主程序, 整数型
.局部变量 配置, 文本型
.局部变量 原始请求体, 字节集
.局部变量 路径, 文本型
.局部变量 时间戳, 文本型
.局部变量 随机数, 文本型
.局部变量 签名, 文本型
.局部变量 响应原始字节, 字节集
.局部变量 响应时间戳, 文本型
.局部变量 响应签名, 文本型

' 只从受保护配置读取占位符替换后的值；不要在源码、日志或窗口打印 AppSecret/卡密。
配置 ＝ 读取受保护配置 ("config.json")

' 每一次请求重新生成 Unix 秒时间戳、CNG 随机 nonce 和签名。
' 不要在超时重试时复用 nonce；consume 超时不要盲目重试。
路径 ＝ "/api/v1/verify"
原始请求体 ＝ UTF8_编码 (JSON_序列化_保持原始字节 ("card_key", "CARD-EXAMPLE", "device_id", "device-001"))
时间戳 ＝ Unix秒文本 ()
随机数 ＝ CNG_随机十六进制 (16)  ' 外部桥接 DLL；不是易语言伪随机数
签名 ＝ CNG_HMAC_SHA256_十六进制 (配置.AppSecret, "POST" ＋ #换行符 ＋ 路径 ＋ #换行符 ＋ 时间戳 ＋ #换行符 ＋ 随机数 ＋ #换行符 ＋ CNG_SHA256_十六进制 (原始请求体))

响应原始字节 ＝ HTTP_POST_发送UTF8 (配置.BaseUrl ＋ 路径, 原始请求体, \
    "X-App-Id", 配置.AppId, \
    "X-Timestamp", 时间戳, \
    "X-Nonce", 随机数, \
    "X-Signature-Version", "v1", \
    "X-Signature", 签名)

响应时间戳 ＝ HTTP_响应头 ("X-Response-Timestamp")
响应签名 ＝ HTTP_响应头 ("X-Response-Signature")
.如果真 (配置.RequireSignedResponses 且 (响应时间戳 ＝ "" 或 响应签名 ＝ ""))
    返回 (0)
.如果真结束

' 先用响应原始字节验签，成功后才 UTF-8 解码和解析 JSON。
.如果真 (CNG_HMAC_SHA256_验证十六进制 (配置.AppSecret, 响应时间戳 ＋ #换行符 ＋ 随机数 ＋ #换行符 ＋ CNG_SHA256_十六进制 (响应原始字节), 响应签名) ＝ 假)
    返回 (0)
.如果真结束

' 同时检查 HTTP 状态、code 和 success。业务错误可能返回 HTTP 200。
返回 (处理API响应 (UTF8_解码 (响应原始字节)))

.子程序 调用五个接口, 整数型
' verify:   POST /api/v1/verify
' activate: POST /api/v1/activate
' consume:  POST /api/v1/consume
' query:    POST /api/v1/query
' unbind:   POST /api/v1/unbind
' 每个方法都必须走同一套“原始 UTF-8 body -> 请求签名 -> raw response 验签”流程。
返回 (1)

.子程序 加密卡密, 文本型
.参数 明文卡密, 文本型
.局部变量 密钥, 字节集
.局部变量 IV, 字节集
.局部变量 密文, 字节集
.局部变量 标签, 字节集

密钥 ＝ CNG_HKDF_SHA256 (UTF8_编码 (配置.AppSecret), UTF8_编码 (配置.AppId), UTF8_编码 ("cardkey-enc-v1"), 32)
IV ＝ CNG_随机字节集 (12)
密文, 标签 ＝ CNG_AES256_GCM_加密 (密钥, IV, UTF8_编码 (明文卡密), UTF8_编码 (配置.AppId), 16)
返回 (JSON_对象 ("iv", Base64编码 (IV), "data", Base64编码 (密文), "tag", Base64编码 (标签)))
