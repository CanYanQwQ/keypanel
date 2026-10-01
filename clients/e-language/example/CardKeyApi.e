# 易语言五个 API 方法编排模板

.版本 2

' 本文件负责五个 POST 方法的路径、请求字段和错误处理编排。
' HTTP、JSON、UTF-8、CNG 函数由组织批准的模块提供；不要把下列外部模块名误认为内置密码学实现。

.子程序 API_验证, 文本型
.参数 配置, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
返回 (签名POST_JSON (配置, "/api/v1/verify", 请求JSON_卡密设备 (卡密值, 设备ID)))

.子程序 API_激活, 文本型
.参数 配置, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
返回 (签名POST_JSON (配置, "/api/v1/activate", 请求JSON_卡密设备 (卡密值, 设备ID)))

.子程序 API_消费, 文本型
.参数 配置, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
.参数 次数, 整数型
返回 (签名POST_JSON (配置, "/api/v1/consume", 请求JSON_卡密设备次数 (卡密值, 设备ID, 次数)))

.子程序 API_查询, 文本型
.参数 配置, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
返回 (签名POST_JSON (配置, "/api/v1/query", 请求JSON_卡密设备 (卡密值, 设备ID)))

.子程序 API_解绑, 文本型
.参数 配置, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
.参数 强制, 逻辑型
返回 (签名POST_JSON (配置, "/api/v1/unbind", 请求JSON_卡密设备强制 (卡密值, 设备ID, 强制)))

.子程序 签名POST_JSON, 文本型
.参数 配置, 文本型
.参数 路径, 文本型
.参数 JSON文本, 文本型
.局部变量 原始请求体, 字节集
.局部变量 时间戳, 文本型
.局部变量 Nonce, 文本型
.局部变量 签名, 文本型
.局部变量 原始响应体, 字节集
.局部变量 响应时间戳, 文本型
.局部变量 响应签名, 文本型

原始请求体 ＝ UTF8_编码 (JSON文本)
时间戳 ＝ Unix秒文本 ()
Nonce ＝ 请求Nonce (16)
签名 ＝ 请求签名v1 (配置.AppSecret, "POST", 路径, 时间戳, Nonce, 原始请求体)
原始响应体 ＝ HTTP_POST_发送UTF8 (配置.BaseUrl ＋ 路径, 原始请求体, \
    "X-App-Id", 配置.AppId, \
    "X-Timestamp", 时间戳, \
    "X-Nonce", Nonce, \
    "X-Signature-Version", "v1", \
    "X-Signature", 签名)

响应时间戳 ＝ HTTP_响应头 ("X-Response-Timestamp")
响应签名 ＝ HTTP_响应头 ("X-Response-Signature")
.如果真 (配置.RequireSignedResponses 且 (响应时间戳 ＝ "" 或 响应签名 ＝ ""))
    返回 ("响应签名缺失")
.如果真结束
.如果真 (配置.RequireSignedResponses 且 验证响应签名 (配置.AppSecret, 响应时间戳, Nonce, 原始响应体, 响应签名) ＝ 假)
    返回 ("响应签名无效")
.如果真结束

' 验签后才解码/解析 JSON；并由调用方同时检查 HTTP 状态、code 和 success。
返回 (UTF8_解码 (原始响应体))

.子程序 请求JSON_卡密设备, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
返回 (JSON对象_卡密设备 (卡密值, 设备ID))

.子程序 请求JSON_卡密设备次数, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
.参数 次数, 整数型
返回 (JSON对象_卡密设备次数 (卡密值, 设备ID, 次数))

.子程序 请求JSON_卡密设备强制, 文本型
.参数 卡密值, 文本型
.参数 设备ID, 文本型
.参数 强制, 逻辑型
返回 (JSON对象_卡密设备强制 (卡密值, 设备ID, 强制))

' 卡密值可以是明文字符串，也可以是 CardKeyTransportCrypto.e 生成的 iv/data/tag 对象。
' 当服务端开启强制密文时，调用方必须传对象 JSON，不能把对象再包成字符串。
' 任何网络超时都不得自动重用同一个 Nonce；consume 超时不要盲目重试。
