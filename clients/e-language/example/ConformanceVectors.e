# CardKey API v1 固定向量测试模板

.版本 2

.子程序 运行固定向量测试, 逻辑型
.局部变量 请求体, 字节集
.局部变量 请求签名, 文本型
.局部变量 响应体, 字节集
.局部变量 响应签名, 文本型
.局部变量 HKDF输出, 字节集

请求体 ＝ UTF8_编码 ("{" ＋ #引号 ＋ "card_key" ＋ #引号 ＋ ":" ＋ #引号 ＋ "CARD-EXAMPLE" ＋ #引号 ＋ "," ＋ #引号 ＋ "device_id" ＋ #引号 ＋ ":" ＋ #引号 ＋ "device-001" ＋ #引号 ＋ "}")
请求签名 ＝ 请求签名v1 ("secret-example", "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", 请求体)
.如果真 (请求签名 ≠ "42b8ab8d1c81c41609a206fefa6bffcc384fb5480e4f312f18e2401e6f0ca652")
    返回 (假)
.如果真结束

响应体 ＝ UTF8_编码 ("{" ＋ #引号 ＋ "code" ＋ #引号 ＋ ":0," ＋ #引号 ＋ "message" ＋ #引号 ＋ ":" ＋ #引号 ＋ "操作成功" ＋ #引号 ＋ "," ＋ #引号 ＋ "success" ＋ #引号 ＋ ":true," ＋ #引号 ＋ "server_time" ＋ #引号 ＋ ":1700000000," ＋ #引号 ＋ "data" ＋ #引号 ＋ ":{" ＋ #引号 ＋ "status" ＋ #引号 ＋ ":" ＋ #引号 ＋ "unused" ＋ #引号 ＋ "}}")
响应签名 ＝ 响应签名v1 ("secret-example", 响应体, "1700000001", "00112233445566778899aabbccddeeff")
.如果真 (响应签名 ≠ "e404631865daf3502a1adc751ca7168ad7b0f4f2fad022798f5664bf05a47874")
    返回 (假)
.如果真结束

HKDF输出 ＝ CNG_HKDF_SHA256 (十六进制解码 ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), 十六进制解码 ("000102030405060708090a0b0c"), 十六进制解码 ("f0f1f2f3f4f5f6f7f8f9"), 42)
.如果真 (十六进制小写 (HKDF输出) ≠ "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    返回 (假)
.如果真结束

返回 (真)

' AES-GCM 固定向量：
' AppSecret=app-secret-vector, AppID=ak_vector, 明文=CARD-EXAMPLE,
' IV=00112233445566778899aabb,
' Base64 data=4RQoywLAvA9x6XJC,
' Base64 tag=2QHtTZb5PG+8QNIAF/zU4Q==。
' 具体 CNG 桥接 DLL 接口测试必须额外确认 AAD=AppID、tag=16 字节。
