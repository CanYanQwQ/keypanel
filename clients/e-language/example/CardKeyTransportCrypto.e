# 易语言卡密传输加密模块模板

.版本 2

.子程序 卡密加密载荷, 文本型
.参数 明文卡密, 文本型
.参数 AppSecret, 文本型
.参数 AppId, 文本型
.局部变量 派生密钥, 字节集
.局部变量 IV, 字节集
.局部变量 密文, 字节集
.局部变量 标签, 字节集

' 本模块只描述调用边界，不在易语言中实现密码学。
' 派生：HKDF-SHA256(IKM=AppSecret, salt=AppId, info=cardkey-enc-v1, L=32)。
派生密钥 ＝ CNG_HKDF_SHA256 (UTF8_编码 (AppSecret), UTF8_编码 (AppId), UTF8_编码 ("cardkey-enc-v1"), 32)
IV ＝ CNG_随机字节集 (12)
密文, 标签 ＝ CNG_AES256_GCM_加密 (派生密钥, IV, UTF8_编码 (明文卡密), UTF8_编码 (AppId), 16)
返回 (JSON_对象 ("iv", Base64编码 (IV), "data", Base64编码 (密文), "tag", Base64编码 (标签)))

.子程序 卡密解密载荷, 文本型
.参数 密文对象JSON, 文本型
.参数 AppSecret, 文本型
.参数 AppId, 文本型
.局部变量 派生密钥, 字节集
.局部变量 IV, 字节集
.局部变量 密文, 字节集
.局部变量 标签, 字节集

' 先严格校验 Base64、IV=12 字节、tag=16 字节；GCM 验证失败必须返回空并拒绝明文。
IV ＝ Base64解码 (JSON取文本 (密文对象JSON, "iv"))
密文 ＝ Base64解码 (JSON取文本 (密文对象JSON, "data"))
标签 ＝ Base64解码 (JSON取文本 (密文对象JSON, "tag"))
.如果真 (取字节集长度 (IV) ≠ 12 或 取字节集长度 (标签) ≠ 16)
    返回 ("")
.如果真结束
派生密钥 ＝ CNG_HKDF_SHA256 (UTF8_编码 (AppSecret), UTF8_编码 (AppId), UTF8_编码 ("cardkey-enc-v1"), 32)
返回 (UTF8_解码 (CNG_AES256_GCM_解密 (派生密钥, IV, 密文, UTF8_编码 (AppId), 标签)))
