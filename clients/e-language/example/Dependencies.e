# 易语言模块清单与外部依赖说明

本示例不捆绑第三方 DLL，也不声称下面名称可以直接导入。实际工程应把组织批准的 DLL 导入易语言模块，并将导出函数映射到这些职责：

- `CNG_随机字节集(length)`：调用 `cardkey_random`；用于 nonce 和 AES-GCM IV。
- `CNG_SHA256_十六进制(bytes)`：调用 SHA-256 并在易语言侧格式化为小写 hex。
- `CNG_HMAC_SHA256_十六进制(key, message)`：调用 `cardkey_hmac_sha256`。
- `CNG_HMAC_SHA256_验证十六进制(key, message, signature)`：先严格解码 64 个 hex 字符，再调用常量时间比较；不得普通字符串比较。
- `CNG_HKDF_SHA256(ikm, salt, info, length)`：调用 `cardkey_hkdf_sha256`。
- `CNG_AES256_GCM_加密(key, iv, plaintext, aad, tagLength)`：调用 GCM 加密并返回 ciphertext/tag。
- `CNG_AES256_GCM_解密(key, iv, ciphertext, aad, tag)`：tag 验证失败返回错误，禁止输出明文。

所有 DLL 缓冲区都必须显式传入字节长度；不要用易语言“文本长度”代替 UTF-8 字节长度。DLL 返回负数时立即停止请求并清理临时字节集，不要把错误中的 key、明文或 body 写入调试输出。

推荐固定依赖：Windows 10/11 x64、`bcrypt.dll` 系统 CNG、经过签名和固定哈希的桥接 DLL、明确支持 UTF-8 的 HTTP 组件和经过审计的 JSON 组件。没有可验证的 AES-GCM/HKDF DLL 时，宁可不提供“可运行加密”，也不要退回 AES-CBC、ECB、XOR 或自定义算法。
