#pragma once

// ============================================================================
//  API 请求签名 v1（严格对应服务端 app/Support/ApiSigner.php）
//
//  待签名字符串 canonical =
//      METHOD        + "\n" +
//      PATH          + "\n" +
//      TIMESTAMP     + "\n" +
//      NONCE         + "\n" +
//      SHA256_HEX(raw_body)
//
//  X-Signature = HEX( HMAC-SHA256( key = AppSecret, data = canonical ) )
//
//  要点：
//    - METHOD 大写；PATH 不含域名/查询串/fragment，需折叠重复斜杠并去掉末尾斜杠。
//    - raw_body 必须是"实际发送的字节"，签名后不得重新序列化 JSON。
//    - 每次重试都要重新生成 timestamp / nonce / signature。
// ============================================================================

#include "卡密/基础算法.h"
#include "卡密/分组加密.h"
#include "卡密/精简JSON.h"

#include <string>

namespace cardkey {

class Signer {
public:
    static constexpr const char *Version = "v1";

    static constexpr const char *HeaderAppId = "X-App-Id";
    static constexpr const char *HeaderTimestamp = "X-Timestamp";
    static constexpr const char *HeaderNonce = "X-Nonce";
    static constexpr const char *HeaderSignature = "X-Signature";
    static constexpr const char *HeaderVersion = "X-Signature-Version";
    static constexpr const char *HeaderResponseTimestamp = "X-Response-Timestamp";
    static constexpr const char *HeaderResponseSignature = "X-Response-Signature";

    /**
     * 路径归一化：去查询串与 fragment、折叠重复斜杠、去末尾斜杠（根路径除外）。
     * 与服务端 ApiSigner::normalizePath() 行为一致。
     */
    static std::string normalizePath(const std::string &path) {
        // 去掉查询串与 fragment
        std::size_t cut = path.find_first_of("?#");
        std::string result = (cut == std::string::npos) ? path : path.substr(0, cut);

        if (result.empty()) {
            return "/";
        }

        // 折叠重复斜杠
        std::string collapsed;
        collapsed.reserve(result.size());
        for (char c : result) {
            if (c == '/' && !collapsed.empty() && collapsed.back() == '/') {
                continue;
            }
            collapsed += c;
        }

        // 去掉末尾斜杠，但保留根路径
        if (collapsed.size() > 1 && collapsed.back() == '/') {
            collapsed.pop_back();
        }

        return collapsed;
    }

    /**
     * 组装待签名字符串。
     */
    static std::string canonicalString(const std::string &method, const std::string &path,
                                       const std::string &timestamp, const std::string &nonce,
                                       const std::string &rawBody) {
        std::string upperMethod;
        upperMethod.reserve(method.size());
        for (char c : method) {
            upperMethod += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }

        return upperMethod + "\n" +
               normalizePath(path) + "\n" +
               timestamp + "\n" +
               nonce + "\n" +
               crypto::toHex(crypto::Sha256::hash(rawBody));
    }

    /**
     * 计算签名（小写十六进制）。
     */
    static std::string sign(const std::string &appSecret, const std::string &canonical) {
        return crypto::toHex(crypto::HmacSha256::mac(appSecret, canonical));
    }

    /**
     * 一步到位计算请求签名。
     */
    static std::string signRequest(const std::string &appSecret, const std::string &method,
                                   const std::string &path, const std::string &timestamp,
                                   const std::string &nonce, const std::string &rawBody) {
        return sign(appSecret, canonicalString(method, path, timestamp, nonce, rawBody));
    }

    /**
     * 响应验签。
     *
     *   X-Response-Signature = HEX(HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + SHA256_HEX(body)))
     *
     * 注意：rawResponseBody 必须是实际收到的原始字节，不能先解析 JSON 再重新序列化。
     */
    static std::string responseCanonical(const std::string &timestamp, const std::string &requestNonce,
                                         const std::string &rawResponseBody) {
        return timestamp + "\n" + requestNonce + "\n" +
               crypto::toHex(crypto::Sha256::hash(rawResponseBody));
    }

    static std::string signResponse(const std::string &appSecret, const std::string &rawResponseBody,
                                    const std::string &timestamp, const std::string &requestNonce) {
        return sign(appSecret, responseCanonical(timestamp, requestNonce, rawResponseBody));
    }

    /**
     * 常量时间比对验签结果。
     */
    static bool verifyResponse(const std::string &appSecret, const std::string &rawResponseBody,
                               const std::string &responseTimestamp, const std::string &requestNonce,
                               const std::string &signature) {
        const std::string expected =
            signResponse(appSecret, rawResponseBody, responseTimestamp, requestNonce);

        // 兼容客户端/服务端大小写差异
        std::string normalized = signature;
        for (char &c : normalized) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        return crypto::constantTimeEquals(expected, normalized);
    }

    /**
     * 生成随机 nonce（十六进制，默认 16 字节 = 32 字符）。
     */
    static std::string generateNonce(std::size_t bytes = 16) {
        const crypto::Bytes raw = crypto::randomBytes(bytes);
        return crypto::toHex(raw);
    }
};

} // namespace cardkey

// ============================================================================
//  卡密传输加密（严格对应服务端 app/Support/CardTransportCrypto.php）
//
//  加密密钥 = HKDF-SHA256(ikm = AppSecret, salt = AppID, info = "cardkey-enc-v1", L = 32)
//  算法     = AES-256-GCM，AAD = AppID，IV = 12 字节随机
//
//  载荷统一格式（各语言模板一致）：
//    {
//      "iv":   base64(12 字节随机数),
//      "data": base64(密文),
//      "tag":  base64(16 字节认证标签)
//    }
//
//  安全要求：
//    - 每次加密必须生成新的 IV，禁止在同一密钥下复用。
//    - tag 校验失败必须拒绝数据，不能返回未认证的明文。
//    - AAD 固定为 AppID，防止把 A 应用的密文拿到 B 应用重放。
// ============================================================================


#include <string>

// ===== 以下为传输加密部分 =====
namespace cardkey {

struct TransportPayload {
    std::string iv;
    std::string data;
    std::string tag;

    Json toJson() const {
        Json json = Json::object();
        json.set("iv", iv);
        json.set("data", data);
        json.set("tag", tag);
        return json;
    }

    static TransportPayload fromJson(const Json &json) {
        TransportPayload payload;
        payload.iv = json["iv"].asString();
        payload.data = json["data"].asString();
        payload.tag = json["tag"].asString();
        return payload;
    }
};

class TransportCrypto {
public:
    static constexpr const char *Info = "cardkey-enc-v1";
    static constexpr std::size_t IvLength = 12;
    static constexpr std::size_t TagLength = 16;
    static constexpr std::size_t KeyLength = 32;

    /**
     * 从 AppSecret 派生传输加密密钥。
     */
    static crypto::Bytes deriveKey(const std::string &appSecret, const std::string &appId) {
        return crypto::hkdfSha256(appSecret, appId, Info, KeyLength);
    }

    /**
     * 加密卡密，返回可 JSON 序列化的载荷。
     */
    static TransportPayload encrypt(const std::string &plaintext, const std::string &appSecret,
                                    const std::string &appId) {
        const crypto::Bytes key = deriveKey(appSecret, appId);
        const crypto::Bytes iv = crypto::randomBytes(IvLength);
        const crypto::Bytes aad(appId.begin(), appId.end());
        const crypto::Bytes input(plaintext.begin(), plaintext.end());

        const crypto::Aes256Gcm gcm(key);
        crypto::Bytes tag;
        const crypto::Bytes ciphertext = gcm.encrypt(iv, input, aad, tag);

        TransportPayload payload;
        payload.iv = crypto::base64Encode(iv);
        payload.data = crypto::base64Encode(ciphertext);
        payload.tag = crypto::base64Encode(tag);
        return payload;
    }

    /**
     * 解密服务端返回的加密载荷（如未来接口返回加密内容时使用）。
     *
     * @throws std::runtime_error 载荷格式错误或认证失败
     */
    static std::string decrypt(const TransportPayload &payload, const std::string &appSecret,
                               const std::string &appId) {
        const crypto::Bytes iv = crypto::base64Decode(payload.iv);
        const crypto::Bytes ciphertext = crypto::base64Decode(payload.data);
        const crypto::Bytes tag = crypto::base64Decode(payload.tag);

        if (iv.size() != IvLength) {
            throw std::runtime_error("IV 长度必须为 12 字节");
        }
        if (tag.size() != TagLength) {
            throw std::runtime_error("认证标签长度必须为 16 字节");
        }

        const crypto::Bytes key = deriveKey(appSecret, appId);
        const crypto::Bytes aad(appId.begin(), appId.end());

        const crypto::Aes256Gcm gcm(key);
        const crypto::Bytes plaintext = gcm.decrypt(iv, ciphertext, tag, aad);

        return std::string(plaintext.begin(), plaintext.end());
    }

    /**
     * 判断 JSON 值是否为加密载荷对象（含 iv/data/tag 三个字段）。
     */
    static bool isEncryptedPayload(const Json &value) {
        return value.isObject() && value.has("iv") && value.has("data") && value.has("tag");
    }
};

} // namespace cardkey
