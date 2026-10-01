// 临时验证：对照服务端 conformance 向量校验密码学原语
#if !defined(__ANDROID__)
#error "本测试仅支持 Android。请用 NDK 编译（见 安卓CMake.txt）。"
#endif

#include "卡密/基础算法.h"
#include "卡密/分组加密.h"

#include <cstdio>
#include <string>

using namespace cardkey::crypto;

static int failures = 0;

static void check(const char *name, const std::string &actual, const std::string &expected) {
    const bool ok = (actual == expected);
    if (!ok) ++failures;
    std::printf("%-40s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        std::printf("    expected: %s\n", expected.c_str());
        std::printf("    actual:   %s\n", actual.c_str());
    }
}

int main() {
    // ---- SHA-256 已知向量 ----
    check("sha256(abc)", toHex(Sha256::hash(std::string("abc"))),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("sha256(empty)", toHex(Sha256::hash(std::string(""))),
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // ---- HMAC-SHA256 RFC 4231 向量 ----
    {
        Bytes key(20, 0x0b);
        check("hmac-sha256 rfc4231 case1",
              toHex(HmacSha256::mac(std::string(key.begin(), key.end()), std::string("Hi There"))),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    // ---- 服务端 signature-v1.json ----
    {
        const std::string secret = "sk_test_secret_for_vectors_do_not_use";
        const std::string rawBody =
            "{\"card_key\":\"ABCD-EFGH-JKMN-PQRS\",\"device_id\":\"device-001\"}";

        check("vector body_sha256", toHex(Sha256::hash(rawBody)),
              "d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb");

        const std::string canonical = "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\n" +
                                      toHex(Sha256::hash(rawBody));
        check("vector canonical", canonical,
              "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\n"
              "d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb");

        check("vector signature", toHex(HmacSha256::mac(secret, canonical)),
              "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e");
    }

    // ---- 服务端 transport-v1.json ----
    {
        const std::string appId = "ak_test_0000000000000000";
        const std::string secret = "sk_test_secret_for_vectors_do_not_use";

        const Bytes key = hkdfSha256(secret, appId, "cardkey-enc-v1", 32);
        check("vector hkdf key_hex", toHex(key),
              "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a");

        const Bytes iv = base64Decode("AAECAwQFBgcICQoL");
        const Bytes data = base64Decode("Dpzc19OrLLuiUzBnVjZ58nx01g==");
        const Bytes tag = base64Decode("OgQTxDEviBNBjrGdUcPfPw==");
        const Bytes aad(appId.begin(), appId.end());

        check("vector iv length", std::to_string(iv.size()), "12");
        check("vector tag length", std::to_string(tag.size()), "16");

        const Aes256Gcm gcm(key);
        const Bytes plain = gcm.decrypt(iv, data, tag, aad);
        check("vector gcm decrypt", std::string(plain.begin(), plain.end()), "ABCD-EFGH-JKMN-PQRS");

        // 反向：用同一 IV 加密必须得到相同的密文与 tag
        Bytes reTag;
        const Bytes reCipher = gcm.encrypt(iv, plain, aad, reTag);
        check("vector gcm encrypt data", base64Encode(reCipher), "Dpzc19OrLLuiUzBnVjZ58nx01g==");
        check("vector gcm encrypt tag", base64Encode(reTag), "OgQTxDEviBNBjrGdUcPfPw==");

        // 篡改密文必须被拒绝
        Bytes tampered = data;
        tampered[0] ^= 0x01;
        bool rejected = false;
        try {
            gcm.decrypt(iv, tampered, tag, aad);
        } catch (const std::exception &) {
            rejected = true;
        }
        check("gcm rejects tampered ciphertext", rejected ? "yes" : "no", "yes");

        // 错误 AAD 必须被拒绝
        rejected = false;
        try {
            const Bytes wrongAad = {'x'};
            gcm.decrypt(iv, data, tag, wrongAad);
        } catch (const std::exception &) {
            rejected = true;
        }
        check("gcm rejects wrong aad", rejected ? "yes" : "no", "yes");
    }

    // ---- Base64 往返 ----
    {
        const std::string original = "ABCD-EFGH-JKMN-PQRS";
        const std::string encoded = base64Encode(
            reinterpret_cast<const std::uint8_t *>(original.data()), original.size());
        check("base64 encode", encoded, "QUJDRC1FRkdILUpLTU4tUFFSUw==");

        const Bytes decoded = base64Decode(encoded);
        check("base64 roundtrip", std::string(decoded.begin(), decoded.end()), original);
    }

    // ---- 随机数不重复 ----
    {
        const Bytes a = randomBytes(16);
        const Bytes b = randomBytes(16);
        check("randomBytes differ", (a != b) ? "yes" : "no", "yes");
        check("randomBytes length", std::to_string(a.size()), "16");
    }

    std::printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
