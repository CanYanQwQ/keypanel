// ============================================================================
//  协议自检
//
//  对照服务端 docs/conformance/*.json 与 app/Support/*.php 的行为，
//  逐项验证本模板生成的请求与签名是否与服务端期望完全一致。
//
//  编译运行：
//    g++ -std=c++17 -I include -Wall -Wextra -O2 tests/protocol_test.cpp -o protocol_test
//    ./protocol_test
// ============================================================================

#if !defined(__ANDROID__)
#error "本测试仅支持 Android。请用 NDK 编译（见 安卓CMake.txt）。"
#endif

#include "卡密/卡密验证.h"
#include "卡密/精简JSON.h"
#include "卡密/协议加密.h"
#include "卡密/协议加密.h"

#include <cstdio>
#include <string>

using namespace cardkey;

static int g_failures = 0;

static void check(const char *name, const std::string &actual, const std::string &expected) {
    const bool ok = (actual == expected);
    if (!ok) ++g_failures;
    std::printf("%-46s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        std::printf("    期望: %s\n", expected.c_str());
        std::printf("    实际: %s\n", actual.c_str());
    }
}

static void checkBool(const char *name, bool actual) {
    if (!actual) ++g_failures;
    std::printf("%-46s %s\n", name, actual ? "PASS" : "FAIL");
}

// ============================================================================
//  1. 签名规范（signature-v1.json）
// ============================================================================
static void testSignatureVector() {
    std::printf("\n[1] 签名规范（服务端 signature-v1.json）\n");

    const std::string appId = "ak_test_0000000000000000";
    const std::string appSecret = "sk_test_secret_for_vectors_do_not_use";
    const std::string method = "POST";
    const std::string path = "/api/v1/verify";
    const std::string timestamp = "1700000000";
    const std::string nonce = "00112233445566778899aabbccddeeff";
    const std::string rawBody =
        "{\"card_key\":\"ABCD-EFGH-JKMN-PQRS\",\"device_id\":\"device-001\"}";

    check("body SHA256",
          crypto::toHex(crypto::Sha256::hash(rawBody)),
          "d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb");

    check("canonical string",
          Signer::canonicalString(method, path, timestamp, nonce, rawBody),
          "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\n"
          "d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb");

    check("X-Signature",
          Signer::signRequest(appSecret, method, path, timestamp, nonce, rawBody),
          "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e");

    (void)appId;
}

// ============================================================================
//  2. 路径归一化（对应 ApiSigner::normalizePath）
// ============================================================================
static void testPathNormalization() {
    std::printf("\n[2] 路径归一化\n");

    check("去掉查询串", Signer::normalizePath("/api/v1/verify?a=1"), "/api/v1/verify");
    check("去掉 fragment", Signer::normalizePath("/api/v1/verify#x"), "/api/v1/verify");
    check("折叠重复斜杠", Signer::normalizePath("/api//v1///verify"), "/api/v1/verify");
    check("去掉末尾斜杠", Signer::normalizePath("/api/v1/verify/"), "/api/v1/verify");
    check("保留根路径", Signer::normalizePath("/"), "/");
    check("空串归一为根", Signer::normalizePath(""), "/");
    check("组合场景", Signer::normalizePath("//api//v1/verify/?a=1#b"), "/api/v1/verify");
}

// ============================================================================
//  3. 传输加密（transport-v1.json）
// ============================================================================
static void testTransportVector() {
    std::printf("\n[3] 传输加密（服务端 transport-v1.json）\n");

    const std::string appId = "ak_test_0000000000000000";
    const std::string appSecret = "sk_test_secret_for_vectors_do_not_use";

    check("HKDF 派生密钥",
          crypto::toHex(TransportCrypto::deriveKey(appSecret, appId)),
          "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a");

    TransportPayload payload;
    payload.iv = "AAECAwQFBgcICQoL";
    payload.data = "Dpzc19OrLLuiUzBnVjZ58nx01g==";
    payload.tag = "OgQTxDEviBNBjrGdUcPfPw==";

    check("解密服务端载荷",
          TransportCrypto::decrypt(payload, appSecret, appId),
          "ABCD-EFGH-JKMN-PQRS");
}

// ============================================================================
//  4. 加密载荷格式与随机 IV
// ============================================================================
static void testPayloadFormat() {
    std::printf("\n[4] 加密载荷格式\n");

    const std::string appId = "ak_test_0000000000000000";
    const std::string appSecret = "sk_test_secret_for_vectors_do_not_use";
    const std::string cardKey = "ABCD-EFGH-JKMN-PQRS";

    const TransportPayload first = TransportCrypto::encrypt(cardKey, appSecret, appId);

    check("载荷可被服务端解密",
          TransportCrypto::decrypt(first, appSecret, appId), cardKey);

    check("IV 为 12 字节", std::to_string(crypto::base64Decode(first.iv).size()), "12");
    check("tag 为 16 字节", std::to_string(crypto::base64Decode(first.tag).size()), "16");

    // 每次加密必须使用新 IV
    const TransportPayload second = TransportCrypto::encrypt(cardKey, appSecret, appId);
    checkBool("两次加密 IV 不同", first.iv != second.iv);
    checkBool("两次加密密文不同", first.data != second.data);

    // JSON 对象形态可被识别
    checkBool("isEncryptedPayload 识别对象", TransportCrypto::isEncryptedPayload(first.toJson()));
    checkBool("isEncryptedPayload 拒绝字符串", !TransportCrypto::isEncryptedPayload(Json("plain")));
}

// ============================================================================
//  5. 响应验签（对应 ApiSigner::signResponse）
// ============================================================================
static void testResponseSignature() {
    std::printf("\n[5] 响应验签\n");

    const std::string appSecret = "sk_test_secret_for_vectors_do_not_use";
    const std::string rawResponse =
        "{\"code\":0,\"message\":\"操作成功\",\"success\":true,\"server_time\":1700000000}";
    const std::string responseTimestamp = "1700000000";
    const std::string requestNonce = "00112233445566778899aabbccddeeff";

    const std::string signature =
        Signer::signResponse(appSecret, rawResponse, responseTimestamp, requestNonce);

    checkBool("正确签名通过校验",
              Signer::verifyResponse(appSecret, rawResponse, responseTimestamp, requestNonce, signature));

    checkBool("篡改响应体被拒绝",
              !Signer::verifyResponse(appSecret, rawResponse + " ", responseTimestamp,
                                      requestNonce, signature));

    checkBool("错误 nonce 被拒绝",
              !Signer::verifyResponse(appSecret, rawResponse, responseTimestamp,
                                      "ffffffffffffffffffffffffffffffff", signature));

    // 大写签名应被接受（对应服务端统一小写后比对的做法）
    std::string upper = signature;
    for (char &c : upper) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    checkBool("大写签名同样通过", Signer::verifyResponse(
                                      appSecret, rawResponse, responseTimestamp, requestNonce, upper));
}

// ============================================================================
//  6. 请求体构造（对应 CardKeyController 的字段校验规则）
// ============================================================================
static void testRequestBody() {
    std::printf("\n[6] 请求体构造\n");

    ClientConfig config;
    config.baseUrl = "http://127.0.0.1:8000";
    config.appId = "ak_test_0000000000000000";
    config.appSecret = "sk_test_secret_for_vectors_do_not_use";
    config.deviceId = "device-001";

    CardKeyClient client(config);

    // 加密后的 card_key 必须是对象，且能被服务端解密
    const Json encrypted = client.encryptCardKey("ABCD-EFGH-JKMN-PQRS");
    checkBool("card_key 是加密对象", TransportCrypto::isEncryptedPayload(encrypted));

    const TransportPayload payload = TransportPayload::fromJson(encrypted);
    check("card_key 可被服务端解密",
          TransportCrypto::decrypt(payload, config.appSecret, config.appId),
          "ABCD-EFGH-JKMN-PQRS");

    // 未设置 device_id 时不应出现该字段
    ClientConfig noDevice = config;
    noDevice.deviceId.clear();
    CardKeyClient clientNoDevice(noDevice);
    checkBool("无设备时仍能构造客户端", clientNoDevice.config().deviceId.empty());
}

// ============================================================================
//  7. JSON 解析
// ============================================================================
static void testJsonParsing() {
    std::printf("\n[7] JSON 解析\n");

    const std::string text =
        "{\"code\":0,\"success\":true,\"message\":\"操作成功\","
        "\"data\":{\"status\":\"activated\",\"type\":\"time\","
        "\"expires_at\":\"2026-10-31T00:00:00+00:00\",\"remaining_uses\":null,"
        "\"device_bound\":true},\"server_time\":1700000000}";

    const Json parsed = Json::parse(text);

    check("code", std::to_string(parsed["code"].asInt()), "0");
    checkBool("success", parsed["success"].asBool());
    check("message", parsed["message"].asString(), "操作成功");
    check("data.status", parsed["data"]["status"].asString(), "activated");
    check("data.type", parsed["data"]["type"].asString(), "time");
    checkBool("remaining_uses 为 null", parsed["data"]["remaining_uses"].isNull());
    checkBool("device_bound", parsed["data"]["device_bound"].asBool());
    check("server_time", std::to_string(parsed["server_time"].asInt()), "1700000000");

    // 缺失字段返回 Null 而不是崩溃
    checkBool("缺失字段安全返回", parsed["data"]["nonexistent"].isNull());

    // 非对象上的下标访问也应安全
    checkBool("字符串下标访问安全", parsed["message"]["nested"].isNull());

    // 序列化往返
    Json built = Json::object();
    built.set("card_key", "ABC");
    built.set("count", 3);
    built.set("force", true);
    check("序列化", built.dump(), "{\"card_key\":\"ABC\",\"count\":3,\"force\":true}");

    // 转义
    Json escaped = Json::object();
    escaped.set("text", std::string("a\"b\\c\nd"));
    check("字符串转义", escaped.dump(), "{\"text\":\"a\\\"b\\\\c\\nd\"}");

    // 中文与 Unicode 转义
    check("中文原样输出", Json(std::string("卡密")).dump(), "\"卡密\"");
    check("\\u 转义解析", Json::parse("\"\\u5361\\u5bc6\"").asString(), "卡密");
}

// ============================================================================
//  8. 错误码镜像（对应 docs/templates/shared/error-codes.json）
// ============================================================================
static void testErrorCodes() {
    std::printf("\n[8] 错误码镜像\n");

    struct Case {
        int value;
        ApiErrorCode code;
        const char *name;
        const char *message;
    };

    const Case cases[] = {
        {0, ApiErrorCode::Success, "Success", "操作成功"},
        {1001, ApiErrorCode::InvalidParams, "InvalidParams", "请求参数不合法"},
        {1004, ApiErrorCode::SignatureInvalid, "SignatureInvalid", "签名验证失败"},
        {1006, ApiErrorCode::NonceReused, "NonceReused", "随机数已被使用（疑似重放请求）"},
        {1011, ApiErrorCode::DecryptFailed, "DecryptFailed", "卡密解密失败，请检查加密参数"},
        {2001, ApiErrorCode::CardNotFound, "CardNotFound", "卡密不存在"},
        {2005, ApiErrorCode::CardDepleted, "CardDepleted", "卡密次数已用完"},
        {2007, ApiErrorCode::DeviceMismatch, "DeviceMismatch", "设备不匹配，该卡密已绑定其他设备"},
        {2010, ApiErrorCode::CardTypeUnsupported, "CardTypeUnsupported", "当前卡密类型不支持该操作"},
        {5000, ApiErrorCode::ServerError, "ServerError", "服务器内部错误"},
    };

    for (const Case &item : cases) {
        ApiErrorCode parsed = ApiErrorCode::ServerError;
        const bool known = apiErrorCodeFromInt(item.value, parsed);

        char label[80];
        std::snprintf(label, sizeof(label), "%s 码值与名称", item.name);

        checkBool(label, known && parsed == item.code);

        std::snprintf(label, sizeof(label), "%s 消息", item.name);
        check(label, apiErrorMessage(item.code), item.message);
    }

    // 未知业务码必须被识别为未知（不得静默当成功）
    ApiErrorCode unknown = ApiErrorCode::Success;
    checkBool("未知码 9999 返回 false", !apiErrorCodeFromInt(9999, unknown));
    checkBool("未知码不改变输出", unknown == ApiErrorCode::Success);
}

// ============================================================================
//  9. 客户端参数校验
// ============================================================================
static void testClientValidation() {
    std::printf("\n[9] 客户端参数校验\n");

    bool threw = false;
    try {
        ClientConfig empty;
        empty.baseUrl = "http://127.0.0.1:8000";
        CardKeyClient client(empty);
    } catch (const std::exception &) {
        threw = true;
    }
    checkBool("缺少 appId/appSecret 时抛异常", threw);

    threw = false;
    try {
        ClientConfig noUrl;
        noUrl.appId = "ak_x";
        noUrl.appSecret = "sk_x";
        CardKeyClient client(noUrl);
    } catch (const std::exception &) {
        threw = true;
    }
    checkBool("缺少 baseUrl 时抛异常", threw);

    // 末尾斜杠应被规范化
    ClientConfig trailing;
    trailing.baseUrl = "http://127.0.0.1:8000///";
    trailing.appId = "ak_x";
    trailing.appSecret = "sk_x";
    CardKeyClient client(trailing);
    check("baseUrl 去掉末尾斜杠", client.config().baseUrl, "http://127.0.0.1:8000");
}

// ============================================================================
//  10. URL 解析
// ============================================================================
static void testUrlParsing() {
    std::printf("\n[10] URL 解析\n");

    const ParsedUrl a = parseUrl("http://127.0.0.1:8000/api/v1/verify");
    check("scheme", a.scheme, "http");
    check("host", a.host, "127.0.0.1");
    check("port", std::to_string(a.port), "8000");
    check("path", a.path, "/api/v1/verify");

    const ParsedUrl b = parseUrl("https://card.example.com/api/v1/verify");
    check("https 默认端口", std::to_string(b.port), "443");
    check("https host", b.host, "card.example.com");

    const ParsedUrl c = parseUrl("http://example.com");
    check("无路径时默认根", c.path, "/");
    check("http 默认端口", std::to_string(c.port), "80");

    bool threw = false;
    try {
        parseUrl("ftp://example.com/x");
    } catch (const std::exception &) {
        threw = true;
    }
    checkBool("不支持协议时抛异常", threw);
}

// ============================================================================
//  11. 请求字节构造（签名与发送必须使用同一份 body）
// ============================================================================
static void testRequestBytes() {
    std::printf("\n[11] 请求字节构造\n");

    const std::string body = "{\"card_key\":{\"iv\":\"a\",\"data\":\"b\",\"tag\":\"c\"}}";

    HttpRequest request;
    request.method = "POST";
    request.url = "http://127.0.0.1:8000/api/v1/verify";
    request.body = body;
    request.setHeader("Content-Type", "application/json; charset=utf-8");
    request.setHeader(Signer::HeaderAppId, "ak_test");

    const ParsedUrl parsed = parseUrl(request.url);
    const std::string raw = request.build(parsed);

    checkBool("请求行正确", raw.rfind("POST /api/v1/verify HTTP/1.1\r\n", 0) == 0);
    checkBool("含 Host 头", raw.find("Host: 127.0.0.1:8000\r\n") != std::string::npos);
    checkBool("含 Content-Length",
              raw.find("Content-Length: " + std::to_string(body.size()) + "\r\n") != std::string::npos);
    checkBool("含空行分隔", raw.find("\r\n\r\n") != std::string::npos);

    // 请求体必须原样附加在头部之后，未被重新序列化
    const std::size_t bodyPos = raw.find("\r\n\r\n") + 4;
    check("请求体字节一致", raw.substr(bodyPos), body);

    // 签名覆盖的必须是同一份字节
    const std::string signature = Signer::signRequest("sk_test", "POST", "/api/v1/verify",
                                                     "1700000000", "nonce", raw.substr(bodyPos));
    const std::string expected = Signer::signRequest("sk_test", "POST", "/api/v1/verify",
                                                     "1700000000", "nonce", body);
    check("签名覆盖实际发送字节", signature, expected);
}

// ============================================================================
int main() {
    std::printf("CardKey 客户端模板 —— 协议自检\n");
    std::printf("==============================================\n");

    testSignatureVector();
    testPathNormalization();
    testTransportVector();
    testPayloadFormat();
    testResponseSignature();
    testRequestBody();
    testJsonParsing();
    testErrorCodes();
    testClientValidation();
    testUrlParsing();
    testRequestBytes();

    std::printf("\n==============================================\n");
    if (g_failures == 0) {
        std::printf("全部通过（0 项失败）\n");
        return 0;
    }
    std::printf("存在失败：%d 项\n", g_failures);
    return 1;
}
