// ============================================================================
//  端到端联调测试
//
//  对着真实运行的 Laravel 服务端跑完整链路：
//    verify / activate / consume / query / unbind
//
//  凭据全部从环境变量读取，不写入任何文件：
//    CARDKEY_BASE_URL   服务端地址，如 http://127.0.0.1:8000
//    CARDKEY_APP_ID     AppID
//    CARDKEY_APP_SECRET AppSecret
//    CARDKEY_TEST_CARD  测试卡密明文
//    CARDKEY_DEVICE_ID  设备指纹（可选，默认 e2e-device-001）
//
//  编译运行：
//    g++ -std=c++17 -I include -Wall -Wextra -O2 tests/e2e_test.cpp -o e2e_test
//    ./e2e_test
// ============================================================================

// 测试环境默认关闭反调试，避免干扰；可用 -DCARDKEY_HARDENED=1 覆盖
#ifndef CARDKEY_HARDENED
#define CARDKEY_HARDENED 0
#endif

#if !defined(__ANDROID__)
#error "本测试仅支持 Android。请用 NDK 编译（见 安卓CMake.txt）。"
#endif

#include "卡密/卡密验证.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace cardkey;

static int g_failures = 0;

static void check(const char *name, bool ok, const std::string &detail = std::string()) {
    if (!ok) ++g_failures;
    std::printf("%-52s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok && !detail.empty()) {
        std::printf("    -> %s\n", detail.c_str());
    }
}

static std::string envOr(const char *key, const std::string &fallback = std::string()) {
    const char *value = std::getenv(key);
    return (value == nullptr || *value == '\0') ? fallback : std::string(value);
}

int main() {
    const std::string baseUrl = envOr("CARDKEY_BASE_URL");
    const std::string appId = envOr("CARDKEY_APP_ID");
    const std::string appSecret = envOr("CARDKEY_APP_SECRET");
    const std::string testCard = envOr("CARDKEY_TEST_CARD");
    const std::string deviceId = envOr("CARDKEY_DEVICE_ID", "e2e-device-001");

    if (baseUrl.empty() || appId.empty() || appSecret.empty() || testCard.empty()) {
        std::printf("缺少环境变量：需要 CARDKEY_BASE_URL / CARDKEY_APP_ID / "
                    "CARDKEY_APP_SECRET / CARDKEY_TEST_CARD\n");
        return 2;
    }

    std::printf("CardKey 客户端模板 —— 端到端联调\n");
    std::printf("==============================================\n");
    std::printf("服务端：%s\n", baseUrl.c_str());
    std::printf("AppID ：%s\n", appId.c_str());
    std::printf("设备  ：%s\n", deviceId.c_str());
    std::printf("（AppSecret 与卡密不打印）\n\n");

    ClientConfig config;
    config.baseUrl = baseUrl;
    config.appId = appId;
    config.appSecret = appSecret;
    config.deviceId = deviceId;
    config.timeoutSeconds = 10;

    CardKeyClient client(config);

    // ========================================================================
    //  1. verify —— 首次校验，应触发设备自动绑定
    // ========================================================================
    std::printf("[1] verify（首次校验）\n");
    {
        const ApiResult result = client.verify(testCard);
        std::printf("    HTTP=%d code=%d known=%d success=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.knownCode ? 1 : 0,
                    result.success ? 1 : 0, result.message.c_str());

        check("HTTP 状态为 200", result.httpStatus == 200,
              "实际 " + std::to_string(result.httpStatus));
        check("业务码为 0", result.rawCode == 0, "实际 " + std::to_string(result.rawCode));
        check("success 为 true", result.success, result.describe());
        check("返回响应签名头", result.responseSigned);
        check("响应签名校验通过", result.responseSignatureVerified);
        check("data 含 status 字段", result.data.has("status"));
        check("data 含 type 字段", result.data.has("type"));

        if (result.data.has("device_bound")) {
            check("设备已绑定", result.data["device_bound"].asBool());
        }
    }

    // ========================================================================
    //  2. query —— 同设备查询应通过
    // ========================================================================
    std::printf("\n[2] query（同设备查询）\n");
    {
        const ApiResult result = client.query(testCard);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("查询成功", result.success, result.describe());
        check("响应签名校验通过", result.responseSignatureVerified);
    }

    // ========================================================================
    //  3. 设备不匹配 —— 换一个设备应被拒绝
    // ========================================================================
    std::printf("\n[3] verify（不同设备，应被拒绝）\n");
    {
        ClientConfig other = config;
        other.deviceId = "e2e-device-999";
        CardKeyClient otherClient(other);

        const ApiResult result = otherClient.verify(testCard);
        std::printf("    HTTP=%d code=%d known=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.knownCode ? 1 : 0,
                    result.message.c_str());

        check("业务码为 DeviceMismatch(2007)",
              result.code == ApiErrorCode::DeviceMismatch,
              "实际 code=" + std::to_string(result.rawCode));
        check("success 为 false", !result.success);
        // 业务失败使用 HTTP 200，客户端必须靠 code 判断
        check("HTTP 仍为 200（业务失败靠 code 判断）", result.httpStatus == 200,
              "实际 " + std::to_string(result.httpStatus));
    }

    // ========================================================================
    //  4. activate —— 激活（幂等）
    // ========================================================================
    std::printf("\n[4] activate\n");
    {
        const ApiResult result = client.activate(testCard);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("激活成功", result.success, result.describe());
        check("响应签名校验通过", result.responseSignatureVerified);

        if (result.data.has("activated")) {
            check("activated 为 true", result.data["activated"].asBool());
        }
        if (result.data.has("expires_at")) {
            std::printf("    到期时间：%s\n", result.data["expires_at"].asString().c_str());
        }
    }

    // ========================================================================
    //  5. 错误路径 —— 不存在的卡密
    // ========================================================================
    std::printf("\n[5] verify（不存在的卡密）\n");
    {
        const ApiResult result = client.verify("ZZZZ-ZZZZ-ZZZZ-ZZZZ");
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("业务码为 CardNotFound(2001)",
              result.code == ApiErrorCode::CardNotFound,
              "实际 code=" + std::to_string(result.rawCode));
        check("success 为 false", !result.success);
    }

    // ========================================================================
    //  6. 错误路径 —— 错误 AppSecret 导致验签失败
    // ========================================================================
    std::printf("\n[6] verify（错误的 AppSecret）\n");
    {
        ClientConfig bad = config;
        bad.appSecret = "sk_wrong_secret_for_e2e_test_0000000000000000000000";
        CardKeyClient badClient(bad);

        const ApiResult result = badClient.verify(testCard);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("业务码为 SignatureInvalid(1004)",
              result.code == ApiErrorCode::SignatureInvalid,
              "实际 code=" + std::to_string(result.rawCode));
        check("success 为 false", !result.success);
    }

    // ========================================================================
    //  7. consume —— 次数卡扣次（非次数卡应返回 CardTypeUnsupported）
    // ========================================================================
    std::printf("\n[7] consume\n");
    {
        const ApiResult result = client.consume(testCard, 1);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        if (result.code == ApiErrorCode::CardTypeUnsupported) {
            check("非次数卡返回 CardTypeUnsupported(2010)",
                  result.code == ApiErrorCode::CardTypeUnsupported);
        } else {
            check("次数卡扣次成功", result.success, result.describe());
            if (result.data.has("consumed")) {
                std::printf("    本次扣减：%lld，剩余：%lld\n",
                            result.data["consumed"].asInt(),
                            result.data["remaining"].asInt());
            }
        }
    }

    // ========================================================================
    //  7b. consume —— 次数卡（可选，通过 CARDKEY_TEST_COUNT_CARD 提供）
    // ========================================================================
    const std::string countCard = envOr("CARDKEY_TEST_COUNT_CARD");
    if (!countCard.empty()) {
        std::printf("\n[7b] consume（次数卡）\n");

        ClientConfig countConfig = config;
        countConfig.deviceId = "e2e-count-device";
        CardKeyClient countClient(countConfig);

        const ApiResult first = countClient.consume(countCard, 3);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    first.httpStatus, first.rawCode, first.message.c_str());

        check("次数卡扣次成功", first.success, first.describe());
        check("本次扣减 3 次", first.data["consumed"].asInt() == 3,
              "实际 " + std::to_string(first.data["consumed"].asInt()));
        std::printf("    剩余次数：%lld\n", first.data["remaining"].asInt());

        // 扣减后的剩余必须单调递减
        const ApiResult second = countClient.consume(countCard, 1);
        check("再次扣次成功", second.success, second.describe());
        check("剩余次数递减",
              second.data["remaining"].asInt() < first.data["remaining"].asInt(),
              "前 " + std::to_string(first.data["remaining"].asInt()) +
                  " 后 " + std::to_string(second.data["remaining"].asInt()));
    }

    // ========================================================================
    //  8. 重放保护 —— 同一个 nonce 重复提交必须被拒绝
    // ========================================================================
    std::printf("\n[8] 重放保护\n");
    {
        // 这里通过"同一签名请求发两次"验证：
        // 由于每次 call() 都会生成新 nonce，需要手工构造重放请求。
        const std::string path = "/api/v1/query";
        Json body = Json::object();
        body.set("card_key", client.encryptCardKey(testCard));
        const std::string rawBody = body.dump();

        const std::string timestamp = crypto::unixTimestamp();
        const std::string nonce = Signer::generateNonce();
        const std::string signature =
            Signer::signRequest(appSecret, "POST", path, timestamp, nonce, rawBody);

        auto sendOnce = [&]() {
            HttpRequest request;
            request.method = "POST";
            request.url = baseUrl + path;
            request.body = rawBody;
            request.setHeader("Content-Type", "application/json; charset=utf-8");
            request.setHeader(Signer::HeaderAppId, appId);
            request.setHeader(Signer::HeaderTimestamp, timestamp);
            request.setHeader(Signer::HeaderNonce, nonce);
            request.setHeader(Signer::HeaderVersion, Signer::Version);
            request.setHeader(Signer::HeaderSignature, signature);
            return httpSend(request);
        };

        const HttpResponse first = sendOnce();
        const HttpResponse second = sendOnce();

        std::printf("    第一次 HTTP=%d，第二次 HTTP=%d\n", first.statusCode, second.statusCode);

        check("第一次请求通过", first.statusCode == 200,
              "实际 " + std::to_string(first.statusCode));
        check("第二次（重放）被拒绝为 401", second.statusCode == 401,
              "实际 " + std::to_string(second.statusCode));

        const Json secondBody = Json::tryParse(second.rawBody);
        check("重放返回 NonceReused(1006)",
              secondBody["code"].asInt(-1) == 1006,
              "实际 code=" + std::to_string(secondBody["code"].asInt(-1)));
    }

    // ========================================================================
    //  9. unbind —— 解绑（force=false，当前设备匹配）
    // ========================================================================
    std::printf("\n[9] unbind\n");
    {
        const ApiResult result = client.unbind(testCard, false);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("解绑请求被正常处理（成功或提示未绑定）",
              result.success || result.code == ApiErrorCode::Success,
              result.describe());

        if (result.success && result.data.has("unbound")) {
            std::printf("    unbound=%d\n", result.data["unbound"].asBool() ? 1 : 0);
        }
    }

    // ========================================================================
    //  10. 解绑后应可重新绑定到新设备
    // ========================================================================
    std::printf("\n[10] 解绑后重新绑定新设备\n");
    {
        ClientConfig fresh = config;
        fresh.deviceId = "e2e-device-002";
        CardKeyClient freshClient(fresh);

        const ApiResult result = freshClient.verify(testCard);
        std::printf("    HTTP=%d code=%d message=%s\n",
                    result.httpStatus, result.rawCode, result.message.c_str());

        check("新设备可以绑定", result.success, result.describe());
    }

    std::printf("\n==============================================\n");
    if (g_failures == 0) {
        std::printf("端到端联调全部通过（0 项失败）\n");
        return 0;
    }
    std::printf("端到端联调存在失败：%d 项\n", g_failures);
    return 1;
}
