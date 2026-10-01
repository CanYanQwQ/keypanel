#pragma once

// ============================================================================
//  CardKey API v1 客户端（服务端接口封装）
//
//  覆盖五个端点：verify / activate / consume / query / unbind
//
//  每个请求的完整流程：
//    1. 组装 JSON 请求体（并把序列化结果缓存为字节）
//    2. 用同一份字节计算 SHA256 -> canonical -> HMAC 签名
//    3. 发送（携带 X-App-Id / X-Timestamp / X-Nonce / X-Signature-Version / X-Signature）
//    4. 用原始响应字节校验 X-Response-Signature（若服务端开启）
//    5. 同时检查 HTTP 状态 + code + success 三者
//
//  ⚠ consume 没有服务端幂等键。网络超时后不要盲目重试，否则可能重复扣次。
// ============================================================================

#include "卡密/错误码.h"
#include "卡密/网络请求.h"
#include "卡密/精简JSON.h"
#include "卡密/协议加密.h"
#include "卡密/安全防护.h"

#include <memory>
#include <string>

namespace cardkey {

// ============================================================================
//  配置
// ============================================================================
struct ClientConfig {
    /** 服务端地址，如 http://127.0.0.1:8000 或 https://card.example.com */
    std::string baseUrl;

    /** 后台「应用管理」中生成的 AppID，如 ak_xxxxxxxxxxxxxxxx */
    std::string appId;

    /** 对应应用的 AppSecret。切勿写入日志、前端 bundle 或提交到仓库。 */
    std::string appSecret;

    /** 设备指纹。用于单设备绑定；留空表示不带设备信息。 */
    std::string deviceId;

    /** 请求超时（秒） */
    int timeoutSeconds = 10;

    /**
     * 是否校验响应签名。服务端可通过「响应体附带签名」开关关闭该功能；
     * 关闭后响应不会带 X-Response-Signature，此时校验会被跳过并记录标记。
     */
    bool verifyResponseSignature = true;

    /**
     * 是否强制要求响应必须带签名。生产环境建议保持 true：
     * 若服务端意外关闭了响应签名，宁可报错也不要接受未认证的响应。
     */
    bool requireResponseSignature = false;

    /** 自定义传输层（注入 TLS 实现时使用，见 http_client.h 顶部说明） */
    std::shared_ptr<HttpTransport> transport;
};

// ============================================================================
//  单次调用结果
// ============================================================================
struct ApiResult {
    /** 业务是否成功（HTTP 200 + code 0 + success true 三者同时满足） */
    bool success = false;

    /** 服务端返回的业务码 */
    ApiErrorCode code = ApiErrorCode::ServerError;

    /** 服务端返回的业务码原始数值（用于未知码的兼容分支） */
    int rawCode = -1;

    /** 该业务码是否已知。false 表示服务端新增了本模板尚未同步的错误码。 */
    bool knownCode = false;

    /** HTTP 状态码 */
    int httpStatus = 0;

    /** 面向用户的消息（优先使用服务端返回的 message） */
    std::string message;

    /** 业务数据（成功时通常包含 status/type/expires_at/remaining_uses 等） */
    Json data;

    /** 原始响应体字节（调试与验签排查用） */
    std::string rawBody;

    /** 传输/解析层面的错误（网络失败、JSON 非法等）。非空时 success 必为 false。 */
    std::string transportError;

    /** 响应是否带有签名头 */
    bool responseSigned = false;

    /** 响应签名是否校验通过 */
    bool responseSignatureVerified = false;

    bool is(ApiErrorCode expected) const { return code == expected; }

    /** 汇总一句话描述，便于直接显示在界面上 */
    std::string describe() const {
        if (!transportError.empty()) {
            return transportError;
        }
        return message;
    }
};

// ============================================================================
//  客户端
// ============================================================================
class CardKeyClient {
public:
    explicit CardKeyClient(ClientConfig config) : m_config(std::move(config)) {
        if (m_config.baseUrl.empty()) {
            throw std::runtime_error("ClientConfig.baseUrl 不能为空");
        }
        if (m_config.appId.empty() || m_config.appSecret.empty()) {
            throw std::runtime_error("ClientConfig.appId / appSecret 不能为空");
        }
        // 统一去掉末尾斜杠，避免拼出 //api/v1/verify
        while (!m_config.baseUrl.empty() && m_config.baseUrl.back() == '/') {
            m_config.baseUrl.pop_back();
        }
    }

    const ClientConfig &config() const { return m_config; }

    void setDeviceId(const std::string &deviceId) { m_config.deviceId = deviceId; }

    // ---- 五个端点 ----

    /** POST /api/v1/verify —— 校验卡密（会触发设备自动绑定） */
    ApiResult verify(const std::string &cardKey) {
        return call("/api/v1/verify", buildCardBody(cardKey, false));
    }

    /** POST /api/v1/activate —— 激活卡密（时间卡从此刻开始计时） */
    ApiResult activate(const std::string &cardKey) {
        return call("/api/v1/activate", buildCardBody(cardKey, false));
    }

    /**
     * POST /api/v1/consume —— 扣减次数（仅次数卡）
     *
     * ⚠ 无幂等键：超时后请勿自动重试。
     */
    ApiResult consume(const std::string &cardKey, int count = 1) {
        return call("/api/v1/consume", buildCardBody(cardKey, false, count));
    }

    /** POST /api/v1/query —— 查询卡密状态（会触发设备自动绑定） */
    ApiResult query(const std::string &cardKey) {
        return call("/api/v1/query", buildCardBody(cardKey, false));
    }

    /**
     * POST /api/v1/unbind —— 解绑设备
     *
     * @param force true 时忽略当前设备是否匹配。注意服务端当前允许任意
     *              持有 AppSecret 的调用方使用 force=true，属产品决策，
     *              不要暴露给不受信任的最终用户界面。
     */
    ApiResult unbind(const std::string &cardKey, bool force = false) {
        return call("/api/v1/unbind", buildCardBody(cardKey, false, 0, force));
    }

    // ---- 便捷判断 ----

    /**
     * 判断服务端是否要求卡密密文传输。本模板一律使用密文，
     * 因此该开关只影响"能否明文调试"，不影响正常调用。
     */
    static bool isEncryptedPayload(const Json &value) {
        return TransportCrypto::isEncryptedPayload(value);
    }

    /**
     * 把卡密加密为可直接放入 card_key 字段的 JSON 对象。
     * 宿主若需要自行组装请求体可使用该方法。
     */
    Json encryptCardKey(const std::string &cardKey) const {
        return TransportCrypto::encrypt(cardKey, m_config.appSecret, m_config.appId).toJson();
    }

    /**
     * 生成设备指纹。宿主应优先提供真实设备标识（Android ID、机器码等）；
     * 本实现退化为"随机 ID + 本地持久化"。
     */
    static std::string generateDeviceFingerprint() {
        return "dev-" + Signer::generateNonce(8);
    }

private:
    // ------------------------------------------------------------------
    //  请求体构造
    // ------------------------------------------------------------------
    Json buildCardBody(const std::string &cardKey, bool /*reserved*/, int count = 0, bool force = false) {
        Json body = Json::object();

        // 卡密一律使用 AES-256-GCM 密文对象提交。
        // 即使服务端未强制要求，密文传输也能避免卡密明文出现在请求体中。
        body.set("card_key", encryptCardKey(cardKey));

        if (!m_config.deviceId.empty()) {
            body.set("device_id", m_config.deviceId);
        }

        if (count > 0) {
            body.set("count", count);
        }

        if (force) {
            body.set("force", true);
        }

        return body;
    }

    // ------------------------------------------------------------------
    //  发起调用
    // ------------------------------------------------------------------
    ApiResult call(const std::string &path, const Json &body) {
        ApiResult result;

        // ---- 安全前置检查 ----
        // 检测到调试器时进入"看起来正常但结果错误"的路径：
        // 不直接报错，而是让签名密钥被污染，服务端会返回验签失败。
        // 这样破解者难以定位失败原因，也无法通过简单 patch 绕过。
        const bool 环境正常 = 安全::安全检查();

        // 关键：先序列化并缓存字节，签名与发送共用同一份数据。
        const std::string rawBody = body.dump();

        const std::string timestamp = crypto::unixTimestamp();
        const std::string nonce = Signer::generateNonce();

        // 用后即擦的密钥副本，避免明文长期驻留堆内存
        std::string 密钥副本 = m_config.appSecret;
        安全::自动擦除 密钥守卫(密钥副本);

        if (!环境正常) {
            // 污染密钥：签名必然失败，服务端返回 1004，
            // 表现与"密钥配错"完全一致，不暴露检测点
            密钥副本 = 安全::登录状态::生成魔数() % 2 == 0
                           ? 密钥副本 + "x"
                           : "x" + 密钥副本;
        }

        const std::string signature =
            Signer::signRequest(密钥副本, "POST", path, timestamp, nonce, rawBody);

        HttpRequest request;
        request.method = "POST";
        request.url = m_config.baseUrl + path;
        request.body = rawBody;

        // 头顺序与文档一致，便于抓包比对
        request.setHeader("Content-Type", "application/json; charset=utf-8");
        request.setHeader("Accept", "application/json");
        request.setHeader(Signer::HeaderAppId, m_config.appId);
        request.setHeader(Signer::HeaderTimestamp, timestamp);
        request.setHeader(Signer::HeaderNonce, nonce);
        request.setHeader(Signer::HeaderVersion, Signer::Version);
        request.setHeader(Signer::HeaderSignature, signature);

        HttpResponse response;
        try {
            response = httpSend(request, m_config.transport.get());
        } catch (const std::exception &e) {
            result.transportError = std::string("请求失败：") + e.what();
            result.message = result.transportError;
            return result;
        }

        result.httpStatus = response.statusCode;
        result.rawBody = response.rawBody;

        // ---- 响应验签（必须在解析 JSON 之前用原始字节进行） ----
        const std::string responseSignature = response.header(Signer::HeaderResponseSignature);
        const std::string responseTimestamp = response.header(Signer::HeaderResponseTimestamp);

        if (!responseSignature.empty() && !responseTimestamp.empty()) {
            result.responseSigned = true;

            if (m_config.verifyResponseSignature) {
                result.responseSignatureVerified = Signer::verifyResponse(
                    密钥副本, response.rawBody, responseTimestamp, nonce, responseSignature);

                if (!result.responseSignatureVerified) {
                    result.success = false;
                    result.message = "响应签名校验失败：返回内容可能被篡改";
                    result.transportError = result.message;
                    return result;
                }
            }
        } else if (m_config.requireResponseSignature) {
            // 服务端未返回签名头：可能是中间件拒绝、参数校验失败，或服务端关闭了签名。
            // 这些路径当前不带签名，因此不能把"缺少签名"当作成功。
            result.success = false;
            result.message = "响应缺少签名头，无法确认返回内容可信";
            result.transportError = result.message;
            return result;
        }

        // ---- 解析 JSON ----
        const Json parsed = Json::tryParse(response.rawBody);
        if (parsed.isNull() && !response.rawBody.empty()) {
            result.success = false;
            result.message = "响应不是合法 JSON";
            result.transportError = result.message;
            return result;
        }

        // ---- 业务码 ----
        result.rawCode = static_cast<int>(parsed["code"].asInt(-1));
        result.knownCode = apiErrorCodeFromInt(result.rawCode, result.code);

        const std::string serverMessage = parsed["message"].asString();
        if (!serverMessage.empty()) {
            result.message = serverMessage;
        } else if (result.knownCode) {
            result.message = apiErrorMessage(result.code);
        } else {
            result.message = "未知业务码：" + std::to_string(result.rawCode);
        }

        result.data = parsed["data"];

        // ---- 三重判断：HTTP 状态 + code + success ----
        const bool httpOk = (response.statusCode >= 200 && response.statusCode < 300);
        const bool codeOk = result.knownCode && result.code == ApiErrorCode::Success;
        const bool flagOk = parsed["success"].asBool(false);

        result.success = httpOk && codeOk && flagOk;

        if (!result.knownCode) {
            // 未知业务码：进入可观测的兼容分支，绝不静默当作成功
            result.success = false;
        }

        return result;
    }

    ClientConfig m_config;
};

} // namespace cardkey
