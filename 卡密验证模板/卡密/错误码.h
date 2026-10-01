#pragma once

// ============================================================================
//  统一 API 错误码（镜像服务端 app/Enums/ApiErrorCode.php）
//
//  约定：0 = 成功，1xxx = 认证/授权，2xxx = 卡密业务，4xxx = 请求，5xxx = 服务端
//
//  ⚠ 重要：部分业务失败使用 HTTP 200（例如设备不匹配、卡密类型不支持）。
//     客户端必须同时检查 HTTP 状态、code 和 success 三者，不能只看 HTTP 状态。
//
//  同步规则（见 docs/templates/shared/README.md）：
//     服务端修改 ApiErrorCode 后，必须同步更新本文件与
//     docs/templates/shared/error-codes.json。
// ============================================================================

#include <string>

namespace cardkey {

enum class ApiErrorCode : int {
    Success = 0,

    // ---- 1xxx 认证与授权 ----
    InvalidParams = 1001,
    AppNotFound = 1002,
    AppDisabled = 1003,
    SignatureInvalid = 1004,
    TimestampExpired = 1005,
    NonceReused = 1006,
    IpNotAllowed = 1007,
    RateLimited = 1008,
    DailyQuotaExceeded = 1009,
    MissingCredentials = 1010,
    DecryptFailed = 1011,

    // ---- 2xxx 卡密业务 ----
    CardNotFound = 2001,
    CardDisabled = 2002,
    CardExpired = 2003,
    CardNotActivated = 2004,
    CardDepleted = 2005,
    CardAlreadyActivated = 2006,
    DeviceMismatch = 2007,
    DeviceNotBound = 2008,
    CardNotBoundToApp = 2009,
    CardTypeUnsupported = 2010,
    CardAlreadyDisabled = 2011,

    // ---- 4xxx 请求类 ----
    NotFound = 4004,
    MethodNotAllowed = 4005,
    PayloadTooLarge = 4013,

    // ---- 5xxx 服务端 ----
    ServerError = 5000,
    Maintenance = 5003,
};

/**
 * 面向用户的中文消息（与服务端 ApiErrorCode::message() 保持一致）。
 */
inline std::string apiErrorMessage(ApiErrorCode code) {
    switch (code) {
        case ApiErrorCode::Success: return "操作成功";
        case ApiErrorCode::InvalidParams: return "请求参数不合法";
        case ApiErrorCode::AppNotFound: return "AppID 不存在";
        case ApiErrorCode::AppDisabled: return "应用已被禁用";
        case ApiErrorCode::SignatureInvalid: return "签名验证失败";
        case ApiErrorCode::TimestampExpired: return "请求时间戳超出允许范围";
        case ApiErrorCode::NonceReused: return "随机数已被使用（疑似重放请求）";
        case ApiErrorCode::IpNotAllowed: return "IP 不在白名单内";
        case ApiErrorCode::RateLimited: return "请求过于频繁，请稍后再试";
        case ApiErrorCode::DailyQuotaExceeded: return "今日调用配额已用尽";
        case ApiErrorCode::MissingCredentials: return "缺少必要的认证头";
        case ApiErrorCode::DecryptFailed: return "卡密解密失败，请检查加密参数";
        case ApiErrorCode::CardNotFound: return "卡密不存在";
        case ApiErrorCode::CardDisabled: return "卡密已被禁用";
        case ApiErrorCode::CardExpired: return "卡密已过期";
        case ApiErrorCode::CardNotActivated: return "卡密尚未激活";
        case ApiErrorCode::CardDepleted: return "卡密次数已用完";
        case ApiErrorCode::CardAlreadyActivated: return "卡密已被激活";
        case ApiErrorCode::DeviceMismatch: return "设备不匹配，该卡密已绑定其他设备";
        case ApiErrorCode::DeviceNotBound: return "该卡密尚未绑定任何设备";
        case ApiErrorCode::CardNotBoundToApp: return "该卡密不属于当前应用";
        case ApiErrorCode::CardTypeUnsupported: return "当前卡密类型不支持该操作";
        case ApiErrorCode::CardAlreadyDisabled: return "卡密已处于禁用状态";
        case ApiErrorCode::NotFound: return "接口不存在";
        case ApiErrorCode::MethodNotAllowed: return "请求方法不被允许";
        case ApiErrorCode::PayloadTooLarge: return "请求体过大";
        case ApiErrorCode::ServerError: return "服务器内部错误";
        case ApiErrorCode::Maintenance: return "系统维护中";
    }
    return "未知错误";
}

inline std::string apiErrorCodeName(ApiErrorCode code) {
    switch (code) {
        case ApiErrorCode::Success: return "Success";
        case ApiErrorCode::InvalidParams: return "InvalidParams";
        case ApiErrorCode::AppNotFound: return "AppNotFound";
        case ApiErrorCode::AppDisabled: return "AppDisabled";
        case ApiErrorCode::SignatureInvalid: return "SignatureInvalid";
        case ApiErrorCode::TimestampExpired: return "TimestampExpired";
        case ApiErrorCode::NonceReused: return "NonceReused";
        case ApiErrorCode::IpNotAllowed: return "IpNotAllowed";
        case ApiErrorCode::RateLimited: return "RateLimited";
        case ApiErrorCode::DailyQuotaExceeded: return "DailyQuotaExceeded";
        case ApiErrorCode::MissingCredentials: return "MissingCredentials";
        case ApiErrorCode::DecryptFailed: return "DecryptFailed";
        case ApiErrorCode::CardNotFound: return "CardNotFound";
        case ApiErrorCode::CardDisabled: return "CardDisabled";
        case ApiErrorCode::CardExpired: return "CardExpired";
        case ApiErrorCode::CardNotActivated: return "CardNotActivated";
        case ApiErrorCode::CardDepleted: return "CardDepleted";
        case ApiErrorCode::CardAlreadyActivated: return "CardAlreadyActivated";
        case ApiErrorCode::DeviceMismatch: return "DeviceMismatch";
        case ApiErrorCode::DeviceNotBound: return "DeviceNotBound";
        case ApiErrorCode::CardNotBoundToApp: return "CardNotBoundToApp";
        case ApiErrorCode::CardTypeUnsupported: return "CardTypeUnsupported";
        case ApiErrorCode::CardAlreadyDisabled: return "CardAlreadyDisabled";
        case ApiErrorCode::NotFound: return "NotFound";
        case ApiErrorCode::MethodNotAllowed: return "MethodNotAllowed";
        case ApiErrorCode::PayloadTooLarge: return "PayloadTooLarge";
        case ApiErrorCode::ServerError: return "ServerError";
        case ApiErrorCode::Maintenance: return "Maintenance";
    }
    return "Unknown";
}

/**
 * 已知错误码 -> 枚举。未知业务码返回 false（调用方应进入可观测的兼容分支，
 * 不要把未知码静默当成成功）。
 */
inline bool apiErrorCodeFromInt(int value, ApiErrorCode &out) {
    switch (value) {
        case 0: out = ApiErrorCode::Success; return true;
        case 1001: out = ApiErrorCode::InvalidParams; return true;
        case 1002: out = ApiErrorCode::AppNotFound; return true;
        case 1003: out = ApiErrorCode::AppDisabled; return true;
        case 1004: out = ApiErrorCode::SignatureInvalid; return true;
        case 1005: out = ApiErrorCode::TimestampExpired; return true;
        case 1006: out = ApiErrorCode::NonceReused; return true;
        case 1007: out = ApiErrorCode::IpNotAllowed; return true;
        case 1008: out = ApiErrorCode::RateLimited; return true;
        case 1009: out = ApiErrorCode::DailyQuotaExceeded; return true;
        case 1010: out = ApiErrorCode::MissingCredentials; return true;
        case 1011: out = ApiErrorCode::DecryptFailed; return true;
        case 2001: out = ApiErrorCode::CardNotFound; return true;
        case 2002: out = ApiErrorCode::CardDisabled; return true;
        case 2003: out = ApiErrorCode::CardExpired; return true;
        case 2004: out = ApiErrorCode::CardNotActivated; return true;
        case 2005: out = ApiErrorCode::CardDepleted; return true;
        case 2006: out = ApiErrorCode::CardAlreadyActivated; return true;
        case 2007: out = ApiErrorCode::DeviceMismatch; return true;
        case 2008: out = ApiErrorCode::DeviceNotBound; return true;
        case 2009: out = ApiErrorCode::CardNotBoundToApp; return true;
        case 2010: out = ApiErrorCode::CardTypeUnsupported; return true;
        case 2011: out = ApiErrorCode::CardAlreadyDisabled; return true;
        case 4004: out = ApiErrorCode::NotFound; return true;
        case 4005: out = ApiErrorCode::MethodNotAllowed; return true;
        case 4013: out = ApiErrorCode::PayloadTooLarge; return true;
        case 5000: out = ApiErrorCode::ServerError; return true;
        case 5003: out = ApiErrorCode::Maintenance; return true;
        default: return false;
    }
}

} // namespace cardkey
