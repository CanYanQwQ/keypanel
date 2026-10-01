<?php

namespace App\Enums;

/**
 * 统一 API 错误码。
 *
 * 约定：0 = 成功，1xxx = 认证/授权类，2xxx = 卡密业务类，4xxx = 请求类，5xxx = 服务端类。
 * 所有语言/框架的客户端模板共用这套错误码。
 */
enum ApiErrorCode: int
{
    case Success = 0;

    // ---- 1xxx 认证与授权 ----
    case InvalidParams = 1001;
    case AppNotFound = 1002;
    case AppDisabled = 1003;
    case SignatureInvalid = 1004;
    case TimestampExpired = 1005;
    case NonceReused = 1006;
    case IpNotAllowed = 1007;
    case RateLimited = 1008;
    case DailyQuotaExceeded = 1009;
    case MissingCredentials = 1010;
    case DecryptFailed = 1011;

    // ---- 2xxx 卡密业务 ----
    case CardNotFound = 2001;
    case CardDisabled = 2002;
    case CardExpired = 2003;
    case CardNotActivated = 2004;
    case CardDepleted = 2005;
    case CardAlreadyActivated = 2006;
    case DeviceMismatch = 2007;
    case DeviceNotBound = 2008;
    case CardNotBoundToApp = 2009;
    case CardTypeUnsupported = 2010;
    case CardAlreadyDisabled = 2011;

    // ---- 4xxx 请求类 ----
    case NotFound = 4004;
    case MethodNotAllowed = 4005;
    case PayloadTooLarge = 4013;

    // ---- 5xxx 服务端 ----
    case ServerError = 5000;
    case Maintenance = 5003;

    /**
     * 面向客户端的可读消息（中文）。
     */
    public function message(): string
    {
        return match ($this) {
            self::Success => '操作成功',
            self::InvalidParams => '请求参数不合法',
            self::AppNotFound => 'AppID 不存在',
            self::AppDisabled => '应用已被禁用',
            self::SignatureInvalid => '签名验证失败',
            self::TimestampExpired => '请求时间戳超出允许范围',
            self::NonceReused => '随机数已被使用（疑似重放请求）',
            self::IpNotAllowed => 'IP 不在白名单内',
            self::RateLimited => '请求过于频繁，请稍后再试',
            self::DailyQuotaExceeded => '今日调用配额已用尽',
            self::MissingCredentials => '缺少必要的认证头',
            self::DecryptFailed => '卡密解密失败，请检查加密参数',
            self::CardNotFound => '卡密不存在',
            self::CardDisabled => '卡密已被禁用',
            self::CardExpired => '卡密已过期',
            self::CardNotActivated => '卡密尚未激活',
            self::CardDepleted => '卡密次数已用完',
            self::CardAlreadyActivated => '卡密已被激活',
            self::DeviceMismatch => '设备不匹配，该卡密已绑定其他设备',
            self::DeviceNotBound => '该卡密尚未绑定任何设备',
            self::CardNotBoundToApp => '该卡密不属于当前应用',
            self::CardTypeUnsupported => '当前卡密类型不支持该操作',
            self::CardAlreadyDisabled => '卡密已处于禁用状态',
            self::NotFound => '接口不存在',
            self::MethodNotAllowed => '请求方法不被允许',
            self::PayloadTooLarge => '请求体过大',
            self::ServerError => '服务器内部错误',
            self::Maintenance => '系统维护中',
        };
    }

    /**
     * 对应的 HTTP 状态码。统一 JSON 返回时同时给出 HTTP 码与业务码。
     */
    public function httpStatus(): int
    {
        return match ($this) {
            self::Success => 200,
            self::InvalidParams, self::MissingCredentials, self::DecryptFailed => 422,
            self::AppNotFound, self::SignatureInvalid, self::TimestampExpired,
            self::NonceReused, self::IpNotAllowed, self::AppDisabled => 401,
            self::RateLimited, self::DailyQuotaExceeded => 429,
            self::CardNotFound, self::DeviceNotBound => 404,
            self::NotFound => 404,
            self::MethodNotAllowed => 405,
            self::PayloadTooLarge => 413,
            self::Maintenance => 503,
            self::ServerError => 500,
            default => 200,
        };
    }

    public function isSuccess(): bool
    {
        return $this === self::Success;
    }

    /**
     * 该错误是否计入「验证失败」统计。
     */
    public function countsAsFailure(): bool
    {
        return ! $this->isSuccess() && $this->httpStatus() !== 500;
    }
}
