<?php

declare(strict_types=1);

namespace CardKey;

final class ErrorCodes
{
    /** @var array<int, string> */
    public const MESSAGES = [
        0 => '操作成功',
        1001 => '请求参数不合法',
        1002 => 'AppID 不存在',
        1003 => '应用已被禁用',
        1004 => '签名验证失败',
        1005 => '请求时间戳超出允许范围',
        1006 => '随机数已被使用（疑似重放请求）',
        1007 => 'IP 不在白名单内',
        1008 => '请求过于频繁，请稍后再试',
        1009 => '今日调用配额已用尽',
        1010 => '缺少必要的认证头',
        1011 => '卡密解密失败，请检查加密参数',
        2001 => '卡密不存在',
        2002 => '卡密已被禁用',
        2003 => '卡密已过期',
        2004 => '卡密尚未激活',
        2005 => '卡密次数已用完',
        2006 => '卡密已被激活',
        2007 => '设备不匹配，该卡密已绑定其他设备',
        2008 => '该卡密尚未绑定任何设备',
        2009 => '该卡密不属于当前应用',
        2010 => '当前卡密类型不支持该操作',
        2011 => '卡密已处于禁用状态',
        4004 => '接口不存在',
        4005 => '请求方法不被允许',
        4013 => '请求体过大',
        5000 => '服务器内部错误',
        5003 => '系统维护中',
    ];

    public static function message(int $code): string
    {
        return self::MESSAGES[$code] ?? '未知 API 错误';
    }
}

class CardKeyException extends \RuntimeException
{
}

class ProtocolException extends CardKeyException
{
}

class ResponseSignatureException extends CardKeyException
{
}

final class ApiException extends CardKeyException
{
    public function __construct(
        public readonly int $apiCode,
        public readonly string $apiMessage,
        public readonly int $httpStatus,
        public readonly ApiResponse $response,
    ) {
        parent::__construct("CardKey API error {$apiCode}: {$apiMessage}");
    }
}
