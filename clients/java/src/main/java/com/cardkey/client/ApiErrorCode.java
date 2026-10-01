package com.cardkey.client;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum ApiErrorCode {
    SUCCESS(0, "操作成功"), INVALID_PARAMS(1001, "请求参数不合法"), APP_NOT_FOUND(1002, "AppID 不存在"),
    APP_DISABLED(1003, "应用已被禁用"), SIGNATURE_INVALID(1004, "签名验证失败"), TIMESTAMP_EXPIRED(1005, "请求时间戳超出允许范围"),
    NONCE_REUSED(1006, "随机数已被使用（疑似重放请求）"), IP_NOT_ALLOWED(1007, "IP 不在白名单内"), RATE_LIMITED(1008, "请求过于频繁，请稍后再试"),
    DAILY_QUOTA_EXCEEDED(1009, "今日调用配额已用尽"), MISSING_CREDENTIALS(1010, "缺少必要的认证头"), DECRYPT_FAILED(1011, "卡密解密失败，请检查加密参数"),
    CARD_NOT_FOUND(2001, "卡密不存在"), CARD_DISABLED(2002, "卡密已被禁用"), CARD_EXPIRED(2003, "卡密已过期"), CARD_NOT_ACTIVATED(2004, "卡密尚未激活"),
    CARD_DEPLETED(2005, "卡密次数已用完"), CARD_ALREADY_ACTIVATED(2006, "卡密已被激活"), DEVICE_MISMATCH(2007, "设备不匹配，该卡密已绑定其他设备"),
    DEVICE_NOT_BOUND(2008, "该卡密尚未绑定任何设备"), CARD_NOT_BOUND_TO_APP(2009, "该卡密不属于当前应用"), CARD_TYPE_UNSUPPORTED(2010, "当前卡密类型不支持该操作"),
    CARD_ALREADY_DISABLED(2011, "卡密已处于禁用状态"), NOT_FOUND(4004, "接口不存在"), METHOD_NOT_ALLOWED(4005, "请求方法不被允许"),
    PAYLOAD_TOO_LARGE(4013, "请求体过大"), SERVER_ERROR(5000, "服务器内部错误"), MAINTENANCE(5003, "系统维护中"), UNKNOWN(-1, "未知错误");

    private static final Map<Integer, ApiErrorCode> BY_CODE = Arrays.stream(values()).collect(Collectors.toUnmodifiableMap(ApiErrorCode::code, Function.identity()));
    private final int code;
    private final String defaultMessage;
    ApiErrorCode(int code, String defaultMessage) { this.code = code; this.defaultMessage = defaultMessage; }
    public int code() { return code; }
    public String defaultMessage() { return defaultMessage; }
    public static ApiErrorCode fromCode(int code) { return BY_CODE.getOrDefault(code, UNKNOWN); }
}
