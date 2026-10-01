package com.cardkey.client;

import com.fasterxml.jackson.databind.JsonNode;

public record ApiResponse(int code, String message, boolean success, Long serverTime, JsonNode data, int httpStatus) {
    public ApiErrorCode error() { return ApiErrorCode.fromCode(code); }
    public boolean isBusinessSuccess() { return success && code == ApiErrorCode.SUCCESS.code(); }
}
