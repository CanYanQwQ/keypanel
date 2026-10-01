package cardkey

import (
	"encoding/json"
	"fmt"
)

type EncryptedCardKey struct {
	IV   string `json:"iv"`
	Data string `json:"data"`
	Tag  string `json:"tag"`
}

type APIResponse struct {
	Code       int             `json:"code"`
	Message    string          `json:"message"`
	Success    bool            `json:"success"`
	ServerTime int64           `json:"server_time"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type APIError struct {
	Code       int
	Message    string
	HTTPStatus int
	Response   APIResponse
}

func (e *APIError) Error() string { return fmt.Sprintf("CardKey API error %d: %s", e.Code, e.Message) }

type ProtocolError struct{ Message string }

func (e *ProtocolError) Error() string { return e.Message }

type ResponseSignatureError struct{ Message string }

func (e *ResponseSignatureError) Error() string { return e.Message }

var ErrorMessages = map[int]string{
	0: "操作成功", 1001: "请求参数不合法", 1002: "AppID 不存在", 1003: "应用已被禁用", 1004: "签名验证失败", 1005: "请求时间戳超出允许范围", 1006: "随机数已被使用（疑似重放请求）", 1007: "IP 不在白名单内", 1008: "请求过于频繁，请稍后再试", 1009: "今日调用配额已用尽", 1010: "缺少必要的认证头", 1011: "卡密解密失败，请检查加密参数", 2001: "卡密不存在", 2002: "卡密已被禁用", 2003: "卡密已过期", 2004: "卡密尚未激活", 2005: "卡密次数已用完", 2006: "卡密已被激活", 2007: "设备不匹配，该卡密已绑定其他设备", 2008: "该卡密尚未绑定任何设备", 2009: "该卡密不属于当前应用", 2010: "当前卡密类型不支持该操作", 2011: "卡密已处于禁用状态", 4004: "接口不存在", 4005: "请求方法不被允许", 4013: "请求体过大", 5000: "服务器内部错误", 5003: "系统维护中",
}

func parseAPIResponse(rawBody []byte) (APIResponse, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &fields); err != nil {
		return APIResponse{}, &ProtocolError{Message: "the API response is not valid JSON"}
	}
	for _, field := range []string{"code", "message", "success", "server_time"} {
		if _, ok := fields[field]; !ok {
			return APIResponse{}, &ProtocolError{Message: "the API response is missing " + field}
		}
	}
	var result APIResponse
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return APIResponse{}, &ProtocolError{Message: "the API response has invalid field types"}
	}
	return result, nil
}
