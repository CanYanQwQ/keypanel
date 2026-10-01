# 共享错误码契约

`error-codes.json` 是各语言客户端可读取的错误码镜像，源头仍是服务端 `ApiErrorCode` 枚举。每项包含稳定的枚举名、业务码、面向客户端的中文消息、对应 HTTP 状态和大类。

## 字段约定

- `name`：服务端枚举名，跨语言映射时保持不变。
- `code`：响应 JSON 的整数 `code`；`0` 代表成功。
- `message`：服务端默认中文消息。客户端可根据产品需要本地化，但不要改变业务码含义。
- `http_status`：服务端通常使用的 HTTP 状态。业务失败可能仍是 HTTP 200，因此必须同时检查 HTTP 状态、`code` 和 `success`。
- `category`：`success`、`auth`、`card`、`request` 或 `server`，只用于展示/分类，不代替业务判断。

## 客户端处理建议

1. 先解析响应 envelope，并确认结构完整。
2. 同时判断 HTTP 状态、`success` 和 `code`。
3. 不要把未知业务码静默当成成功；未知码应进入可观测的兼容分支。
4. 错误码不是自动重试许可。特别是 `consume` 可能已经产生扣次副作用，网络超时或未知结果时禁止盲重试。
5. 日志只保留脱敏的错误码、操作名和内部关联 ID，不记录完整卡密、AppSecret、签名头或完整请求体。

## 同步规则

服务端新增、删除或修改 `ApiErrorCode` 后，必须同步更新：

- `docs/templates/shared/error-codes.json`
- 各语言客户端的错误码映射/类型
- 面向集成方的 API 文档和测试向量

该 JSON 不包含任何真实 AppID、AppSecret、卡密或数据库数据；其中若出现测试值，也只能是明确标注的合成向量。
