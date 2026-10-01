#pragma once

// ============================================================================
//  ImGui 登录界面模板
//
//  界面结构：输入框 -> 粘贴 -> 登录 -> 解绑 -> 提示，
//  登录成功后显示到期时间。变量名（isLogin / s / 提示 / 错误提示 / 到期时间）
//  沿用既有界面习惯，便于把现成界面代码直接替换过来。
//
//  协议层：HMAC-SHA256 签名 + HKDF/AES-256-GCM 传输加密 + JSON 体
//
//  后端调用被封装进 CardKeySession，界面只负责展示，不直接接触 AppSecret。
// ============================================================================

#include "卡密/接口客户端.h"
#include "卡密/安全防护.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#if defined(__has_include)
#if __has_include(<imgui.h>)
#include <imgui.h>
#define CARDKEY_HAS_IMGUI 1
#endif
#endif

namespace cardkey {

// ============================================================================
//  会话状态：界面与后端之间的桥接层
// ============================================================================
class CardKeySession {
public:
    explicit CardKeySession(ClientConfig config)
        : m_client(std::make_shared<CardKeyClient>(std::move(config))) {}

    CardKeyClient &client() { return *m_client; }

    // ---- 界面读取的状态（由工作线程写入，读取时加锁） ----

    bool isLogin() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        // 登录标志使用随机魔数而非 0/1，
        // 破解者搜常量或直接改内存为 1 都无法伪造成功
        return m_登录状态.已登录();
    }

    bool hasError() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_hasError;
    }

    std::string message() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_message;
    }

    std::string expiresAt() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_expiresAt;
    }

    std::string remainingText() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_remainingText;
    }

    bool isBusy() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_busy;
    }

    /** 卡密是否仍处于登录态（心跳失败会置为 false） */
    void logout() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_登录状态.置为未登录();
        m_expiresAt.clear();
        m_remainingText.clear();
    }

    void clearError() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hasError = false;
    }

    /**
     * 由外部设置提示信息。
     *
     * 用于安全检查失败等场景：不直接暴露"检测到调试器"，
     * 而是显示与常规失败一致的文案，避免告诉破解者检测点位置。
     */
    void setExternalError(const std::string &text) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hasError = true;
        m_message = text;
    }

    /** 当前是否处于环境异常状态（供宿主决定是否降级） */
    bool environmentSuspect() const {
        return !安全::安全检查();
    }

    /**
     * 登录：调用 /api/v1/verify 校验卡密，成功则进入已登录状态。
     *
     * 同步执行（模板默认，便于集成时观察结果）。界面若需非阻塞，
     * 可调用 loginAsync()。
     */
    ApiResult login(const std::string &cardKey) {
        setBusy(true);

        // 先激活再校验：时间卡从激活时刻开始计时。
        // 对已激活的卡，activate 是幂等的，可安全重复调用。
        ApiResult result = m_client->activate(cardKey);
        if (!result.success && result.is(ApiErrorCode::CardNotActivated)) {
            result = m_client->verify(cardKey);
        }

        applyLoginResult(cardKey, result);
        setBusy(false);
        return result;
    }

    /** 非阻塞登录：在工作线程中执行，界面立即返回。 */
    void loginAsync(std::string cardKey) {
        if (isBusy()) {
            return;
        }
        std::thread([this, cardKey]() { login(cardKey); }).detach();
    }

    /**
     * 解绑：调用 /api/v1/unbind。
     *
     * force=false 表示只允许卡密当前绑定的设备解绑；force=true 会强制解绑，
     * 服务端允许任何持有 AppSecret 的调用方使用 force=true，因此不要在
     * 面向最终用户的界面上提供该选项（除非业务明确允许换绑）。
     */
    ApiResult unbind(const std::string &cardKey, bool force = false) {
        setBusy(true);
        const ApiResult result = m_client->unbind(cardKey, force);
        setBusy(false);

        if (result.success) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hasError = false;
            m_message = "解绑成功";
        } else {
            setError(result.describe());
        }

        return result;
    }

    /**
     * 心跳：调用 /api/v1/query 复查卡密状态。
     *
     * 本项目的 API 没有独立的心跳端点，query 会返回卡密最新状态与剩余权益，
     * 因此用它承担心跳职责。心跳失败会立即把界面切回未登录状态。
     */
    ApiResult heartbeat() {
        std::string cardKey;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            cardKey = m_cardKey;
        }

        if (cardKey.empty()) {
            return ApiResult{};
        }

        const ApiResult result = m_client->query(cardKey);

        if (result.success) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_hasError = false;
            m_expiresAt = formatExpiry(result.data);
            m_remainingText = formatRemaining(result.data);
        } else {
            // 心跳失败：立即下线，避免界面停留在已登录状态
            std::lock_guard<std::mutex> lock(m_mutex);
            m_登录状态.置为未登录();
            m_hasError = true;
            m_message = "心跳验证失败：" + result.describe();
        }

        return result;
    }

    /**
     * 启动后台心跳线程。每 intervalSeconds 秒复查一次卡密状态。
     * 传 0 表示只执行一次（用于手动触发）。
     */
    void startHeartbeat(int intervalSeconds = 300) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_heartbeatRunning) {
                return;
            }
            m_heartbeatRunning = true;
        }

        std::thread([this, intervalSeconds]() {
            while (true) {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (!m_heartbeatRunning) {
                        break;
                    }
                    if (!m_登录状态.已登录()) {
                        break;  // 已下线，停止心跳
                    }
                }

                if (intervalSeconds <= 0) {
                    heartbeat();
                    break;
                }

                // 分片睡眠，便于及时响应停止请求
                for (int slept = 0; slept < intervalSeconds; ++slept) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (!m_heartbeatRunning || !m_登录状态.已登录()) {
                        break;
                    }
                }
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            m_heartbeatRunning = false;
        }).detach();
    }

    void stopHeartbeat() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_heartbeatRunning = false;
    }

private:
    void setBusy(bool busy) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_busy = busy;
    }

    void setError(const std::string &text) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hasError = true;
        m_message = text;
    }

    void applyLoginResult(const std::string &cardKey, const ApiResult &result) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (result.success) {
            m_登录状态.置为已登录();
            m_hasError = false;
            m_message.clear();
            m_cardKey = cardKey;
            m_expiresAt = formatExpiry(result.data);
            m_remainingText = formatRemaining(result.data);
            return;
        }

        m_登录状态.置为未登录();
        m_hasError = true;
        m_message = result.describe();
    }

    /** 把服务端返回的 expires_at（ISO8601）转成展示文本 */
    static std::string formatExpiry(const Json &data) {
        const Json &expires = data["expires_at"];

        if (expires.isNull() || expires.asString().empty()) {
            return "永久";
        }

        std::string text = expires.asString();
        // "2026-10-01T12:34:56+00:00" -> "2026-10-01 12:34:56"
        const std::size_t t = text.find('T');
        if (t != std::string::npos) {
            text = text.substr(0, t) + " " + text.substr(t + 1);
        }
        const std::size_t zone = text.find_first_of("+Z");
        if (zone != std::string::npos && zone > 10) {
            text = text.substr(0, zone);
        }

        return text;
    }

    /** 组装剩余权益描述（剩余次数 / 剩余秒数 / 永久） */
    static std::string formatRemaining(const Json &data) {
        const Json &remainingUses = data["remaining_uses"];
        if (remainingUses.isNumber()) {
            return "剩余次数：" + std::to_string(remainingUses.asInt());
        }

        const Json &remainingSeconds = data["remaining_seconds"];
        if (remainingSeconds.isNumber()) {
            const long long seconds = remainingSeconds.asInt();
            if (seconds <= 0) {
                return std::string();
            }
            const long long days = seconds / 86400;
            if (days > 0) {
                return "剩余 " + std::to_string(days) + " 天";
            }
            const long long hours = seconds / 3600;
            if (hours > 0) {
                return "剩余 " + std::to_string(hours) + " 小时";
            }
            return "剩余 " + std::to_string(seconds / 60) + " 分钟";
        }

        return std::string();
    }

    std::shared_ptr<CardKeyClient> m_client;

    mutable std::mutex m_mutex;
    // 登录状态：内部使用随机魔数，不暴露 0/1
    安全::登录状态 m_登录状态;
    bool m_hasError = false;
    bool m_busy = false;
    bool m_heartbeatRunning = false;
    std::string m_message;
    std::string m_expiresAt;
    std::string m_remainingText;
    std::string m_cardKey;
};

// ============================================================================
//  剪贴板读取（宿主平台提供）
//
//  Windows / Android JNI / 其他平台各自实现，返回 UTF-8 文本。
// ============================================================================
std::string getClipboardText();

} // namespace cardkey

// ============================================================================
//  ImGui 界面
//
//  结构、控件顺序与变量命名保持既有风格，后端由 CardKeySession 承担。
//  在宿主的渲染循环中调用 cardkey::drawLoginPanel(session) 即可。
// ============================================================================
#if defined(CARDKEY_HAS_IMGUI)

namespace cardkey {

/**
 * 绘制登录面板。
 *
 * @param session 会话对象，持有客户端与状态
 * @return 当前是否已登录（便于宿主据此决定是否放行主功能）
 */
inline bool drawLoginPanel(CardKeySession &session) {
    // 沿用原模板的静态缓冲：输入框直接绑定
    static char s[64] = {0};

    if (!session.isLogin()) {
        ImGui::PushItemWidth(-1);
        ImGui::InputText("##key", s, sizeof s);

        // auto paste
        if (ImGui::Button("粘贴", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            const std::string key = getClipboardText();
            std::strncpy(s, key.c_str(), sizeof s - 1);
            s[sizeof s - 1] = '\0';
        }
        // auto login
        ImGui::PopItemWidth();

        ImGui::PushItemWidth(-1);
        if (ImGui::Button("登录", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            session.clearError();
            session.login(s);
            // 登录成功后启动心跳（每 300 秒复查一次）
            if (session.isLogin()) {
                session.startHeartbeat(300);
            }
        }
        ImGui::PopItemWidth();

        if (ImGui::Button("解绑", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            session.unbind(s);
        }

        if (session.hasError()) {
            ImGui::Text("提示:%s", session.message().c_str());
        }

    } else {
        ImGui::Text("到期时间:%s", session.expiresAt().c_str());

        const std::string remaining = session.remainingText();
        if (!remaining.empty()) {
            ImGui::Text("%s", remaining.c_str());
        }

        if (ImGui::Button("退出登录", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            session.stopHeartbeat();
            session.logout();
        }

        if (session.hasError()) {
            ImGui::Text("提示:%s", session.message().c_str());
        }
    }

    return session.isLogin();
}

} // namespace cardkey

#endif  // CARDKEY_HAS_IMGUI
