// ============================================================================
//  卡密验证 —— Android 对接代码（直接复制进你的 JNI 工程）
//
//  本文件是接入入口：改配置、调接口都在这里。
//
//  ---------------------------------------------------------------------------
//  接入步骤：
//
//    1. 把「卡密」文件夹复制到 app/src/main/cpp/
//    2. 把「源码/平台剪贴板.cpp」加入编译
//    3. 修改下面【配置区】的服务器地址 / AppID / AppSecret / 签名指纹
//    4. 在 Java 侧按注释注入 Activity 与签名指纹
//
//  ⚠ 生产环境必须用 HTTPS。内置传输层只支持 http://，
//    访问 https:// 会明确报错而不会静默降级（避免误以为已加密）。
//    接入方式见 卡密/网络请求.h 顶部说明。
//  ---------------------------------------------------------------------------
// ============================================================================

#if !defined(__ANDROID__)
#error "本模板仅支持 Android。请在 NDK 工具链下编译。"
#endif

#include "卡密/卡密验证.h"

#include <android/log.h>
#include <string>

#define 日志标签 "卡密验证"

// ============================================================================
//  【配置区】—— 只改这里
//
//  ⚠ 这些值必须写成字符串字面量（不能是变量），
//     因为 加密字符串() 需要在编译期推导数组长度。
//     编译后它们不会以明文形式出现在 .so 中。
// ============================================================================

// 服务端地址。生产环境改成 https:// 并接入 TLS 传输层
#define 卡密_服务器地址   "https://card.example.com"

// 后台「应用管理」里生成
#define 卡密_AppID        "ak_请替换为你的AppID"
#define 卡密_AppSecret    "sk_请替换为你的AppSecret"

// APK 签名指纹（SHA-256 小写十六进制，不含冒号）
//
// 获取方式：
//   apksigner verify --print-certs your.apk
//   或 keytool -list -v -keystore your.keystore -alias your_alias
//
// ⚠ 这是防二次打包的关键。留空则不做签名校验（不推荐）。
#define 卡密_签名指纹     ""

// 心跳间隔（秒）。0 表示不启用。
const int 卡密_心跳间隔 = 300;

// ============================================================================
//  会话与安全
// ============================================================================
namespace 卡密 {

namespace {

/** 全局会话。Android 上进程可能长期驻留，用函数内 static 延迟构造 */
cardkey::CardKeySession &会话实例() {
    static cardkey::CardKeySession 实例 = [] {
        cardkey::ClientConfig 配置;

        // 敏感字段编译期加密，二进制中搜不到明文
        配置.baseUrl = 加密字符串(卡密_服务器地址);
        配置.appId = 加密字符串(卡密_AppID);
        配置.appSecret = 加密字符串(卡密_AppSecret);

        // 设备指纹由 Java 侧通过 设置设备指纹() 传入
        配置.verifyResponseSignature = true;
        配置.requireResponseSignature = false;

        return cardkey::CardKeySession(配置);
    }();

    return 实例;
}

} // namespace

/** 获取会话（供 JNI 层调用） */
inline cardkey::CardKeySession &会话() {
    return 会话实例();
}

/**
 * 初始化安全模块。建议在 JNI_OnLoad 或 Activity 创建时调用一次。
 *
 * 做三件事：
 *   1. 设置 APK 签名期望指纹
 *   2. 启动双进程反附加守卫
 *   3. 做一次初始环境检查
 *
 * @return true 表示初始环境正常
 */
inline bool 初始化安全() {
    // 1. 签名指纹（留空则跳过校验）
    const std::string 期望指纹 = 加密字符串(卡密_签名指纹);
    if (!期望指纹.empty()) {
        cardkey::安全::签名校验::设置期望指纹(期望指纹);
    }

    // 2. 启动反附加守卫（fork 出子进程互检）
    cardkey::安全::反附加守卫::启动();

    // 3. 初始环境检查
    const bool 正常 = cardkey::安全::安全检查();

    if (!正常) {
        __android_log_print(ANDROID_LOG_WARN, 日志标签, "初始环境检查未通过");
    }

    return 正常;
}

/** 由 Java 侧传入 APK 签名指纹 */
inline void 设置签名指纹(const std::string &指纹) {
    cardkey::安全::签名校验::设置实际指纹(指纹);
}

/** 由 Java 侧传入设备指纹（建议用 ANDROID_ID） */
inline void 设置设备指纹(const std::string &设备指纹) {
    会话().client().setDeviceId(设备指纹);
}

/**
 * 综合安全校验。
 *
 * 所有关键操作前的统一入口，依次检查：
 *   1. APK 签名（防二次打包）
 *   2. 反附加守卫（防调试器 attach）
 *   3. 环境检测（Frida / Hook / root / 模拟器）
 *
 * @return true 表示环境可信
 */
inline bool 综合校验() {
    // 签名不符 —— 二次打包，直接拒绝
    if (!cardkey::安全::签名校验::校验()) {
        __android_log_print(ANDROID_LOG_ERROR, 日志标签, "签名校验失败");
        return false;
    }

    // 反附加守卫
    if (!cardkey::安全::反附加守卫::环境正常()) {
        __android_log_print(ANDROID_LOG_WARN, 日志标签, "反附加检查未通过");
        return false;
    }

    // 环境检测
    if (!cardkey::安全::安全检查()) {
        __android_log_print(ANDROID_LOG_WARN, 日志标签, "环境检查未通过");
        return false;
    }

    return true;
}

/**
 * 登录。
 *
 * @return true 表示登录成功
 *
 * ⚠ 这是同步网络请求，**不要在主线程调用**，否则会触发
 *    NetworkOnMainThreadException 并卡死界面。请在子线程调用。
 */
inline bool 登录(const std::string &卡密明文) {
    // 关键操作前做综合校验
    if (!综合校验()) {
        // 注意：不返回具体失败原因，避免告诉破解者检测点位置。
        // 界面统一显示"卡密验证失败"，与普通失败无法区分。
        会话().setExternalError("卡密验证失败，请检查卡密是否正确");
        return false;
    }

    const cardkey::ApiResult 结果 = 会话().login(卡密明文);

    if (结果.success && 卡密_心跳间隔 > 0) {
        会话().startHeartbeat(卡密_心跳间隔);
    }

    return 结果.success;
}

/** 解绑设备 */
inline bool 解绑(const std::string &卡密明文) {
    if (!综合校验()) {
        会话().setExternalError("操作失败");
        return false;
    }

    return 会话().unbind(卡密明文, false).success;
}

/**
 * 心跳。
 *
 * 除了复查卡密状态，还顺带做一次环境检查——
 * 攻击者可能在登录成功后才注入，所以运行期也要检测。
 */
inline void 心跳() {
    if (!卡密安全检查()) {
        会话().logout();
        return;
    }

    会话().heartbeat();
}

/** 退出登录 */
inline void 退出() {
    会话().stopHeartbeat();
    会话().logout();
}

/** 程序退出前调用，回收守卫子进程 */
inline void 清理() {
    cardkey::安全::反附加守卫::停止();
}

} // namespace 卡密

// ============================================================================
//  ImGui 登录面板（可选）
//
//  如果 Android 工程用 ImGui 渲染界面，直接用这个函数。
//  如果用原生 Android 界面（Java/Kotlin），不需要它，
//  通过 JNI 把下面的接口暴露给 Java 即可（见 源码/安卓接入示例.cpp）。
// ============================================================================
#if defined(CARDKEY_HAS_IMGUI)
namespace 卡密 {

inline bool 绘制登录面板() {
    auto &session = 会话();
    static char s[64] = {0};

    if (!session.isLogin()) {
        ImGui::PushItemWidth(-1);
        ImGui::InputText("##key", s, sizeof s);

        if (ImGui::Button("粘贴", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            const std::string key = cardkey::getClipboardText();
            std::strncpy(s, key.c_str(), sizeof s - 1);
            s[sizeof s - 1] = '\0';
        }
        ImGui::PopItemWidth();

        ImGui::PushItemWidth(-1);
        if (ImGui::Button("登录", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            session.clearError();
            登录(s);
        }
        ImGui::PopItemWidth();

        if (ImGui::Button("解绑", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
            解绑(s);
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
            退出();
        }

        if (session.hasError()) {
            ImGui::Text("提示:%s", session.message().c_str());
        }
    }

    return session.isLogin();
}

} // namespace 卡密
#endif  // CARDKEY_HAS_IMGUI
