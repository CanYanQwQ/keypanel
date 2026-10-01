#pragma once

// ============================================================================
//  APK 签名校验 —— 对抗二次打包
//
//  ---------------------------------------------------------------------------
//  为什么这是 Android 上最重要的防护
//
//  二次打包（重新签名）是 Android 破解的主流手法：
//    1. 反编译 APK，改 smali（比如把登录判断改成恒真）
//    2. 用工具重新打包并签名
//    3. 分发修改版
//
//  这种攻击**完全绕过了 native 层的所有检测**——因为攻击者改的是 Java 层，
//  你的 .so 可能原封不动。所以必须校验 APK 签名，确认自己运行在
//  官方签名的包里。
//
//  原理：Android 的签名是写在 APK 的 META-INF/ 里的，重新打包必然要用
//        攻击者自己的密钥签名，签名值会变。我们读取签名并比对期望值。
//  ---------------------------------------------------------------------------
//
//  两种实现方式：
//
//    【推荐】方式 A：由 Java 侧读取后传入 native
//        优点：不需要在 native 解析 APK zip，实现简单可靠
//        缺点：Java 侧可被 hook 篡改返回值（但配合 native 侧校验可缓解）
//
//    【加固】方式 B：native 侧直接读 APK 的 META-INF/CERT.RSA
//        优点：不经过 Java 层，hook 难度高
//        缺点：需要解析 zip 结构，代码较复杂
//
//  本文件实现方式 A 的框架 + 方式 B 的签名比对核心。
//  实际项目中建议**两者都用**：Java 侧传值，native 侧比对，互相印证。
//  ---------------------------------------------------------------------------
// ============================================================================

#if !defined(__ANDROID__)
#error "本模板仅支持 Android。"
#endif

#include <cstdint>
#include <cstring>
#include <string>

namespace cardkey {
namespace 安全 {

/**
 * 签名指纹（SHA-256 的十六进制小写）。
 *
 * 获取方法：
 *     keytool -list -v -keystore your.keystore -alias your_alias
 *     复制 "SHA256:" 后面的值，去掉冒号，转小写
 *
 * 或者用 apksigner：
 *     apksigner verify --print-certs your.apk
 *
 * ⚠ 必须填你自己的签名指纹，否则校验永远失败。
 */
class 签名校验 {
public:
    /**
     * 设置期望的签名指纹（由宿主在初始化时传入，建议用 加密字符串() 包裹）。
     */
    static void 设置期望指纹(const std::string &指纹小写十六进制) {
        期望指纹() = 规范化(指纹小写十六进制);
    }

    /**
     * 由 Java 侧传入当前 APK 的签名指纹。
     *
     * Java 侧获取方式（放在 MainActivity 或 Application 里）：
     *
     *     public static String getApkSignature() {
     *         try {
     *             PackageInfo info = Build.VERSION.SDK_INT >= 28
     *                 ? getPackageManager().getPackageInfo(
     *                       getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES)
     *                 : getPackageManager().getPackageInfo(
     *                       getPackageName(), PackageManager.GET_SIGNATURES);
     *
     *             Signature[] signs = Build.VERSION.SDK_INT >= 28
     *                 ? info.signingInfo.getApkContentsSigners()
     *                 : info.signatures;
     *
     *             MessageDigest md = MessageDigest.getInstance("SHA-256");
     *             byte[] digest = md.digest(signs[0].toByteArray());
     *
     *             StringBuilder sb = new StringBuilder();
     *             for (byte b : digest) {
     *                 sb.append(String.format("%02x", b));
     *             }
     *             return sb.toString();
     *         } catch (Exception e) {
     *             return "";
     *         }
     *     }
     */
    static void 设置实际指纹(const std::string &指纹小写十六进制) {
        实际指纹() = 规范化(指纹小写十六进制);
    }

    /**
     * 校验签名是否匹配。
     *
     * 未设置期望指纹时返回 true（表示未启用校验），
     * 这样模板在集成初期不会因为忘记配置而完全不可用。
     */
    static bool 校验() {
        const std::string &期望 = 期望指纹();
        const std::string &实际 = 实际指纹();

        // 未配置期望值 → 不校验
        if (期望.empty()) {
            return true;
        }

        // 配置了期望值但拿不到实际值 → 异常
        // （可能是 Java 侧被 hook，或读取失败）
        if (实际.empty()) {
            return false;
        }

        return 常量时间比较(期望, 实际);
    }

    /** 是否已启用签名校验 */
    static bool 已启用() {
        return !期望指纹().empty();
    }

    /** 清空状态（测试用） */
    static void 重置() {
        期望指纹().clear();
        实际指纹().clear();
    }

private:
    /** 去掉冒号、空格并转小写，兼容各种格式的输入 */
    static std::string 规范化(const std::string &输入) {
        std::string 输出;
        输出.reserve(输入.size());

        for (char c : 输入) {
            if (c == ':' || c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r') {
                continue;
            }
            输出 += static_cast<char>(
                (c >= 'A' && c <= 'F') ? (c - 'A' + 'a') : c);
        }

        return 输出;
    }

    /** 常量时间比较，避免时序侧信道 */
    static bool 常量时间比较(const std::string &a, const std::string &b) {
        if (a.size() != b.size()) {
            return false;
        }
        std::uint8_t 差异 = 0;
        for (std::size_t i = 0; i < a.size(); ++i) {
            差异 |= static_cast<std::uint8_t>(a[i] ^ b[i]);
        }
        return 差异 == 0;
    }

    static std::string &期望指纹() {
        static std::string 实例;
        return 实例;
    }

    static std::string &实际指纹() {
        static std::string 实例;
        return 实例;
    }
};

} // namespace 安全
} // namespace cardkey
