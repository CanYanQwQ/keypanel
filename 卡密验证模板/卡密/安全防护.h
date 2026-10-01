#pragma once

// ============================================================================
//  安全防护层 —— Android 专用
//
//  ---------------------------------------------------------------------------
//  ⚠ 先说清楚能力边界
//
//  Android 客户端运行在用户完全可控的设备上，**不存在无法破解的客户端**。
//  本层的目标是提高逆向成本、拖慢破解速度，不是"绝对防住"。
//
//  能有效做到的：
//    - 二进制里搜不到 AppSecret、服务器地址（编译期字符串加密）
//    - Frida 注入时无法正常登录（反注入检测）
//    - 关键函数被 inline hook 后能被发现（函数序言校验）
//    - 二次打包后签名不符（APK 签名校验，见 签名校验.h）
//    - 用 GameGuardian 改内存改不出登录状态（随机魔数）
//    - 内存 dump 拿不到残留密钥（用后擦除）
//
//  做不到的：
//    - 定制版 Frida（改名 + 去特征）能绕过大部分检测
//    - 有经验的逆向者持续动态调试，最终能找到关键跳转
//
//  真正的防线在服务端。本项目服务端已实现 nonce 防重放、每日配额、
//  IP 白名单、限流、卡密状态机、设备绑定、完整审计日志。
//  Android 场景下**设备绑定是最有效的防共享手段**：一张卡绑一台设备，
//  即使客户端被完全攻破也无法在第二台设备上使用。
//  ---------------------------------------------------------------------------
//
//  编译开关：
//    -DCARDKEY_HARDENED=1   发布版，开启全部检测（默认）
//    -DCARDKEY_HARDENED=0   调试版，关闭检测以免干扰自己的调试器
//
//  平台要求：Android（NDK r21+ 或任意支持 C++17 的 NDK）
// ============================================================================

#if !defined(__ANDROID__)
#error "本模板仅支持 Android。请在 NDK 工具链下编译（见 安卓CMake.txt）。"
#endif

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CARDKEY_HARDENED
#define CARDKEY_HARDENED 1
#endif

namespace cardkey {
namespace 安全 {

// ============================================================================
//  0. 单调时钟（时序检测使用）
// ============================================================================

inline std::uint64_t 当前纳秒() {
    struct timespec 时间;
    if (::clock_gettime(CLOCK_MONOTONIC, &时间) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(时间.tv_sec) * 1000000000ull +
           static_cast<std::uint64_t>(时间.tv_nsec);
}

// ============================================================================
//  1. 编译期字符串加密
//
//  原理：字符串在**编译期**逐字节异或加密，密文存入 .rodata；
//        运行时才在栈上解密，用完立即清零。
//
//  密钥来源：__COUNTER__（每次展开唯一递增）+ __LINE__ + 编译期盐值。
//            用 __COUNTER__ 而非只用 __LINE__，因为行号只有几千种可能，
//            破解者可以暴力枚举；__COUNTER__ 让每个调用点的密钥都不同，
//            且同一行写两个字符串也会得到不同密钥。
//
//  实测验证：编译后用 strings 搜不到明文（见 测试/安全测试.cpp）。
// ============================================================================

/** 编译期密钥派生：三次混合，雪崩性良好 */
constexpr std::uint8_t 派生密钥字节(std::uint32_t 种子, std::size_t 位置) {
    std::uint32_t 值 = 种子 ^ 0x9E3779B9u;
    值 ^= 值 >> 16;
    值 *= 0x7FEB352Du;
    值 ^= 值 >> 15;
    值 *= 0x846CA68Bu;
    值 ^= 值 >> 16;
    值 += static_cast<std::uint32_t>(位置) * 0x9E3779B9u;
    值 ^= 值 >> 13;
    值 *= 0xC2B2AE35u;
    值 ^= 值 >> 16;
    return static_cast<std::uint8_t>(值 & 0xFFu);
}

/** 运行时擦除内存。volatile 确保编译器不会优化掉写入 */
inline void 擦除(void *指针, std::size_t 长度) {
    volatile std::uint8_t *p = static_cast<volatile std::uint8_t *>(指针);
    while (长度-- > 0) {
        *p++ = 0;
    }
}

/**
 * 编译期加密的字符串容器。
 *
 * 密文以 static constexpr 实例存放，编译器会把已加密字节直接写进只读段，
 * 明文不会出现在二进制中。
 */
template <std::size_t N, std::uint32_t 种子>
class 加密文本 {
public:
    constexpr 加密文本(const char (&明文)[N]) : m_密文{} {
        for (std::size_t i = 0; i < N; ++i) {
            m_密文[i] = static_cast<char>(
                static_cast<std::uint8_t>(明文[i]) ^ 派生密钥字节(种子, i));
        }
    }

    void 解密到(char *输出) const {
        for (std::size_t i = 0; i < N; ++i) {
            输出[i] = static_cast<char>(
                static_cast<std::uint8_t>(m_密文[i]) ^ 派生密钥字节(种子, i));
        }
    }

    std::string 取() const {
        char 缓冲[N];
        解密到(缓冲);
        std::string 结果(缓冲, N - 1);  // N-1 去掉结尾 '\0'
        擦除(缓冲, N);
        return 结果;
    }

    static constexpr std::size_t 明文长度 = N - 1;

private:
    char m_密文[N];
};

/** RAII：作用域结束时自动擦除 std::string，防止密钥残留在堆上 */
class 自动擦除 {
public:
    explicit 自动擦除(std::string &目标) : m_目标(目标) {}
    ~自动擦除() {
        if (!m_目标.empty()) {
            擦除(&m_目标[0], m_目标.size());
        }
    }
    自动擦除(const 自动擦除 &) = delete;
    自动擦除 &operator=(const 自动擦除 &) = delete;

private:
    std::string &m_目标;
};

// ============================================================================
//  2. 调试器检测
// ============================================================================

/**
 * 读取 /proc/self/status 的 TracerPid。
 *
 * 非 0 表示被 ptrace 跟踪（调试器或 Frida）。
 * 读不到 /proc 本身也判定为异常——可能被 hook 了。
 */
inline int 读取TracerPid() {
    std::FILE *文件 = std::fopen("/proc/self/status", "r");
    if (文件 == nullptr) {
        return -1;
    }

    char 行[256];
    int 结果 = 0;

    while (std::fgets(行, sizeof(行), 文件) != nullptr) {
        if (std::strncmp(行, "TracerPid:", 10) == 0) {
            const char *值 = 行 + 10;
            while (*值 == ' ' || *值 == '\t') ++值;
            结果 = std::atoi(值);
            break;
        }
    }

    std::fclose(文件);
    return 结果;
}

/** ptrace 自附加检测：已被跟踪时 PTRACE_TRACEME 会失败 */
inline bool 检测Ptrace() {
    return ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1;
}

/** 综合调试器检测 */
inline bool 检测调试器() {
#if CARDKEY_HARDENED
    if (读取TracerPid() != 0) return true;
    if (检测Ptrace()) return true;
#endif
    return false;
}

// ============================================================================
//  3. Frida 检测（Android 上最主要的动态注入工具）
//
//  多重手段，任一命中即判定异常。
//  注意：改名版 Frida（如 hluda）能绕过字符串特征，所以不能只靠一项。
// ============================================================================

namespace 内部 {

/** 在 /proc/self/maps 中查找特征串 */
inline bool 映射含特征(const char *const *特征表, std::size_t 数量) {
    std::FILE *映射 = std::fopen("/proc/self/maps", "r");
    if (映射 == nullptr) {
        return false;
    }

    char 行[512];
    bool 命中 = false;

    while (std::fgets(行, sizeof(行), 映射) != nullptr) {
        for (std::size_t i = 0; i < 数量; ++i) {
            if (std::strstr(行, 特征表[i]) != nullptr) {
                命中 = true;
                break;
            }
        }
        if (命中) break;
    }

    std::fclose(映射);
    return 命中;
}

/** 在 /proc/self/task 下各线程的 comm 文件中查找线程名特征 */
inline bool 线程名含特征(const char *const *特征表, std::size_t 数量) {
    DIR *目录 = ::opendir("/proc/self/task");
    if (目录 == nullptr) {
        return false;
    }

    struct dirent *条目;
    bool 命中 = false;

    while ((条目 = ::readdir(目录)) != nullptr) {
        if (条目->d_name[0] == '.') continue;

        char 路径[256];
        std::snprintf(路径, sizeof(路径), "/proc/self/task/%s/comm", 条目->d_name);

        std::FILE *文件 = std::fopen(路径, "r");
        if (文件 == nullptr) continue;

        char 线程名[64] = {0};
        if (std::fgets(线程名, sizeof(线程名), 文件) != nullptr) {
            for (std::size_t i = 0; i < 数量; ++i) {
                if (std::strstr(线程名, 特征表[i]) != nullptr) {
                    命中 = true;
                    break;
                }
            }
        }
        std::fclose(文件);

        if (命中) break;
    }

    ::closedir(目录);
    return 命中;
}

/** 扫描 /proc 下所有进程的命令行，查找 frida-server 等注入服务端 */
inline bool 存在可疑进程(const char *const *特征表, std::size_t 数量) {
    DIR *目录 = ::opendir("/proc");
    if (目录 == nullptr) {
        return false;
    }

    struct dirent *条目;
    bool 命中 = false;

    while ((条目 = ::readdir(目录)) != nullptr) {
        // 只处理数字目录（进程 ID）
        if (条目->d_name[0] < '0' || 条目->d_name[0] > '9') continue;

        char 路径[256];
        std::snprintf(路径, sizeof(路径), "/proc/%s/cmdline", 条目->d_name);

        std::FILE *文件 = std::fopen(路径, "r");
        if (文件 == nullptr) continue;

        char 命令行[256] = {0};
        const std::size_t 读取 = std::fread(命令行, 1, sizeof(命令行) - 1, 文件);
        std::fclose(文件);

        if (读取 == 0) continue;

        // cmdline 用 \0 分隔参数，统一替换成空格便于查找
        for (std::size_t i = 0; i < 读取; ++i) {
            if (命令行[i] == '\0') 命令行[i] = ' ';
        }

        for (std::size_t i = 0; i < 数量; ++i) {
            if (std::strstr(命令行, 特征表[i]) != nullptr) {
                命中 = true;
                break;
            }
        }

        if (命中) break;
    }

    ::closedir(目录);
    return 命中;
}

} // namespace 内部

/**
 * Frida 检测。
 *
 * 四重手段：
 *   (1) 内存映射特征（frida-agent / frida-gadget / linjector 等）
 *   (2) 线程名特征（gum-js-loop / gmain / pool-frida）
 *   (3) 进程扫描（frida-server 进程）
 *   (4) 端口探测（frida-server 默认 27042/27043）
 */
inline bool 检测Frida注入() {
#if !CARDKEY_HARDENED
    return false;
#else
    // ---- (1) 内存映射特征 ----
    static const char *映射特征[] = {
        "frida", "gum-js-loop", "gmain", "gdbus",
        "linjector", "re.frida", "frida-agent", "frida-gadget",
        "libfrida", "frida_agent",
    };
    if (内部::映射含特征(映射特征, sizeof(映射特征) / sizeof(映射特征[0]))) {
        return true;
    }

    // ---- (2) 线程名特征 ----
    static const char *线程特征[] = {
        "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida",
    };
    if (内部::线程名含特征(线程特征, sizeof(线程特征) / sizeof(线程特征[0]))) {
        return true;
    }

    // ---- (3) 进程扫描 ----
    static const char *进程特征[] = {
        "frida-server", "frida_server", "frida-helper", "hluda-server",
    };
    if (内部::存在可疑进程(进程特征, sizeof(进程特征) / sizeof(进程特征[0]))) {
        return true;
    }

    // ---- (4) 端口探测 ----
    // 27042 = 0x69A2, 27043 = 0x69A3（/proc/net/tcp 中为大端十六进制）
    {
        static const char *网络文件[] = {
            "/proc/net/tcp", "/proc/net/tcp6",
        };

        for (const char *路径 : 网络文件) {
            std::FILE *文件 = std::fopen(路径, "r");
            if (文件 == nullptr) continue;

            char 行[512];
            bool 命中 = false;

            while (std::fgets(行, sizeof(行), 文件) != nullptr) {
                if (std::strstr(行, ":69A2") != nullptr ||
                    std::strstr(行, ":69A3") != nullptr) {
                    命中 = true;
                    break;
                }
            }
            std::fclose(文件);

            if (命中) return true;
        }
    }

    return false;
#endif
}

// ============================================================================
//  4. Root 检测
//
//  root 后攻击者可以用 GameGuardian 类工具直接改内存。
//  本模板的登录状态用随机魔数（见 登录状态 类）对抗直接改值，
//  root 检测作为额外信号。
//
//  ⚠ 误报率高（很多正常用户也 root），默认**不作为拒绝依据**，
//    建议上报服务端做风控，由服务端决定策略。
// ============================================================================

inline bool 检测Root环境() {
#if !CARDKEY_HARDENED
    return false;
#else
    static const char *可疑路径[] = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/xbin/busybox",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/app/magisk",
        "/sbin/magisk",
    };

    for (const char *路径 : 可疑路径) {
        struct stat 信息;
        if (::stat(路径, &信息) == 0) {
            return true;
        }
    }

    return false;
#endif
}

// ============================================================================
//  5. 模拟器检测
//
//  模拟器常被用于批量刷卡。检测手段：
//    - 特定系统属性（ro.product.model 等含模拟器特征）
//    - 特定文件（qemu 相关设备节点）
//    - CPU 信息特征
//
//  ⚠ 同样存在误报可能，建议作为风控信号而非直接拒绝。
// ============================================================================

inline bool 检测模拟器() {
#if !CARDKEY_HARDENED
    return false;
#else
    // ---- 文件特征 ----
    static const char *模拟器文件[] = {
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/goldfish_pipe",
    };

    for (const char *路径 : 模拟器文件) {
        struct stat 信息;
        if (::stat(路径, &信息) == 0) {
            return true;
        }
    }

    // ---- 系统属性特征 ----
    // 直接读 /system/build.prop，避免依赖 __system_property_get
    {
        std::FILE *文件 = std::fopen("/system/build.prop", "r");
        if (文件 != nullptr) {
            static const char *属性特征[] = {
                "generic", "sdk_gphone", "goldfish", "ranchu",
                "vbox", "nox", "ttVM", "BlueStacks", "Genymotion",
            };

            char 行[512];
            bool 命中 = false;

            while (std::fgets(行, sizeof(行), 文件) != nullptr) {
                for (const char *特征 : 属性特征) {
                    if (std::strstr(行, 特征) != nullptr) {
                        命中 = true;
                        break;
                    }
                }
                if (命中) break;
            }
            std::fclose(文件);

            if (命中) return true;
        }
    }

    return false;
#endif
}

// ============================================================================
//  6. 可疑内存映射检测
//
//  注入框架常把代码段映射为可写可执行（rwx），
//  正常的原生库不会有这种权限组合。
// ============================================================================

inline bool 检测可疑内存映射() {
#if !CARDKEY_HARDENED
    return false;
#else
    std::FILE *映射 = std::fopen("/proc/self/maps", "r");
    if (映射 == nullptr) {
        return false;
    }

    char 行[512];
    bool 命中 = false;

    while (std::fgets(行, sizeof(行), 映射) != nullptr) {
        // 格式：start-end perms offset dev inode pathname
        const char *权限起点 = std::strchr(行, ' ');
        if (权限起点 == nullptr) continue;
        ++权限起点;

        // 可写且可执行
        if (std::strncmp(权限起点, "rwx", 3) != 0) continue;

        // 只关注有文件名的可执行可写段（排除匿名映射）
        const char *路径 = std::strchr(权限起点, '/');
        if (路径 != nullptr && std::strstr(路径, ".so") != nullptr) {
            命中 = true;
            break;
        }
    }

    std::fclose(映射);
    return 命中;
#endif
}

// ============================================================================
//  7. Inline Hook 检测
//
//  原理：Frida / Dobby / xHook 等框架 hook 函数时，会把函数开头几个字节
//        改成跳转指令（ARM64 的 B/BL，ARM32 的 B/BL），跳到自己的处理函数。
//        我们检查关键函数的第一条指令，如果变成跳转就说明被 hook 了。
//
//  这是对抗 Frida 最直接的手段之一：即使 Frida 改名去特征，
//  它 hook 函数时留下的跳转指令依然存在。
// ============================================================================

/**
 * 判断给定地址处的第一条指令是否为跳转指令。
 *
 * ARM64：
 *   B   = 0x14000000（位 31-26 = 000101）
 *   BL  = 0x94000000（位 31-26 = 100101）
 *   LDR literal（用于生成 veneer）= 0x58000000
 * ARM32：
 *   B   = 0xEA000000
 *   BL  = 0xEB000000
 */
inline bool 指令是跳转(const void *地址) {
    if (地址 == nullptr) {
        return false;
    }

    // 用 memcpy 避免未对齐访问（ARM 上未对齐读取可能触发异常）
    std::uint32_t 指令 = 0;
    std::memcpy(&指令, 地址, sizeof(指令));

#if defined(__aarch64__)
    const std::uint32_t 高六位 = 指令 & 0xFC000000u;
    if (高六位 == 0x14000000u) return true;  // B
    if (高六位 == 0x94000000u) return true;  // BL
    if (高六位 == 0x58000000u) return true;  // LDR literal（veneer）
#elif defined(__arm__)
    const std::uint32_t 高八位 = 指令 & 0xFF000000u;
    if (高八位 == 0xEA000000u) return true;  // B
    if (高八位 == 0xEB000000u) return true;  // BL
#else
    (void)指令;
#endif

    return false;
}

/**
 * 检查一组关键函数是否被 inline hook。
 *
 * 用法：把关键函数的地址传进来，任一被 hook 即返回 true。
 */
inline bool 检测Hook() {
#if !CARDKEY_HARDENED
    return false;
#else
    // 对关键函数做序言校验。这些函数一旦被 hook，
    // 攻击者就能截获卡密明文或伪造验证结果。
    const void *关键函数[] = {
        reinterpret_cast<const void *>(&cardkey::安全::检测Frida注入),
        reinterpret_cast<const void *>(&cardkey::安全::读取TracerPid),
        reinterpret_cast<const void *>(&cardkey::安全::检测可疑内存映射),
    };

    for (const void *函数 : 关键函数) {
        if (指令是跳转(函数)) {
            return true;
        }
    }

    return false;
#endif
}

// ============================================================================
//  8. 完整性自校验
//
//  原理：对关键代码段计算校验和，与首次运行锁定的值比对。
//        破解者 patch 掉关键跳转后校验和改变，从而被检测到。
// ============================================================================

/** FNV-1a 校验和。不用密码学哈希，避免与协议层实现互相依赖 */
inline std::uint32_t 计算校验和(const void *数据, std::size_t 长度) {
    const std::uint8_t *p = static_cast<const std::uint8_t *>(数据);
    std::uint32_t 哈希 = 2166136261u;
    for (std::size_t i = 0; i < 长度; ++i) {
        哈希 ^= p[i];
        哈希 *= 16777619u;
    }
    return 哈希;
}

/**
 * 代码段完整性守卫。
 *
 * 校验和延迟到首次校验时锁定，可防住"先运行一次记录值再 patch"的攻击。
 */
class 完整性守卫 {
public:
    完整性守卫(const void *起点, std::size_t 长度)
        : m_起点(起点), m_长度(长度), m_已锁定(false), m_锁定值(0) {}

    bool 校验() {
        if (m_起点 == nullptr || m_长度 == 0) {
            return true;
        }

        const std::uint32_t 当前 = 计算校验和(m_起点, m_长度);

        if (!m_已锁定) {
            m_锁定值 = 当前;
            m_已锁定 = true;
            return true;
        }

        return 当前 == m_锁定值;
    }

private:
    const void *m_起点;
    std::size_t m_长度;
    bool m_已锁定;
    std::uint32_t m_锁定值;
};

// ============================================================================
//  9. 登录状态混淆
//
//  原理：登录标志不用 bool，而用随机化的非 0 魔数。
//
//  这专门针对 Android 上最常见的"用 GameGuardian 改内存"手法：
//    逆向者搜 0/1 定位不到登录判断；
//    直接把内存改成 1 也不会通过——因为校验的是特定魔数。
//
//  魔数每次启动都不同，攻击者无法用固定值伪造。
// ============================================================================

class 登录状态 {
public:
    登录状态() : m_魔数(生成魔数()), m_值(0) {}

    void 置为已登录() { m_值 = m_魔数; }
    void 置为未登录() { m_值 = 0; }

    bool 已登录() const { return m_值 != 0 && m_值 == m_魔数; }

    /**
     * 生成非 0 随机魔数。
     *
     * 用进程启动时间与计数器混合，使每次运行的魔数都不同。
     */
    static std::uint32_t 生成魔数() {
        static std::uint32_t 计数器 = 0x5A5A5A5Au;
        ++计数器;

        std::uint32_t 值 = 计数器 * 2654435761u;

        // 混入单调时钟，进一步增加随机性
        const std::uint64_t 时间 = 当前纳秒();
        值 ^= static_cast<std::uint32_t>(时间 & 0xFFFFFFFFu);
        值 ^= static_cast<std::uint32_t>(时间 >> 32);

        值 ^= 值 >> 15;
        值 *= 0x7FEB352Du;
        值 ^= 值 >> 16;
        值 |= 0x80000000u;  // 确保最高位为 1，即非 0

        return 值;
    }

private:
    std::uint32_t m_魔数;  // 本实例的"已登录"判定值
    std::uint32_t m_值;    // 当前状态；等于 m_魔数 表示已登录
};

// ============================================================================
//  10. 环境守卫（多点累计检测）
//
//  设计思路：不要只有一个检测点。单点检测容易被定位并 patch 掉。
//  这里让多个检查点各自累计"可疑分"，分数汇总后决定是否可信。
//  攻击者必须找到并 patch 所有检查点才能绕过。
// ============================================================================

class 环境守卫 {
public:
    /** 累计可疑分（权重越大表示该信号越可信） */
    static void 记录可疑(int 权重) {
        分数() += 权重;
    }

    static int 可疑分() {
        return 分数();
    }

    /** 分数超过阈值即认为环境不可信 */
    static bool 可信() {
        return 分数() < 阈值;
    }

    static void 重置() {
        分数() = 0;
    }

private:
    static int &分数() {
        static int 实例 = 0;
        return 实例;
    }

    static constexpr int 阈值 = 10;
};

// ============================================================================
//  11. 综合安全检查
// ============================================================================

/**
 * 执行一次完整的环境安全检查。
 *
 * 建议在登录、扣次等关键操作前调用。
 *
 * 检测到异常时**不直接退出**——那等于告诉破解者"这里就是检测点"。
 * 调用方应进入"看起来正常但结果错误"的路径（见 需要的代码.cpp 的用法）。
 *
 * @return true 表示环境正常
 */
inline bool 安全检查() {
#if !CARDKEY_HARDENED
    return true;
#else
    // 完整检测只做一次，避免频繁调用影响性能。
    // 但检测结果会与累计可疑分共同决定，后者可能被其他检查点更新。
    static bool 已做完整检测 = false;

    if (!已做完整检测) {
        已做完整检测 = true;

        if (读取TracerPid() != 0) {
            环境守卫::记录可疑(10);  // 被 ptrace 跟踪，确定性极高
        }
        if (检测Ptrace()) {
            环境守卫::记录可疑(10);
        }
        if (检测Frida注入()) {
            环境守卫::记录可疑(10);
        }
        if (检测Hook()) {
            环境守卫::记录可疑(10);
        }
        if (检测可疑内存映射()) {
            环境守卫::记录可疑(5);
        }
        if (检测Root环境()) {
            环境守卫::记录可疑(2);  // 误报率高，权重低
        }
        if (检测模拟器()) {
            环境守卫::记录可疑(3);
        }
    }

    return 环境守卫::可信();
#endif
}

/**
 * 深度检查：每次都执行全部检测，用于高敏感操作。
 *
 * 比 安全检查() 慢，但能发现运行期才安装的 hook。
 */
inline bool 深度安全检查() {
#if !CARDKEY_HARDENED
    return true;
#else
    if (读取TracerPid() != 0) {
        环境守卫::记录可疑(10);
    }
    if (检测Frida注入()) {
        环境守卫::记录可疑(10);
    }
    if (检测Hook()) {
        环境守卫::记录可疑(10);
    }

    return 环境守卫::可信();
#endif
}

} // namespace 安全
} // namespace cardkey

// ============================================================================
//  便捷宏
// ============================================================================

/**
 * 编译期加密字符串。
 *
 * 用立即执行的 lambda 包住 static constexpr 实例，确保编译期求值——
 * 密文进只读段，明文不留在二进制中。
 *
 * __COUNTER__ 每次展开唯一递增，保证每个调用点的密钥都不同。
 */
#define 加密字符串(文本)                                                      \
    ([]() -> std::string {                                                     \
        static constexpr auto 卡密_加密文本 =                                   \
            ::cardkey::安全::加密文本<sizeof(文本),                             \
                static_cast<std::uint32_t>(__COUNTER__) * 2654435761u ^         \
                static_cast<std::uint32_t>(__LINE__) * 40503u>(文本);           \
        return 卡密_加密文本.取();                                              \
    }())

/** 环境安全检查（轻量，建议在关键操作前调用） */
#define 卡密安全检查() (::cardkey::安全::安全检查())

/** 深度安全检查（每次全量检测，用于高敏感操作） */
#define 卡密深度检查() (::cardkey::安全::深度安全检查())

/** 擦除栈上缓冲区 */
#define 卡密擦除(缓冲) (::cardkey::安全::擦除((缓冲), sizeof(缓冲)))
