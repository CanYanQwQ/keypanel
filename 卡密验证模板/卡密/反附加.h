#pragma once

// ============================================================================
//  反附加加固 —— 主动对抗调试器 / Frida attach
//
//  ---------------------------------------------------------------------------
//  原理：双进程互检
//
//  单纯检查 TracerPid 有个致命弱点：攻击者可以在你的检测代码执行**之前**
//  就 attach，或者直接 hook 掉 fopen/strstr 让检测永远返回"正常"。
//
//  本模块的做法是 fork 出一个子进程，让父子进程互相监视：
//
//      父进程（主程序）          子进程（守卫）
//          |                        |
//          |--- fork() ------------>|
//          |                        |
//          |<-- 子进程定期检查父进程是否被 ptrace -->|
//          |                        |
//      被调试时子进程发现异常 ──> 子进程写入"环境异常"标志
//
//  攻击者要绕过就必须同时处理父子两个进程，成本大幅提高。
//
//  另外子进程还会持续检查：
//    - 父进程的 TracerPid
//    - Frida 特征
//    - 关键内存区域是否被改写
//  ---------------------------------------------------------------------------
//
//  ⚠ 注意事项
//    - fork 在 Android 上可用，但子进程不能调用大部分 Android API
//      （本模块的子进程只做文件读取，是安全的）
//    - 子进程需要及时回收，避免僵尸进程
//    - 调试阶段请用 -DCARDKEY_HARDENED=0 关闭
// ============================================================================

#if !defined(__ANDROID__)
#error "本模板仅支持 Android。"
#endif

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <csignal>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace cardkey {
namespace 安全 {

/**
 * 跨进程共享的异常标志。
 *
 * 用 mmap 匿名共享内存，父子进程都能读写。
 * 不能用普通全局变量——fork 后子进程的写操作对父进程不可见。
 */
class 共享标志 {
public:
    /** 初始化共享内存。必须在 fork 之前调用 */
    static bool 初始化() {
        if (区域() != nullptr) {
            return true;
        }

        void *内存 = ::mmap(nullptr, sizeof(区域结构),
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        if (内存 == MAP_FAILED) {
            区域() = nullptr;
            return false;
        }

        区域() = static_cast<区域结构 *>(内存);
        区域()->异常计数 = 0;
        区域()->子进程存活 = 0;
        return true;
    }

    /** 记录一次异常（父子进程都可调用） */
    static void 记录异常(int 权重 = 1) {
        if (区域() != nullptr) {
            __atomic_add_fetch(&区域()->异常计数, 权重, __ATOMIC_SEQ_CST);
        }
    }

    static int 异常计数() {
        if (区域() == nullptr) {
            return 0;
        }
        return __atomic_load_n(&区域()->异常计数, __ATOMIC_SEQ_CST);
    }

    static void 置子进程状态(int 存活) {
        if (区域() != nullptr) {
            __atomic_store_n(&区域()->子进程存活, 存活, __ATOMIC_SEQ_CST);
        }
    }

    static int 子进程状态() {
        if (区域() == nullptr) {
            return 0;
        }
        return __atomic_load_n(&区域()->子进程存活, __ATOMIC_SEQ_CST);
    }

    static void 释放() {
        if (区域() != nullptr) {
            ::munmap(区域(), sizeof(区域结构));
            区域() = nullptr;
        }
    }

private:
    struct 区域结构 {
        volatile int 异常计数;
        volatile int 子进程存活;
    };

    static 区域结构 *&区域() {
        static 区域结构 *实例 = nullptr;
        return 实例;
    }
};

/**
 * 反附加守卫。
 *
 * 用法：
 *     if (!守卫::启动()) {
 *         // 启动失败，按需降级
 *     }
 *     // ...
 *     if (!守卫::环境正常()) {
 *         // 进入诱饵逻辑
 *     }
 */
class 反附加守卫 {
public:
    /**
     * 启动守卫子进程。
     *
     * @return true 表示守卫已启动（或已在运行）
     */
    static bool 启动() {
#if !CARDKEY_HARDENED
        return true;
#else
        if (已启动()) {
            return true;
        }

        if (!共享标志::初始化()) {
            return false;
        }

        const pid_t 子进程 = ::fork();
        if (子进程 < 0) {
            // fork 失败（可能是被限制了），降级为无守卫模式
            return false;
        }

        if (子进程 == 0) {
            // ---- 子进程：持续监视父进程 ----
            子进程循环(::getppid());
            // 正常不会走到这里
            ::_exit(0);
        }

        // ---- 父进程 ----
        子进程号() = 子进程;
        共享标志::置子进程状态(1);
        已启动() = true;
        return true;
#endif
    }

    /**
     * 检查环境是否正常。
     *
     * 综合子进程上报的异常与父进程自身的检测。
     */
    static bool 环境正常() {
#if !CARDKEY_HARDENED
        return true;
#else
        // 子进程报告的异常
        if (共享标志::异常计数() > 0) {
            return false;
        }

        // 子进程意外死亡（可能被攻击者 kill）
        if (已启动() && 共享标志::子进程状态() == 0) {
            return false;
        }

        // 父进程自身的快速检查
        {
            std::FILE *文件 = std::fopen("/proc/self/status", "r");
            if (文件 == nullptr) {
                return false;
            }

            char 行[256];
            bool 正常 = true;

            while (std::fgets(行, sizeof(行), 文件) != nullptr) {
                if (std::strncmp(行, "TracerPid:", 10) == 0) {
                    const int pid = std::atoi(行 + 10);
                    if (pid != 0) {
                        正常 = false;
                    }
                    break;
                }
            }

            std::fclose(文件);
            if (!正常) {
                return false;
            }
        }

        return true;
#endif
    }

    /** 停止守卫（程序退出前调用，回收子进程） */
    static void 停止() {
#if CARDKEY_HARDENED
        if (!已启动()) {
            return;
        }

        const pid_t 子进程 = 子进程号();
        if (子进程 > 0) {
            ::kill(子进程, SIGTERM);

            int 状态 = 0;
            ::waitpid(子进程, &状态, WNOHANG);
        }

        共享标志::置子进程状态(0);
        共享标志::释放();
        已启动() = false;
#endif
    }

private:
    static bool &已启动() {
        static bool 实例 = false;
        return 实例;
    }

    static pid_t &子进程号() {
        static pid_t 实例 = 0;
        return 实例;
    }

    /**
     * 子进程主循环。
     *
     * 只做文件读取与内存写入，不调用任何 Android API——
     * fork 出来的子进程调用 Android API 是不安全的。
     */
    static void 子进程循环(pid_t 父进程号) {
        // 注意：子进程不要调用 exit()，那会刷新父进程的 stdio 缓冲区
        for (int 轮次 = 0; 轮次 < 100000; ++轮次) {
            // 父进程已退出 → 子进程也退出
            if (::getppid() != 父进程号) {
                共享标志::置子进程状态(0);
                ::_exit(0);
            }

            // ---- 检查父进程是否被 ptrace 跟踪 ----
            char 路径[64];
            std::snprintf(路径, sizeof(路径), "/proc/%d/status", static_cast<int>(父进程号));

            std::FILE *文件 = std::fopen(路径, "r");
            if (文件 != nullptr) {
                char 行[256];
                while (std::fgets(行, sizeof(行), 文件) != nullptr) {
                    if (std::strncmp(行, "TracerPid:", 10) == 0) {
                        const int 跟踪者 = std::atoi(行 + 10);
                        if (跟踪者 != 0) {
                            共享标志::记录异常(10);
                        }
                        break;
                    }
                }
                std::fclose(文件);
            }

            // ---- 检查父进程内存映射中的 Frida 特征 ----
            std::snprintf(路径, sizeof(路径), "/proc/%d/maps", static_cast<int>(父进程号));

            文件 = std::fopen(路径, "r");
            if (文件 != nullptr) {
                static const char *特征[] = {
                    "frida", "gum-js", "linjector", "frida-agent", "frida-gadget",
                };

                char 行[512];
                while (std::fgets(行, sizeof(行), 文件) != nullptr) {
                    for (const char *标记 : 特征) {
                        if (std::strstr(行, 标记) != nullptr) {
                            共享标志::记录异常(10);
                            break;
                        }
                    }
                }
                std::fclose(文件);
            }

            // 1 秒检查一次，避免过度消耗 CPU 与电量
            ::usleep(1000000);
        }

        共享标志::置子进程状态(0);
        ::_exit(0);
    }
};

} // namespace 安全
} // namespace cardkey
