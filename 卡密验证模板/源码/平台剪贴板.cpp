// ============================================================================
//  平台适配层：剪贴板读取 + Android JNI 环境注入
//
//  界面登录.h 中的「粘贴」按钮依赖 cardkey::getClipboardText()。
//
//  实现方式：通过 JNI 调用 Android 的 ClipboardManager
//            （需要宿主注入 JavaVM 与 Activity）
//
//  ---------------------------------------------------------------------------
//  Android 使用说明
//
//  Android 侧读取剪贴板需要三样东西：
//    JavaVM*      —— 进程级，JNI_OnLoad 时缓存
//    jobject      —— 当前 Activity（用于取得 ClipboardManager）
//    JNIEnv*      —— 线程级，用 JavaVM->AttachCurrentThread 获取
//
//  宿主需要在 JNI_OnLoad 里调用 设置JavaVM()，并在 Activity 创建后调用
//  设置Activity()。示例（放在你的 jni 入口文件里）：
//
//      extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
//          cardkey::设置JavaVM(vm);
//          return JNI_VERSION_1_6;
//      }
//
//      extern "C" JNIEXPORT void JNICALL
//      Java_com_example_app_MainActivity_onCreate(JNIEnv* env, jobject thiz, ...) {
//          cardkey::设置Activity(env, thiz);
//          // ... 你的其它初始化
//      }
//
//  若宿主不设置 Activity，读取剪贴板会返回空字符串（不会崩溃），
//  「粘贴」按钮表现为无响应。
//  ---------------------------------------------------------------------------
// ============================================================================

#include "卡密/界面登录.h"

#include <string>

#include <jni.h>

#include "卡密/安卓接口.h"

namespace cardkey {

// ---------------------------------------------------------------------------
//  注意：这两个全局量**不能**放进匿名 namespace。
//
//  匿名 namespace 给变量内部链接，每个翻译单元会得到各自独立的一份副本；
//  若 设置JavaVM() 在 A 文件被调用、getClipboardText() 在 B 文件读取，
//  两者看到的将是不同的变量，且优化器能证明"本文件从未写入"从而
//  把整个 JNI 读取逻辑优化成 return ""（实测 -O2 下确实被完全消除）。
//
//  因此这里用函数内静态量 + 外部链接的访问函数，保证全局唯一。
// ---------------------------------------------------------------------------
namespace {

JavaVM *&javaVM引用() {
    static JavaVM *实例 = nullptr;
    return 实例;
}

jobject &activity引用() {
    static jobject 实例 = nullptr;
    return 实例;
}

} // namespace

/** 由 JNI_OnLoad 调用，缓存 JavaVM */
void 设置JavaVM(JavaVM *vm) {
    javaVM引用() = vm;
}

/**
 * 由 Activity 的 onCreate 调用，缓存 Activity 全局引用。
 *
 * 重复调用会释放旧引用，避免泄漏。
 */
void 设置Activity(JNIEnv *env, jobject activity) {
    JavaVM *vm = javaVM引用();

    if (activity引用() != nullptr) {
        // 需要临时 attach 才能释放旧引用
        JNIEnv *当前环境 = nullptr;
        bool 需要分离 = false;

        if (vm != nullptr) {
            const jint 状态 = vm->GetEnv(reinterpret_cast<void **>(&当前环境), JNI_VERSION_1_6);
            if (状态 == JNI_EDETACHED) {
                if (vm->AttachCurrentThread(&当前环境, nullptr) == JNI_OK) {
                    需要分离 = true;
                } else {
                    当前环境 = nullptr;
                }
            }
        }

        if (当前环境 != nullptr) {
            当前环境->DeleteGlobalRef(activity引用());
        }
        if (需要分离 && vm != nullptr) {
            vm->DetachCurrentThread();
        }

        activity引用() = nullptr;
    }

    if (env != nullptr && activity != nullptr) {
        activity引用() = env->NewGlobalRef(activity);
    }
}

/**
 * 通过 JNI 读取 Android 剪贴板。
 *
 * 调用链：
 *   Activity.getSystemService(Context.CLIPBOARD_SERVICE)
 *     -> ClipboardManager.getPrimaryClip()
 *     -> ClipData.getItemAt(0).getText()
 */
/** 宿主可用来做启动自检 */
bool 安卓环境就绪() {
    return javaVM引用() != nullptr && activity引用() != nullptr;
}

std::string getClipboardText() {
    if (javaVM引用() == nullptr || activity引用() == nullptr) {
        // 宿主未注入 JavaVM / Activity，无法读取
        return std::string();
    }

    JNIEnv *env = nullptr;
    bool 需要分离 = false;

    JavaVM *vm = javaVM引用();
    const jint 状态 = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (状态 == JNI_EDETACHED) {
        // 该线程尚未 attach（常见于原生线程），临时 attach
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return std::string();
        }
        需要分离 = true;
    } else if (状态 != JNI_OK || env == nullptr) {
        return std::string();
    }

    std::string 结果;

    // ---- Activity.getSystemService("clipboard") ----
    jclass 活动类 = env->GetObjectClass(activity引用());
    if (活动类 == nullptr) {
        if (需要分离) vm->DetachCurrentThread();
        return 结果;
    }

    jmethodID 取服务 = env->GetMethodID(活动类, "getSystemService",
                                        "(Ljava/lang/String;)Ljava/lang/Object;");
    if (取服务 == nullptr) {
        env->DeleteLocalRef(活动类);
        if (需要分离) vm->DetachCurrentThread();
        return 结果;
    }

    jstring 服务名 = env->NewStringUTF("clipboard");
    jobject 剪贴板服务 = env->CallObjectMethod(activity引用(), 取服务, 服务名);
    env->DeleteLocalRef(服务名);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (剪贴板服务 == nullptr) {
        env->DeleteLocalRef(活动类);
        if (需要分离) vm->DetachCurrentThread();
        return 结果;
    }

    // ---- ClipboardManager.getPrimaryClip() ----
    jclass 剪贴板类 = env->GetObjectClass(剪贴板服务);
    jmethodID 取主剪贴 = env->GetMethodID(剪贴板类, "getPrimaryClip",
                                          "()Landroid/content/ClipData;");
    if (取主剪贴 == nullptr) {
        env->DeleteLocalRef(剪贴板类);
        env->DeleteLocalRef(剪贴板服务);
        env->DeleteLocalRef(活动类);
        if (需要分离) vm->DetachCurrentThread();
        return 结果;
    }

    jobject 剪贴数据 = env->CallObjectMethod(剪贴板服务, 取主剪贴);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    if (剪贴数据 != nullptr) {
        // ---- ClipData.getItemAt(0) ----
        jclass 数据类 = env->GetObjectClass(剪贴数据);
        jmethodID 取项 = env->GetMethodID(数据类, "getItemAt",
                                          "(I)Landroid/content/ClipData$Item;");

        if (取项 != nullptr) {
            jobject 项 = env->CallObjectMethod(剪贴数据, 取项, 0);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }

            if (项 != nullptr) {
                // ---- Item.getText() ----
                jclass 项类 = env->GetObjectClass(项);
                jmethodID 取文本 = env->GetMethodID(项类, "getText",
                                                    "()Ljava/lang/CharSequence;");

                if (取文本 != nullptr) {
                    jobject 文本对象 = env->CallObjectMethod(项, 取文本);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                    }

                    if (文本对象 != nullptr) {
                        // CharSequence.toString() -> String
                        jclass 文本类 = env->GetObjectClass(文本对象);
                        jmethodID 转字符串 = env->GetMethodID(文本类, "toString",
                                                              "()Ljava/lang/String;");

                        if (转字符串 != nullptr) {
                            jstring 文本 = static_cast<jstring>(
                                env->CallObjectMethod(文本对象, 转字符串));
                            if (env->ExceptionCheck()) {
                                env->ExceptionClear();
                            }

                            if (文本 != nullptr) {
                                // Java 字符串是 UTF-16，转成 UTF-8
                                const char *utf8 = env->GetStringUTFChars(文本, nullptr);
                                if (utf8 != nullptr) {
                                    结果 = utf8;
                                    env->ReleaseStringUTFChars(文本, utf8);
                                }
                                env->DeleteLocalRef(文本);
                            }
                        }

                        env->DeleteLocalRef(文本类);
                        env->DeleteLocalRef(文本对象);
                    }
                }

                env->DeleteLocalRef(项类);
                env->DeleteLocalRef(项);
            }
        }

        env->DeleteLocalRef(数据类);
        env->DeleteLocalRef(剪贴数据);
    }

    env->DeleteLocalRef(剪贴板类);
    env->DeleteLocalRef(剪贴板服务);
    env->DeleteLocalRef(活动类);

    if (需要分离) {
        vm->DetachCurrentThread();
    }

    return 结果;
}

} // namespace cardkey
