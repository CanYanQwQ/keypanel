// ============================================================================
//  Android JNI 接入示例
//
//  本文件演示如何把本模板接入 Android 工程。你需要把内容合并到自己的
//  JNI 入口文件（通常叫 native-lib.cpp 或 jni_main.cpp）。
//
//  ---------------------------------------------------------------------------
//  接入三步：
//
//    1. 实现 JNI_OnLoad，缓存 JavaVM
//    2. 在 Activity.onCreate 里缓存 Activity（剪贴板需要）
//    3. 提供 Java 侧调用原生登录的方法
//
//  对应的 Java 侧（MainActivity.java）：
//
//      public class MainActivity extends Activity {
//          static { System.loadLibrary("cardkey"); }
//
//          @Override
//          protected void onCreate(Bundle savedInstanceState) {
//              super.onCreate(savedInstanceState);
//              nativeInit(this);           // 注入 Activity
//          }
//
//          public native void nativeInit(Activity activity);
//          public native boolean nativeLogin(String cardKey);
//          public native String  nativeExpiresAt();
//          public native void    nativeHeartbeat();
//      }
//  ---------------------------------------------------------------------------
// ============================================================================

#if defined(__ANDROID__)

#include "卡密/卡密验证.h"
#include "卡密/安卓接口.h"

#include <android/log.h>
#include <jni.h>
#include <string>

// 复用「需要的代码.cpp」里的配置与安全封装（会话/初始化安全/综合校验/登录...）
// 实际工程里二者取其一：要么把「需要的代码.cpp」加入编译，
// 要么把它的内容合并进本文件。
#include "需要的代码.cpp"

// ============================================================================
//  JNI 入口
// ============================================================================

/** 进程启动时缓存 JavaVM（剪贴板读取需要） */
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    cardkey::设置JavaVM(vm);
    return JNI_VERSION_1_6;
}

/**
 * Activity 创建时调用，注入 Activity 引用。
 *
 * Java 侧：nativeInit(this)
 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeInit(JNIEnv *env, jobject /*thiz*/, jobject activity) {
    // 保存 Activity 供剪贴板使用
    cardkey::设置Activity(env, activity);

    // 启动自检：确认注入成功
    if (!cardkey::安卓环境就绪()) {
        __android_log_print(ANDROID_LOG_WARN, 日志标签, "环境注入失败，粘贴功能不可用");
    }

    // 初始化安全模块（签名校验 + 反附加守卫 + 环境检查）
    卡密::初始化安全();
}

/**
 * 注入 APK 签名指纹。
 *
 * Java 侧：nativeSetSignature(getApkSignature())
 * 签名获取代码见 卡密/签名校验.h 的注释。
 *
 * 这是防二次打包的关键——签名不符时 综合校验() 会失败，
 * 登录被拒绝。
 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeSetSignature(JNIEnv *env, jobject /*thiz*/, jstring signature) {
    if (signature == nullptr) {
        return;
    }

    const char *utf8 = env->GetStringUTFChars(signature, nullptr);
    if (utf8 != nullptr) {
        卡密::设置签名指纹(utf8);
        env->ReleaseStringUTFChars(signature, utf8);
    }
}

/**
 * 设置设备指纹。
 *
 * 建议传入 ANDROID_ID 或你自己的设备唯一标识，
 * 用于服务端的单设备绑定。
 *
 * Java 侧：nativeSetDeviceId(Settings.Secure.getString(getContentResolver(), ANDROID_ID))
 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeSetDeviceId(JNIEnv *env, jobject /*thiz*/, jstring deviceId) {
    if (deviceId == nullptr) {
        return;
    }

    const char *utf8 = env->GetStringUTFChars(deviceId, nullptr);
    if (utf8 != nullptr) {
        卡密::设置设备指纹(utf8);
        env->ReleaseStringUTFChars(deviceId, utf8);
    }
}

/**
 * 登录。
 *
 * @return 成功返回 true
 *
 * 注意：这是同步调用，会阻塞当前线程做网络请求。
 *      在 Android 上**不要**在主线程调用，否则会触发 NetworkOnMainThreadException
 *      并卡死界面。请在子线程调用，或使用 卡密::会话().loginAsync()。
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_app_MainActivity_nativeLogin(JNIEnv *env, jobject /*thiz*/, jstring cardKey) {
    if (cardKey == nullptr) {
        return JNI_FALSE;
    }

    const char *utf8 = env->GetStringUTFChars(cardKey, nullptr);
    if (utf8 == nullptr) {
        return JNI_FALSE;
    }

    const std::string 卡密明文 = utf8;
    env->ReleaseStringUTFChars(cardKey, utf8);

    // 卡密::登录 内部已包含签名校验 / 反附加 / 环境检测
    return 卡密::登录(卡密明文) ? JNI_TRUE : JNI_FALSE;
}

/** 查询到期时间，供界面显示 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_app_MainActivity_nativeExpiresAt(JNIEnv *env, jobject /*thiz*/) {
    return env->NewStringUTF(卡密::会话().expiresAt().c_str());
}

/** 查询剩余权益描述 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_app_MainActivity_nativeRemaining(JNIEnv *env, jobject /*thiz*/) {
    return env->NewStringUTF(卡密::会话().remainingText().c_str());
}

/** 查询最近一次操作的提示信息 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_app_MainActivity_nativeMessage(JNIEnv *env, jobject /*thiz*/) {
    return env->NewStringUTF(卡密::会话().message().c_str());
}

/** 当前是否已登录 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_app_MainActivity_nativeIsLoggedIn(JNIEnv * /*env*/, jobject /*thiz*/) {
    return 卡密::会话().isLogin() ? JNI_TRUE : JNI_FALSE;
}

/** 解绑设备 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_app_MainActivity_nativeUnbind(JNIEnv *env, jobject /*thiz*/, jstring cardKey) {
    if (cardKey == nullptr) {
        return JNI_FALSE;
    }

    const char *utf8 = env->GetStringUTFChars(cardKey, nullptr);
    if (utf8 == nullptr) {
        return JNI_FALSE;
    }

    const std::string 卡密明文 = utf8;
    env->ReleaseStringUTFChars(cardKey, utf8);

    return 卡密::解绑(卡密明文) ? JNI_TRUE : JNI_FALSE;
}

/** 手动触发一次心跳 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeHeartbeat(JNIEnv * /*env*/, jobject /*thiz*/) {
    // 心跳顺带做环境检查，防止登录后才注入
    卡密::心跳();
}

/** 退出登录 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeLogout(JNIEnv * /*env*/, jobject /*thiz*/) {
    卡密::退出();
}

/** 程序退出前调用，回收守卫子进程 */
extern "C" JNIEXPORT void JNICALL
Java_com_example_app_MainActivity_nativeCleanup(JNIEnv * /*env*/, jobject /*thiz*/) {
    卡密::清理();
}

/** 读取剪贴板（供 Java 侧「粘贴」按钮使用，也可直接用 ImGui 面板的按钮） */
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_app_MainActivity_nativeClipboard(JNIEnv *env, jobject /*thiz*/) {
    return env->NewStringUTF(cardkey::getClipboardText().c_str());
}

#endif  // __ANDROID__
