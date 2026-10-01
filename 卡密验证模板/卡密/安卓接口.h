#pragma once

// ============================================================================
//  Android 平台接口
//
//  Android 侧读取剪贴板（「粘贴」按钮）需要宿主注入 JavaVM 与 Activity。
//  本头文件声明这两个注入函数，宿主在自己的 JNI 入口调用即可。
//
//  为什么必须单独放在头文件里声明：
//    「设置JavaVM / 设置Activity」若只定义在 .cpp 中且标记 inline，
//    则没有任何其它翻译单元能调用它们。优化器在 -O2 下能据此证明
//    "缓存变量从未被写入"，从而把整个剪贴板读取逻辑优化成 return ""。
//    实测确实如此——所以这两个函数必须有外部链接并在头文件声明。
//
//  接入示例（放在你自己的 JNI 入口文件里）：
//
//      #include "卡密/安卓接口.h"
//
//      extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
//          cardkey::设置JavaVM(vm);
//          return JNI_VERSION_1_6;
//      }
//
//      extern "C" JNIEXPORT void JNICALL
//      Java_com_example_app_MainActivity_onCreate(JNIEnv* env, jobject thiz, jobject bundle) {
//          cardkey::设置Activity(env, thiz);
//          // ... 你的其它初始化
//      }
//
//  未注入时的行为：读取剪贴板返回空字符串，「粘贴」按钮无响应，不会崩溃。
// ============================================================================

#if defined(__ANDROID__)

#include <jni.h>

namespace cardkey {

/**
 * 缓存 JavaVM。应在 JNI_OnLoad 中调用一次。
 *
 * @param vm 进程级 JavaVM 指针
 */
void 设置JavaVM(JavaVM *vm);

/**
 * 缓存当前 Activity 的全局引用。应在 Activity.onCreate 中调用。
 *
 * 内部用 NewGlobalRef 保存，重复调用会先释放旧引用，不会泄漏。
 *
 * @param env      当前 JNIEnv
 * @param activity 当前 Activity 对象（局部引用即可，内部会转全局引用）
 */
void 设置Activity(JNIEnv *env, jobject activity);

/**
 * 检查是否已正确注入 JavaVM 与 Activity。
 *
 * 宿主可用它做启动自检：未注入时「粘贴」按钮不会工作。
 */
bool 安卓环境就绪();

} // namespace cardkey

#endif  // __ANDROID__
