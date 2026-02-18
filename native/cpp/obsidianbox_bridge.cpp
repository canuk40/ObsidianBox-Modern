/*
 * Copyright 2026 ObsidianBox Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * JNI Bridge for ObsidianBox Modern
 *
 * This bridge provides C++ JNI wrappers for the Rust FFI functions.
 * The main native code is in Rust, but JNI requires C/C++ entry points.
 *
 * Safety Features:
 * - All JNI functions are exception-safe
 * - Null checks on all arguments
 * - JSON error returns instead of crashes
 * - Proper memory management (GetStringUTFChars/ReleaseStringUTFChars)
 */

#include <jni.h>
#include <string>
#include <android/log.h>
#include <exception>
#include <cstring>
#include <unistd.h>

#define LOG_TAG "ObsidianBoxBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// =============================================================================
// Safety Helpers
// =============================================================================

/**
 * Create a JSON error string for JNI returns
 */
static jstring makeJsonError(JNIEnv *env, const char *message, const char *code = "jni_error")
{
    char buffer[1024];
    snprintf(buffer, sizeof(buffer),
             R"({"success":false,"status":"error","message":"%s","code":"%s"})",
             message, code);
    return env->NewStringUTF(buffer);
}

/**
 * Create a JSON error for null argument
 */
static jstring makeNullArgError(JNIEnv *env, const char *argName)
{
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "Null argument: %s", argName);
    return makeJsonError(env, buffer, "invalid_argument");
}

/**
 * Safe wrapper for NewStringUTF that handles null
 */
static jstring safeNewStringUTF(JNIEnv *env, const char *str)
{
    if (str == nullptr)
    {
        return makeJsonError(env, "Null string from native code");
    }
    jstring result = env->NewStringUTF(str);
    if (result == nullptr)
    {
        return makeJsonError(env, "Failed to create Java string");
    }
    return result;
}

/**
 * RAII wrapper for GetStringUTFChars to ensure Release is called
 */
class JStringGuard
{
public:
    JStringGuard(JNIEnv *env, jstring str) : env_(env), str_(str), chars_(nullptr)
    {
        if (str != nullptr)
        {
            chars_ = env->GetStringUTFChars(str, nullptr);
        }
    }

    ~JStringGuard()
    {
        if (chars_ != nullptr && str_ != nullptr)
        {
            env_->ReleaseStringUTFChars(str_, chars_);
        }
    }

    const char *get() const { return chars_; }
    bool isNull() const { return chars_ == nullptr; }

    // Prevent copying
    JStringGuard(const JStringGuard &) = delete;
    JStringGuard &operator=(const JStringGuard &) = delete;

private:
    JNIEnv *env_;
    jstring str_;
    const char *chars_;
};

/**
 * Macro for try-catch wrapping of JNI calls
 */
#define JNI_TRY_CATCH(env, body)                                                    \
    try                                                                             \
    {                                                                               \
        body                                                                        \
    }                                                                               \
    catch (const std::exception &e)                                                 \
    {                                                                               \
        LOGE("JNI exception: %s", e.what());                                        \
        return makeJsonError(env, e.what(), "cpp_exception");                       \
    }                                                                               \
    catch (...)                                                                     \
    {                                                                               \
        LOGE("JNI unknown exception");                                              \
        return makeJsonError(env, "Unknown native exception", "unknown_exception"); \
    }

// =============================================================================
// Forward declarations for Rust FFI functions
// These are implemented in the Rust static library (libobsidianbox_native.a)
// In stub mode, these are implemented as stubs at the bottom of this file
// =============================================================================

// Forward declarations - always needed for wrapper functions to compile
extern "C"
{
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectPartitions(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeInstallBusybox(JNIEnv *, jobject, jstring, jbyteArray);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSymlinks(JNIEnv *, jobject, jstring, jstring, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRemoveSymlinks(JNIEnv *, jobject, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativePatchPermissions(JNIEnv *, jobject, jstring, jint, jboolean);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinux(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagisk(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListMagiskModules(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagiskConflicts(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetBusyboxInfo(JNIEnv *, jobject, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSnapshot(JNIEnv *, jobject, jstring, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRestoreSnapshot(JNIEnv *, jobject, jstring, jstring);

    // Installer FFI functions
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectObsidianBox(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeUninstallObsidianBox(JNIEnv *, jobject, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxSnapshot(JNIEnv *, jobject, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxRestore(JNIEnv *, jobject, jstring);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListSnapshots(JNIEnv *, jobject);

    // Diagnostics FFI functions
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSymlinkDiagnostics(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunPathDiagnostics(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSelinuxDiagnostics(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunMagiskDiagnostics(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunObsidianBoxDiagnostics(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunFullDiagnostics(JNIEnv *, jobject);

    // Enhanced SELinux & Cgroup FFI functions
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinuxExtended(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetAvcDenials(JNIEnv *, jobject);
    jstring Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectCgroups(JNIEnv *, jobject);

    // NOTE: testNative is implemented directly in Rust, no C++ wrapper needed
}

extern "C"
{

    // =============================================================================
    // JNI Lifecycle
    // =============================================================================

    /**
     * Called when the library is loaded
     */
    JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
    {
        LOGI("ObsidianBox Native Bridge loaded");

        JNIEnv *env;
        if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
        {
            LOGE("Failed to get JNI environment");
            return JNI_ERR;
        }

        LOGI("JNI version 1.6 initialized successfully");
        return JNI_VERSION_1_6;
    }

    /**
     * Called when the library is unloaded
     */
    JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved)
    {
        LOGI("ObsidianBox Native Bridge unloaded");
    }

    // =============================================================================
    // Bridge Utility Functions (C++ implementations)
    // =============================================================================

    /**
     * Get native library version
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_getNativeVersion(
        JNIEnv *env,
        jobject /* this */
    )
    {
        return env->NewStringUTF("1.0.0");
    }

    /**
     * Check if native library is properly loaded
     */
    JNIEXPORT jboolean JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_isNativeReady(
        JNIEnv *env,
        jobject /* this */
    )
    {
        LOGD("isNativeReady check");
        return JNI_TRUE;
    }

    // NOTE: testNative is implemented directly in Rust JNI export
    // No C++ wrapper needed - Rust handles the JNI call directly

    // =============================================================================
    // ObsidianBox Installer JNI Wrappers
    // =============================================================================

    /**
     * Detect ObsidianBox installation - searches common paths
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_detectObsidianBox(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("detectObsidianBox called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectObsidianBox(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeDetectObsidianBox returned null");
            return makeJsonError(env, "Native detectObsidianBox returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Uninstall ObsidianBox from specified directory
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_uninstallObsidianBox(
        JNIEnv *env,
        jobject thiz,
        jstring targetDir)
    {
        LOGI("uninstallObsidianBox called");

        if (targetDir == nullptr)
        {
            LOGE("Target directory is null");
            return makeJsonError(env, "Target directory is null", "invalid_argument");
        }

        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeUninstallObsidianBox(env, thiz, targetDir);

        if (result == nullptr)
        {
            LOGE("Rust nativeUninstallObsidianBox returned null");
            return makeJsonError(env, "Native uninstallObsidianBox returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Create snapshot of ObsidianBox installation
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_createObsidianBoxSnapshot(
        JNIEnv *env,
        jobject thiz,
        jstring targetPath)
    {
        LOGI("createObsidianBoxSnapshot called");

        if (targetPath == nullptr)
        {
            LOGE("Target path is null");
            return makeJsonError(env, "Target path is null", "invalid_argument");
        }

        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxSnapshot(env, thiz, targetPath);

        if (result == nullptr)
        {
            LOGE("Rust nativeObsidianBoxSnapshot returned null");
            return makeJsonError(env, "Native busyBoxSnapshot returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Restore ObsidianBox from snapshot
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_restoreObsidianBoxSnapshot(
        JNIEnv *env,
        jobject thiz,
        jstring snapshotId)
    {
        LOGI("restoreObsidianBoxSnapshot called");

        if (snapshotId == nullptr)
        {
            LOGE("Snapshot ID is null");
            return makeJsonError(env, "Snapshot ID is null", "invalid_argument");
        }

        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxRestore(env, thiz, snapshotId);

        if (result == nullptr)
        {
            LOGE("Rust nativeObsidianBoxRestore returned null");
            return makeJsonError(env, "Native busyBoxRestore returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * List available snapshots
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_listSnapshots(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("listSnapshots called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListSnapshots(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeListSnapshots returned null");
            return makeJsonError(env, "Native listSnapshots returned null", "native_call_failed");
        }

        return result;
    }

    // =============================================================================
    // Diagnostics JNI Wrappers
    // =============================================================================

    /**
     * Run symlink diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runSymlinkDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runSymlinkDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSymlinkDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunSymlinkDiagnostics returned null");
            return makeJsonError(env, "Native runSymlinkDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Run PATH diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runPathDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runPathDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunPathDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunPathDiagnostics returned null");
            return makeJsonError(env, "Native runPathDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Run SELinux diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runSelinuxDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runSelinuxDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSelinuxDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunSelinuxDiagnostics returned null");
            return makeJsonError(env, "Native runSelinuxDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Run Magisk diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runMagiskDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runMagiskDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunMagiskDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunMagiskDiagnostics returned null");
            return makeJsonError(env, "Native runMagiskDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Run ObsidianBox diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runObsidianBoxDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runObsidianBoxDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunObsidianBoxDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunObsidianBoxDiagnostics returned null");
            return makeJsonError(env, "Native runObsidianBoxDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Run full diagnostics
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_runFullDiagnostics(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("runFullDiagnostics called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunFullDiagnostics(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeRunFullDiagnostics returned null");
            return makeJsonError(env, "Native runFullDiagnostics returned null", "native_call_failed");
        }

        return result;
    }

    // =============================================================================
    // Enhanced SELinux & Cgroup JNI Wrappers
    // =============================================================================

    /**
     * Extended SELinux detection (thread contexts, policy, AVC, capabilities)
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_detectSelinuxExtended(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("detectSelinuxExtended called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinuxExtended(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeDetectSelinuxExtended returned null");
            return makeJsonError(env, "Native detectSelinuxExtended returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Get AVC (Access Vector Cache) denials from dmesg
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_getAvcDenials(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("getAvcDenials called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetAvcDenials(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeGetAvcDenials returned null");
            return makeJsonError(env, "Native getAvcDenials returned null", "native_call_failed");
        }

        return result;
    }

    /**
     * Detect cgroup state (v1/v2, cpuset, scheduling group)
     */
    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_detectCgroups(
        JNIEnv *env,
        jobject thiz)
    {
        LOGI("detectCgroups called");
        jstring result = Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectCgroups(env, thiz);

        if (result == nullptr)
        {
            LOGE("Rust nativeDetectCgroups returned null");
            return makeJsonError(env, "Native detectCgroups returned null", "native_call_failed");
        }

        return result;
    }

    // =============================================================================
    // Terminal PTY Functions
    // =============================================================================
    // NOTE: Terminal functions are implemented directly in Rust (native/rust/src/terminal.rs)
    // and exposed via JNI in native/rust/src/lib.rs
    // The C++ bridge does NOT wrap these - Rust implementations are used directly

} // extern "C"

// =============================================================================
// Stub Implementations (when Rust library is not available)
// =============================================================================
#ifdef OBSIDIANBOX_STUB_MODE

extern "C"
{

    static jstring makeStubResponse(JNIEnv *env, const char *function)
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer),
                 R"({"success":false,"error":"Rust native library not built. Run native/rust/build-android.sh to build native functions.","timestamp":0})",
                 function);
        return env->NewStringUTF(buffer);
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectPartitions(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectPartitions");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeInstallBusybox(JNIEnv *env, jobject, jstring, jbyteArray)
    {
        return makeStubResponse(env, "installBusybox");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSymlinks(JNIEnv *env, jobject, jstring, jstring, jstring)
    {
        return makeStubResponse(env, "createSymlinks");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRemoveSymlinks(JNIEnv *env, jobject, jstring)
    {
        return makeStubResponse(env, "removeSymlinks");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativePatchPermissions(JNIEnv *env, jobject, jstring, jint, jboolean)
    {
        return makeStubResponse(env, "patchPermissions");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinux(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectSelinux");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagisk(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectMagisk");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListMagiskModules(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "listMagiskModules");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagiskConflicts(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectMagiskConflicts");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetBusyboxInfo(JNIEnv *env, jobject, jstring)
    {
        return makeStubResponse(env, "getBusyboxInfo");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSnapshot(JNIEnv *env, jobject, jstring, jstring)
    {
        return makeStubResponse(env, "createSnapshot");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRestoreSnapshot(JNIEnv *env, jobject, jstring, jstring)
    {
        return makeStubResponse(env, "restoreSnapshot");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTestNative(JNIEnv *env, jobject)
    {
        return env->NewStringUTF(R"JSON({"success":true,"data":{"status":"stub","message":"Native bridge loaded (stub mode)","timestamp":0}})JSON");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectObsidianBox(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectObsidianBox");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeUninstallObsidianBox(JNIEnv *env, jobject, jstring)
    {
        return makeStubResponse(env, "uninstallObsidianBox");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxSnapshot(JNIEnv *env, jobject, jstring)
    {
        return makeStubResponse(env, "busyBoxSnapshot");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeObsidianBoxRestore(JNIEnv *env, jobject, jstring)
    {
        return makeStubResponse(env, "busyBoxRestore");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListSnapshots(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "listSnapshots");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSymlinkDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runSymlinkDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunPathDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runPathDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSelinuxDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runSelinuxDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunMagiskDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runMagiskDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunObsidianBoxDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runObsidianBoxDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunFullDiagnostics(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "runFullDiagnostics");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinuxExtended(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectSelinuxExtended");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetAvcDenials(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "getAvcDenials");
    }

    JNIEXPORT jstring JNICALL
    Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectCgroups(JNIEnv *env, jobject)
    {
        return makeStubResponse(env, "detectCgroups");
    }

} // extern "C"

#endif // OBSIDIANBOX_STUB_MODE
