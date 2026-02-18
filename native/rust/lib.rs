// Copyright 2026 ObsidianBox Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ObsidianBox Modern Native Library
//! 
//! Rust FFI library for privileged operations on Android
//! All functions return JSON strings for safe cross-JNI data transfer

// Suppress known warnings that are intentional or false positives:
// - unused_mut: JNI 0.21+ methods require &mut self but macro expansion may confuse rustc
// - unreachable_patterns: EAGAIN == EWOULDBLOCK on Linux/Android
#![allow(unused_mut)]
#![allow(unreachable_patterns)]

mod partition;
mod symlink;
mod permission;
mod selinux;
mod cgroup;
mod magisk;
mod obsidianbox;
mod snapshot;
mod result;
mod diagnostics;
mod terminal;
pub mod safety;

use jni::JNIEnv;
use jni::objects::{JClass, JString, JByteArray};
use jni::sys::{jboolean, jint, jstring};
use log::LevelFilter;
use android_logger::Config;
use std::panic::AssertUnwindSafe;

/// Initialize logging for Android
fn init_logging() {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("ObsidianBoxNative")
    );
}

/// Convert a Rust string to JNI jstring, with error handling
pub fn string_to_jstring(env: &JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|js| js.into_raw())
        .unwrap_or_else(|_| {
            // If we can't create a string, return null (JNI will handle it)
            std::ptr::null_mut()
        })
}

/// Create an error jstring safely
fn error_jstring(env: &JNIEnv, message: &str) -> jstring {
    let error_json = safety::json_error_simple(message);
    string_to_jstring(env, &error_json)
}

/// Wrap a JNI call with panic catching
macro_rules! safe_jni {
    ($env:expr, $body:expr) => {{
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            $body
        }));
        
        match result {
            Ok(jstr) => jstr,
            Err(panic_payload) => {
                let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                
                log::error!("JNI panic caught: {}", panic_msg);
                let error_json = safety::json_panic_error(&panic_msg);
                string_to_jstring(&$env, &error_json)
            }
        }
    }};
}

/// JNI: Detect available partitions
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectPartitions(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    safe_jni!(env, {
        let result = partition::detect_partitions();
        string_to_jstring(&env, &result)
    })
}

/// JNI: Install ObsidianBox binary
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeInstallBusybox(
    mut env: JNIEnv,
    _class: JClass,
    target_path: JString,
    binary_data: JByteArray,
) -> jstring {
    init_logging();
    
    let path: String = match env.get_string(&target_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid target path"),
    };
    
    let data: Vec<u8> = match env.convert_byte_array(&binary_data) {
        Ok(d) => d,
        Err(_) => return error_jstring(&env, "Invalid binary data"),
    };
    
    let result = obsidianbox::install_obsidianbox(&path, &data);
    string_to_jstring(&env, &result)
}

/// JNI: Create symlinks for applets
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSymlinks(
    mut env: JNIEnv,
    _class: JClass,
    obsidianbox_path: JString,
    symlink_dir: JString,
    applets_json: JString,
) -> jstring {
    init_logging();
    
    let bb_path: String = match env.get_string(&obsidianbox_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid obsidianbox path"),
    };
    
    let sym_dir: String = match env.get_string(&symlink_dir) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid symlink dir"),
    };
    
    let applets_str: String = match env.get_string(&applets_json) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid applets JSON"),
    };
    
    let result = symlink::create_symlinks(&bb_path, &sym_dir, &applets_str);
    string_to_jstring(&env, &result)
}

/// JNI: Remove symlinks
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRemoveSymlinks(
    mut env: JNIEnv,
    _class: JClass,
    symlink_dir: JString,
) -> jstring {
    init_logging();
    
    let dir: String = match env.get_string(&symlink_dir) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid symlink dir"),
    };
    
    let result = symlink::remove_symlinks(&dir);
    string_to_jstring(&env, &result)
}

/// JNI: Patch permissions
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativePatchPermissions(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    mode: jni::sys::jint,
    recursive: jni::sys::jboolean,
) -> jstring {
    init_logging();
    
    let file_path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid path"),
    };
    
    let result = permission::patch_permissions(&file_path, mode as u32, recursive != 0);
    string_to_jstring(&env, &result)
}

/// JNI: Detect SELinux mode
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinux(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = selinux::detect_selinux();
    string_to_jstring(&env, &result)
}

/// JNI: Extended SELinux detection (thread contexts, policy info, AVC stats, capabilities)
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectSelinuxExtended(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = selinux::detect_selinux_extended();
    string_to_jstring(&env, &result)
}

/// JNI: Get AVC denials from dmesg
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetAvcDenials(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = selinux::get_avc_denials();
    string_to_jstring(&env, &result)
}

/// JNI: Detect cgroup state
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectCgroups(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = cgroup::detect_cgroups();
    string_to_jstring(&env, &result)
}

/// JNI: Detect Magisk
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagisk(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = magisk::detect_magisk();
    string_to_jstring(&env, &result)
}

/// JNI: List Magisk modules
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeListMagiskModules(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = magisk::list_magisk_modules();
    string_to_jstring(&env, &result)
}

/// JNI: Detect Magisk ObsidianBox conflicts
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectMagiskConflicts(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = magisk::detect_obsidianbox_conflicts();
    string_to_jstring(&env, &result)
}

/// JNI: Get ObsidianBox info
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetBusyboxInfo(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jstring {
    init_logging();
    
    let bb_path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid path"),
    };
    
    let result = obsidianbox::get_obsidianbox_info(&bb_path);
    string_to_jstring(&env, &result)
}

/// JNI: Create snapshot
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeCreateSnapshot(
    mut env: JNIEnv,
    _class: JClass,
    target_path: JString,
    snapshot_name: JString,
) -> jstring {
    init_logging();
    
    let path: String = match env.get_string(&target_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid target path"),
    };
    
    let name: String = match env.get_string(&snapshot_name) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid snapshot name"),
    };
    
    let result = snapshot::create_snapshot(&path, &name);
    string_to_jstring(&env, &result)
}

/// JNI: Restore snapshot
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRestoreSnapshot(
    mut env: JNIEnv,
    _class: JClass,
    snapshot_path: JString,
    target_path: JString,
) -> jstring {
    init_logging();
    
    let snap_path: String = match env.get_string(&snapshot_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid snapshot path"),
    };
    
    let tgt_path: String = match env.get_string(&target_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid target path"),
    };
    
    let result = snapshot::restore_snapshot(&snap_path, &tgt_path);
    string_to_jstring(&env, &result)
}

/// JNI: Test native pipeline - comprehensive validation of Kotlin → JNI → Rust → System
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_testNative(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    log::info!("testNative called - comprehensive pipeline validation");

    safe_jni!(env, {
        // Test 1: Basic Rust functionality
        let rust_test = test_rust_functionality();

        // Test 2: JNI string handling
        let jni_test = test_jni_functionality(&env);

        // Test 3: System access
        let system_test = test_system_access();

        // Test 4: File system operations
        let fs_test = test_filesystem_access();

        // Test 5: Process capabilities
        let proc_test = test_process_capabilities();

        // Compile comprehensive results
        let all_passed = rust_test.success && jni_test.success && system_test.success &&
                        fs_test.success && proc_test.success;

        // Compute the test count message before the JSON to avoid temporary borrow issues
        let test_count = if all_passed {
            "5/5".to_string()
        } else {
            format!("{}/5", [&rust_test, &jni_test, &system_test, &fs_test, &proc_test]
                .iter().filter(|t| t.success).count())
        };

        let validation_results = serde_json::json!({
            "success": true,
            "data": {
                "status": if all_passed { "ok" } else { "warning" },
                "message": format!("Pipeline validation {} - {} tests",
                    if all_passed { "passed" } else { "completed with warnings" },
                    test_count
                ),
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                "tests": {
                    "rust_core": {
                        "passed": rust_test.success,
                        "message": rust_test.message,
                        "details": rust_test.details
                    },
                    "jni_bridge": {
                        "passed": jni_test.success,
                        "message": jni_test.message,
                        "details": jni_test.details
                    },
                    "system_access": {
                        "passed": system_test.success,
                        "message": system_test.message,
                        "details": system_test.details
                    },
                    "filesystem": {
                        "passed": fs_test.success,
                        "message": fs_test.message,
                        "details": fs_test.details
                    },
                    "process_caps": {
                        "passed": proc_test.success,
                        "message": proc_test.message,
                        "details": proc_test.details
                    }
                },
                "environment": {
                    "architecture": std::env::consts::ARCH,
                    "operating_system": std::env::consts::OS,
                    "family": std::env::consts::FAMILY,
                    "rust_version": env!("CARGO_PKG_VERSION"),
                    "process_id": std::process::id(),
                    "thread_id": format!("{:?}", std::thread::current().id())
                }
            }
        });

        log::info!("testNative validation completed: {}",
            if all_passed { "ALL TESTS PASSED" } else { "SOME TESTS FAILED" });

        string_to_jstring(&env, &validation_results.to_string())
    })
}

/// Validation test results structure
#[derive(Debug)]
struct TestResult {
    success: bool,
    message: String,
    details: serde_json::Value,
}

/// Test 1: Core Rust functionality
fn test_rust_functionality() -> TestResult {
    let mut details = serde_json::Map::new();

    // Test string handling
    let test_string = "ObsidianBox validation test";
    details.insert("string_handling".to_string(),
        serde_json::json!({"input": test_string, "length": test_string.len()}));

    // Test JSON serialization
    let test_json = serde_json::json!({"test": true, "value": 42});
    details.insert("json_serialization".to_string(),
        serde_json::json!({"serialized": test_json.to_string()}));

    // Test memory allocation
    let test_vec: Vec<u32> = (0..1000).collect();
    details.insert("memory_allocation".to_string(),
        serde_json::json!({"vector_sum": test_vec.iter().sum::<u32>()}));

    // Test time functionality
    let now = std::time::SystemTime::now();
    details.insert("time_functions".to_string(),
        serde_json::json!({"unix_timestamp": now.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()}));

    TestResult {
        success: true,
        message: "Core Rust functionality operational".to_string(),
        details: serde_json::Value::Object(details),
    }
}

/// Test 2: JNI functionality
fn test_jni_functionality(env: &JNIEnv) -> TestResult {
    let mut details = serde_json::Map::new();

    // Test string creation
    let test_str = "JNI Bridge Test";
    let jni_result = env.new_string(test_str);
    let string_creation = jni_result.is_ok();
    details.insert("string_creation".to_string(),
        serde_json::json!({"success": string_creation, "test_string": test_str}));

    // Test JNI version info
    let version_result = env.get_version();
    let version_info = match version_result {
        Ok(v) => format!("JNI {:?}", v),
        Err(e) => format!("JNI version error: {:?}", e)
    };
    details.insert("jni_version".to_string(),
        serde_json::json!({"version_info": version_info}));

    // Test exception checking
    let exception_pending = env.exception_check().unwrap_or(false);
    details.insert("exception_state".to_string(),
        serde_json::json!({"pending": exception_pending}));

    TestResult {
        success: string_creation && !exception_pending,
        message: if string_creation && !exception_pending {
            "JNI bridge fully operational".to_string()
        } else {
            "JNI bridge has issues".to_string()
        },
        details: serde_json::Value::Object(details),
    }
}

/// Test 3: System access
fn test_system_access() -> TestResult {
    let mut details = serde_json::Map::new();

    // Test environment variable access
    let path_var = std::env::var("PATH").unwrap_or_else(|_| "not_available".to_string());
    details.insert("environment_access".to_string(),
        serde_json::json!({"path_variable_length": path_var.len(), "available": path_var != "not_available"}));

    // Test current directory access
    let current_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unavailable".to_string());
    details.insert("directory_access".to_string(),
        serde_json::json!({"current_dir": current_dir, "available": current_dir != "unavailable"}));

    // Test user ID access (Android specific)
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    details.insert("user_info".to_string(),
        serde_json::json!({"uid": uid, "gid": gid}));

    let success = path_var != "not_available" && current_dir != "unavailable";

    TestResult {
        success,
        message: if success {
            "System access operational".to_string()
        } else {
            "Limited system access".to_string()
        },
        details: serde_json::Value::Object(details),
    }
}

/// Test 4: Filesystem access
fn test_filesystem_access() -> TestResult {
    let mut details = serde_json::Map::new();

    // Test /proc filesystem access (Android/Linux)
    let proc_version = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unavailable".to_string());
    let proc_accessible = proc_version != "unavailable";
    details.insert("proc_filesystem".to_string(),
        serde_json::json!({
            "accessible": proc_accessible,
            "version_info": if proc_accessible {
                proc_version.lines().next().unwrap_or("").to_string()
            } else {
                "not_accessible".to_string()
            }
        }));

    // Test /system access (Android specific)
    let system_accessible = std::path::Path::new("/system").exists();
    details.insert("system_partition".to_string(),
        serde_json::json!({"accessible": system_accessible}));

    // Test /data access
    let data_accessible = std::path::Path::new("/data").exists();
    details.insert("data_partition".to_string(),
        serde_json::json!({"accessible": data_accessible}));

    // Test tmpdir access
    let tmp_dir = std::env::temp_dir();
    let tmp_accessible = tmp_dir.exists();
    details.insert("temp_directory".to_string(),
        serde_json::json!({"path": tmp_dir.to_string_lossy(), "accessible": tmp_accessible}));

    let success = proc_accessible && system_accessible;

    TestResult {
        success,
        message: if success {
            "Filesystem access operational".to_string()
        } else {
            "Limited filesystem access".to_string()
        },
        details: serde_json::Value::Object(details),
    }
}

/// Test 5: Process capabilities
fn test_process_capabilities() -> TestResult {
    let mut details = serde_json::Map::new();

    // Test process ID access
    let pid = std::process::id();
    details.insert("process_info".to_string(),
        serde_json::json!({"pid": pid}));

    // Test thread spawning capability
    let thread_test = std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        42u32
    }).join();

    let threading_works = thread_test.is_ok() && thread_test.unwrap() == 42;
    details.insert("threading".to_string(),
        serde_json::json!({"capable": threading_works}));

    // Test command execution capability
    let command_test = std::process::Command::new("echo")
        .arg("test")
        .output();

    let command_works = command_test.is_ok() &&
        command_test.as_ref().map(|o| o.status.success()).unwrap_or(false);
    details.insert("command_execution".to_string(),
        serde_json::json!({"capable": command_works}));

    // Test memory mapping (basic test)
    let memory_test = Box::new([0u8; 1024]);
    let memory_works = memory_test.len() == 1024;
    details.insert("memory_management".to_string(),
        serde_json::json!({"capable": memory_works}));

    let success = threading_works && memory_works;

    TestResult {
        success,
        message: if success {
            "Process capabilities operational".to_string()
        } else {
            "Limited process capabilities".to_string()
        },
        details: serde_json::Value::Object(details),
    }
}

/// JNI: Detect ObsidianBox installation
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_detectObsidianBox(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = obsidianbox::detect_obsidianbox();
    string_to_jstring(&env, &result)
}

/// JNI: Uninstall ObsidianBox
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_uninstallObsidianBox(
    mut env: JNIEnv,
    _class: JClass,
    target_dir: JString,
) -> jstring {
    init_logging();
    
    let dir: String = match env.get_string(&target_dir) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid target directory"),
    };
    
    let result = obsidianbox::uninstall_obsidianbox(&dir);
    string_to_jstring(&env, &result)
}

/// JNI: Create ObsidianBox snapshot
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_createObsidianBoxSnapshot(
    mut env: JNIEnv,
    _class: JClass,
    target_path: JString,
) -> jstring {
    init_logging();
    
    let path: String = match env.get_string(&target_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid target path"),
    };
    
    let result = obsidianbox::obsidianbox_snapshot(&path);
    string_to_jstring(&env, &result)
}

/// JNI: Restore ObsidianBox from snapshot
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_restoreObsidianBoxSnapshot(
    mut env: JNIEnv,
    _class: JClass,
    snapshot_id: JString,
) -> jstring {
    init_logging();
    
    let id: String = match env.get_string(&snapshot_id) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid snapshot ID"),
    };
    
    let result = obsidianbox::obsidianbox_restore(&id);
    string_to_jstring(&env, &result)
}

/// JNI: List ObsidianBox snapshots
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_listSnapshots(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let result = obsidianbox::list_obsidianbox_snapshots();
    string_to_jstring(&env, &result)
}

// ============================================================
// Legacy Detection & Migration FFI Functions
// ============================================================

/// JNI: Detect legacy ObsidianBox installations
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectLegacyObsidianBox(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    log::info!("nativeDetectLegacyObsidianBox called");
    let result = obsidianbox::detect_legacy_obsidianbox();
    string_to_jstring(&env, &result)
}

/// JNI: Generate migration plan for legacy installation
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGenerateMigrationPlan(
    mut env: JNIEnv,
    _class: JClass,
    legacy_path: JString,
) -> jstring {
    init_logging();
    
    let path: String = match env.get_string(&legacy_path) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid legacy path"),
    };
    
    log::info!("nativeGenerateMigrationPlan called for: {}", path);
    let result = obsidianbox::generate_migration_plan(&path);
    string_to_jstring(&env, &result)
}

/// JNI: Execute a migration action
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeExecuteMigrationAction(
    mut env: JNIEnv,
    _class: JClass,
    action_json: JString,
) -> jstring {
    init_logging();
    
    let action: String = match env.get_string(&action_json) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid action JSON"),
    };
    
    log::info!("nativeExecuteMigrationAction called");
    let result = obsidianbox::execute_migration_action(&action);
    string_to_jstring(&env, &result)
}

// ============================================================
// Multi-Provider FFI Functions
// ============================================================

/// JNI: Detect all ObsidianBox providers
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDetectAllProviders(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    log::info!("nativeDetectAllProviders called");
    let result = obsidianbox::detect_all_providers();
    string_to_jstring(&env, &result)
}

/// JNI: Generate unified symlink map
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGenerateUnifiedSymlinkMap(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    log::info!("nativeGenerateUnifiedSymlinkMap called");
    let result = obsidianbox::generate_unified_symlink_map();
    string_to_jstring(&env, &result)
}

/// JNI: Deduplicate applets for preferred provider
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeDeduplicateApplets(
    mut env: JNIEnv,
    _class: JClass,
    preferred_provider: JString,
) -> jstring {
    init_logging();
    
    let provider_id: String = match env.get_string(&preferred_provider) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid provider ID"),
    };
    
    log::info!("nativeDeduplicateApplets called for: {}", provider_id);
    let result = obsidianbox::deduplicate_applets(&provider_id);
    string_to_jstring(&env, &result)
}

// ============================================================
// Conflict Resolution FFI Functions
// ============================================================

/// JNI: Resolve a Magisk conflict
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeResolveConflict(
    mut env: JNIEnv,
    _class: JClass,
    conflict_json: JString,
    strategy_json: JString,
) -> jstring {
    init_logging();
    
    let conflict: String = match env.get_string(&conflict_json) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid conflict JSON"),
    };
    
    let strategy: String = match env.get_string(&strategy_json) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid strategy JSON"),
    };
    
    log::info!("nativeResolveConflict called");
    let result = magisk::resolve_conflict(&conflict, &strategy);
    string_to_jstring(&env, &result)
}

/// JNI: Get applets from a module
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGetModuleApplets(
    mut env: JNIEnv,
    _class: JClass,
    module_id: JString,
) -> jstring {
    init_logging();
    
    let id: String = match env.get_string(&module_id) {
        Ok(s) => s.into(),
        Err(_) => return error_jstring(&env, "Invalid module ID"),
    };
    
    log::info!("nativeGetModuleApplets called for: {}", id);
    let result = magisk::get_module_applets(&id);
    string_to_jstring(&env, &result)
}

// ============================================================
// Boot Monitor FFI Functions
// ============================================================

/// JNI: Generate boot monitor Magisk module
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeGenerateBootMonitorModule(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jstring {
    init_logging();
    
    let config: safety::BootHealthConfig = if env.get_string(&config_json).is_ok() {
        let config_str: String = env.get_string(&config_json).unwrap().into();
        serde_json::from_str(&config_str).unwrap_or_default()
    } else {
        safety::BootHealthConfig::default()
    };
    
    log::info!("nativeGenerateBootMonitorModule called");
    let result = safety::generate_boot_monitor_module(&config);
    string_to_jstring(&env, &result)
}

/// JNI: Run boot health check
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunBootHealthCheck(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    log::info!("nativeRunBootHealthCheck called");
    let result = safety::run_boot_health_check();
    string_to_jstring(&env, &result)
}

// ============================================================
// Diagnostics FFI Functions
// ============================================================

/// JNI: Run symlink diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSymlinkDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::check_symlinks() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("Symlink diagnostics failed: {}", e)),
    }
}

/// JNI: Run PATH diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunPathDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::check_path_integrity() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("PATH diagnostics failed: {}", e)),
    }
}

/// JNI: Run SELinux diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunSelinuxDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::check_selinux() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("SELinux diagnostics failed: {}", e)),
    }
}

/// JNI: Run Magisk diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunMagiskDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::check_magisk() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("Magisk diagnostics failed: {}", e)),
    }
}

/// JNI: Run ObsidianBox diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunObsidianBoxDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::check_obsidianbox_version() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("ObsidianBox diagnostics failed: {}", e)),
    }
}

/// JNI: Run full diagnostics
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeRunFullDiagnostics(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    match diagnostics::run_full_diagnostics() {
        Ok(result) => string_to_jstring(&env, &result),
        Err(e) => error_jstring(&env, &format!("Full diagnostics failed: {}", e)),
    }
}

// ============================================================
// Terminal PTY Functions
// ============================================================

/// JNI: Create terminal session
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalCreate(
    mut env: JNIEnv,
    _class: JClass,
    shell: JString,
    rows: jint,
    cols: jint,
    use_root: jboolean,
) -> jstring {
    init_logging();
    let shell_str = env.get_string(&shell)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    let result = terminal::terminal_create(
        &shell_str,
        rows as u16,
        cols as u16,
        use_root != 0,
    );
    string_to_jstring(&env, &result)
}

/// JNI: Write to terminal
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalWrite(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    data: JString,
) -> jstring {
    init_logging();
    let data_str = env.get_string(&data)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    let result = terminal::terminal_write(fd, &data_str);
    string_to_jstring(&env, &result)
}

/// JNI: Read from terminal
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalRead(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    timeout_ms: jint,
) -> jstring {
    init_logging();
    let result = terminal::terminal_read(fd, timeout_ms);
    string_to_jstring(&env, &result)
}

/// JNI: Resize terminal
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalResize(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    rows: jint,
    cols: jint,
) -> jstring {
    init_logging();
    let result = terminal::terminal_resize(fd, rows as u16, cols as u16);
    string_to_jstring(&env, &result)
}

/// JNI: Close terminal session
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalClose(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jstring {
    init_logging();
    let result = terminal::terminal_close(fd);
    string_to_jstring(&env, &result)
}

/// JNI: Get terminal session info
#[no_mangle]
pub extern "system" fn Java_com_obsidianbox_data_nativebridge_NativeBridge_nativeTerminalGetInfo(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jstring {
    init_logging();
    let result = terminal::terminal_get_info(fd);
    string_to_jstring(&env, &result)
}
