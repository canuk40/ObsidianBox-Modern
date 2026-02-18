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

//! Safety utilities for panic-free FFI operations
//!
//! Provides helpers to ensure all Rust FFI exports are panic-safe
//! and return structured JSON errors instead of crashing.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::panic::{self, AssertUnwindSafe};

// =============================================================================
// Error Types
// =============================================================================

/// Standard error codes for structured errors
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InternalPanic,
    InvalidArgument,
    IoError,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    RootRequired,
    MagiskNotFound,
    SelinuxBlocked,
    SnapshotFailed,
    RollbackFailed,
    ParseError,
    ShellError,
    TimeoutError,
    Unknown,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::InternalPanic => "internal_panic",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::IoError => "io_error",
            ErrorCode::PermissionDenied => "permission_denied",
            ErrorCode::NotFound => "not_found",
            ErrorCode::AlreadyExists => "already_exists",
            ErrorCode::RootRequired => "root_required",
            ErrorCode::MagiskNotFound => "magisk_not_found",
            ErrorCode::SelinuxBlocked => "selinux_blocked",
            ErrorCode::SnapshotFailed => "snapshot_failed",
            ErrorCode::RollbackFailed => "rollback_failed",
            ErrorCode::ParseError => "parse_error",
            ErrorCode::ShellError => "shell_error",
            ErrorCode::TimeoutError => "timeout_error",
            ErrorCode::Unknown => "unknown",
        }
    }
}

/// Standard status values
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warning,
    Error,
}

// =============================================================================
// JSON Error Helpers
// =============================================================================

/// Create a structured JSON error string
pub fn json_error(message: &str, code: ErrorCode, details: Option<Value>) -> String {
    let error = json!({
        "success": false,
        "status": "error",
        "message": message,
        "code": code.as_str(),
        "details": details.unwrap_or(Value::Null)
    });
    error.to_string()
}

/// Create a JSON error with just a message
pub fn json_error_simple(message: &str) -> String {
    json_error(message, ErrorCode::Unknown, None)
}

/// Create a JSON warning (non-fatal)
pub fn json_warning(message: &str, details: Option<Value>) -> String {
    let warning = json!({
        "success": true,
        "status": "warning",
        "message": message,
        "details": details.unwrap_or(Value::Null)
    });
    warning.to_string()
}

/// Create a panic error from catch_unwind result
pub fn json_panic_error(panic_info: &str) -> String {
    json_error(
        "Internal error occurred",
        ErrorCode::InternalPanic,
        Some(json!({
            "panic": panic_info,
            "suggestion": "Please report this issue"
        }))
    )
}

/// Convert anyhow::Error to JSON error string
pub fn anyhow_to_json(err: &anyhow::Error, code: ErrorCode) -> String {
    let chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
    json_error(
        &err.to_string(),
        code,
        Some(json!({
            "error_chain": chain
        }))
    )
}

/// Convert std::io::Error to JSON error string
pub fn io_error_to_json(err: &std::io::Error) -> String {
    let code = match err.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        std::io::ErrorKind::TimedOut => ErrorCode::TimeoutError,
        _ => ErrorCode::IoError,
    };
    json_error(
        &err.to_string(),
        code,
        Some(json!({
            "kind": format!("{:?}", err.kind())
        }))
    )
}

// =============================================================================
// Panic-Safe FFI Wrapper
// =============================================================================

/// Execute a function with panic catching, returning JSON error on panic
pub fn safe_execute<F, T>(f: F) -> String
where
    F: FnOnce() -> T + panic::UnwindSafe,
    T: Into<String>,
{
    match panic::catch_unwind(f) {
        Ok(result) => result.into(),
        Err(panic_payload) => {
            // Extract panic message
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            
            log::error!("FFI panic caught: {}", panic_msg);
            json_panic_error(&panic_msg)
        }
    }
}

/// Execute an async-like closure with panic safety
/// Use when the inner function returns a String directly
pub fn safe_ffi<F>(f: F) -> String
where
    F: FnOnce() -> String + panic::UnwindSafe,
{
    safe_execute(f)
}

/// Execute with AssertUnwindSafe wrapper for closures that capture mutable state
pub fn safe_ffi_mut<F>(f: F) -> String
where
    F: FnOnce() -> String,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            
            log::error!("FFI panic caught (mut): {}", panic_msg);
            json_panic_error(&panic_msg)
        }
    }
}

// =============================================================================
// Result Helpers
// =============================================================================

/// Convert a Result to JSON string
pub fn result_to_json<T: Serialize, E: std::fmt::Display>(
    result: Result<T, E>,
    error_code: ErrorCode
) -> String {
    match result {
        Ok(data) => {
            serde_json::to_string(&json!({
                "success": true,
                "status": "ok",
                "data": data
            })).unwrap_or_else(|_| json_error_simple("Serialization failed"))
        }
        Err(err) => json_error(&err.to_string(), error_code, None)
    }
}

/// Convert Option to JSON, treating None as warning
pub fn option_to_json<T: Serialize>(
    opt: Option<T>,
    none_message: &str
) -> String {
    match opt {
        Some(data) => {
            serde_json::to_string(&json!({
                "success": true,
                "status": "ok",
                "data": data
            })).unwrap_or_else(|_| json_error_simple("Serialization failed"))
        }
        None => json_warning(none_message, None)
    }
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Validate a path string is not empty
pub fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Path cannot be empty".to_string());
    }
    if path.contains('\0') {
        return Err("Path contains null byte".to_string());
    }
    Ok(())
}

/// Validate a string is valid UTF-8 and not empty
pub fn validate_string(s: &str, field_name: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("{} cannot be empty", field_name));
    }
    Ok(())
}

// =============================================================================
// Macro for FFI Safety (use in lib.rs)
// =============================================================================

/// Macro to wrap FFI functions with panic catching
/// 
/// Usage:
/// ```rust
/// safe_jni_call!(env, {
///     let result = my_rust_function();
///     string_to_jstring(&env, &result)
/// })
/// ```
#[macro_export]
macro_rules! safe_jni_call {
    ($env:expr, $body:expr) => {{
        use std::panic::{self, AssertUnwindSafe};
        
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
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
                let error_json = $crate::safety::json_panic_error(&panic_msg);
                $crate::string_to_jstring(&$env, &error_json)
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_error() {
        let error = json_error("Test error", ErrorCode::NotFound, None);
        assert!(error.contains("error"));
        assert!(error.contains("not_found"));
    }

    #[test]
    fn test_safe_execute_normal() {
        let result = safe_execute(|| "success".to_string());
        assert_eq!(result, "success");
    }

    #[test]
    fn test_safe_execute_panic() {
        let result = safe_execute(|| -> String {
            panic!("test panic");
        });
        assert!(result.contains("internal_panic"));
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/valid/path").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("path\0with\0nulls").is_err());
    }
}

// =============================================================================
// Boot-Time Safety Monitor (Improvement Recommendation #4)
// =============================================================================

use std::path::Path;

/// Boot-time health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootHealthConfig {
    /// Check for ObsidianBox binary presence
    pub check_binary: bool,
    /// Check critical symlinks
    pub check_symlinks: bool,
    /// Critical symlinks to verify
    pub critical_symlinks: Vec<String>,
    /// Auto-repair if issues found
    pub auto_repair: bool,
    /// Log to file
    pub log_to_file: bool,
    /// Log file path
    pub log_path: String,
    /// Notify user on issues
    pub notify_user: bool,
}

impl Default for BootHealthConfig {
    fn default() -> Self {
        Self {
            check_binary: true,
            check_symlinks: true,
            critical_symlinks: vec![
                "ls".to_string(),
                "cp".to_string(),
                "mv".to_string(),
                "rm".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "find".to_string(),
                "sh".to_string(),
            ],
            auto_repair: false,
            log_to_file: true,
            log_path: "/data/adb/obsidianbox_modern/boot.log".to_string(),
            notify_user: true,
        }
    }
}

/// Generate Magisk module template for boot-time safety monitor
pub fn generate_boot_monitor_module(config: &BootHealthConfig) -> String {
    let module_prop = r#"id=obsidianbox-modern-monitor
name=ObsidianBox Modern Boot Monitor
version=1.0.0
versionCode=1
author=ObsidianBox Modern
description=Boot-time health check for ObsidianBox Modern installation
updateJson=
"#;

    let post_fs_data_sh = generate_post_fs_data_script(config);
    let service_sh = generate_service_script(config);
    
    serde_json::to_string_pretty(&serde_json::json!({
        "module_prop": module_prop,
        "post-fs-data.sh": post_fs_data_sh,
        "service.sh": service_sh,
        "files": [
            {"path": "module.prop", "content": module_prop},
            {"path": "post-fs-data.sh", "content": post_fs_data_sh},
            {"path": "service.sh", "content": service_sh},
        ]
    })).unwrap_or_else(|_| "{}".to_string())
}

fn generate_post_fs_data_script(config: &BootHealthConfig) -> String {
    let mut script = String::from(r#"#!/system/bin/sh
# ObsidianBox Modern Boot Monitor - post-fs-data stage
# This runs before Zygote starts

MODDIR=${0%/*}
LOGFILE="$MODDIR/boot.log"
BB_PATH="/system/xbin/obsidianbox"
BB_INSTALL_DIR="/system/xbin"

log() {
    echo "[$(date +%H:%M:%S)] $1" >> "$LOGFILE"
}

log "=== ObsidianBox Modern Boot Monitor Starting ==="

"#);

    if config.check_binary {
        script.push_str(r#"
# Check ObsidianBox binary exists
if [ -f "$BB_PATH" ] || [ -L "$BB_PATH" ]; then
    log "OK: ObsidianBox binary found at $BB_PATH"
    
    # Verify it's executable
    if [ -x "$BB_PATH" ]; then
        log "OK: ObsidianBox is executable"
        VERSION=$("$BB_PATH" --help 2>/dev/null | head -1)
        log "VERSION: $VERSION"
    else
        log "ERROR: ObsidianBox exists but is not executable"
        # Attempt repair if enabled
"#);

        if config.auto_repair {
            script.push_str(r#"        chmod 755 "$BB_PATH" 2>/dev/null && log "REPAIRED: Set executable permission"
"#);
        }

        script.push_str(r#"    fi
else
    log "ERROR: ObsidianBox binary not found at $BB_PATH"
fi
"#);
    }

    if config.check_symlinks {
        script.push_str(r#"
# Check critical symlinks
SYMLINK_ERRORS=0
"#);
        for symlink in &config.critical_symlinks {
            script.push_str(&format!(r#"
if [ -L "$BB_INSTALL_DIR/{}" ]; then
    log "OK: Symlink {} exists"
else
    log "WARNING: Symlink {} missing"
    SYMLINK_ERRORS=$((SYMLINK_ERRORS + 1))
"#, symlink, symlink, symlink));

            if config.auto_repair {
                script.push_str(&format!(r#"    # Attempt repair
    if [ -x "$BB_PATH" ]; then
        "$BB_PATH" --install -s "$BB_INSTALL_DIR" 2>/dev/null
        log "REPAIR: Attempted symlink reinstall"
    fi
"#));
            }

            script.push_str("fi\n");
        }
        
        script.push_str(r#"
if [ $SYMLINK_ERRORS -gt 0 ]; then
    log "SUMMARY: $SYMLINK_ERRORS symlink issues found"
else
    log "SUMMARY: All critical symlinks present"
fi
"#);
    }

    script.push_str(r#"
log "=== Boot Monitor Complete ==="
"#);

    script
}

fn generate_service_script(config: &BootHealthConfig) -> String {
    let mut script = String::from(r#"#!/system/bin/sh
# ObsidianBox Modern Boot Monitor - service stage
# This runs after boot is complete

MODDIR=${0%/*}
LOGFILE="$MODDIR/boot.log"
BB_PATH="/system/xbin/obsidianbox"

log() {
    echo "[$(date +%H:%M:%S)] [service] $1" >> "$LOGFILE"
}

log "=== Service Stage Starting ==="

# Wait for boot to complete
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

log "Boot completed, running post-boot checks"

"#);

    // Check if ObsidianBox is actually functional
    script.push_str(r#"
# Functional test
TEST_OUTPUT=$("$BB_PATH" echo "test" 2>/dev/null)
if [ "$TEST_OUTPUT" = "test" ]; then
    log "OK: ObsidianBox functional test passed"
else
    log "ERROR: ObsidianBox functional test failed"
fi

# Check PATH
if echo "$PATH" | grep -q "/system/xbin"; then
    log "OK: /system/xbin in PATH"
else
    log "WARNING: /system/xbin not in PATH"
fi

"#);

    if config.notify_user {
        script.push_str(r#"
# Notify user if there were errors
if grep -q "ERROR" "$LOGFILE"; then
    # Send notification (requires proper permissions)
    log "NOTIFY: Errors detected during boot"
fi
"#);
    }

    script.push_str(r#"
log "=== Service Stage Complete ==="
"#);

    script
}

/// Run boot-time health check manually
pub fn run_boot_health_check() -> String {
    let mut issues: Vec<serde_json::Value> = Vec::new();
    let mut checks: Vec<serde_json::Value> = Vec::new();
    
    let bb_path = Path::new("/system/xbin/obsidianbox");
    let install_dir = Path::new("/system/xbin");
    
    // Check ObsidianBox binary
    let binary_check = if bb_path.exists() {
        if bb_path.is_symlink() {
            // Check symlink target
            match std::fs::read_link(bb_path) {
                Ok(target) => {
                    if target.exists() {
                        serde_json::json!({
                            "check": "obsidianbox_binary",
                            "status": "ok",
                            "message": format!("ObsidianBox symlink points to {:?}", target)
                        })
                    } else {
                        issues.push(serde_json::json!({
                            "type": "broken_symlink",
                            "path": "/system/xbin/obsidianbox",
                            "severity": "critical"
                        }));
                        serde_json::json!({
                            "check": "obsidianbox_binary",
                            "status": "error",
                            "message": "ObsidianBox symlink is broken"
                        })
                    }
                }
                Err(_) => serde_json::json!({
                    "check": "obsidianbox_binary",
                    "status": "ok",
                    "message": "ObsidianBox binary exists"
                })
            }
        } else {
            serde_json::json!({
                "check": "obsidianbox_binary",
                "status": "ok",
                "message": "ObsidianBox binary exists"
            })
        }
    } else {
        issues.push(serde_json::json!({
            "type": "missing_binary",
            "path": "/system/xbin/obsidianbox",
            "severity": "critical"
        }));
        serde_json::json!({
            "check": "obsidianbox_binary",
            "status": "error",
            "message": "ObsidianBox binary not found"
        })
    };
    checks.push(binary_check);
    
    // Check critical symlinks
    let critical_symlinks = ["ls", "cp", "mv", "rm", "cat", "grep", "find"];
    let mut symlink_ok = 0;
    let mut symlink_missing = 0;
    
    for applet in &critical_symlinks {
        let symlink_path = install_dir.join(applet);
        if symlink_path.exists() || symlink_path.is_symlink() {
            symlink_ok += 1;
        } else {
            symlink_missing += 1;
            issues.push(serde_json::json!({
                "type": "missing_symlink",
                "applet": applet,
                "severity": "warning"
            }));
        }
    }
    
    checks.push(serde_json::json!({
        "check": "critical_symlinks",
        "status": if symlink_missing == 0 { "ok" } else { "warning" },
        "ok_count": symlink_ok,
        "missing_count": symlink_missing
    }));
    
    // Check PATH
    let path_check = if let Ok(path) = std::env::var("PATH") {
        let has_xbin = path.contains("/system/xbin");
        let has_bin = path.contains("/system/bin");
        serde_json::json!({
            "check": "path_config",
            "status": if has_xbin { "ok" } else { "warning" },
            "has_system_xbin": has_xbin,
            "has_system_bin": has_bin
        })
    } else {
        serde_json::json!({
            "check": "path_config",
            "status": "error",
            "message": "Could not read PATH"
        })
    };
    checks.push(path_check);
    
    serde_json::to_string_pretty(&serde_json::json!({
        "success": true,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "checks": checks,
        "issues": issues,
        "healthy": issues.iter().all(|i| 
            i.get("severity").and_then(|s| s.as_str()) != Some("critical")
        )
    })).unwrap_or_else(|_| r#"{"success":false,"error":"Serialization failed"}"#.to_string())
}
