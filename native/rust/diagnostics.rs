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

//! Diagnostics Engine for ObsidianBox Modern
//! 
//! Provides comprehensive system diagnostics for:
//! - Symlink integrity
//! - PATH environment analysis
//! - SELinux status and conflicts
//! - Magisk environment detection
//! - ObsidianBox version verification

use crate::result::NativeResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

/// Severity level for diagnostic issues
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Error,
    Critical,
}

/// Individual diagnostic issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticIssue {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_path: Option<String>,
    pub can_auto_fix: bool,
    pub fix_command: Option<String>,
}

/// Result of a single diagnostic check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    #[serde(rename = "type")]
    pub check_type: String,
    pub status: Severity,
    pub summary: String,
    pub issues: Vec<DiagnosticIssue>,
    pub details: Value,
}

/// Full diagnostic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub status: Severity,
    pub timestamp: i64,
    pub checks: Vec<CheckResult>,
    pub summary: DiagnosticSummary,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticSummary {
    pub total_checks: i32,
    pub passed: i32,
    pub warnings: i32,
    pub errors: i32,
    pub critical: i32,
}

/// Common symlink directories to scan
const SYMLINK_DIRS: &[&str] = &[
    "/system/bin",
    "/system/xbin",
    "/data/adb/obsidianbox",
    "/data/local/tmp",
    "/sbin",
    "/vendor/bin",
];

/// Common ObsidianBox applets
const COMMON_APPLETS: &[&str] = &[
    "ls", "cat", "cp", "mv", "rm", "mkdir", "chmod", "chown", "grep", "sed",
    "awk", "find", "tar", "gzip", "wget", "ping", "ps", "kill", "df", "du",
    "mount", "ln", "touch", "head", "tail", "sort", "uniq", "wc", "vi", "sh",
];

/// Execute shell command and return output
fn run_shell(cmd: &str) -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .context("Failed to execute shell command")?;
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Execute shell command as root
fn run_root_shell(cmd: &str) -> Result<String> {
    let output = Command::new("su")
        .arg("-c")
        .arg(cmd)
        .output()
        .context("Failed to execute root shell command")?;
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Check if path is world-writable
fn is_world_writable(path: &str) -> bool {
    if let Ok(metadata) = fs::metadata(path) {
        (metadata.mode() & 0o002) != 0
    } else {
        false
    }
}

/// Check symlink integrity
pub fn check_symlinks() -> Result<String> {
    let mut valid_count = 0;
    let mut broken_count = 0;
    let mut missing_count = 0;
    let mut issues: Vec<DiagnosticIssue> = Vec::new();
    let mut details: Vec<Value> = Vec::new();

    for dir in SYMLINK_DIRS {
        if !Path::new(dir).exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();

                if path.is_symlink() {
                    match fs::read_link(&path) {
                        Ok(target) => {
                            let target_path = if target.is_absolute() {
                                target.clone()
                            } else {
                                path.parent().unwrap_or(Path::new("/")).join(&target)
                            };

                            if target_path.exists() {
                                valid_count += 1;
                                details.push(json!({
                                    "path": path_str,
                                    "target": target.to_string_lossy(),
                                    "status": "valid"
                                }));
                            } else {
                                broken_count += 1;
                                details.push(json!({
                                    "path": path_str,
                                    "target": target.to_string_lossy(),
                                    "status": "broken"
                                }));
                                issues.push(DiagnosticIssue {
                                    id: format!("broken_symlink_{}", broken_count),
                                    severity: Severity::Warning,
                                    title: "Broken Symlink".to_string(),
                                    description: format!(
                                        "Symlink {} points to non-existent target {}",
                                        path_str,
                                        target.to_string_lossy()
                                    ),
                                    affected_path: Some(path_str.clone()),
                                    can_auto_fix: true,
                                    fix_command: Some(format!("rm -f '{}'", path_str)),
                                });
                            }
                        }
                        Err(_) => {
                            broken_count += 1;
                            issues.push(DiagnosticIssue {
                                id: format!("unreadable_symlink_{}", broken_count),
                                severity: Severity::Error,
                                title: "Unreadable Symlink".to_string(),
                                description: format!("Cannot read symlink target: {}", path_str),
                                affected_path: Some(path_str),
                                can_auto_fix: false,
                                fix_command: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for missing common applets
    for applet in COMMON_APPLETS {
        let mut found = false;
        for dir in SYMLINK_DIRS {
            let applet_path = format!("{}/{}", dir, applet);
            if Path::new(&applet_path).exists() {
                found = true;
                break;
            }
        }
        if !found {
            missing_count += 1;
        }
    }

    let status = if broken_count > 0 || missing_count > 10 {
        Severity::Warning
    } else {
        Severity::Ok
    };

    let result = CheckResult {
        check_type: "symlinks".to_string(),
        status,
        summary: format!(
            "{} valid, {} broken, {} missing applets",
            valid_count, broken_count, missing_count
        ),
        issues,
        details: json!({
            "valid": valid_count,
            "broken": broken_count,
            "missing": missing_count,
            "scanned_dirs": SYMLINK_DIRS,
            "symlinks": details
        }),
    };

    serde_json::to_string(&result).context("Failed to serialize symlink check result")
}

/// Check PATH integrity
pub fn check_path_integrity() -> Result<String> {
    let path_var = std::env::var("PATH").unwrap_or_else(|_| {
        run_shell("echo $PATH").unwrap_or_default()
    });

    let mut issues: Vec<DiagnosticIssue> = Vec::new();
    let mut valid_dirs: Vec<String> = Vec::new();
    let mut missing_dirs: Vec<String> = Vec::new();
    let mut duplicate_dirs: Vec<String> = Vec::new();
    let mut insecure_dirs: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    
    // Legacy paths that are optional on modern Android
    let legacy_optional_paths = [
        "/system/xbin",    // Removed in Android 10
        "/vendor/xbin",    // Optional vendor directory
        "/product/bin",    // Optional product directory
        "/odm/bin",        // Optional ODM directory
    ];

    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }

        // Check for duplicates
        if seen.contains(dir) {
            duplicate_dirs.push(dir.to_string());
            issues.push(DiagnosticIssue {
                id: format!("duplicate_path_{}", duplicate_dirs.len()),
                severity: Severity::Info,
                title: "Duplicate PATH Entry".to_string(),
                description: format!("Directory appears multiple times in PATH: {}", dir),
                affected_path: Some(dir.to_string()),
                can_auto_fix: true,
                fix_command: None,
            });
            continue;
        }
        seen.insert(dir.to_string());

        let path = Path::new(dir);
        if !path.exists() {
            missing_dirs.push(dir.to_string());
            
            // Check if this is a legacy/optional path
            let is_optional = legacy_optional_paths.contains(&dir);
            
            issues.push(DiagnosticIssue {
                id: format!("missing_path_{}", missing_dirs.len()),
                severity: if is_optional { Severity::Info } else { Severity::Warning },
                title: if is_optional { 
                    "Optional PATH Directory Not Present".to_string()
                } else {
                    "Missing PATH Directory".to_string()
                },
                description: if is_optional {
                    format!("Legacy directory not present (expected on modern Android): {}", dir)
                } else {
                    format!("Directory in PATH does not exist: {}", dir)
                },
                affected_path: Some(dir.to_string()),
                can_auto_fix: false,
                fix_command: None,
            });
        } else {
            valid_dirs.push(dir.to_string());

            // Check for insecure (world-writable) directories
            if is_world_writable(dir) {
                insecure_dirs.push(dir.to_string());
                issues.push(DiagnosticIssue {
                    id: format!("insecure_path_{}", insecure_dirs.len()),
                    severity: Severity::Critical,
                    title: "Insecure PATH Directory".to_string(),
                    description: format!(
                        "Directory {} is world-writable, potential security risk",
                        dir
                    ),
                    affected_path: Some(dir.to_string()),
                    can_auto_fix: true,
                    fix_command: Some(format!("chmod o-w '{}'", dir)),
                });
            }
        }
    }

    // Filter out Info-level issues (keep only Warning/Error/Critical)
    // Info messages are just FYI, not actual problems that need user attention
    let actionable_issues: Vec<DiagnosticIssue> = issues.iter()
        .filter(|issue| issue.severity != Severity::Info)
        .cloned()
        .collect();

    // Count only non-legacy missing directories for summary
    let actionable_missing: Vec<String> = missing_dirs.iter()
        .filter(|dir| !legacy_optional_paths.contains(&dir.as_str()))
        .cloned()
        .collect();

    let status = if !insecure_dirs.is_empty() {
        Severity::Critical
    } else if !actionable_missing.is_empty() {
        Severity::Warning
    } else if !duplicate_dirs.is_empty() {
        Severity::Info
    } else {
        Severity::Ok
    };

    let result = CheckResult {
        check_type: "path".to_string(),
        status,
        summary: if !actionable_missing.is_empty() || !insecure_dirs.is_empty() {
            format!(
                "{} valid, {} missing, {} insecure",
                valid_dirs.len(),
                actionable_missing.len(),
                insecure_dirs.len()
            )
        } else if valid_dirs.is_empty() {
            "No valid directories in PATH".to_string()
        } else {
            "No issues".to_string()
        },
        issues: actionable_issues,
        details: json!({
            "path_variable": path_var,
            "valid_dirs": valid_dirs,
            "missing_dirs": missing_dirs,
            "duplicate_dirs": duplicate_dirs,
            "insecure_dirs": insecure_dirs
        }),
    };

    serde_json::to_string(&result).context("Failed to serialize PATH check result")
}

/// Check SELinux status
pub fn check_selinux() -> Result<String> {
    let mut issues: Vec<DiagnosticIssue> = Vec::new();

    // Get SELinux mode
    let selinux_mode = run_shell("getenforce 2>/dev/null || echo 'Unknown'")
        .unwrap_or_else(|_| "Unknown".to_string());

    // Get SELinux policy info
    let selinux_policy = run_shell("cat /sys/fs/selinux/policyvers 2>/dev/null || echo 'Unknown'")
        .unwrap_or_else(|_| "Unknown".to_string());

    // Check for ObsidianBox-related denials
    let denials = run_root_shell(
        "dmesg 2>/dev/null | grep -i 'avc.*obsidianbox' | tail -5 || echo ''"
    ).unwrap_or_default();

    let has_denials = !denials.is_empty() && denials != "";

    if selinux_mode == "Enforcing" && has_denials {
        issues.push(DiagnosticIssue {
            id: "selinux_denials".to_string(),
            severity: Severity::Warning,
            title: "SELinux Denials Detected".to_string(),
            description: "Recent SELinux denials may affect ObsidianBox functionality".to_string(),
            affected_path: None,
            can_auto_fix: false,
            fix_command: None,
        });
    }

    if selinux_mode == "Enforcing" {
        issues.push(DiagnosticIssue {
            id: "selinux_enforcing".to_string(),
            severity: Severity::Info,
            title: "SELinux Enforcing".to_string(),
            description: "SELinux is enforcing. Some ObsidianBox operations may require policy adjustments.".to_string(),
            affected_path: None,
            can_auto_fix: false,
            fix_command: None,
        });
    }

    let status = if has_denials {
        Severity::Warning
    } else {
        Severity::Ok
    };

    let result = CheckResult {
        check_type: "selinux".to_string(),
        status,
        summary: format!("SELinux: {}", selinux_mode),
        issues,
        details: json!({
            "mode": selinux_mode,
            "policy_version": selinux_policy,
            "has_denials": has_denials,
            "recent_denials": if has_denials { denials } else { "None".to_string() }
        }),
    };

    serde_json::to_string(&result).context("Failed to serialize SELinux check result")
}

/// Check Magisk environment
pub fn check_magisk() -> Result<String> {
    let mut issues: Vec<DiagnosticIssue> = Vec::new();

    // Detect Magisk
    let magisk_version = run_shell("magisk -V 2>/dev/null || echo ''")
        .unwrap_or_default();
    let magisk_version_name = run_shell("magisk -v 2>/dev/null || echo ''")
        .unwrap_or_default();
    let is_magisk_installed = !magisk_version.is_empty();

    let mut modules: Vec<Value> = Vec::new();
    let mut conflicting_modules: Vec<String> = Vec::new();

    if is_magisk_installed {
        // List installed modules
        let modules_dir = "/data/adb/modules";
        if let Ok(entries) = fs::read_dir(modules_dir) {
            for entry in entries.flatten() {
                let module_path = entry.path();
                let module_name = entry.file_name().to_string_lossy().to_string();
                
                // Check if module is disabled
                let disabled = module_path.join("disable").exists();
                let remove = module_path.join("remove").exists();

                // Read module.prop for details
                let prop_path = module_path.join("module.prop");
                let props = if prop_path.exists() {
                    fs::read_to_string(&prop_path).unwrap_or_default()
                } else {
                    String::new()
                };

                // Check for ObsidianBox-related modules
                let is_obsidianbox_related = module_name.to_lowercase().contains("obsidianbox")
                    || props.to_lowercase().contains("obsidianbox");

                if is_obsidianbox_related && !disabled && !remove {
                    conflicting_modules.push(module_name.clone());
                    issues.push(DiagnosticIssue {
                        id: format!("magisk_conflict_{}", module_name),
                        severity: Severity::Warning,
                        title: "Potential Module Conflict".to_string(),
                        description: format!(
                            "Magisk module '{}' may conflict with ObsidianBox Modern",
                            module_name
                        ),
                        affected_path: Some(module_path.to_string_lossy().to_string()),
                        can_auto_fix: true,
                        fix_command: Some(format!("touch '{}/disable'", module_path.display())),
                    });
                }

                modules.push(json!({
                    "name": module_name,
                    "path": module_path.to_string_lossy(),
                    "disabled": disabled,
                    "pending_remove": remove,
                    "obsidianbox_related": is_obsidianbox_related
                }));
            }
        }

        // Check MagiskHide / DenyList status
        let deny_list = run_shell("magisk --denylist status 2>/dev/null || echo 'Unknown'")
            .unwrap_or_else(|_| "Unknown".to_string());

        if deny_list.contains("enabled") {
            issues.push(DiagnosticIssue {
                id: "magisk_denylist".to_string(),
                severity: Severity::Info,
                title: "DenyList Active".to_string(),
                description: "Magisk DenyList is enabled. Some apps may not see ObsidianBox.".to_string(),
                affected_path: None,
                can_auto_fix: false,
                fix_command: None,
            });
        }
    }

    let status = if !conflicting_modules.is_empty() {
        Severity::Warning
    } else if is_magisk_installed {
        Severity::Ok
    } else {
        Severity::Info
    };

    let result = CheckResult {
        check_type: "magisk".to_string(),
        status,
        summary: if is_magisk_installed {
            format!("Magisk {} ({} modules)", magisk_version_name, modules.len())
        } else {
            "Magisk not detected".to_string()
        },
        issues,
        details: json!({
            "installed": is_magisk_installed,
            "version": magisk_version,
            "version_name": magisk_version_name,
            "modules": modules,
            "conflicting_modules": conflicting_modules,
            "modules_path": "/data/adb/modules"
        }),
    };

    serde_json::to_string(&result).context("Failed to serialize Magisk check result")
}

/// Check ObsidianBox version
pub fn check_obsidianbox_version() -> Result<String> {
    let mut issues: Vec<DiagnosticIssue> = Vec::new();
    let bundled_version = "1.36.1"; // Version bundled with app

    // Try to find and get ObsidianBox version
    let mut found_path: Option<String> = None;
    let mut installed_version: Option<String> = None;
    let mut searched_paths = Vec::new();

    let search_paths = [
        // PRIORITY #1: App-internal installation (most common, always works)
        // Check both debug and release package names
        "/data/data/com.busyboxmodern.app.debug/files/obsidianbox",  // Debug build
        "/data/data/com.busyboxmodern.app/files/obsidianbox",        // Release build
        "/data/data/com.busyboxmodern.app.debug/files/busybox",      // Debug build (legacy)
        "/data/data/com.busyboxmodern.app/files/busybox",            // Release build (legacy)
        // PRIORITY #2: Magisk module paths
        "/data/adb/obsidianbox/obsidianbox",
        "/data/adb/busybox/busybox",
        // PRIORITY #3: System paths (requires root + system writable)
        "/system/xbin/obsidianbox",
        "/system/bin/obsidianbox",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        // PRIORITY #4: Alternative locations
        "/data/local/tmp/obsidianbox",
        "/sbin/obsidianbox",
    ];

    for path in search_paths {
        searched_paths.push(path.to_string());
        let path_obj = Path::new(path);
        
        // Check if file exists and is executable
        if path_obj.exists() {
            // Verify it's a file (not directory) and executable
            if let Ok(metadata) = fs::metadata(path) {
                let is_executable = metadata.mode() & 0o111 != 0; // Check any execute bit
                
                if metadata.is_file() && is_executable {
                    found_path = Some(path.to_string());
                    
                    // Try to get version from --help output (best effort, not required)
                    let version_output = run_shell(&format!("{} --help 2>&1 | head -1", path))
                        .unwrap_or_default();
                    
                    // Extract version if output contains BusyBox/ObsidianBox
                    if version_output.contains("BusyBox") || version_output.contains("ObsidianBox") {
                        if let Some(start) = version_output.find('v') {
                            if let Some(end) = version_output[start..].find(' ') {
                                installed_version = Some(version_output[start + 1..start + end].to_string());
                            } else {
                                installed_version = Some(version_output[start + 1..].trim().to_string());
                            }
                        }
                    } else {
                        // If --help doesn't work, use "app-internal" as version indicator
                        installed_version = Some("app-internal".to_string());
                    }
                    break;
                }
            }
        }
    }

    // Get applet count if found
    let applet_count = if let Some(ref path) = found_path {
        run_shell(&format!("{} --list 2>/dev/null | wc -l", path))
            .unwrap_or_default()
            .parse::<i32>()
            .unwrap_or(0)
    } else {
        0
    };

    // Compare versions (skip comparison for app-internal installations)
    let is_outdated = installed_version
        .as_ref()
        .map(|v| {
            // App-internal installations are always considered up-to-date
            // since they're bundled with the app
            if v == "app-internal" {
                false
            } else {
                version_compare(v, bundled_version) < 0
            }
        })
        .unwrap_or(false);

    if found_path.is_none() {
        issues.push(DiagnosticIssue {
            id: "obsidianbox_not_found".to_string(),
            severity: Severity::Warning,
            title: "ObsidianBox Not Installed".to_string(),
            description: "No ObsidianBox installation detected. Use the Installer to install it.".to_string(),
            affected_path: None,
            can_auto_fix: true,
            fix_command: None,
        });
    } else if is_outdated {
        issues.push(DiagnosticIssue {
            id: "obsidianbox_outdated".to_string(),
            severity: Severity::Info,
            title: "ObsidianBox Outdated".to_string(),
            description: format!(
                "Installed version {} is older than bundled version {}",
                installed_version.as_deref().unwrap_or("unknown"),
                bundled_version
            ),
            affected_path: found_path.clone(),
            can_auto_fix: true,
            fix_command: None,
        });
    }

    let status = if found_path.is_none() {
        Severity::Warning
    } else if is_outdated {
        Severity::Info
    } else {
        Severity::Ok
    };

    let result = CheckResult {
        check_type: "obsidianbox".to_string(),
        status,
        summary: if let Some(ref version) = installed_version {
            format!("ObsidianBox v{} ({} applets)", version, applet_count)
        } else {
            "ObsidianBox not installed".to_string()
        },
        issues,
        details: json!({
            "installed": found_path.is_some(),
            "path": found_path,
            "version": installed_version,
            "bundled_version": bundled_version,
            "applet_count": applet_count,
            "is_outdated": is_outdated,
            "searched_paths": searched_paths
        }),
    };

    // Return raw CheckResult JSON (not wrapped) for use by run_full_diagnostics
    serde_json::to_string(&result).context("Failed to serialize ObsidianBox check result")
}

/// Simple version comparison (returns -1, 0, 1)
fn version_compare(a: &str, b: &str) -> i32 {
    let parse_version = |v: &str| -> Vec<i32> {
        v.split('.')
            .filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
            .collect()
    };

    let va = parse_version(a);
    let vb = parse_version(b);

    for i in 0..va.len().max(vb.len()) {
        let a_part = va.get(i).unwrap_or(&0);
        let b_part = vb.get(i).unwrap_or(&0);
        
        if a_part < b_part {
            return -1;
        } else if a_part > b_part {
            return 1;
        }
    }
    0
}

/// Run full diagnostics
pub fn run_full_diagnostics() -> Result<String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut passed = 0;
    let mut warnings = 0;
    let mut errors = 0;
    let mut critical = 0;

    // Run all checks
    let check_fns: Vec<(&str, fn() -> Result<String>)> = vec![
        ("symlinks", check_symlinks),
        ("path", check_path_integrity),
        ("selinux", check_selinux),
        ("magisk", check_magisk),
        ("obsidianbox", check_obsidianbox_version),
    ];

    for (name, check_fn) in check_fns {
        match check_fn() {
            Ok(json_str) => {
                if let Ok(result) = serde_json::from_str::<CheckResult>(&json_str) {
                    match result.status {
                        Severity::Ok => passed += 1,
                        Severity::Info => passed += 1,
                        Severity::Warning => warnings += 1,
                        Severity::Error => errors += 1,
                        Severity::Critical => critical += 1,
                    }
                    checks.push(result);
                }
            }
            Err(e) => {
                errors += 1;
                checks.push(CheckResult {
                    check_type: name.to_string(),
                    status: Severity::Error,
                    summary: format!("Check failed: {}", e),
                    issues: vec![DiagnosticIssue {
                        id: format!("{}_failed", name),
                        severity: Severity::Error,
                        title: "Check Failed".to_string(),
                        description: e.to_string(),
                        affected_path: None,
                        can_auto_fix: false,
                        fix_command: None,
                    }],
                    details: json!({}),
                });
            }
        }
    }

    let total_checks = checks.len() as i32;
    let overall_status = if critical > 0 {
        Severity::Critical
    } else if errors > 0 {
        Severity::Error
    } else if warnings > 0 {
        Severity::Warning
    } else {
        Severity::Ok
    };

    let report = DiagnosticReport {
        status: overall_status,
        timestamp,
        checks,
        summary: DiagnosticSummary {
            total_checks,
            passed,
            warnings,
            errors,
            critical,
        },
    };

    // Wrap in NativeResult for proper JSON format
    Ok(NativeResult::success(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compare() {
        assert_eq!(version_compare("1.36.0", "1.36.1"), -1);
        assert_eq!(version_compare("1.36.1", "1.36.1"), 0);
        assert_eq!(version_compare("1.37.0", "1.36.1"), 1);
        assert_eq!(version_compare("2.0.0", "1.99.99"), 1);
    }
}
