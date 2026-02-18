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

//! SELinux detection module
//!
//! Enhanced SELinux detection inspired by SKRoot's selinux_procattr approach.
//! Reads thread-level contexts, policy info, AVC stats, and denial logs.

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SelinuxInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub enforcing: bool,
}

/// Extended SELinux information including thread contexts, policy, and AVC stats
#[derive(Serialize)]
pub struct SelinuxExtendedInfo {
    pub mode: String,
    pub enforcing: bool,
    /// Current process/thread SELinux context (domain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    /// Exec transition context (what context new children will inherit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_context: Option<String>,
    /// Previous context (if kernel exposes it)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_context: Option<String>,
    /// Whether SELinux filesystem is mounted
    pub selinuxfs_mounted: bool,
    /// Policy info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_info: Option<SelinuxPolicyInfo>,
    /// AVC cache statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avc_stats: Option<AvcCacheStats>,
    /// Process capability info (for integrity checking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_info: Option<CapabilityInfo>,
}

#[derive(Serialize)]
pub struct SelinuxPolicyInfo {
    /// Whether a policy is loaded
    pub policy_loaded: bool,
    /// Policy file size in bytes (if readable)
    pub policy_size_bytes: Option<u64>,
    /// Number of SELinux object classes
    pub object_class_count: Option<usize>,
    /// Whether checkreqprot is enabled (1 = check requested protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkreqprot: Option<bool>,
    /// Whether deny_unknown is set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_unknown: Option<bool>,
}

#[derive(Serialize)]
pub struct AvcCacheStats {
    /// Total AVC lookups
    pub lookups: u64,
    /// AVC cache hits
    pub hits: u64,
    /// AVC cache misses
    pub misses: u64,
    /// AVC allocations
    pub allocations: u64,
    /// AVC reclaims
    pub reclaims: u64,
    /// AVC frees
    pub frees: u64,
}

#[derive(Serialize)]
pub struct AvcDenial {
    /// Raw denial message
    pub raw: String,
    /// Source context (scontext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scontext: Option<String>,
    /// Target context (tcontext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcontext: Option<String>,
    /// Object class
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tclass: Option<String>,
    /// Permission
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
}

/// Process capability info from /proc/self/status
#[derive(Serialize)]
pub struct CapabilityInfo {
    /// Effective capabilities (hex)
    pub cap_eff: String,
    /// Permitted capabilities (hex)
    pub cap_prm: String,
    /// Inheritable capabilities (hex)
    pub cap_inh: String,
    /// Bounding set (hex)
    pub cap_bnd: String,
    /// Ambient set (hex)
    pub cap_amb: String,
    /// Whether effective caps look like full root (all bits set)
    pub has_full_caps: bool,
}

// ---------------------------------------------------------------------------
// Original detect_selinux (backward compatible)
// ---------------------------------------------------------------------------

/// Detect SELinux mode and status (original API, kept for compatibility)
pub fn detect_selinux() -> String {
    let mode = get_selinux_mode();
    let context = get_selinux_context_current();
    let enforcing = mode == "Enforcing";

    NativeResult::success(SelinuxInfo {
        mode,
        context,
        enforcing,
    })
}

// ---------------------------------------------------------------------------
// New: Extended SELinux detection
// ---------------------------------------------------------------------------

/// Extended SELinux detection with thread contexts, policy info, and AVC stats
pub fn detect_selinux_extended() -> String {
    let mode = get_selinux_mode();
    let enforcing = mode == "Enforcing";
    let selinuxfs_mounted = Path::new("/sys/fs/selinux").exists();

    let current_context = read_thread_attr("current");
    let exec_context = read_thread_attr("exec");
    let prev_context = read_thread_attr("prev");

    let policy_info = if selinuxfs_mounted {
        Some(get_policy_info())
    } else {
        None
    };

    let avc_stats = if selinuxfs_mounted {
        parse_avc_cache_stats()
    } else {
        None
    };

    let capability_info = get_capability_info();

    NativeResult::success(SelinuxExtendedInfo {
        mode,
        enforcing,
        current_context,
        exec_context,
        prev_context,
        selinuxfs_mounted,
        policy_info,
        avc_stats,
        capability_info,
    })
}

/// Parse AVC denials from dmesg (requires root to be useful)
pub fn get_avc_denials() -> String {
    let denials = parse_avc_denials_from_dmesg();
    NativeResult::success(denials)
}

// ---------------------------------------------------------------------------
// Thread-level SELinux context reading
// Mirrors SKRoot's selinux_procattr approach in safe Rust:
//   1. Try /proc/thread-self/attr/<attr> (newer kernels, preferred)
//   2. Fallback to /proc/self/task/<tid>/attr/<attr>
//   3. Fallback to /proc/self/attr/<attr>
// ---------------------------------------------------------------------------

fn read_thread_attr(attr: &str) -> Option<String> {
    // Method 1: /proc/thread-self/attr/<attr> (Linux 3.17+)
    let thread_self_path = format!("/proc/thread-self/attr/{}", attr);
    if let Some(ctx) = read_and_clean_context(&thread_self_path) {
        return Some(ctx);
    }

    // Method 2: /proc/self/task/<tid>/attr/<attr>
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
    if tid > 0 {
        let tid_path = format!("/proc/self/task/{}/attr/{}", tid, attr);
        if let Some(ctx) = read_and_clean_context(&tid_path) {
            return Some(ctx);
        }
    }

    // Method 3: /proc/self/attr/<attr> (process-level fallback)
    let self_path = format!("/proc/self/attr/{}", attr);
    read_and_clean_context(&self_path)
}

/// Read a procattr file and strip trailing NUL/newline (same cleanup as SKRoot)
fn read_and_clean_context(path: &str) -> Option<String> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.is_empty() {
                return None;
            }
            let mut s = String::from_utf8_lossy(&bytes).to_string();
            // Strip trailing NUL and newline (matches SKRoot's cleanup)
            while s.ends_with('\0') || s.ends_with('\n') {
                s.pop();
            }
            if s.is_empty() { None } else { Some(s) }
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// SELinux mode detection (original, robust multi-method)
// ---------------------------------------------------------------------------

fn get_selinux_mode() -> String {
    // Try reading from /sys/fs/selinux/enforce
    if let Ok(content) = fs::read_to_string("/sys/fs/selinux/enforce") {
        let trimmed = content.trim();
        return match trimmed {
            "1" => "Enforcing".to_string(),
            "0" => "Permissive".to_string(),
            _ => "Unknown".to_string(),
        };
    }

    // Try getenforce command
    if let Ok(output) = Command::new("getenforce").output() {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    // Check if SELinux is disabled entirely
    if !Path::new("/sys/fs/selinux").exists() {
        return "Disabled".to_string();
    }

    "Unknown".to_string()
}

/// Original process-level context reader (kept for backward compat)
fn get_selinux_context_current() -> Option<String> {
    // Prefer thread-level reading
    if let Some(ctx) = read_thread_attr("current") {
        return Some(ctx);
    }

    // Fallback to id -Z
    if let Ok(output) = Command::new("id").arg("-Z").output() {
        if output.status.success() {
            let ctx = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ctx.is_empty() {
                return Some(ctx);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// SELinux policy info
// ---------------------------------------------------------------------------

fn get_policy_info() -> SelinuxPolicyInfo {
    let policy_path = Path::new("/sys/fs/selinux/policy");
    let policy_loaded = policy_path.exists();

    let policy_size_bytes = if policy_loaded {
        fs::metadata(policy_path).ok().map(|m| m.len())
    } else {
        None
    };

    // Count object classes in /sys/fs/selinux/class/
    let class_dir = Path::new("/sys/fs/selinux/class");
    let object_class_count = if class_dir.exists() {
        fs::read_dir(class_dir)
            .ok()
            .map(|entries| entries.filter_map(|e| e.ok()).count())
    } else {
        None
    };

    let checkreqprot = read_sysfs_bool("/sys/fs/selinux/checkreqprot");
    let deny_unknown = read_sysfs_bool("/sys/fs/selinux/deny_unknown");

    SelinuxPolicyInfo {
        policy_loaded,
        policy_size_bytes,
        object_class_count,
        checkreqprot,
        deny_unknown,
    }
}

fn read_sysfs_bool(path: &str) -> Option<bool> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v != 0)
}

// ---------------------------------------------------------------------------
// AVC cache stats
// ---------------------------------------------------------------------------

fn parse_avc_cache_stats() -> Option<AvcCacheStats> {
    let content = fs::read_to_string("/sys/fs/selinux/avc/cache_stats").ok()?;
    let lines: Vec<&str> = content.lines().collect();

    // Format: header line + data lines per CPU
    // "lookups hits misses allocations reclaims frees"
    // Sum across all CPUs
    let mut totals = AvcCacheStats {
        lookups: 0, hits: 0, misses: 0,
        allocations: 0, reclaims: 0, frees: 0,
    };

    for line in lines.iter().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            totals.lookups += parts[0].parse::<u64>().unwrap_or(0);
            totals.hits += parts[1].parse::<u64>().unwrap_or(0);
            totals.misses += parts[2].parse::<u64>().unwrap_or(0);
            totals.allocations += parts[3].parse::<u64>().unwrap_or(0);
            totals.reclaims += parts[4].parse::<u64>().unwrap_or(0);
            totals.frees += parts[5].parse::<u64>().unwrap_or(0);
        }
    }

    Some(totals)
}

// ---------------------------------------------------------------------------
// AVC denial parsing from dmesg
// ---------------------------------------------------------------------------

fn parse_avc_denials_from_dmesg() -> Vec<AvcDenial> {
    // Try dmesg (may fail without root)
    let output = Command::new("dmesg").output();
    let dmesg_text = match output {
        Ok(ref o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).to_string()
        }
        _ => return Vec::new(),
    };

    dmesg_text
        .lines()
        .filter(|line| line.contains("avc:") && line.contains("denied"))
        .take(50) // Limit to last 50 denials
        .map(|line| parse_single_denial(line))
        .collect()
}

fn parse_single_denial(line: &str) -> AvcDenial {
    AvcDenial {
        raw: line.to_string(),
        scontext: extract_field(line, "scontext="),
        tcontext: extract_field(line, "tcontext="),
        tclass: extract_field(line, "tclass="),
        permission: extract_permission(line),
    }
}

fn extract_field(line: &str, prefix: &str) -> Option<String> {
    line.find(prefix).map(|start| {
        let value_start = start + prefix.len();
        let end = line[value_start..].find(' ').unwrap_or(line.len() - value_start);
        line[value_start..value_start + end].to_string()
    })
}

fn extract_permission(line: &str) -> Option<String> {
    // Format: "{ read write }" - extract first permission
    if let Some(start) = line.find("{ ") {
        if let Some(end) = line[start..].find(" }") {
            let perms = &line[start + 2..start + end];
            return Some(perms.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Process capability info
// ---------------------------------------------------------------------------

fn get_capability_info() -> Option<CapabilityInfo> {
    let status = fs::read_to_string("/proc/self/status").ok()?;

    let cap_eff = extract_status_field(&status, "CapEff:")?;
    let cap_prm = extract_status_field(&status, "CapPrm:")?;
    let cap_inh = extract_status_field(&status, "CapInh:").unwrap_or_default();
    let cap_bnd = extract_status_field(&status, "CapBnd:").unwrap_or_default();
    let cap_amb = extract_status_field(&status, "CapAmb:").unwrap_or_default();

    // Full caps: all bits set (varies by kernel, but 0000003fffffffff or similar)
    // A process with uid!=0 but full CapEff is suspicious
    let has_full_caps = u64::from_str_radix(&cap_eff, 16)
        .map(|v| v.count_ones() >= 30) // 30+ capability bits = effectively full
        .unwrap_or(false);

    Some(CapabilityInfo {
        cap_eff,
        cap_prm,
        cap_inh,
        cap_bnd,
        cap_amb,
        has_full_caps,
    })
}

fn extract_status_field(status: &str, field: &str) -> Option<String> {
    status
        .lines()
        .find(|line| line.starts_with(field))
        .map(|line| line[field.len()..].trim().to_string())
}

/// Check if SELinux would block an operation
pub fn check_selinux_allows(
    _source_context: &str,
    _target_context: &str,
    _class: &str,
    _permission: &str,
) -> bool {
    // This would require seinfo/sesearch tools for proper checking
    // For now, return true if permissive
    get_selinux_mode() == "Permissive"
}
