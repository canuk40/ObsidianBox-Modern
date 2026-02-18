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

//! ObsidianBox installation module
//! Complete installation, detection, and management of ObsidianBox binaries
//! 
//! Includes legacy detection and migration support based on analysis of:
//! - Original ObsidianBox source (obsidianbox-old/obsidianbox)
//! - BuiltIn-ObsidianBox Magisk module
//! - Magisk framework internals

use crate::result::NativeResult;
use crate::symlink::find_broken_symlinks;
use crate::snapshot::{create_snapshot as create_snapshot_impl, restore_snapshot as restore_snapshot_impl, list_snapshots};
use serde::{Serialize, Deserialize};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use log::{debug, info, warn};

/// Common ObsidianBox installation locations
const COMMON_PATHS: &[&str] = &[
    // PRIORITY #1: App-internal installation (debug and release)
    "/data/data/com.busyboxmodern.app.debug/files/obsidianbox",
    "/data/data/com.busyboxmodern.app/files/obsidianbox",
    // PRIORITY #2: Magisk module paths
    "/data/adb/obsidianbox/obsidianbox",
    "/data/adb/modules/obsidianbox-ndk/system/xbin/obsidianbox",
    // PRIORITY #3: System paths
    "/system/bin/obsidianbox",
    "/system/xbin/obsidianbox",
    "/data/local/tmp/obsidianbox",
    "/sbin/obsidianbox",
    "/vendor/bin/obsidianbox",
];

// =============================================================================
// LEGACY OBSIDIANBOX DETECTION (Improvement Recommendation #1)
// Based on analysis of obsidianbox-old and Magisk module patterns
// =============================================================================

/// Legacy ObsidianBox installation paths from various installers
const LEGACY_OBSIDIANBOX_PATHS: &[&str] = &[
    // SuperSU legacy paths
    "/su/xbin/obsidianbox",
    "/su/bin/obsidianbox",
    // Old Magisk paths (pre-v20)
    "/magisk/.core/bin/obsidianbox",
    "/magisk/.core/obsidianbox/obsidianbox",
    // System paths from manual installs
    "/system/xbin/obsidianbox",
    "/system/bin/obsidianbox",
    // Vendor paths
    "/vendor/bin/obsidianbox",
    "/vendor/xbin/obsidianbox",
    // Alternative system paths
    "/system/addon.d/obsidianbox",
    // Recovery/boot paths
    "/sbin/obsidianbox",
    "/tmp/obsidianbox",
    // Termux paths
    "/data/data/com.termux/files/usr/bin/obsidianbox",
    // Common user install paths
    "/sdcard/obsidianbox",
    "/data/local/obsidianbox",
    "/data/local/tmp/obsidianbox",
];

/// Known legacy ObsidianBox module IDs in Magisk
const LEGACY_MODULE_IDS: &[&str] = &[
    "obsidianbox-ndk",
    "BuiltIn-ObsidianBox",
    "obsidianbox",
    "obsidianbox-static",
    "obsidianbox-installer",
    "obsidianbox-advanced",
    "toolbox-obsidianbox",
];

/// Legacy installation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LegacyInstallType {
    /// SuperSU-era installation
    SuperSU,
    /// Old Magisk (pre-v20)
    OldMagisk,
    /// Current Magisk module
    MagiskModule,
    /// Manual system installation
    ManualSystem,
    /// Vendor partition install
    Vendor,
    /// Termux installation
    Termux,
    /// Unknown/other
    Unknown,
}

impl LegacyInstallType {
    fn as_str(&self) -> &'static str {
        match self {
            LegacyInstallType::SuperSU => "SuperSU",
            LegacyInstallType::OldMagisk => "Old Magisk",
            LegacyInstallType::MagiskModule => "Magisk Module",
            LegacyInstallType::ManualSystem => "Manual System Install",
            LegacyInstallType::Vendor => "Vendor Partition",
            LegacyInstallType::Termux => "Termux",
            LegacyInstallType::Unknown => "Unknown",
        }
    }
}

/// Information about a legacy ObsidianBox installation
#[derive(Debug, Clone, Serialize)]
pub struct LegacyObsidianBoxInfo {
    /// Path to the ObsidianBox binary
    pub path: String,
    /// Type of legacy installation
    #[serde(rename = "installType")]
    pub install_type: String,
    /// Version if detectable
    pub version: Option<String>,
    /// Number of applets available
    #[serde(rename = "appletCount")]
    pub applet_count: u32,
    /// Number of symlinks found
    #[serde(rename = "symlinkCount")]
    pub symlink_count: u32,
    /// Directory containing symlinks
    #[serde(rename = "symlinkDir")]
    pub symlink_dir: Option<String>,
    /// Whether the installation is active (in PATH)
    #[serde(rename = "isActive")]
    pub is_active: bool,
    /// Migration risk level (low, medium, high)
    #[serde(rename = "migrationRisk")]
    pub migration_risk: String,
    /// Migration recommendation
    #[serde(rename = "migrationNotes")]
    pub migration_notes: Vec<String>,
    /// Associated Magisk module ID if applicable
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
}

/// Result of legacy ObsidianBox detection
#[derive(Debug, Clone, Serialize)]
pub struct LegacyDetectionResult {
    /// Whether any legacy installations were found
    pub found: bool,
    /// Number of legacy installations
    pub count: u32,
    /// List of legacy installations
    pub installations: Vec<LegacyObsidianBoxInfo>,
    /// Overall migration recommendation
    #[serde(rename = "overallRecommendation")]
    pub overall_recommendation: String,
    /// Paths that were searched
    #[serde(rename = "searchedPaths")]
    pub searched_paths: Vec<String>,
}

#[derive(Serialize)]
pub struct InstallResult {
    pub installed: bool,
    #[serde(rename = "installedPath")]
    pub installed_path: String,
    pub size: u64,
    pub permissions: String,
    #[serde(rename = "symlinkCount")]
    pub symlink_count: u32,
    pub warnings: Vec<String>,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: Option<String>,
}

#[derive(Serialize)]
pub struct UninstallResult {
    pub uninstalled: bool,
    #[serde(rename = "binaryRemoved")]
    pub binary_removed: bool,
    #[serde(rename = "symlinksRemoved")]
    pub symlinks_removed: u32,
    pub errors: Vec<String>,
}

#[derive(Serialize)]
pub struct BusyboxInfo {
    pub version: String,
    pub path: String,
    pub applets: Vec<String>,
    pub symlinks: u32,
    #[serde(rename = "brokenSymlinks")]
    pub broken_symlinks: Vec<String>,
    #[serde(rename = "fileSize")]
    pub file_size: u64,
    pub permissions: String,
    #[serde(rename = "isExecutable")]
    pub is_executable: bool,
}

#[derive(Serialize)]
pub struct DetectResult {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<BusyboxInfo>,
    #[serde(rename = "searchedPaths")]
    pub searched_paths: Vec<String>,
}

/// Detect ObsidianBox installation by checking common paths
pub fn detect_obsidianbox() -> String {
    info!("Detecting ObsidianBox installation...");
    let searched_paths: Vec<String> = COMMON_PATHS.iter().map(|s| s.to_string()).collect();
    
    for path in COMMON_PATHS {
        debug!("Checking path: {}", path);
        let p = Path::new(path);
        if p.exists() && p.is_file() {
            if let Some(info) = get_obsidianbox_info_internal(path) {
                info!("Found ObsidianBox at: {}", path);
                return NativeResult::success(DetectResult {
                    found: true,
                    info: Some(info),
                    searched_paths,
                });
            }
        }
    }
    
    info!("ObsidianBox not found in common paths");
    NativeResult::success(DetectResult {
        found: false,
        info: None,
        searched_paths,
    })
}

/// Install ObsidianBox binary to specified path
pub fn install_obsidianbox(target_path: &str, binary_data: &[u8]) -> String {
    info!("Installing ObsidianBox to: {}", target_path);
    let mut warnings: Vec<String> = Vec::new();
    
    // Validate target path
    if target_path.is_empty() {
        return NativeResult::<InstallResult>::error("Target path cannot be empty");
    }
    
    // Resolve target: if path is a directory, append /obsidianbox filename
    let resolved_path = if Path::new(target_path).is_dir() {
        let p = format!("{}/obsidianbox", target_path.trim_end_matches('/'));
        info!("Target is a directory, resolved to file path: {}", p);
        p
    } else {
        target_path.to_string()
    };
    let target = Path::new(&resolved_path);
    
    // If resolved path itself exists as a directory (previous failed install), remove it
    if target.is_dir() {
        warn!("Target path {} exists as directory, removing with root", resolved_path);
        let rm_cmd = format!("rm -rf '{}'", resolved_path);
        if let Err(e) = run_shell_command(&rm_cmd) {
            return NativeResult::<InstallResult>::error(
                &format!("Target path exists as a directory from a previous install. Failed to clean up: {}", e)
            );
        }
        warnings.push("Cleaned up directory at target path from previous install attempt".to_string());
    }
    
    // Check if target directory exists and is writable
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            info!("Creating parent directory: {:?}", parent);
            // Always use su for creating directories in system paths
            let parent_str = parent.to_string_lossy();
            let cmd = format!("mkdir -p '{}'", parent_str);
            if let Err(e) = run_shell_command(&cmd) {
                // Try without root as fallback
                if let Err(_) = fs::create_dir_all(parent) {
                    return NativeResult::<InstallResult>::error(&format!("Cannot create directory: {}", e));
                }
            }
        }
        
        // Check mount status via /proc/mounts for accurate ro/rw detection
        let parent_str = parent.to_string_lossy().to_string();
        if is_path_on_readonly_mount(&parent_str) {
            warn!("Parent directory is on a read-only mount, attempting remount");
            // Find the mount point for this path and try remounting
            if let Some(mount_point) = get_mount_point_for_path(&parent_str) {
                let remount_cmd = format!("mount -o rw,remount '{}' 2>/dev/null", mount_point);
                match run_shell_command(&remount_cmd) {
                    Ok(_) => warnings.push(format!("Remounted {} as read-write", mount_point)),
                    Err(_) => {
                        // Fallback: try remounting root (covers SAR devices)
                        match run_shell_command("mount -o rw,remount / 2>/dev/null") {
                            Ok(_) => warnings.push("Remounted / as read-write (SAR fallback)".to_string()),
                            Err(_) => warnings.push(format!(
                                "Could not remount {} as read-write. On Android 10+, /system is often permanently read-only. Consider using /data/adb instead.",
                                mount_point
                            )),
                        }
                    }
                }
            }
        }
    }
    
    // If binary data is empty, this is a placeholder
    if binary_data.is_empty() {
        return NativeResult::<InstallResult>::error("Binary data is empty - bundled ObsidianBox binary required");
    }
    
    // Determine install strategy based on path
    let use_temp_file = resolved_path.starts_with("/system") || resolved_path.starts_with("/vendor");
    
    if use_temp_file {
        // For system paths, ALWAYS use temp file + su cp (direct write won't work as app user)
        info!("Using temp file approach for system path: {}", resolved_path);
        let temp_path = "/data/local/tmp/obsidianbox_temp";
        
        if let Err(e) = File::create(temp_path).and_then(|mut f| f.write_all(binary_data)) {
            return NativeResult::<InstallResult>::error(&format!("Cannot write temp file: {}", e));
        }
        
        let cp_cmd = format!("cp '{}' '{}'", temp_path, resolved_path);
        if let Err(e) = run_shell_command(&cp_cmd) {
            let _ = fs::remove_file(temp_path);
            return NativeResult::<InstallResult>::error(&format!(
                "Cannot copy to target path: {}. On Android 10+, /system is often read-only even with root. Try /data/adb instead.",
                e
            ));
        }
        let _ = run_shell_command(&format!("rm '{}'", temp_path));
        
        let chmod_cmd = format!("chmod 755 '{}'", resolved_path);
        if let Err(e) = run_shell_command(&chmod_cmd) {
            warnings.push(format!("Failed to set permissions: {}", e));
        }
        // Set root ownership (critical — without this, SELinux denies access)
        let chown_cmd = format!("chown 0:0 '{}'", resolved_path);
        if let Err(e) = run_shell_command(&chown_cmd) {
            warnings.push(format!("Failed to set root ownership: {}", e));
        }
        let _ = run_shell_command(&format!("chcon u:object_r:system_file:s0 '{}' 2>/dev/null", resolved_path));
    } else {
        // For non-system paths, try direct write first, fall back to su
        match File::create(target) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(binary_data) {
                    return NativeResult::<InstallResult>::error(&format!("Cannot write binary: {}", e));
                }
                // Set executable permissions
                if let Ok(metadata) = fs::metadata(target) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755);
                    if let Err(_) = fs::set_permissions(target, perms) {
                        let cmd = format!("chmod 755 '{}'", resolved_path);
                        let _ = run_shell_command(&cmd);
                    }
                }
            }
            Err(_) => {
                // Direct write failed, use temp file + su approach
                info!("Direct write failed, using temp file with root access");
                let temp_path = "/data/local/tmp/obsidianbox_temp";
                if let Err(e) = File::create(temp_path).and_then(|mut f| f.write_all(binary_data)) {
                    return NativeResult::<InstallResult>::error(&format!("Cannot write temp file: {}", e));
                }
                let cp_cmd = format!("cp '{}' '{}'", temp_path, resolved_path);
                if let Err(e) = run_shell_command(&cp_cmd) {
                    let _ = fs::remove_file(temp_path);
                    return NativeResult::<InstallResult>::error(&format!("Cannot install to target: {}", e));
                }
                let _ = run_shell_command(&format!("rm '{}'", temp_path));
                let _ = run_shell_command(&format!("chmod 755 '{}'", resolved_path));
                let _ = run_shell_command(&format!("chown 0:0 '{}'", resolved_path));
                let _ = run_shell_command(&format!("chcon u:object_r:system_file:s0 '{}' 2>/dev/null", resolved_path));
                warnings.push("Installed via temp file with root access".to_string());
            }
        }
    }
    
    // Verify installation
    if !verify_obsidianbox(&resolved_path) {
        return NativeResult::<InstallResult>::error("Installation verification failed - binary may be corrupted");
    }
    
    let size = binary_data.len() as u64;
    info!("Installed ObsidianBox to {} ({} bytes)", resolved_path, size);
    
    NativeResult::success(InstallResult {
        installed: true,
        installed_path: resolved_path,
        size,
        permissions: "755".to_string(),
        symlink_count: 0,
        warnings,
        snapshot_id: None,
    })
}

/// Check if a path is on a read-only mount by parsing /proc/mounts
fn is_path_on_readonly_mount(path: &str) -> bool {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        // Find the longest matching mount point for this path
        let mut best_match = "";
        let mut is_ro = false;
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount_point = parts[1];
                let options = parts[3];
                if path.starts_with(mount_point) && mount_point.len() > best_match.len() {
                    best_match = mount_point;
                    is_ro = options.split(',').any(|opt| opt == "ro");
                }
            }
        }
        return is_ro;
    }
    false
}

/// Get the mount point for a given path from /proc/mounts
fn get_mount_point_for_path(path: &str) -> Option<String> {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        let mut best_match = String::new();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mount_point = parts[1];
                if path.starts_with(mount_point) && mount_point.len() > best_match.len() {
                    best_match = mount_point.to_string();
                }
            }
        }
        if !best_match.is_empty() {
            return Some(best_match);
        }
    }
    None
}

/// Uninstall ObsidianBox from specified directory
pub fn uninstall_obsidianbox(target_dir: &str) -> String {
    info!("Uninstalling ObsidianBox from: {}", target_dir);
    let mut errors: Vec<String> = Vec::new();
    let mut symlinks_removed = 0u32;
    let mut binary_removed = false;
    
    let dir_path = Path::new(target_dir);
    
    // Find obsidianbox binary
    let obsidianbox_path = if dir_path.is_file() {
        dir_path.to_path_buf()
    } else {
        dir_path.join("obsidianbox")
    };
    
    // Remove symlinks first
    let parent_dir = if dir_path.is_file() {
        dir_path.parent().map(|p| p.to_path_buf())
    } else {
        Some(dir_path.to_path_buf())
    };
    
    if let Some(parent) = parent_dir {
        if let Ok(entries) = fs::read_dir(&parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_symlink() {
                    // Check if symlink points to obsidianbox binary
                    if let Ok(target) = fs::read_link(&path) {
                        let target_str = target.to_string_lossy();
                        if target_str == obsidianbox_path.to_string_lossy() 
                            || target_str.ends_with("/obsidianbox")
                            || target_str == "obsidianbox"
                            || target_str == "./obsidianbox" {
                            match fs::remove_file(&path) {
                                Ok(_) => {
                                    symlinks_removed += 1;
                                    debug!("Removed symlink: {:?}", path);
                                }
                                Err(e) => {
                                    // Try with shell
                                    let cmd = format!("rm -f {:?}", path);
                                    if run_shell_command(&cmd).is_ok() {
                                        symlinks_removed += 1;
                                    } else {
                                        errors.push(format!("Failed to remove symlink {:?}: {}", path, e));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Remove obsidianbox binary
    if obsidianbox_path.exists() {
        match fs::remove_file(&obsidianbox_path) {
            Ok(_) => {
                binary_removed = true;
                info!("Removed ObsidianBox binary: {:?}", obsidianbox_path);
            }
            Err(e) => {
                // Try with shell
                let cmd = format!("rm -f {:?}", obsidianbox_path);
                if run_shell_command(&cmd).is_ok() {
                    binary_removed = true;
                } else {
                    errors.push(format!("Failed to remove binary: {}", e));
                }
            }
        }
    } else {
        binary_removed = true; // Nothing to remove
    }
    
    info!("Uninstall complete: binary_removed={}, symlinks_removed={}", binary_removed, symlinks_removed);
    
    NativeResult::success(UninstallResult {
        uninstalled: binary_removed && errors.is_empty(),
        binary_removed,
        symlinks_removed,
        errors,
    })
}

/// Get ObsidianBox info from installed binary (for JNI export)
pub fn get_obsidianbox_info(path: &str) -> String {
    match get_obsidianbox_info_internal(path) {
        Some(info) => NativeResult::success(info),
        None => NativeResult::<BusyboxInfo>::error("ObsidianBox not found at specified path"),
    }
}

/// Internal implementation to get ObsidianBox info
fn get_obsidianbox_info_internal(path: &str) -> Option<BusyboxInfo> {
    let bb_path = Path::new(path);
    
    if !bb_path.exists() || !bb_path.is_file() {
        return None;
    }
    
    // Get file metadata
    let (file_size, permissions, is_executable) = match fs::metadata(bb_path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            let perm_str = format!("{:o}", mode & 0o777);
            let exec = mode & 0o111 != 0;
            (meta.len(), perm_str, exec)
        }
        Err(_) => (0, "unknown".to_string(), false),
    };
    
    // Get version
    let version = match Command::new(path).arg("--help").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_obsidianbox_version(&stdout)
        }
        Err(_) => "Unknown".to_string(),
    };
    
    // Get applets list
    let applets = match Command::new(path).arg("--list").output() {
        Ok(output) => {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        Err(_) => vec![],
    };
    
    // Count symlinks and find broken ones
    let parent = bb_path.parent().map(|p| p.to_string_lossy().to_string());
    let (symlinks, broken) = if let Some(dir) = parent {
        let broken = find_broken_symlinks(&dir);
        let total = count_symlinks(&dir);
        (total, broken)
    } else {
        (0, vec![])
    };
    
    Some(BusyboxInfo {
        version,
        path: path.to_string(),
        applets,
        symlinks,
        broken_symlinks: broken,
        file_size,
        permissions,
        is_executable,
    })
}

/// Create snapshot before installation
pub fn obsidianbox_snapshot(target_path: &str) -> String {
    info!("Creating snapshot of: {}", target_path);
    create_snapshot_impl(target_path, "obsidianbox_backup")
}

/// Restore from snapshot
pub fn obsidianbox_restore(snapshot_id: &str) -> String {
    info!("Restoring from snapshot: {}", snapshot_id);
    let snapshot_path = format!("/data/local/tmp/obsidianbox_snapshots/{}", snapshot_id);
    
    // Determine target path from snapshot
    // For now, restore to /system/xbin (could be made configurable)
    let target_path = "/system/xbin";
    
    restore_snapshot_impl(&snapshot_path, target_path)
}

/// List available snapshots
pub fn list_obsidianbox_snapshots() -> String {
    let snapshots = list_snapshots();
    NativeResult::success(snapshots)
}

fn parse_obsidianbox_version(output: &str) -> String {
    // Parse version from "ObsidianBox v1.36.1 (2024-01-15 ...)" format
    for line in output.lines() {
        if line.contains("ObsidianBox") && line.contains("v") {
            if let Some(start) = line.find('v') {
                let version_part = &line[start..];
                if let Some(end) = version_part.find(|c: char| c.is_whitespace() || c == '(') {
                    return version_part[1..end].to_string();
                }
            }
        }
    }
    "Unknown".to_string()
}

fn count_symlinks(dir: &str) -> u32 {
    let path = Path::new(dir);
    let mut count = 0u32;
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.path().is_symlink() {
                count += 1;
            }
        }
    }
    
    count
}

/// Run a shell command with root privileges
fn run_shell_command(cmd: &str) -> Result<String, String> {
    let output = Command::new("su")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Verify ObsidianBox installation
pub fn verify_obsidianbox(path: &str) -> bool {
    if let Ok(output) = Command::new(path).arg("--help").output() {
        return output.status.success() && 
               String::from_utf8_lossy(&output.stdout).contains("ObsidianBox");
    }
    false
}

// =============================================================================
// LEGACY DETECTION IMPLEMENTATION (Improvement Recommendation #1)
// =============================================================================

/// Detect all legacy ObsidianBox installations on the device
pub fn detect_legacy_obsidianbox() -> String {
    info!("Scanning for legacy ObsidianBox installations...");
    
    let mut installations: Vec<LegacyObsidianBoxInfo> = Vec::new();
    let searched_paths: Vec<String> = LEGACY_OBSIDIANBOX_PATHS.iter()
        .map(|s| s.to_string())
        .collect();
    
    // Check all legacy paths
    for path in LEGACY_OBSIDIANBOX_PATHS.iter() {
        if let Some(info) = detect_legacy_at_path(path) {
            installations.push(info);
        }
    }
    
    // Also check Magisk modules directory
    let module_installs = detect_legacy_magisk_modules();
    for install in module_installs {
        // Avoid duplicates
        if !installations.iter().any(|i| i.path == install.path) {
            installations.push(install);
        }
    }
    
    let count = installations.len() as u32;
    let found = count > 0;
    
    // Generate overall recommendation
    let overall_recommendation = if !found {
        "No legacy installations found. Safe to install ObsidianBox Modern.".to_string()
    } else if installations.iter().any(|i| i.migration_risk == "high") {
        format!(
            "Found {} legacy installation(s), including high-risk ones. Create backup before migration.",
            count
        )
    } else {
        format!(
            "Found {} legacy installation(s). Migration recommended for cleaner setup.",
            count
        )
    };
    
    info!("Found {} legacy ObsidianBox installation(s)", count);
    
    NativeResult::success(LegacyDetectionResult {
        found,
        count,
        installations,
        overall_recommendation,
        searched_paths,
    })
}

/// Detect legacy ObsidianBox at a specific path
fn detect_legacy_at_path(path: &str) -> Option<LegacyObsidianBoxInfo> {
    let bb_path = Path::new(path);
    
    if !bb_path.exists() {
        return None;
    }
    
    debug!("Found potential legacy ObsidianBox at: {}", path);
    
    // Determine installation type
    let install_type = determine_legacy_type(path);
    
    // Get version
    let version = if bb_path.is_file() {
        get_obsidianbox_version(path)
    } else {
        None
    };
    
    // Count applets
    let applet_count = if bb_path.is_file() {
        count_obsidianbox_applets(path)
    } else {
        0
    };
    
    // Find symlink directory and count
    let (symlink_dir, symlink_count) = find_legacy_symlinks(path);
    
    // Check if active in PATH
    let is_active = is_obsidianbox_in_path(path);
    
    // Determine migration risk
    let (migration_risk, migration_notes) = assess_migration_risk(&install_type, path, is_active);
    
    Some(LegacyObsidianBoxInfo {
        path: path.to_string(),
        install_type: install_type.as_str().to_string(),
        version,
        applet_count,
        symlink_count,
        symlink_dir,
        is_active,
        migration_risk,
        migration_notes,
        module_id: None,
    })
}

/// Determine the type of legacy installation based on path patterns
fn determine_legacy_type(path: &str) -> LegacyInstallType {
    if path.starts_with("/su/") {
        LegacyInstallType::SuperSU
    } else if path.contains("/magisk/.core/") {
        LegacyInstallType::OldMagisk
    } else if path.contains("/data/adb/modules/") {
        LegacyInstallType::MagiskModule
    } else if path.contains("/vendor/") {
        LegacyInstallType::Vendor
    } else if path.contains("com.termux") {
        LegacyInstallType::Termux
    } else if path.starts_with("/system/") {
        LegacyInstallType::ManualSystem
    } else {
        LegacyInstallType::Unknown
    }
}

/// Detect ObsidianBox installations in Magisk modules
fn detect_legacy_magisk_modules() -> Vec<LegacyObsidianBoxInfo> {
    let mut results: Vec<LegacyObsidianBoxInfo> = Vec::new();
    let modules_path = Path::new("/data/adb/modules");
    
    if !modules_path.exists() {
        return results;
    }
    
    if let Ok(entries) = fs::read_dir(modules_path) {
        for entry in entries.flatten() {
            let module_path = entry.path();
            let module_id = module_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            
            // Skip hidden directories
            if module_id.starts_with('.') {
                continue;
            }
            
            // Check if this is a known ObsidianBox module or contains obsidianbox
            let _is_obsidianbox_module = LEGACY_MODULE_IDS.iter()
                .any(|id| module_id.to_lowercase().contains(&id.to_lowercase()));
            
            // Check for obsidianbox binary in module
            let obsidianbox_paths = [
                module_path.join("system/xbin/obsidianbox"),
                module_path.join("system/bin/obsidianbox"),
                module_path.join("obsidianbox"),
            ];
            
            for bb_path in obsidianbox_paths.iter() {
                if bb_path.exists() {
                    let path_str = bb_path.to_string_lossy().to_string();
                    let version = get_obsidianbox_version(&path_str);
                    let applet_count = count_obsidianbox_applets(&path_str);
                    
                    // Check if module is enabled
                    let is_active = !module_path.join("disable").exists();
                    
                    // Determine symlink directory (overlay path)
                    let overlay_xbin = format!("/system/xbin");
                    let symlink_count = if is_active {
                        count_symlinks(&overlay_xbin)
                    } else {
                        0
                    };
                    
                    let (migration_risk, migration_notes) = assess_module_migration_risk(
                        &module_id,
                        is_active,
                    );
                    
                    results.push(LegacyObsidianBoxInfo {
                        path: path_str,
                        install_type: LegacyInstallType::MagiskModule.as_str().to_string(),
                        version,
                        applet_count,
                        symlink_count,
                        symlink_dir: Some("/system/xbin".to_string()),
                        is_active,
                        migration_risk,
                        migration_notes,
                        module_id: Some(module_id.clone()),
                    });
                    
                    break; // Found obsidianbox in this module
                }
            }
        }
    }
    
    results
}

/// Get ObsidianBox version from binary
fn get_obsidianbox_version(path: &str) -> Option<String> {
    if let Ok(output) = Command::new(path).arg("--help").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Some(parse_obsidianbox_version(&stdout));
    }
    None
}

/// Count ObsidianBox applets
fn count_obsidianbox_applets(path: &str) -> u32 {
    if let Ok(output) = Command::new(path).arg("--list").output() {
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count() as u32;
    }
    0
}

/// Find symlinks directory for legacy installation
fn find_legacy_symlinks(obsidianbox_path: &str) -> (Option<String>, u32) {
    let bb_path = Path::new(obsidianbox_path);
    
    // Symlinks are typically in the same directory as the binary
    if let Some(parent) = bb_path.parent() {
        let parent_str = parent.to_string_lossy().to_string();
        let count = count_obsidianbox_symlinks_in_dir(&parent_str, obsidianbox_path);
        if count > 0 {
            return (Some(parent_str), count);
        }
    }
    
    // Also check common symlink locations
    for dir in ["/system/xbin", "/system/bin", "/sbin", "/vendor/bin"] {
        let count = count_obsidianbox_symlinks_in_dir(dir, obsidianbox_path);
        if count > 0 {
            return (Some(dir.to_string()), count);
        }
    }
    
    (None, 0)
}

/// Count symlinks that point to a specific obsidianbox binary
fn count_obsidianbox_symlinks_in_dir(dir: &str, obsidianbox_path: &str) -> u32 {
    let dir_path = Path::new(dir);
    let mut count = 0u32;
    
    if !dir_path.exists() {
        return 0;
    }
    
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_symlink() {
                if let Ok(target) = fs::read_link(&path) {
                    let target_str = target.to_string_lossy();
                    if target_str.contains("obsidianbox") || target_str == obsidianbox_path {
                        count += 1;
                    }
                }
            }
        }
    }
    
    count
}

/// Check if ObsidianBox binary is accessible via PATH
fn is_obsidianbox_in_path(obsidianbox_path: &str) -> bool {
    // Check if 'which obsidianbox' returns this path
    if let Ok(output) = Command::new("which").arg("obsidianbox").output() {
        let which_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if which_path == obsidianbox_path {
            return true;
        }
    }
    
    // Also check if the directory is in PATH
    if let Ok(path_env) = std::env::var("PATH") {
        let bb_path = Path::new(obsidianbox_path);
        if let Some(parent) = bb_path.parent() {
            return path_env.split(':')
                .any(|p| p == parent.to_string_lossy());
        }
    }
    
    false
}

/// Assess migration risk for a legacy installation
fn assess_migration_risk(
    install_type: &LegacyInstallType,
    path: &str,
    is_active: bool,
) -> (String, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    let risk;
    
    match install_type {
        LegacyInstallType::SuperSU => {
            risk = "high";
            notes.push("SuperSU installation detected - this is a very old root method".to_string());
            notes.push("Recommend full uninstall before migration".to_string());
            notes.push("May have system-level modifications".to_string());
        }
        LegacyInstallType::OldMagisk => {
            risk = "medium";
            notes.push("Old Magisk installation (pre-v20) detected".to_string());
            notes.push("Update Magisk before installing ObsidianBox Modern".to_string());
        }
        LegacyInstallType::MagiskModule => {
            risk = "low";
            notes.push("Magisk module installation - easy to disable".to_string());
            notes.push("Disable module before installing ObsidianBox Modern".to_string());
        }
        LegacyInstallType::ManualSystem => {
            risk = if is_active { "medium" } else { "low" };
            notes.push("Manual system installation detected".to_string());
            if path.starts_with("/system/") {
                notes.push("Requires remount of /system to remove".to_string());
            }
        }
        LegacyInstallType::Vendor => {
            risk = "medium";
            notes.push("Vendor partition installation".to_string());
            notes.push("May be part of ROM - check before removing".to_string());
        }
        LegacyInstallType::Termux => {
            risk = "low";
            notes.push("Termux installation - isolated from system".to_string());
            notes.push("Can coexist with ObsidianBox Modern".to_string());
        }
        LegacyInstallType::Unknown => {
            risk = "medium";
            notes.push("Unknown installation type".to_string());
            notes.push("Investigate before migration".to_string());
        }
    }
    
    if is_active {
        notes.push("Currently active in PATH - will be replaced".to_string());
    }
    
    (risk.to_string(), notes)
}

/// Assess migration risk for a Magisk module
fn assess_module_migration_risk(module_id: &str, is_active: bool) -> (String, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    
    notes.push(format!("Module ID: {}", module_id));
    
    if is_active {
        notes.push("Module is currently enabled".to_string());
        notes.push("Run 'magisk --remove-modules' or disable in Magisk Manager".to_string());
    } else {
        notes.push("Module is disabled - no action needed".to_string());
    }
    
    let risk = if is_active { "low" } else { "none" };
    
    (risk.to_string(), notes)
}

// =============================================================================
// MIGRATION SUPPORT (Improvement Recommendation #2)
// =============================================================================

/// Migration action to take for a legacy installation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationAction {
    /// Action type
    #[serde(rename = "actionType")]
    pub action_type: String,
    /// Human-readable description
    pub description: String,
    /// Shell command to execute (if applicable)
    pub command: Option<String>,
    /// Risk level of this action
    pub risk: String,
    /// Whether this requires user confirmation
    #[serde(rename = "requiresConfirmation")]
    pub requires_confirmation: bool,
}

/// Migration plan for a legacy installation
#[derive(Debug, Clone, Serialize)]
pub struct MigrationPlan {
    /// Path of legacy installation
    #[serde(rename = "legacyPath")]
    pub legacy_path: String,
    /// Installation type
    #[serde(rename = "installType")]
    pub install_type: String,
    /// List of actions to perform
    pub actions: Vec<MigrationAction>,
    /// Overall risk level
    #[serde(rename = "overallRisk")]
    pub overall_risk: String,
    /// Whether automatic migration is supported
    #[serde(rename = "autoMigrationSupported")]
    pub auto_migration_supported: bool,
}

/// Generate a migration plan for a legacy installation
pub fn generate_migration_plan(legacy_path: &str) -> String {
    info!("Generating migration plan for: {}", legacy_path);
    
    let install_type = determine_legacy_type(legacy_path);
    let mut actions: Vec<MigrationAction> = Vec::new();
    let mut overall_risk = "low";
    let mut auto_supported = true;
    
    // Step 1: Create backup
    actions.push(MigrationAction {
        action_type: "backup".to_string(),
        description: "Create snapshot of current ObsidianBox state".to_string(),
        command: None, // Handled by snapshot system
        risk: "none".to_string(),
        requires_confirmation: false,
    });
    
    // Step 2: Disable/remove based on install type
    match install_type {
        LegacyInstallType::MagiskModule => {
            // Extract module ID from path
            let module_id = legacy_path
                .split("/data/adb/modules/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("unknown");
            
            actions.push(MigrationAction {
                action_type: "disable_module".to_string(),
                description: format!("Disable Magisk module: {}", module_id),
                command: Some(format!("touch /data/adb/modules/{}/disable", module_id)),
                risk: "low".to_string(),
                requires_confirmation: true,
            });
        }
        LegacyInstallType::SuperSU => {
            overall_risk = "high";
            auto_supported = false;
            
            actions.push(MigrationAction {
                action_type: "manual".to_string(),
                description: "SuperSU installation requires manual removal".to_string(),
                command: None,
                risk: "high".to_string(),
                requires_confirmation: true,
            });
            
            actions.push(MigrationAction {
                action_type: "remove_symlinks".to_string(),
                description: "Remove SuperSU ObsidianBox symlinks".to_string(),
                command: Some("rm -f /su/xbin/[a-z]*".to_string()),
                risk: "medium".to_string(),
                requires_confirmation: true,
            });
        }
        LegacyInstallType::ManualSystem => {
            overall_risk = "medium";
            
            actions.push(MigrationAction {
                action_type: "remount".to_string(),
                description: "Remount /system as read-write".to_string(),
                command: Some("mount -o rw,remount /system".to_string()),
                risk: "medium".to_string(),
                requires_confirmation: true,
            });
            
            // Find symlink directory
            let (symlink_dir, _) = find_legacy_symlinks(legacy_path);
            if let Some(dir) = symlink_dir {
                actions.push(MigrationAction {
                    action_type: "remove_symlinks".to_string(),
                    description: format!("Remove legacy symlinks from {}", dir),
                    command: Some(format!(
                        "for f in {}/*; do [ -L \"$f\" ] && readlink \"$f\" | grep -q obsidianbox && rm -f \"$f\"; done",
                        dir
                    )),
                    risk: "medium".to_string(),
                    requires_confirmation: true,
                });
            }
            
            actions.push(MigrationAction {
                action_type: "remove_binary".to_string(),
                description: format!("Remove legacy ObsidianBox binary: {}", legacy_path),
                command: Some(format!("rm -f {}", legacy_path)),
                risk: "medium".to_string(),
                requires_confirmation: true,
            });
        }
        LegacyInstallType::Termux => {
            // Termux is isolated, can coexist
            actions.push(MigrationAction {
                action_type: "info".to_string(),
                description: "Termux ObsidianBox is isolated and can coexist with ObsidianBox Modern".to_string(),
                command: None,
                risk: "none".to_string(),
                requires_confirmation: false,
            });
        }
        _ => {
            overall_risk = "medium";
            
            actions.push(MigrationAction {
                action_type: "remove_binary".to_string(),
                description: format!("Remove legacy ObsidianBox binary: {}", legacy_path),
                command: Some(format!("rm -f {}", legacy_path)),
                risk: "medium".to_string(),
                requires_confirmation: true,
            });
        }
    }
    
    // Step 3: Install ObsidianBox Modern
    actions.push(MigrationAction {
        action_type: "install".to_string(),
        description: "Install ObsidianBox Modern to selected location".to_string(),
        command: None, // Handled by installer
        risk: "low".to_string(),
        requires_confirmation: false,
    });
    
    // Step 4: Verify
    actions.push(MigrationAction {
        action_type: "verify".to_string(),
        description: "Verify ObsidianBox Modern installation".to_string(),
        command: None,
        risk: "none".to_string(),
        requires_confirmation: false,
    });
    
    NativeResult::success(MigrationPlan {
        legacy_path: legacy_path.to_string(),
        install_type: install_type.as_str().to_string(),
        actions,
        overall_risk: overall_risk.to_string(),
        auto_migration_supported: auto_supported,
    })
}

/// Execute a single migration action
pub fn execute_migration_action(action_json: &str) -> String {
    let action: MigrationAction = match serde_json::from_str(action_json) {
        Ok(a) => a,
        Err(e) => return NativeResult::<bool>::error(&format!("Invalid action JSON: {}", e)),
    };
    
    info!("Executing migration action: {}", action.action_type);
    
    match action.action_type.as_str() {
        "backup" => {
            // Create snapshot - path would be provided
            NativeResult::success(true)
        }
        "disable_module" | "remove_symlinks" | "remove_binary" | "remount" => {
            if let Some(cmd) = action.command {
                match run_shell_command(&cmd) {
                    Ok(_) => NativeResult::success(true),
                    Err(e) => NativeResult::<bool>::error(&format!("Command failed: {}", e)),
                }
            } else {
                NativeResult::<bool>::error("No command specified for action")
            }
        }
        "info" | "manual" => {
            // No-op, just informational
            NativeResult::success(true)
        }
        "install" | "verify" => {
            // Handled by main installer
            NativeResult::success(true)
        }
        _ => {
            NativeResult::<bool>::error(&format!("Unknown action type: {}", action.action_type))
        }
    }
}

// =============================================================================
// MULTI-OBSIDIANBOX PROVIDER HANDLING (Improvement Recommendation #5)
// =============================================================================

/// Information about a ObsidianBox provider (installation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObsidianBoxProvider {
    /// Unique identifier for this provider
    pub id: String,
    /// Path to the ObsidianBox binary
    pub path: String,
    /// Type of provider
    #[serde(rename = "providerType")]
    pub provider_type: ProviderType,
    /// Version of ObsidianBox if detected
    pub version: Option<String>,
    /// List of applets this provider offers
    pub applets: Vec<String>,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Whether this provider is active (symlinks in use)
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderType {
    ObsidianBoxModern,
    MagiskModule,
    SystemInstall,
    Termux,
    LegacyInstall,
    Unknown,
}

/// Unified symlink map entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedSymlinkEntry {
    /// Applet name (e.g., "ls", "grep")
    pub applet: String,
    /// Provider that should own this symlink
    #[serde(rename = "preferredProvider")]
    pub preferred_provider: String,
    /// All providers that offer this applet
    #[serde(rename = "availableProviders")]
    pub available_providers: Vec<String>,
    /// Current symlink path (if exists)
    #[serde(rename = "currentPath")]
    pub current_path: Option<String>,
    /// Current target (if symlink exists)
    #[serde(rename = "currentTarget")]
    pub current_target: Option<String>,
    /// Is there a conflict?
    pub conflict: bool,
}

/// Detect all ObsidianBox providers on the system
pub fn detect_all_providers() -> String {
    info!("Detecting all ObsidianBox providers...");
    let mut providers: Vec<ObsidianBoxProvider> = Vec::new();
    
    // Check ObsidianBox Modern installation
    for path in &["/system/xbin/obsidianbox", "/data/adb/obsidianbox_modern/obsidianbox"] {
        if Path::new(path).exists() {
            if let Some(provider) = create_provider_info(path, ProviderType::ObsidianBoxModern, 0) {
                providers.push(provider);
            }
        }
    }
    
    // Check Magisk modules
    let module_dir = Path::new("/data/adb/modules");
    if module_dir.exists() {
        if let Ok(entries) = fs::read_dir(module_dir) {
            for entry in entries.flatten() {
                let module_path = entry.path();
                if !module_path.is_dir() {
                    continue;
                }
                
                // Check for disable file
                if module_path.join("disable").exists() {
                    continue;
                }
                
                // Look for obsidianbox in module
                for subpath in ["system/xbin/obsidianbox", "system/bin/obsidianbox"] {
                    let bb_path = module_path.join(subpath);
                    if bb_path.exists() {
                        if let Some(mut provider) = create_provider_info(
                            bb_path.to_str().unwrap_or(""),
                            ProviderType::MagiskModule,
                            10
                        ) {
                            provider.id = entry.file_name().to_string_lossy().to_string();
                            providers.push(provider);
                        }
                    }
                }
            }
        }
    }
    
    // Check system installs
    for path in &["/system/bin/obsidianbox", "/vendor/bin/obsidianbox"] {
        if Path::new(path).exists() {
            if let Some(provider) = create_provider_info(path, ProviderType::SystemInstall, 20) {
                providers.push(provider);
            }
        }
    }
    
    // Check Termux
    let termux_path = "/data/data/com.termux/files/usr/bin/obsidianbox";
    if Path::new(termux_path).exists() {
        if let Some(provider) = create_provider_info(termux_path, ProviderType::Termux, 30) {
            providers.push(provider);
        }
    }
    
    // Check legacy installs
    for path in LEGACY_OBSIDIANBOX_PATHS {
        if !providers.iter().any(|p| p.path == *path) {
            if Path::new(path).exists() {
                if let Some(provider) = create_provider_info(path, ProviderType::LegacyInstall, 50) {
                    providers.push(provider);
                }
            }
        }
    }
    
    NativeResult::success(serde_json::json!({
        "provider_count": providers.len(),
        "providers": providers
    }))
}

/// Create provider info from a ObsidianBox path
fn create_provider_info(path: &str, provider_type: ProviderType, priority: u32) -> Option<ObsidianBoxProvider> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return None;
    }
    
    // Get version
    let version = get_obsidianbox_version(path);
    
    // Get applets
    let applets = get_obsidianbox_applets(path);
    
    // Check if active (has symlinks pointing to it)
    let active = check_provider_active(path);
    
    Some(ObsidianBoxProvider {
        id: path.replace("/", "_").trim_start_matches('_').to_string(),
        path: path.to_string(),
        provider_type,
        version,
        applets,
        priority,
        active,
    })
}

// Duplicate function removed - using the implementation at line 785

/// Get applets from ObsidianBox binary
fn get_obsidianbox_applets(path: &str) -> Vec<String> {
    match Command::new(path).arg("--list").output() {
        Ok(output) => {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        Err(_) => Vec::new()
    }
}

/// Check if provider has active symlinks
fn check_provider_active(path: &str) -> bool {
    let install_dirs = ["/system/xbin", "/system/bin"];
    
    for dir in &install_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_symlink() {
                    if let Ok(target) = fs::read_link(&entry_path) {
                        if target.to_string_lossy() == path {
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    false
}

/// Generate unified symlink map considering all providers
pub fn generate_unified_symlink_map() -> String {
    info!("Generating unified symlink map...");
    
    // First, detect all providers
    let providers_json = detect_all_providers();
    let providers_result: Result<serde_json::Value, _> = serde_json::from_str(&providers_json);
    
    let providers: Vec<ObsidianBoxProvider> = match providers_result {
        Ok(v) => {
            if let Some(data) = v.get("data").and_then(|d| d.get("providers")) {
                serde_json::from_value(data.clone()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new()
    };
    
    if providers.is_empty() {
        return NativeResult::<Vec<UnifiedSymlinkEntry>>::error("No ObsidianBox providers found");
    }
    
    // Build unified map
    let mut symlink_map: std::collections::HashMap<String, UnifiedSymlinkEntry> = 
        std::collections::HashMap::new();
    
    // Process providers by priority (lower = higher priority)
    let mut sorted_providers = providers.clone();
    sorted_providers.sort_by_key(|p| p.priority);
    
    for provider in &sorted_providers {
        for applet in &provider.applets {
            let entry = symlink_map.entry(applet.clone()).or_insert_with(|| {
                UnifiedSymlinkEntry {
                    applet: applet.clone(),
                    preferred_provider: provider.id.clone(),
                    available_providers: Vec::new(),
                    current_path: None,
                    current_target: None,
                    conflict: false,
                }
            });
            
            entry.available_providers.push(provider.id.clone());
        }
    }
    
    // Check current symlink status
    for (applet, entry) in symlink_map.iter_mut() {
        for dir in &["/system/xbin", "/system/bin"] {
            let symlink_path = format!("{}/{}", dir, applet);
            let path_obj = Path::new(&symlink_path);
            
            if path_obj.exists() || path_obj.is_symlink() {
                entry.current_path = Some(symlink_path.clone());
                
                if let Ok(target) = fs::read_link(path_obj) {
                    entry.current_target = Some(target.to_string_lossy().to_string());
                    
                    // Check for conflict
                    let preferred = providers.iter().find(|p| p.id == entry.preferred_provider);
                    if let Some(pref) = preferred {
                        if target.to_string_lossy() != pref.path {
                            entry.conflict = true;
                        }
                    }
                }
                break;
            }
        }
    }
    
    let entries: Vec<UnifiedSymlinkEntry> = symlink_map.into_values().collect();
    let conflicts: Vec<&UnifiedSymlinkEntry> = entries.iter().filter(|e| e.conflict).collect();
    
    NativeResult::success(serde_json::json!({
        "total_applets": entries.len(),
        "conflict_count": conflicts.len(),
        "entries": entries,
        "conflicts": conflicts
    }))
}

/// Deduplicate applets across providers
pub fn deduplicate_applets(preferred_provider_id: &str) -> String {
    info!("Deduplicating applets, preferring provider: {}", preferred_provider_id);
    
    let map_json = generate_unified_symlink_map();
    let map_result: Result<serde_json::Value, _> = serde_json::from_str(&map_json);
    
    let entries: Vec<UnifiedSymlinkEntry> = match map_result {
        Ok(v) => {
            if let Some(data) = v.get("data").and_then(|d| d.get("entries")) {
                serde_json::from_value(data.clone()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new()
    };
    
    let mut actions: Vec<serde_json::Value> = Vec::new();
    let mut skipped = 0;
    let mut updated = 0;
    
    for entry in &entries {
        // Skip if preferred provider doesn't have this applet
        if !entry.available_providers.contains(&preferred_provider_id.to_string()) {
            skipped += 1;
            continue;
        }
        
        // Check if symlink needs update
        if entry.conflict {
            actions.push(serde_json::json!({
                "action": "update_symlink",
                "applet": entry.applet,
                "current_target": entry.current_target,
                "new_target": preferred_provider_id,
                "reason": "conflict_resolution"
            }));
            updated += 1;
        } else if entry.current_path.is_none() {
            actions.push(serde_json::json!({
                "action": "create_symlink",
                "applet": entry.applet,
                "target": preferred_provider_id,
                "reason": "missing_symlink"
            }));
            updated += 1;
        }
    }
    
    NativeResult::success(serde_json::json!({
        "preferred_provider": preferred_provider_id,
        "total_applets": entries.len(),
        "skipped": skipped,
        "actions_needed": updated,
        "actions": actions
    }))
}

// =============================================================================
// JNI EXPORTS FOR LEGACY DETECTION
// =============================================================================

/// FFI: Detect legacy ObsidianBox installations
#[no_mangle]
pub extern "C" fn rust_detect_legacy_obsidianbox() -> *mut std::os::raw::c_char {
    let result = detect_legacy_obsidianbox();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Generate migration plan
#[no_mangle]
pub extern "C" fn rust_generate_migration_plan(path: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let path_str = unsafe {
        if path.is_null() {
            return std::ptr::null_mut();
        }
        std::ffi::CStr::from_ptr(path).to_string_lossy().into_owned()
    };
    
    let result = generate_migration_plan(&path_str);
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Detect all providers
#[no_mangle]
pub extern "C" fn rust_detect_all_providers() -> *mut std::os::raw::c_char {
    let result = detect_all_providers();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Generate unified symlink map
#[no_mangle]
pub extern "C" fn rust_generate_unified_symlink_map() -> *mut std::os::raw::c_char {
    let result = generate_unified_symlink_map();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Deduplicate applets
#[no_mangle]
pub extern "C" fn rust_deduplicate_applets(provider_id: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let id = unsafe {
        if provider_id.is_null() {
            return std::ptr::null_mut();
        }
        std::ffi::CStr::from_ptr(provider_id).to_string_lossy().into_owned()
    };
    
    let result = deduplicate_applets(&id);
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Free string
#[no_mangle]
pub extern "C" fn rust_obsidianbox_free_string(s: *mut std::os::raw::c_char) {
    if !s.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(s);
        }
    }
}
