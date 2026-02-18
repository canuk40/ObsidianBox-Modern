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

//! Magisk detection and integration module
//!
//! Provides comprehensive Magisk environment detection, module enumeration,
//! and conflict analysis for ObsidianBox Modern.

use crate::result::NativeResult;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use log::{debug, info, warn};

// =============================================================================
// Data Structures
// =============================================================================

/// Magisk environment information
#[derive(Debug, Clone, Serialize)]
pub struct MagiskInfo {
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionCode", skip_serializing_if = "Option::is_none")]
    pub version_code: Option<i32>,
    pub path: Option<String>,
    #[serde(rename = "suPath", skip_serializing_if = "Option::is_none")]
    pub su_path: Option<String>,
    #[serde(rename = "modulesPath", skip_serializing_if = "Option::is_none")]
    pub modules_path: Option<String>,
    #[serde(rename = "overlayfs")]
    pub overlayfs: bool,
    #[serde(rename = "zygiskEnabled")]
    pub zygisk_enabled: bool,
    #[serde(rename = "denylistEnabled")]
    pub denylist_enabled: bool,
    #[serde(rename = "superuserStatus")]
    pub superuser_status: String,
    pub notes: Vec<String>,
}

/// Magisk module metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagiskModule {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "versionCode")]
    pub version_code: i32,
    pub author: String,
    pub description: String,
    pub path: String,
    pub enabled: bool,
    pub remove: bool,
    pub update: bool,
    #[serde(rename = "affectsObsidianBox")]
    pub affects_obsidianbox: bool,
    #[serde(rename = "affectsPath")]
    pub affects_path: bool,
}

/// Module list result
#[derive(Debug, Clone, Serialize)]
pub struct MagiskModuleList {
    pub success: bool,
    #[serde(rename = "moduleCount")]
    pub module_count: i32,
    pub modules: Vec<MagiskModule>,
    #[serde(rename = "obsidianboxModules")]
    pub obsidianbox_modules: Vec<String>,
    pub warnings: Vec<String>,
}

/// Conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagiskConflict {
    #[serde(rename = "type")]
    pub conflict_type: String,
    pub severity: String,
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
    #[serde(rename = "moduleName")]
    pub module_name: Option<String>,
    pub path: Option<String>,
    pub description: String,
    pub suggestion: String,
}

/// Conflict analysis result
#[derive(Debug, Clone, Serialize)]
pub struct MagiskConflictResult {
    pub success: bool,
    pub severity: String,
    #[serde(rename = "conflictCount")]
    pub conflict_count: i32,
    pub conflicts: Vec<MagiskConflict>,
    pub summary: String,
    pub warnings: Vec<String>,
}

// =============================================================================
// Constants
// =============================================================================

const MAGISK_PATHS: &[&str] = &[
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/data/adb/ksu",  // KernelSU
    "/data/adb/ap",   // APatch
];

const MAGISK_BINARIES: &[&str] = &[
    "/sbin/magisk",
    "/data/adb/magisk/magisk64",
    "/data/adb/magisk/magisk32",
    "/system/bin/magisk",
    "/data/adb/ksu/bin/ksud",
    "/data/adb/ap/bin/apd",
];

const SU_PATHS: &[&str] = &[
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/data/adb/ksu/bin/su",
    "/data/adb/ap/bin/su",
];

const MODULES_PATH: &str = "/data/adb/modules";

const OBSIDIANBOX_KEYWORDS: &[&str] = &[
    "obsidianbox",
    "toybox",
    "coreutils",
    "applets",
];

const PATH_KEYWORDS: &[&str] = &[
    "PATH",
    "path",
    "system/bin",
    "system/xbin",
    "/xbin",
];

// =============================================================================
// Main Detection Functions
// =============================================================================

/// Detect Magisk installation and environment
pub fn detect_magisk() -> String {
    info!("Detecting Magisk environment...");
    
    let mut installed = false;
    let mut version: Option<String> = None;
    let mut version_code: Option<i32> = None;
    let mut magisk_path: Option<String> = None;
    let mut su_path: Option<String> = None;
    let mut modules_path: Option<String> = None;
    let mut zygisk_enabled = false;
    let mut denylist_enabled = false;
    let mut notes: Vec<String> = Vec::new();
    
    // Check for Magisk directory
    for path in MAGISK_PATHS.iter() {
        if Path::new(path).exists() {
            installed = true;
            magisk_path = Some(path.to_string());
            debug!("Found Magisk at: {}", path);
            
            // Detect variant
            if path.contains("ksu") {
                notes.push("KernelSU detected".to_string());
            } else if path.contains("ap") {
                notes.push("APatch detected".to_string());
            }
            break;
        }
    }
    
    // Get version from magisk binary
    if let Some(binary_path) = find_magisk_binary() {
        installed = true;
        
        if let Ok(output) = Command::new(&binary_path).arg("-v").output() {
            if output.status.success() {
                version = Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
        }
        
        if let Ok(output) = Command::new(&binary_path).arg("-V").output() {
            if output.status.success() {
                if let Ok(code) = String::from_utf8_lossy(&output.stdout).trim().parse() {
                    version_code = Some(code);
                }
            }
        }
    }
    
    // Find su binary
    for path in SU_PATHS.iter() {
        if Path::new(path).exists() {
            su_path = Some(path.to_string());
            break;
        }
    }
    
    // Check modules path
    if Path::new(MODULES_PATH).exists() {
        modules_path = Some(MODULES_PATH.to_string());
    }
    
    // Detect overlayfs
    let overlayfs = detect_overlayfs();
    if overlayfs {
        notes.push("Overlay filesystem detected".to_string());
    }
    
    // Check Magisk settings
    if installed {
        let db_path = "/data/adb/magisk.db";
        if Path::new(db_path).exists() {
            if let Ok(settings) = read_magisk_settings(db_path) {
                zygisk_enabled = settings.get("zygisk").map(|v| v == "1").unwrap_or(false);
                denylist_enabled = settings.get("denylist").map(|v| v == "1").unwrap_or(false);
                
                if zygisk_enabled {
                    notes.push("Zygisk enabled".to_string());
                }
                if denylist_enabled {
                    notes.push("DenyList enabled".to_string());
                }
            }
        }
    }
    
    // Check superuser status
    let superuser_status = check_superuser_status();

    // Module count note
    if let Some(ref path) = modules_path {
        if let Ok(count) = count_modules(path) {
            notes.push(format!("{} modules installed", count));
        }
    }
    
    let info = MagiskInfo {
        installed,
        version,
        version_code,
        path: magisk_path,
        su_path,
        modules_path,
        overlayfs,
        zygisk_enabled,
        denylist_enabled,
        superuser_status,
        notes,
    };
    
    NativeResult::success(info)
}

/// List all Magisk modules with metadata
pub fn list_magisk_modules() -> String {
    info!("Listing Magisk modules...");
    
    let mut modules: Vec<MagiskModule> = Vec::new();
    let mut obsidianbox_modules: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    
    if !Path::new(MODULES_PATH).exists() {
        return NativeResult::success(MagiskModuleList {
            success: true,
            module_count: 0,
            modules: vec![],
            obsidianbox_modules: vec![],
            warnings: vec!["Modules directory not found".to_string()],
        });
    }
    
    // Scan modules directory
    let entries = match fs::read_dir(MODULES_PATH) {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to read modules directory: {}", e);
            return NativeResult::<MagiskModuleList>::error(&format!("Failed to read modules: {}", e));
        }
    };
    
    for entry in entries.filter_map(|e| e.ok()) {
        let module_path = entry.path();
        
        if !module_path.is_dir() {
            continue;
        }
        
        let module_id = module_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Skip hidden and system directories
        if module_id.starts_with('.') {
            continue;
        }
        
        // Parse module.prop
        let prop_path = module_path.join("module.prop");
        let (name, version, version_code, author, description) = 
            parse_module_prop(&prop_path).unwrap_or_else(|_| {
                (module_id.clone(), "unknown".to_string(), 0, "unknown".to_string(), String::new())
            });
        
        // Check module state
        let enabled = !module_path.join("disable").exists();
        let remove = module_path.join("remove").exists();
        let update = module_path.join("update").exists();
        
        // Check if module affects ObsidianBox or PATH
        let (affects_obsidianbox, affects_path) = analyze_module_impact(&module_path);
        
        if affects_obsidianbox {
            obsidianbox_modules.push(module_id.clone());
        }
        
        modules.push(MagiskModule {
            id: module_id,
            name,
            version,
            version_code,
            author,
            description,
            path: module_path.to_string_lossy().to_string(),
            enabled,
            remove,
            update,
            affects_obsidianbox,
            affects_path,
        });
    }
    
    // Sort by name
    modules.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    
    let module_count = modules.len() as i32;
    
    if !obsidianbox_modules.is_empty() {
        warnings.push(format!(
            "{} module(s) may affect ObsidianBox: {}",
            obsidianbox_modules.len(),
            obsidianbox_modules.join(", ")
        ));
    }
    
    NativeResult::success(MagiskModuleList {
        success: true,
        module_count,
        modules,
        obsidianbox_modules,
        warnings,
    })
}

/// Detect conflicts between Magisk modules and ObsidianBox
pub fn detect_obsidianbox_conflicts() -> String {
    info!("Detecting ObsidianBox conflicts...");
    
    let mut conflicts: Vec<MagiskConflict> = Vec::new();
    let warnings: Vec<String> = Vec::new();
    let mut max_severity = "ok";
    
    // Get list of modules
    let modules_result = list_magisk_modules_internal();
    let modules = match modules_result {
        Ok(m) => m,
        Err(e) => {
            return NativeResult::<MagiskConflictResult>::error(&format!("Failed to list modules: {}", e));
        }
    };
    
    // Check each module for conflicts
    for module in &modules {
        if !module.enabled {
            continue;
        }
        
        let module_path = Path::new(&module.path);
        
        // Check for ObsidianBox binaries in module
        if let Some(conflict) = check_obsidianbox_binary_conflict(module) {
            if conflict.severity == "error" {
                max_severity = "error";
            } else if conflict.severity == "warning" && max_severity != "error" {
                max_severity = "warning";
            }
            conflicts.push(conflict);
        }
        
        // Check for symlink overrides
        if let Some(conflict) = check_symlink_override_conflict(module) {
            if conflict.severity == "error" {
                max_severity = "error";
            } else if conflict.severity == "warning" && max_severity != "error" {
                max_severity = "warning";
            }
            conflicts.push(conflict);
        }
        
        // Check for PATH modifications
        if let Some(conflict) = check_path_modification_conflict(module) {
            if conflict.severity == "error" {
                max_severity = "error";
            } else if conflict.severity == "warning" && max_severity != "error" {
                max_severity = "warning";
            }
            conflicts.push(conflict);
        }
        
        // Check system overlay conflicts
        let overlay_conflicts = check_system_overlay_conflicts(&module_path, &module.id);
        for conflict in overlay_conflicts {
            if conflict.severity == "error" {
                max_severity = "error";
            } else if conflict.severity == "warning" && max_severity != "error" {
                max_severity = "warning";
            }
            conflicts.push(conflict);
        }
    }
    
    // Check for multiple ObsidianBox providers
    let obsidianbox_providers: Vec<_> = modules.iter()
        .filter(|m| m.enabled && m.affects_obsidianbox)
        .collect();
    
    if obsidianbox_providers.len() > 1 {
        let names: Vec<_> = obsidianbox_providers.iter().map(|m| m.name.clone()).collect();
        conflicts.push(MagiskConflict {
            conflict_type: "multiple_obsidianbox".to_string(),
            severity: "warning".to_string(),
            module_id: None,
            module_name: None,
            path: None,
            description: format!(
                "Multiple modules provide ObsidianBox: {}",
                names.join(", ")
            ),
            suggestion: "Keep only one ObsidianBox provider to avoid conflicts".to_string(),
        });
        if max_severity == "ok" {
            max_severity = "warning";
        }
    }
    
    let conflict_count = conflicts.len() as i32;
    
    let summary = if conflict_count == 0 {
        "No conflicts detected".to_string()
    } else if max_severity == "error" {
        format!("{} critical conflict(s) require attention", conflict_count)
    } else {
        format!("{} potential conflict(s) detected", conflict_count)
    };
    
    NativeResult::success(MagiskConflictResult {
        success: true,
        severity: max_severity.to_string(),
        conflict_count,
        conflicts,
        summary,
        warnings,
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

fn find_magisk_binary() -> Option<String> {
    for path in MAGISK_BINARIES.iter() {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    
    // Try which command
    if let Ok(output) = Command::new("which").arg("magisk").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    
    None
}

fn detect_overlayfs() -> bool {
    // Check /proc/mounts for overlay
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        if mounts.contains("overlay") || mounts.contains("overlayfs") {
            return true;
        }
    }
    
    // Check for magic mount indicator
    if Path::new("/data/adb/.magisk_mount").exists() {
        return true;
    }
    
    // Check for overlay mirror directories
    if Path::new("/data/adb/modules/.mirrorfs").exists() {
        return true;
    }
    
    false
}

fn read_magisk_settings(_db_path: &str) -> Result<HashMap<String, String>> {
    let mut settings = HashMap::new();
    
    // Try to read settings from magisk.db
    // Note: This is a simplified approach; actual implementation would use SQLite
    // For now, check for indicator files
    
    let zygisk_file = "/data/adb/magisk/zygisk";
    if Path::new(zygisk_file).exists() {
        settings.insert("zygisk".to_string(), "1".to_string());
    }
    
    let denylist_file = "/data/adb/magisk/denylist";
    if Path::new(denylist_file).exists() {
        settings.insert("denylist".to_string(), "1".to_string());
    }
    
    Ok(settings)
}

fn check_superuser_status() -> String {
    // Try to execute a root command
    if let Ok(output) = Command::new("su").args(["-c", "id"]).output() {
        if output.status.success() {
            let id_output = String::from_utf8_lossy(&output.stdout);
            if id_output.contains("uid=0") {
                return "granted".to_string();
            }
        }
        return "denied".to_string();
    }
    
    // Check if su binary exists
    for path in SU_PATHS.iter() {
        if Path::new(path).exists() {
            return "available".to_string();
        }
    }
    
    "unavailable".to_string()
}

fn count_modules(modules_path: &str) -> Result<i32> {
    let count = fs::read_dir(modules_path)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir() && !e.file_name().to_string_lossy().starts_with('.'))
        .count();
    
    Ok(count as i32)
}

fn parse_module_prop(prop_path: &Path) -> Result<(String, String, i32, String, String)> {
    let content = fs::read_to_string(prop_path)
        .context("Failed to read module.prop")?;
    
    let mut name = String::new();
    let mut version = String::new();
    let mut version_code = 0;
    let mut author = String::new();
    let mut description = String::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            
            match key {
                "name" => name = value.to_string(),
                "version" => version = value.to_string(),
                "versionCode" => version_code = value.parse().unwrap_or(0),
                "author" => author = value.to_string(),
                "description" => description = value.to_string(),
                _ => {}
            }
        }
    }
    
    Ok((name, version, version_code, author, description))
}

fn analyze_module_impact(module_path: &Path) -> (bool, bool) {
    let mut affects_obsidianbox = false;
    let mut affects_path = false;
    
    // Check module.prop for obsidianbox-related content
    let prop_path = module_path.join("module.prop");
    if let Ok(content) = fs::read_to_string(&prop_path) {
        let lower = content.to_lowercase();
        for keyword in OBSIDIANBOX_KEYWORDS.iter() {
            if lower.contains(keyword) {
                affects_obsidianbox = true;
                break;
            }
        }
    }
    
    // Check system directory for obsidianbox binaries
    let system_xbin = module_path.join("system/xbin");
    let system_bin = module_path.join("system/bin");
    
    for dir in [&system_xbin, &system_bin] {
        if dir.exists() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if name.contains("obsidianbox") || name.contains("toybox") {
                        affects_obsidianbox = true;
                    }
                }
            }
            affects_path = true;
        }
    }
    
    // Check post-fs-data.sh and service.sh for PATH modifications
    for script in ["post-fs-data.sh", "service.sh", "customize.sh"] {
        let script_path = module_path.join(script);
        if let Ok(content) = fs::read_to_string(&script_path) {
            let lower = content.to_lowercase();
            
            for keyword in OBSIDIANBOX_KEYWORDS.iter() {
                if lower.contains(keyword) {
                    affects_obsidianbox = true;
                    break;
                }
            }
            
            for keyword in PATH_KEYWORDS.iter() {
                if lower.contains(&keyword.to_lowercase()) {
                    affects_path = true;
                    break;
                }
            }
        }
    }
    
    (affects_obsidianbox, affects_path)
}

fn list_magisk_modules_internal() -> Result<Vec<MagiskModule>> {
    let mut modules: Vec<MagiskModule> = Vec::new();
    
    if !Path::new(MODULES_PATH).exists() {
        return Ok(modules);
    }
    
    let entries = fs::read_dir(MODULES_PATH)?;
    
    for entry in entries.filter_map(|e| e.ok()) {
        let module_path = entry.path();
        
        if !module_path.is_dir() {
            continue;
        }
        
        let module_id = module_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        if module_id.starts_with('.') {
            continue;
        }
        
        let prop_path = module_path.join("module.prop");
        let (name, version, version_code, author, description) = 
            parse_module_prop(&prop_path).unwrap_or_else(|_| {
                (module_id.clone(), "unknown".to_string(), 0, "unknown".to_string(), String::new())
            });
        
        let enabled = !module_path.join("disable").exists();
        let remove = module_path.join("remove").exists();
        let update = module_path.join("update").exists();
        let (affects_obsidianbox, affects_path) = analyze_module_impact(&module_path);
        
        modules.push(MagiskModule {
            id: module_id,
            name,
            version,
            version_code,
            author,
            description,
            path: module_path.to_string_lossy().to_string(),
            enabled,
            remove,
            update,
            affects_obsidianbox,
            affects_path,
        });
    }
    
    Ok(modules)
}

fn check_obsidianbox_binary_conflict(module: &MagiskModule) -> Option<MagiskConflict> {
    let module_path = Path::new(&module.path);
    
    // Check for obsidianbox binary in system directories
    for subdir in ["system/xbin", "system/bin", "vendor/bin"] {
        let dir_path = module_path.join(subdir);
        if !dir_path.exists() {
            continue;
        }
        
        if let Ok(entries) = fs::read_dir(&dir_path) {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if name == "obsidianbox" {
                    return Some(MagiskConflict {
                        conflict_type: "obsidianbox_binary".to_string(),
                        severity: "warning".to_string(),
                        module_id: Some(module.id.clone()),
                        module_name: Some(module.name.clone()),
                        path: Some(entry.path().to_string_lossy().to_string()),
                        description: format!(
                            "Module '{}' provides a ObsidianBox binary at {}",
                            module.name,
                            entry.path().to_string_lossy()
                        ),
                        suggestion: "Consider disabling this module if you're using ObsidianBox Modern".to_string(),
                    });
                }
            }
        }
    }
    
    None
}

fn check_symlink_override_conflict(module: &MagiskModule) -> Option<MagiskConflict> {
    let module_path = Path::new(&module.path);
    
    // Check for symlinks that might override ObsidianBox applets
    let xbin_path = module_path.join("system/xbin");
    
    if xbin_path.exists() {
        let symlink_count = fs::read_dir(&xbin_path)
            .map(|entries| entries.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        
        if symlink_count > 50 {  // Likely a full applet set
            return Some(MagiskConflict {
                conflict_type: "symlink_override".to_string(),
                severity: "warning".to_string(),
                module_id: Some(module.id.clone()),
                module_name: Some(module.name.clone()),
                path: Some(xbin_path.to_string_lossy().to_string()),
                description: format!(
                    "Module '{}' provides {} binaries in system/xbin that may override ObsidianBox applets",
                    module.name,
                    symlink_count
                ),
                suggestion: "These may conflict with ObsidianBox Modern symlinks".to_string(),
            });
        }
    }
    
    None
}

fn check_path_modification_conflict(module: &MagiskModule) -> Option<MagiskConflict> {
    let module_path = Path::new(&module.path);
    
    // Check scripts for PATH manipulation
    for script in ["post-fs-data.sh", "service.sh"] {
        let script_path = module_path.join(script);
        
        if let Ok(content) = fs::read_to_string(&script_path) {
            // Look for PATH export statements
            if content.contains("export PATH=") || content.contains("PATH=") {
                // Check if it prepends a path before system paths
                if content.contains("PATH=/") && content.contains("$PATH") {
                    return Some(MagiskConflict {
                        conflict_type: "path_modification".to_string(),
                        severity: "info".to_string(),
                        module_id: Some(module.id.clone()),
                        module_name: Some(module.name.clone()),
                        path: Some(script_path.to_string_lossy().to_string()),
                        description: format!(
                            "Module '{}' modifies PATH in {}",
                            module.name,
                            script
                        ),
                        suggestion: "Ensure PATH order doesn't conflict with ObsidianBox location".to_string(),
                    });
                }
            }
        }
    }
    
    None
}

fn check_system_overlay_conflicts(module_path: &Path, module_id: &str) -> Vec<MagiskConflict> {
    let mut conflicts = Vec::new();
    
    // Check for system overlay directories that might conflict
    let overlay_dirs = ["system", "vendor", "product"];
    
    for overlay in overlay_dirs.iter() {
        let overlay_path = module_path.join(overlay);
        if !overlay_path.exists() {
            continue;
        }
        
        // Look for specific conflicts in bin/xbin
        for bindir in ["bin", "xbin"] {
            let bin_path = overlay_path.join(bindir);
            if !bin_path.exists() {
                continue;
            }
            
            // Check for commonly conflicting binaries
            let conflicting_binaries = ["ls", "cp", "mv", "rm", "cat", "grep", "find", "sed", "awk"];
            
            for binary in conflicting_binaries.iter() {
                let binary_path = bin_path.join(binary);
                if binary_path.exists() {
                    conflicts.push(MagiskConflict {
                        conflict_type: "system_override".to_string(),
                        severity: "info".to_string(),
                        module_id: Some(module_id.to_string()),
                        module_name: None,
                        path: Some(binary_path.to_string_lossy().to_string()),
                        description: format!(
                            "Module overrides /{}/{}/{}",
                            overlay, bindir, binary
                        ),
                        suggestion: "This may shadow ObsidianBox applet if PATH ordering conflicts".to_string(),
                    });
                }
            }
        }
    }
    
    conflicts
}

/// Check if running as Magisk module
pub fn is_magisk_module_context() -> bool {
    if let Ok(exe) = std::env::current_exe() {
        return exe.to_string_lossy().contains("/data/adb/modules/");
    }
    false
}

// =============================================================================
// CONFLICT RESOLUTION (Improvement Recommendation #3)
// =============================================================================

/// Strategy for resolving a Magisk conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolutionStrategy {
    /// Disable the conflicting module
    DisableModule,
    /// Adjust PATH priority
    AdjustPriority,
    /// Skip specific applets that conflict
    SkipApplets { applets: Vec<String> },
    /// Ignore the warning
    IgnoreWarning,
    /// Remove conflicting symlinks
    RemoveSymlinks { paths: Vec<String> },
    /// Custom action
    Custom { command: String },
}

/// Result of a conflict resolution action
#[derive(Debug, Clone, Serialize)]
pub struct ResolutionResult {
    pub success: bool,
    pub strategy: String,
    #[serde(rename = "moduleId")]
    pub module_id: Option<String>,
    pub message: String,
    #[serde(rename = "requiresReboot")]
    pub requires_reboot: bool,
    pub warnings: Vec<String>,
}

/// Resolve a specific conflict
pub fn resolve_conflict(conflict_json: &str, strategy_json: &str) -> String {
    info!("Resolving conflict with strategy...");
    
    let conflict: MagiskConflict = match serde_json::from_str(conflict_json) {
        Ok(c) => c,
        Err(e) => return NativeResult::<ResolutionResult>::error(&format!("Invalid conflict JSON: {}", e)),
    };
    
    let strategy: ConflictResolutionStrategy = match serde_json::from_str(strategy_json) {
        Ok(s) => s,
        Err(e) => return NativeResult::<ResolutionResult>::error(&format!("Invalid strategy JSON: {}", e)),
    };
    
    let result = match strategy {
        ConflictResolutionStrategy::DisableModule => {
            disable_conflicting_module(&conflict.module_id)
        }
        ConflictResolutionStrategy::AdjustPriority => {
            adjust_path_priority(&conflict)
        }
        ConflictResolutionStrategy::SkipApplets { applets } => {
            skip_conflicting_applets(&conflict, &applets)
        }
        ConflictResolutionStrategy::IgnoreWarning => {
            ResolutionResult {
                success: true,
                strategy: "IgnoreWarning".to_string(),
                module_id: conflict.module_id,
                message: "Warning acknowledged and ignored".to_string(),
                requires_reboot: false,
                warnings: vec![],
            }
        }
        ConflictResolutionStrategy::RemoveSymlinks { paths } => {
            remove_conflicting_symlinks(&paths)
        }
        ConflictResolutionStrategy::Custom { command } => {
            execute_custom_resolution(&command)
        }
    };
    
    NativeResult::success(result)
}

/// Disable a conflicting Magisk module
fn disable_conflicting_module(module_id: &Option<String>) -> ResolutionResult {
    let id = match module_id {
        Some(id) => id,
        None => return ResolutionResult {
            success: false,
            strategy: "DisableModule".to_string(),
            module_id: None,
            message: "No module ID provided".to_string(),
            requires_reboot: false,
            warnings: vec![],
        },
    };
    
    let disable_file = format!("/data/adb/modules/{}/disable", id);
    
    // Create disable file
    match std::fs::File::create(&disable_file) {
        Ok(_) => {
            info!("Disabled module: {}", id);
            ResolutionResult {
                success: true,
                strategy: "DisableModule".to_string(),
                module_id: Some(id.clone()),
                message: format!("Module '{}' disabled. Reboot required.", id),
                requires_reboot: true,
                warnings: vec!["Changes will take effect after reboot".to_string()],
            }
        }
        Err(e) => {
            // Try with root
            let cmd = format!("touch {}", disable_file);
            match std::process::Command::new("su").args(["-c", &cmd]).output() {
                Ok(output) if output.status.success() => {
                    ResolutionResult {
                        success: true,
                        strategy: "DisableModule".to_string(),
                        module_id: Some(id.clone()),
                        message: format!("Module '{}' disabled with root. Reboot required.", id),
                        requires_reboot: true,
                        warnings: vec!["Changes will take effect after reboot".to_string()],
                    }
                }
                _ => {
                    ResolutionResult {
                        success: false,
                        strategy: "DisableModule".to_string(),
                        module_id: Some(id.clone()),
                        message: format!("Failed to disable module: {}", e),
                        requires_reboot: false,
                        warnings: vec![],
                    }
                }
            }
        }
    }
}

/// Adjust PATH priority for ObsidianBox Modern
fn adjust_path_priority(conflict: &MagiskConflict) -> ResolutionResult {
    // This would typically involve modifying shell profile files
    // For now, provide guidance
    ResolutionResult {
        success: true,
        strategy: "AdjustPriority".to_string(),
        module_id: conflict.module_id.clone(),
        message: "PATH priority adjustment requires manual configuration".to_string(),
        requires_reboot: false,
        warnings: vec![
            "Add ObsidianBox Modern path before other ObsidianBox paths in your shell profile".to_string(),
            "Example: export PATH=/system/xbin:$PATH".to_string(),
        ],
    }
}

/// Skip specific applets that conflict
fn skip_conflicting_applets(conflict: &MagiskConflict, applets: &[String]) -> ResolutionResult {
    // This would be saved to a config file for the installer to use
    let config_path = "/data/adb/obsidianbox_modern/skip_applets.json";
    
    // Ensure directory exists
    let _ = std::fs::create_dir_all("/data/adb/obsidianbox_modern");
    
    // Write skip list
    let skip_list = serde_json::json!({
        "skipped_applets": applets,
        "reason": conflict.description,
        "module_id": conflict.module_id,
    });
    
    match std::fs::write(config_path, skip_list.to_string()) {
        Ok(_) => {
            ResolutionResult {
                success: true,
                strategy: "SkipApplets".to_string(),
                module_id: conflict.module_id.clone(),
                message: format!("Configured to skip {} applets during installation", applets.len()),
                requires_reboot: false,
                warnings: vec![format!("Skipping: {}", applets.join(", "))],
            }
        }
        Err(e) => {
            ResolutionResult {
                success: false,
                strategy: "SkipApplets".to_string(),
                module_id: conflict.module_id.clone(),
                message: format!("Failed to save skip list: {}", e),
                requires_reboot: false,
                warnings: vec![],
            }
        }
    }
}

/// Remove conflicting symlinks
fn remove_conflicting_symlinks(paths: &[String]) -> ResolutionResult {
    let mut removed = 0;
    let mut failed = Vec::new();
    
    for path in paths {
        let p = Path::new(path);
        if p.is_symlink() {
            match std::fs::remove_file(p) {
                Ok(_) => removed += 1,
                Err(_) => {
                    // Try with root
                    let cmd = format!("rm -f {}", path);
                    if std::process::Command::new("su").args(["-c", &cmd]).output()
                        .map(|o| o.status.success())
                        .unwrap_or(false) 
                    {
                        removed += 1;
                    } else {
                        failed.push(path.clone());
                    }
                }
            }
        }
    }
    
    ResolutionResult {
        success: failed.is_empty(),
        strategy: "RemoveSymlinks".to_string(),
        module_id: None,
        message: format!("Removed {} symlinks, {} failed", removed, failed.len()),
        requires_reboot: false,
        warnings: if failed.is_empty() { 
            vec![] 
        } else { 
            vec![format!("Failed to remove: {}", failed.join(", "))]
        },
    }
}

/// Execute a custom resolution command
fn execute_custom_resolution(command: &str) -> ResolutionResult {
    match std::process::Command::new("su")
        .args(["-c", command])
        .output() 
    {
        Ok(output) if output.status.success() => {
            ResolutionResult {
                success: true,
                strategy: "Custom".to_string(),
                module_id: None,
                message: "Custom command executed successfully".to_string(),
                requires_reboot: false,
                warnings: vec![],
            }
        }
        Ok(output) => {
            ResolutionResult {
                success: false,
                strategy: "Custom".to_string(),
                module_id: None,
                message: format!("Command failed: {}", 
                    String::from_utf8_lossy(&output.stderr)),
                requires_reboot: false,
                warnings: vec![],
            }
        }
        Err(e) => {
            ResolutionResult {
                success: false,
                strategy: "Custom".to_string(),
                module_id: None,
                message: format!("Failed to execute command: {}", e),
                requires_reboot: false,
                warnings: vec![],
            }
        }
    }
}

/// Get list of applets provided by a specific module
pub fn get_module_applets(module_id: &str) -> String {
    let module_path = format!("/data/adb/modules/{}", module_id);
    let mut applets: Vec<String> = Vec::new();
    
    // Check system/xbin and system/bin
    for subdir in ["system/xbin", "system/bin"] {
        let dir_path = format!("{}/{}", module_path, subdir);
        if let Ok(entries) = std::fs::read_dir(&dir_path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    applets.push(name.to_string());
                }
            }
        }
    }
    
    NativeResult::success(serde_json::json!({
        "module_id": module_id,
        "applet_count": applets.len(),
        "applets": applets,
    }))
}

// =============================================================================
// FFI Exports for JNI
// =============================================================================

/// FFI: Detect Magisk environment
#[no_mangle]
pub extern "C" fn rust_magisk_detect() -> *mut std::os::raw::c_char {
    let result = detect_magisk();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: List Magisk modules
#[no_mangle]
pub extern "C" fn rust_magisk_list_modules() -> *mut std::os::raw::c_char {
    let result = list_magisk_modules();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Detect ObsidianBox conflicts
#[no_mangle]
pub extern "C" fn rust_magisk_detect_conflicts() -> *mut std::os::raw::c_char {
    let result = detect_obsidianbox_conflicts();
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Resolve conflict
#[no_mangle]
pub extern "C" fn rust_magisk_resolve_conflict(
    conflict: *const std::os::raw::c_char,
    strategy: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    let conflict_str = unsafe {
        if conflict.is_null() { return std::ptr::null_mut(); }
        std::ffi::CStr::from_ptr(conflict).to_string_lossy().into_owned()
    };
    let strategy_str = unsafe {
        if strategy.is_null() { return std::ptr::null_mut(); }
        std::ffi::CStr::from_ptr(strategy).to_string_lossy().into_owned()
    };
    
    let result = resolve_conflict(&conflict_str, &strategy_str);
    std::ffi::CString::new(result).unwrap().into_raw()
}

/// FFI: Free string (for memory management)
#[no_mangle]
pub extern "C" fn rust_magisk_free_string(s: *mut std::os::raw::c_char) {
    if !s.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(s);
        }
    }
}
