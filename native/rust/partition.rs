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

//! Partition detection module

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
pub struct PartitionInfo {
    pub path: String,
    #[serde(rename = "mountPoint")]
    pub mount_point: String,
    pub filesystem: String,
    pub writable: bool,
    #[serde(rename = "availableBytes")]
    pub available_bytes: u64,
    pub recommended: bool,
}

/// Detect available partitions for ObsidianBox installation
pub fn detect_partitions() -> String {
    let mut partitions = Vec::new();
    
    // Common installation paths on Android
    let paths = [
        ("/system/bin", "/system", "ext4"),
        ("/system/xbin", "/system", "ext4"),
        ("/vendor/bin", "/vendor", "ext4"),
        ("/data/local/tmp", "/data", "ext4"),
        ("/data/adb/modules", "/data", "ext4"),
    ];
    
    for (path, mount_point, fs_type) in paths.iter() {
        let writable = check_writable(path);
        let available = get_available_space(mount_point);
        let recommended = *path == "/system/xbin" || *path == "/data/adb/modules";
        
        partitions.push(PartitionInfo {
            path: path.to_string(),
            mount_point: mount_point.to_string(),
            filesystem: fs_type.to_string(),
            writable,
            available_bytes: available,
            recommended,
        });
    }
    
    NativeResult::success(partitions)
}

fn check_writable(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        // Try to check parent directory
        if let Some(parent) = p.parent() {
            return parent.exists() && !is_readonly_fs(parent);
        }
        return false;
    }
    !is_readonly_fs(p)
}

fn is_readonly_fs(path: &Path) -> bool {
    // Try to get metadata to check if path is accessible
    match fs::metadata(path) {
        Ok(meta) => meta.permissions().readonly(),
        Err(_) => true,
    }
}

fn get_available_space(mount_point: &str) -> u64 {
    // Read from /proc/mounts or use statfs
    // Placeholder - in production would use libc::statfs64
    match mount_point {
        "/system" => 50 * 1024 * 1024,  // 50 MB typical
        "/data" => 1024 * 1024 * 1024,  // 1 GB typical
        _ => 0,
    }
}
