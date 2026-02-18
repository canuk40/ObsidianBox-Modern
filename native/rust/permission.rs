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

//! Permission patching module

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use walkdir::WalkDir;
use log::{debug, error};

#[derive(Serialize)]
pub struct PermissionResult {
    pub path: String,
    pub mode: String,
    #[serde(rename = "filesModified")]
    pub files_modified: u32,
}

/// Patch file or directory permissions
pub fn patch_permissions(path: &str, mode: u32, recursive: bool) -> String {
    let target = Path::new(path);
    
    if !target.exists() {
        return NativeResult::<PermissionResult>::error("Path does not exist");
    }
    
    let mut files_modified = 0u32;
    
    if recursive && target.is_dir() {
        for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
            if patch_single_permission(entry.path(), mode) {
                files_modified += 1;
            }
        }
    } else {
        if patch_single_permission(target, mode) {
            files_modified = 1;
        } else {
            return NativeResult::<PermissionResult>::error("Failed to set permissions");
        }
    }
    
    NativeResult::success(PermissionResult {
        path: path.to_string(),
        mode: format!("{:o}", mode),
        files_modified,
    })
}

fn patch_single_permission(path: &Path, mode: u32) -> bool {
    match fs::metadata(path) {
        Ok(meta) => {
            let mut perms = meta.permissions();
            perms.set_mode(mode);
            
            match fs::set_permissions(path, perms) {
                Ok(_) => {
                    debug!("Set permissions {:o} on {}", mode, path.display());
                    true
                }
                Err(e) => {
                    error!("Failed to set permissions on {}: {}", path.display(), e);
                    false
                }
            }
        }
        Err(e) => {
            error!("Cannot read metadata for {}: {}", path.display(), e);
            false
        }
    }
}

/// Set executable permission
pub fn make_executable(path: &str) -> String {
    patch_permissions(path, 0o755, false)
}

/// Get current permissions as octal string
pub fn get_permissions(path: &str) -> Option<String> {
    fs::metadata(path)
        .ok()
        .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
}
