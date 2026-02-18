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

//! Symlink management module

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use log::{debug, error};

#[derive(Serialize)]
pub struct SymlinkResult {
    pub created: u32,
    pub removed: u32,
    pub failed: Vec<String>,
}

/// Create symlinks for ObsidianBox applets
pub fn create_symlinks(obsidianbox_path: &str, symlink_dir: &str, applets_json: &str) -> String {
    let applets: Vec<String> = match serde_json::from_str(applets_json) {
        Ok(a) => a,
        Err(e) => return NativeResult::<SymlinkResult>::error(&format!("Invalid applets JSON: {}", e)),
    };
    
    let bb_path = Path::new(obsidianbox_path);
    if !bb_path.exists() {
        return NativeResult::<SymlinkResult>::error("ObsidianBox binary not found");
    }
    
    let sym_dir = Path::new(symlink_dir);
    if !sym_dir.exists() {
        if let Err(e) = fs::create_dir_all(sym_dir) {
            return NativeResult::<SymlinkResult>::error(&format!("Cannot create symlink dir: {}", e));
        }
    }
    
    let mut created = 0u32;
    let mut failed = Vec::new();
    
    for applet in applets {
        let link_path = sym_dir.join(&applet);
        
        // Remove existing symlink if present
        if link_path.exists() || link_path.is_symlink() {
            let _ = fs::remove_file(&link_path);
        }
        
        match symlink(bb_path, &link_path) {
            Ok(_) => {
                debug!("Created symlink: {} -> {}", link_path.display(), obsidianbox_path);
                created += 1;
            }
            Err(e) => {
                error!("Failed to create symlink {}: {}", applet, e);
                failed.push(applet);
            }
        }
    }
    
    NativeResult::success(SymlinkResult {
        created,
        removed: 0,
        failed,
    })
}

/// Remove all symlinks from directory
pub fn remove_symlinks(symlink_dir: &str) -> String {
    let dir = Path::new(symlink_dir);
    if !dir.exists() {
        return NativeResult::success(SymlinkResult {
            created: 0,
            removed: 0,
            failed: vec![],
        });
    }
    
    let mut removed = 0u32;
    let mut failed = Vec::new();
    
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_symlink() {
                    match fs::remove_file(&path) {
                        Ok(_) => removed += 1,
                        Err(e) => {
                            error!("Failed to remove symlink {}: {}", path.display(), e);
                            failed.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
        Err(e) => {
            return NativeResult::<SymlinkResult>::error(&format!("Cannot read directory: {}", e));
        }
    }
    
    NativeResult::success(SymlinkResult {
        created: 0,
        removed,
        failed,
    })
}

/// Check for broken symlinks
pub fn find_broken_symlinks(dir: &str) -> Vec<String> {
    let mut broken = Vec::new();
    let path = Path::new(dir);
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_symlink() {
                if let Ok(target) = fs::read_link(&p) {
                    if !target.exists() {
                        broken.push(p.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    
    broken
}
