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

//! Snapshot and rollback module

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::path::Path;
use chrono::Utc;
use walkdir::WalkDir;
use log::{error, info};

#[derive(Serialize)]
pub struct SnapshotResult {
    pub id: String,
    pub path: String,
    pub timestamp: i64,
    pub size: u64,
}

#[derive(Serialize)]
pub struct RestoreResult {
    pub restored: bool,
    #[serde(rename = "filesRestored")]
    pub files_restored: u32,
    pub errors: Vec<String>,
}

const SNAPSHOT_DIR: &str = "/data/local/tmp/obsidianbox_snapshots";

/// Create a backup snapshot of the target directory
pub fn create_snapshot(target_path: &str, snapshot_name: &str) -> String {
    let target = Path::new(target_path);
    
    if !target.exists() {
        return NativeResult::<SnapshotResult>::error("Target path does not exist");
    }
    
    // Ensure snapshot directory exists
    let snapshot_base = Path::new(SNAPSHOT_DIR);
    if !snapshot_base.exists() {
        if let Err(e) = fs::create_dir_all(snapshot_base) {
            return NativeResult::<SnapshotResult>::error(&format!("Cannot create snapshot dir: {}", e));
        }
    }
    
    // Generate unique snapshot ID
    let timestamp = Utc::now().timestamp();
    let id = format!("{}_{}", snapshot_name, timestamp);
    let snapshot_path = snapshot_base.join(&id);
    
    // Create snapshot directory
    if let Err(e) = fs::create_dir_all(&snapshot_path) {
        return NativeResult::<SnapshotResult>::error(&format!("Cannot create snapshot: {}", e));
    }
    
    // Copy files
    let mut total_size = 0u64;
    
    if target.is_dir() {
        for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
            let source = entry.path();
            let relative = source.strip_prefix(target).unwrap_or(source);
            let dest = snapshot_path.join(relative);
            
            if source.is_dir() {
                let _ = fs::create_dir_all(&dest);
            } else if source.is_file() {
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Ok(meta) = fs::metadata(source) {
                    total_size += meta.len();
                }
                if let Err(e) = fs::copy(source, &dest) {
                    error!("Failed to copy {}: {}", source.display(), e);
                }
            }
        }
    } else {
        // Single file
        let dest = snapshot_path.join(target.file_name().unwrap_or_default());
        if let Ok(meta) = fs::metadata(target) {
            total_size = meta.len();
        }
        if let Err(e) = fs::copy(target, &dest) {
            return NativeResult::<SnapshotResult>::error(&format!("Cannot copy file: {}", e));
        }
    }
    
    info!("Created snapshot {} ({} bytes)", id, total_size);
    
    NativeResult::success(SnapshotResult {
        id: id.clone(),
        path: snapshot_path.to_string_lossy().to_string(),
        timestamp,
        size: total_size,
    })
}

/// Restore from a snapshot
pub fn restore_snapshot(snapshot_path: &str, target_path: &str) -> String {
    let snapshot = Path::new(snapshot_path);
    let target = Path::new(target_path);
    
    if !snapshot.exists() {
        return NativeResult::<RestoreResult>::error("Snapshot not found");
    }
    
    let mut files_restored = 0u32;
    let mut errors = Vec::new();
    
    // Ensure target directory exists
    if target.is_dir() || !target.exists() {
        if let Err(e) = fs::create_dir_all(target) {
            return NativeResult::<RestoreResult>::error(&format!("Cannot create target dir: {}", e));
        }
    }
    
    // Restore files
    for entry in WalkDir::new(snapshot).into_iter().filter_map(|e| e.ok()) {
        let source = entry.path();
        let relative = source.strip_prefix(snapshot).unwrap_or(source);
        let dest = target.join(relative);
        
        if source.is_dir() {
            let _ = fs::create_dir_all(&dest);
        } else if source.is_file() {
            if let Some(parent) = dest.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::copy(source, &dest) {
                Ok(_) => files_restored += 1,
                Err(e) => errors.push(format!("{}: {}", source.display(), e)),
            }
        }
    }
    
    info!("Restored {} files from snapshot", files_restored);
    
    NativeResult::success(RestoreResult {
        restored: errors.is_empty(),
        files_restored,
        errors,
    })
}

/// List available snapshots
pub fn list_snapshots() -> Vec<SnapshotResult> {
    let mut snapshots = Vec::new();
    let snapshot_base = Path::new(SNAPSHOT_DIR);
    
    if let Ok(entries) = fs::read_dir(snapshot_base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let id = path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                
                let size = calculate_dir_size(&path);
                let timestamp = path.metadata()
                    .ok()
                    .and_then(|m| m.created().ok())
                    .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64)
                    .unwrap_or(0);
                
                snapshots.push(SnapshotResult {
                    id,
                    path: path.to_string_lossy().to_string(),
                    timestamp,
                    size,
                });
            }
        }
    }
    
    snapshots
}

fn calculate_dir_size(path: &Path) -> u64 {
    let mut size = 0u64;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() {
            if let Ok(meta) = fs::metadata(entry.path()) {
                size += meta.len();
            }
        }
    }
    size
}

/// Delete a snapshot
pub fn delete_snapshot(snapshot_id: &str) -> bool {
    let snapshot_path = Path::new(SNAPSHOT_DIR).join(snapshot_id);
    if snapshot_path.exists() {
        return fs::remove_dir_all(snapshot_path).is_ok();
    }
    false
}
