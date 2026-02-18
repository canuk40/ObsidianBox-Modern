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

//! Cgroup detection module
//!
//! Detects cgroup v1/v2 membership, cpuset/stune assignments, and scheduling state.
//! Inspired by SKRoot's cgroup_v1_tasks_self.h and cgroup_v2_self.h utilities.

use crate::result::NativeResult;
use serde::Serialize;
use std::fs;
use std::path::Path;

/// Complete cgroup state for the current process
#[derive(Serialize)]
pub struct CgroupInfo {
    /// Whether cgroup v2 (unified) is active
    pub v2_active: bool,
    /// Whether cgroup v1 (legacy) hierarchies exist
    pub v1_active: bool,
    /// Raw /proc/self/cgroup contents parsed into entries
    pub memberships: Vec<CgroupMembership>,
    /// Cpuset assignment (which CPUs this process can use)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<CpusetInfo>,
    /// Scheduling group (foreground/background/top-app etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduling_group: Option<String>,
    /// Whether process appears to be in a frozen/stopped cgroup
    pub frozen: bool,
}

/// A single cgroup membership entry from /proc/self/cgroup
#[derive(Serialize)]
pub struct CgroupMembership {
    /// Hierarchy ID (0 for v2)
    pub hierarchy_id: u32,
    /// Controllers (empty string for v2)
    pub controllers: String,
    /// Path within the cgroup hierarchy
    pub path: String,
}

/// CPU set assignment info
#[derive(Serialize)]
pub struct CpusetInfo {
    /// Which CPUs are allowed (e.g., "0-7")
    pub cpus: String,
    /// Which memory nodes are allowed
    pub mems: String,
    /// Cpuset cgroup path
    pub cgroup_path: String,
}

/// Detect cgroup state for the current process
pub fn detect_cgroups() -> String {
    let v2_active = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let v1_active = Path::new("/dev/cpuset").exists() || Path::new("/dev/stune").exists();

    let memberships = parse_proc_cgroup();
    let cpuset = detect_cpuset(&memberships);
    let scheduling_group = detect_scheduling_group(&memberships);
    let frozen = detect_frozen_state(&memberships);

    NativeResult::success(CgroupInfo {
        v2_active,
        v1_active,
        memberships,
        cpuset,
        scheduling_group,
        frozen,
    })
}

/// Parse /proc/self/cgroup into structured entries
fn parse_proc_cgroup() -> Vec<CgroupMembership> {
    let content = match fs::read_to_string("/proc/self/cgroup") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            // Format: hierarchy-ID:controller-list:cgroup-path
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                Some(CgroupMembership {
                    hierarchy_id: parts[0].parse().unwrap_or(0),
                    controllers: parts[1].to_string(),
                    path: parts[2].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Detect cpuset assignment
fn detect_cpuset(memberships: &[CgroupMembership]) -> Option<CpusetInfo> {
    // Find cpuset controller in memberships
    let cpuset_entry = memberships
        .iter()
        .find(|m| m.controllers.contains("cpuset"));

    let cgroup_path = cpuset_entry.map(|e| e.path.clone()).unwrap_or_default();

    // Try reading from the cpuset cgroup path
    // On Android, cpuset is typically at /dev/cpuset/<group>
    let cpuset_base = if cgroup_path.is_empty() || cgroup_path == "/" {
        "/dev/cpuset".to_string()
    } else {
        format!("/dev/cpuset{}", cgroup_path)
    };

    let cpus = fs::read_to_string(format!("{}/cpus", cpuset_base))
        .or_else(|_| fs::read_to_string("/dev/cpuset/cpus"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let mems = fs::read_to_string(format!("{}/mems", cpuset_base))
        .or_else(|_| fs::read_to_string("/dev/cpuset/mems"))
        .unwrap_or_default()
        .trim()
        .to_string();

    if cpus.is_empty() && mems.is_empty() {
        return None;
    }

    Some(CpusetInfo {
        cpus,
        mems,
        cgroup_path,
    })
}

/// Detect the scheduling group (top-app, foreground, background, etc.)
/// Mirrors SKRoot's cpuset/stune path hierarchy
fn detect_scheduling_group(memberships: &[CgroupMembership]) -> Option<String> {
    // Check cpuset path for scheduling group
    for m in memberships {
        if m.controllers.contains("cpuset") || m.controllers.contains("cpu") {
            let path = &m.path;
            if path.contains("top-app") {
                return Some("top-app".to_string());
            } else if path.contains("foreground") {
                return Some("foreground".to_string());
            } else if path.contains("background") {
                return Some("background".to_string());
            } else if path.contains("system-background") {
                return Some("system-background".to_string());
            } else if path.contains("restricted") {
                return Some("restricted".to_string());
            }
        }
    }

    // For cgroup v2, check unified hierarchy
    for m in memberships {
        if m.hierarchy_id == 0 {
            let path = &m.path;
            if path.contains("top-app") {
                return Some("top-app".to_string());
            } else if path.contains("foreground") {
                return Some("foreground".to_string());
            } else if path.contains("background") {
                return Some("background".to_string());
            }
        }
    }

    None
}

/// Detect if the process is in a frozen/stopped cgroup
fn detect_frozen_state(memberships: &[CgroupMembership]) -> bool {
    for m in memberships {
        let path = &m.path;
        if path.contains("frozen") || path.contains("uid_0/pid_") {
            // Check freezer state if accessible
            let freezer_path = if m.controllers.contains("freezer") {
                format!("/sys/fs/cgroup/freezer{}/freezer.state", path)
            } else {
                continue;
            };
            if let Ok(state) = fs::read_to_string(&freezer_path) {
                if state.trim() == "FROZEN" {
                    return true;
                }
            }
        }
    }
    false
}
