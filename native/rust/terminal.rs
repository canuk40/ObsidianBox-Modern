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

//! Terminal PTY Backend
//!
//! Provides pseudo-terminal functionality for the ObsidianBox Modern terminal emulator.
//! Uses nix crate for POSIX PTY operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, BorrowedFd, RawFd};
use std::sync::Mutex;

#[cfg(target_os = "android")]
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::libc;
use nix::pty::{forkpty, ForkptyResult, Winsize};
use nix::sys::select::{select, FdSet};
use nix::sys::signal::{kill, Signal};
use nix::sys::time::TimeVal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, execvp, read, write, Pid};

/// Terminal session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    pub fd: i32,
    pub pid: i32,
    pub rows: u16,
    pub cols: u16,
    pub alive: bool,
    pub created_at: u64,
}

/// Terminal creation result
#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalCreateResult {
    pub success: bool,
    pub session: Option<TerminalSession>,
    pub error: Option<String>,
}

/// Terminal operation result
#[derive(Debug, Serialize, Deserialize)]
pub struct TerminalResult {
    pub success: bool,
    pub data: Option<String>,
    pub bytes_processed: i32,
    pub error: Option<String>,
}

// Active sessions storage
lazy_static::lazy_static! {
    static ref SESSIONS: Mutex<HashMap<i32, TerminalSessionInternal>> = Mutex::new(HashMap::new());
}

#[derive(Debug)]
struct TerminalSessionInternal {
    master_fd: RawFd,
    child_pid: Pid,
    rows: u16,
    cols: u16,
    created_at: u64,
}

/// Default terminal dimensions
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;

/// Read buffer size
const READ_BUFFER_SIZE: usize = 8192;

/// Create a new terminal session
///
/// # Arguments
/// * `shell` - Path to shell executable (empty for default)
/// * `rows` - Initial terminal rows
/// * `cols` - Initial terminal columns
/// * `use_root` - Whether to attempt root shell
///
/// # Returns
/// JSON string with session info or error
pub fn terminal_create(shell: &str, rows: u16, cols: u16, use_root: bool) -> String {
    let actual_rows = if rows > 0 { rows } else { DEFAULT_ROWS };
    let actual_cols = if cols > 0 { cols } else { DEFAULT_COLS };

    let winsize = Winsize {
        ws_row: actual_rows,
        ws_col: actual_cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // Fork PTY
    let fork_result = match unsafe { forkpty(&winsize, None) } {
        Ok(result) => result,
        Err(e) => {
            return serde_json::to_string(&TerminalCreateResult {
                success: false,
                session: None,
                error: Some(format!("forkpty failed: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization failed"}"#.to_string());
        }
    };

    match fork_result {
        ForkptyResult::Parent { child, master } => {
            // Parent process
            let master_fd = master.as_raw_fd();

            // Set non-blocking
            if let Ok(flags) = fcntl(master_fd, FcntlArg::F_GETFL) {
                let _ = fcntl(
                    master_fd,
                    FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
                );
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            // Store session
            let mut sessions = SESSIONS.lock().unwrap();
            sessions.insert(
                master_fd,
                TerminalSessionInternal {
                    master_fd,
                    child_pid: child,
                    rows: actual_rows,
                    cols: actual_cols,
                    created_at: now,
                },
            );

            // Don't close master - we need it
            std::mem::forget(master);

            let session = TerminalSession {
                fd: master_fd,
                pid: child.as_raw() as i32,
                rows: actual_rows,
                cols: actual_cols,
                alive: true,
                created_at: now,
            };

            serde_json::to_string(&TerminalCreateResult {
                success: true,
                session: Some(session),
                error: None,
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization failed"}"#.to_string())
        }
        ForkptyResult::Child => {
            // Child process - exec shell
            setup_child_environment(use_root);
            exec_shell(shell, use_root);

            // If exec fails
            std::process::exit(127);
        }
    }
}

/// Set up child process environment
fn setup_child_environment(use_root: bool) {
    std::env::set_var("TERM", "xterm-256color");
    std::env::set_var("COLORTERM", "truecolor");
    std::env::set_var("HOME", "/data/data/com.obsidianbox");
    std::env::set_var("USER", if use_root { "root" } else { "shell" });

    // Extend PATH
    if let Ok(path) = std::env::var("PATH") {
        std::env::set_var(
            "PATH",
            format!("/system/xbin:/system/bin:/data/adb/obsidianbox:{}", path),
        );
    }
}

/// Execute shell in child process
fn exec_shell(shell: &str, use_root: bool) {
    let shell_path = if shell.is_empty() {
        find_shell()
    } else {
        shell.to_string()
    };

    if use_root {
        // Try to find su
        let su_paths = [
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/adb/su",
        ];

        for su_path in &su_paths {
            if std::path::Path::new(su_path).exists() {
                let su = CString::new(*su_path).unwrap();
                let shell_arg = CString::new(shell_path.as_str()).unwrap();
                let args = [
                    CString::new("su").unwrap(),
                    CString::new("-c").unwrap(),
                    shell_arg,
                ];

                let _ = execvp(&su, &args);
                // If exec fails, continue to try regular shell
                break;
            }
        }
    }

    // Execute regular shell
    let shell = CString::new(shell_path.as_str()).unwrap();
    let args = [CString::new(shell_path.as_str()).unwrap(), CString::new("-l").unwrap()];

    let _ = execvp(&shell, &args);

    // Fallback to sh
    let sh = CString::new("sh").unwrap();
    let args = [CString::new("sh").unwrap()];
    let _ = execvp(&sh, &args);
}

/// Find available shell
fn find_shell() -> String {
    let shells = ["/system/bin/sh", "/bin/sh", "sh"];

    for shell in &shells {
        if std::path::Path::new(shell).exists() || shell == &"sh" {
            return shell.to_string();
        }
    }

    "sh".to_string()
}

/// Write data to terminal
///
/// # Arguments
/// * `fd` - Master PTY file descriptor
/// * `data` - UTF-8 data to write
///
/// # Returns
/// JSON string with result
pub fn terminal_write(fd: i32, data: &str) -> String {
    let sessions = SESSIONS.lock().unwrap();
    if !sessions.contains_key(&fd) {
        return serde_json::to_string(&TerminalResult {
            success: false,
            data: None,
            bytes_processed: 0,
            error: Some("Session not found".to_string()),
        })
        .unwrap();
    }
    drop(sessions);

    // SAFETY: fd is a valid file descriptor from a PTY session
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    match write(&borrowed_fd, data.as_bytes()) {
        Ok(n) => serde_json::to_string(&TerminalResult {
            success: true,
            data: None,
            bytes_processed: n as i32,
            error: None,
        })
        .unwrap(),
        Err(e) => serde_json::to_string(&TerminalResult {
            success: false,
            data: None,
            bytes_processed: 0,
            error: Some(format!("Write failed: {}", e)),
        })
        .unwrap(),
    }
}

/// Read data from terminal (non-blocking)
///
/// # Arguments
/// * `fd` - Master PTY file descriptor
/// * `timeout_ms` - Timeout in milliseconds (0 for no wait)
///
/// # Returns
/// JSON string with result and data
pub fn terminal_read(fd: i32, timeout_ms: i32) -> String {
    {
        let sessions = SESSIONS.lock().unwrap();
        if !sessions.contains_key(&fd) {
            return serde_json::to_string(&TerminalResult {
                success: false,
                data: None,
                bytes_processed: -2,
                error: Some("Session not found".to_string()),
            })
            .unwrap();
        }
    }

    // Check child status
    if !is_session_alive(fd) {
        return serde_json::to_string(&TerminalResult {
            success: false,
            data: None,
            bytes_processed: -2,
            error: Some("Session closed".to_string()),
        })
        .unwrap();
    }

    // Use select for timeout
    if timeout_ms > 0 {
        let mut read_fds = FdSet::new();
        // SAFETY: fd is a valid file descriptor from a PTY session
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        read_fds.insert(borrowed_fd);

        // Create timeout from milliseconds (convert to seconds + microseconds)
        let seconds = (timeout_ms / 1000) as i32;
        let microseconds = ((timeout_ms % 1000) * 1000) as i32;
        let mut timeout = TimeVal::new(seconds.into(), microseconds.into());

        match select(fd + 1, Some(&mut read_fds), None, None, Some(&mut timeout)) {
            Ok(0) => {
                // Timeout - no data
                return serde_json::to_string(&TerminalResult {
                    success: true,
                    data: Some(String::new()),
                    bytes_processed: 0,
                    error: None,
                })
                .unwrap();
            }
            Err(e) => {
                return serde_json::to_string(&TerminalResult {
                    success: false,
                    data: None,
                    bytes_processed: -1,
                    error: Some(format!("Select failed: {}", e)),
                })
                .unwrap();
            }
            _ => {}
        }
    }

    // Read data
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];
    match read(fd, &mut buffer) {
        Ok(0) => {
            // EOF
            serde_json::to_string(&TerminalResult {
                success: false,
                data: None,
                bytes_processed: -2,
                error: Some("EOF".to_string()),
            })
            .unwrap()
        }
        Ok(n) => {
            buffer.truncate(n);
            let data = String::from_utf8_lossy(&buffer).to_string();
            serde_json::to_string(&TerminalResult {
                success: true,
                data: Some(data),
                bytes_processed: n as i32,
                error: None,
            })
            .unwrap()
        }
        Err(nix::errno::Errno::EAGAIN) => {
            // No data available (EWOULDBLOCK is the same as EAGAIN on Linux/Android)
            serde_json::to_string(&TerminalResult {
                success: true,
                data: Some(String::new()),
                bytes_processed: 0,
                error: None,
            })
            .unwrap()
        }
        Err(e) => serde_json::to_string(&TerminalResult {
            success: false,
            data: None,
            bytes_processed: -1,
            error: Some(format!("Read failed: {}", e)),
        })
        .unwrap(),
    }
}

/// Resize terminal
///
/// # Arguments
/// * `fd` - Master PTY file descriptor
/// * `rows` - New row count
/// * `cols` - New column count
///
/// # Returns
/// JSON string with result
pub fn terminal_resize(fd: i32, rows: u16, cols: u16) -> String {
    let winsize = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let result = unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &winsize as *const Winsize)
    };

    if result < 0 {
        serde_json::to_string(&TerminalResult {
            success: false,
            data: None,
            bytes_processed: 0,
            error: Some("ioctl TIOCSWINSZ failed".to_string()),
        })
        .unwrap()
    } else {
        // Update stored dimensions
        if let Ok(mut sessions) = SESSIONS.lock() {
            if let Some(session) = sessions.get_mut(&fd) {
                session.rows = rows;
                session.cols = cols;
            }
        }

        serde_json::to_string(&TerminalResult {
            success: true,
            data: None,
            bytes_processed: 0,
            error: None,
        })
        .unwrap()
    }
}

/// Close terminal session
///
/// # Arguments
/// * `fd` - Master PTY file descriptor
///
/// # Returns
/// JSON string with result
pub fn terminal_close(fd: i32) -> String {
    let session = {
        let mut sessions = SESSIONS.lock().unwrap();
        sessions.remove(&fd)
    };

    if let Some(session) = session {
        // Send SIGHUP first
        let _ = kill(session.child_pid, Signal::SIGHUP);
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if still running
        match waitpid(session.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                // Force kill
                let _ = kill(session.child_pid, Signal::SIGKILL);
                let _ = waitpid(session.child_pid, None);
            }
            _ => {}
        }

        // Close FD
        let _ = close(fd);
    } else {
        // Just close the fd
        let _ = close(fd);
    }

    serde_json::to_string(&TerminalResult {
        success: true,
        data: None,
        bytes_processed: 0,
        error: None,
    })
    .unwrap()
}

/// Check if session is alive
fn is_session_alive(fd: i32) -> bool {
    let sessions = SESSIONS.lock().unwrap();
    if let Some(session) = sessions.get(&fd) {
        match waitpid(session.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Get session information
///
/// # Arguments
/// * `fd` - Master PTY file descriptor
///
/// # Returns
/// JSON string with session info
pub fn terminal_get_info(fd: i32) -> String {
    let sessions = SESSIONS.lock().unwrap();
    if let Some(session) = sessions.get(&fd) {
        let alive = match waitpid(session.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => true,
            _ => false,
        };

        let info = TerminalSession {
            fd: session.master_fd,
            pid: session.child_pid.as_raw() as i32,
            rows: session.rows,
            cols: session.cols,
            alive,
            created_at: session.created_at,
        };

        serde_json::to_string(&TerminalCreateResult {
            success: true,
            session: Some(info),
            error: None,
        })
        .unwrap()
    } else {
        serde_json::to_string(&TerminalCreateResult {
            success: false,
            session: None,
            error: Some("Session not found".to_string()),
        })
        .unwrap()
    }
}

// FFI exports
#[no_mangle]
pub extern "C" fn rust_terminal_create(
    shell: *const std::os::raw::c_char,
    rows: u16,
    cols: u16,
    use_root: bool,
) -> *mut std::os::raw::c_char {
    let shell_str = if shell.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(shell).to_str().unwrap_or("") }
    };

    let result = terminal_create(shell_str, rows, cols, use_root);
    std::ffi::CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_terminal_write(
    fd: i32,
    data: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    let data_str = if data.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(data).to_str().unwrap_or("") }
    };

    let result = terminal_write(fd, data_str);
    std::ffi::CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_terminal_read(
    fd: i32,
    timeout_ms: i32,
) -> *mut std::os::raw::c_char {
    let result = terminal_read(fd, timeout_ms);
    std::ffi::CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_terminal_resize(
    fd: i32,
    rows: u16,
    cols: u16,
) -> *mut std::os::raw::c_char {
    let result = terminal_resize(fd, rows, cols);
    std::ffi::CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_terminal_close(fd: i32) -> *mut std::os::raw::c_char {
    let result = terminal_close(fd);
    std::ffi::CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_terminal_get_info(fd: i32) -> *mut std::os::raw::c_char {
    let result = terminal_get_info(fd);
    std::ffi::CString::new(result).unwrap().into_raw()
}
