/*
 * Copyright 2026 ObsidianBox Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Terminal PTY Backend for ObsidianBox Modern
 * 
 * Provides pseudo-terminal functionality for the terminal emulator.
 * Uses POSIX PTY APIs (forkpty/openpty) for shell session management.
 * 
 * IMPORTANT: Functions that return char* allocate memory that must be freed
 * by the caller using pty_free_string().
 */

#include <jni.h>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <termios.h>
#include <pty.h>
#include <utmp.h>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "TerminalPTY"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Buffer size for PTY read operations
#define PTY_READ_BUFFER_SIZE 8192

// Default terminal dimensions
#define DEFAULT_ROWS 24
#define DEFAULT_COLS 80

/**
 * Session tracking structure
 */
struct PtySession {
    int masterFd;
    pid_t childPid;
    bool isAlive;
};

// Maximum concurrent sessions
#define MAX_SESSIONS 8
static PtySession sessions[MAX_SESSIONS];
static bool sessionsInitialized = false;

/**
 * Initialize session tracking
 */
static void initSessions() {
    if (!sessionsInitialized) {
        for (int i = 0; i < MAX_SESSIONS; i++) {
            sessions[i].masterFd = -1;
            sessions[i].childPid = -1;
            sessions[i].isAlive = false;
        }
        sessionsInitialized = true;
    }
}

/**
 * Find a free session slot
 */
static int findFreeSession() {
    initSessions();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].isAlive) {
            return i;
        }
    }
    return -1;
}

/**
 * Find session by master FD
 */
static int findSessionByFd(int fd) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].masterFd == fd && sessions[i].isAlive) {
            return i;
        }
    }
    return -1;
}

/**
 * Set terminal to raw mode
 */
static void setRawMode(int fd) {
    struct termios term;
    if (tcgetattr(fd, &term) == 0) {
        // Disable canonical mode and echo
        term.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ISIG | IEXTEN);
        term.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        term.c_cflag &= ~(CSIZE | PARENB);
        term.c_cflag |= CS8;
        term.c_oflag &= ~(OPOST);
        
        // Set read timeout
        term.c_cc[VMIN] = 1;
        term.c_cc[VTIME] = 0;
        
        tcsetattr(fd, TCSANOW, &term);
    }
}

/**
 * Setup signal handlers for PTY management
 */
static void setupSignalHandlers() {
    // Ignore SIGPIPE (broken pipe when PTY closes)
    signal(SIGPIPE, SIG_IGN);
    
    // Register SIGCHLD handler for child process cleanup
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL; // Let waitpid handle it
    sa.sa_flags = SA_NOCLDSTOP; // Only notify on termination
    sigaction(SIGCHLD, &sa, nullptr);
}

/**
 * Helper to allocate result string (caller must free with pty_free_string)
 */
static char* allocResultString(size_t size) {
    char* buffer = (char*)malloc(size);
    if (!buffer) {
        LOGE("Failed to allocate result buffer");
        return strdup("{\"success\":false,\"error\":\"Out of memory\"}");
    }
    return buffer;
}

/**
 * Free a string returned by PTY functions
 */
extern "C" void pty_free_string(char* str) {
    if (str) {
        free(str);
    }
}
/**
 * Create a new PTY session
 * 
 * @param shell Path to shell executable
 * @param dataDir App data directory path
 * @param rows Initial terminal rows
 * @param cols Initial terminal columns
 * @param useRoot Whether to use root shell (su)
 * @return JSON string with session info or error (caller must free with pty_free_string)
 */
extern "C" char* pty_create(const char* shell, const char* dataDir, int rows, int cols, bool useRoot) {
    // Ensure signal handlers are set up
    static bool handlersInitialized = false;
    if (!handlersInitialized) {
        setupSignalHandlers();
        handlersInitialized = true;
    }
    
    initSessions();
    
    int sessionIdx = findFreeSession();
    if (sessionIdx < 0) {
        return strdup("{\"success\":false,\"error\":\"Maximum sessions reached\"}");
    }
    
    int masterFd;
    pid_t pid;
    
    // Set up window size with bounds checking
    struct winsize ws;
    ws.ws_row = (rows > 0 && rows < 9999) ? rows : DEFAULT_ROWS;
    ws.ws_col = (cols > 0 && cols < 9999) ? cols : DEFAULT_COLS;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    
    // Fork PTY
    pid = forkpty(&masterFd, nullptr, nullptr, &ws);
    
    if (pid < 0) {
        LOGE("forkpty failed: %s", strerror(errno));
        char* resultBuffer = allocResultString(256);
        snprintf(resultBuffer, 256,
            "{\"success\":false,\"error\":\"forkpty failed: %s\"}", strerror(errno));
        return resultBuffer;
    }
    
    if (pid == 0) {
        // Child process
        
        // Set up environment
        setenv("TERM", "xterm-256color", 1);
        setenv("COLORTERM", "truecolor", 1);
        
        // Use passed dataDir instead of hardcoded path
        if (dataDir && strlen(dataDir) > 0) {
            setenv("HOME", dataDir, 1);
            
            // Add app directories to PATH
            char newPath[2048];
            const char* existingPath = getenv("PATH");
            if (existingPath) {
                snprintf(newPath, sizeof(newPath),
                    "%s/files:%s/cache:/system/xbin:/system/bin:/data/adb/obsidianbox:%s", 
                    dataDir, dataDir, existingPath);
            } else {
                snprintf(newPath, sizeof(newPath),
                    "%s/files:%s/cache:/system/xbin:/system/bin:/data/adb/obsidianbox:/vendor/bin",
                    dataDir, dataDir);
            }
            setenv("PATH", newPath, 1);
        } else {
            // Fallback if dataDir not provided
            setenv("HOME", "/data/local/tmp", 1);
            const char* existingPath = getenv("PATH");
            if (existingPath) {
                char newPath[2048];
                snprintf(newPath, sizeof(newPath),
                    "/system/xbin:/system/bin:/data/adb/obsidianbox:%s", existingPath);
                setenv("PATH", newPath, 1);
            }
        }
        
        // Determine shell to execute
        const char* shellPath = shell;
        if (!shellPath || strlen(shellPath) == 0) {
            // Try common shell paths
            if (access("/system/bin/sh", X_OK) == 0) {
                shellPath = "/system/bin/sh";
            } else if (access("/bin/sh", X_OK) == 0) {
                shellPath = "/bin/sh";
            } else {
                shellPath = "sh";
            }
        }
        
        setenv("SHELL", shellPath, 1);
        setenv("USER", useRoot ? "root" : "shell", 1);
        
        if (useRoot) {
            // Try to get root shell
            const char* suPaths[] = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/adb/su",
                nullptr
            };
            
            const char* suPath = nullptr;
            for (int i = 0; suPaths[i] != nullptr; i++) {
                if (access(suPaths[i], X_OK) == 0) {
                    suPath = suPaths[i];
                    break;
                }
            }
            
            if (suPath) {
                LOGI("Launching root shell via %s", suPath);
                execlp(suPath, "su", nullptr);
            } else {
                LOGE("Root shell not available, falling back to regular shell");
            }
        }
        
        // Execute shell
        LOGI("Launching shell: %s", shellPath);
        execl(shellPath, shellPath, "-l", nullptr);
        
        // If exec fails, try sh directly
        execlp("sh", "sh", nullptr);
        
        // If all fails, exit
        LOGE("Failed to exec shell: %s", strerror(errno));
        _exit(127);
    }
    
    // Parent process
    LOGI("PTY created: master_fd=%d, child_pid=%d", masterFd, pid);
    
    // Set master to non-blocking for reads
    int flags = fcntl(masterFd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(masterFd, F_SETFL, flags | O_NONBLOCK);
    }
    
    // Store session
    sessions[sessionIdx].masterFd = masterFd;
    sessions[sessionIdx].childPid = pid;
    sessions[sessionIdx].isAlive = true;
    
    char* resultBuffer = allocResultString(512);
    snprintf(resultBuffer, 512,
        "{\"success\":true,\"session\":{\"fd\":%d,\"pid\":%d,\"rows\":%d,\"cols\":%d,\"alive\":true}}",
        masterFd, pid, ws.ws_row, ws.ws_col);
    
    return resultBuffer;
}

/**
 * Write data to PTY
 * 
 * @param fd Master PTY file descriptor
 * @param data UTF-8 encoded string to write
 * @param len Length of data
 * @return Bytes written or -1 on error
 */
/**
 * Write data to PTY
 * 
 * @param fd Master PTY file descriptor
 * @param data UTF-8 encoded string to write
 * @param len Length of data (max 1MB)
 * @return Bytes written or -1 on error
 */
extern "C" int pty_write(int fd, const char* data, int len) {
    // Validate parameters with reasonable max length (1MB)
    if (fd < 0 || data == nullptr || len <= 0 || len > 1024*1024) {
        LOGE("Invalid write parameters: fd=%d, len=%d", fd, len);
        return -1;
    }
    
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        LOGE("Invalid session for fd %d", fd);
        return -1;
    }
    
    ssize_t written = write(fd, data, len);
    if (written < 0) {
        LOGE("Write failed: %s", strerror(errno));
        return -1;
    }
    
    LOGD("Wrote %zd bytes to PTY", written);
    return (int)written;
}

/**
 * Read data from PTY (non-blocking)
 * 
 * @param fd Master PTY file descriptor
 * @param buffer Output buffer
 * @param bufferSize Size of output buffer
 * @param timeoutMs Timeout in milliseconds (0 for no wait)
 * @return Bytes read, 0 if no data, -1 on error, -2 if session closed
 */
/**
 * Read data from PTY (non-blocking)
 * 
 * @param fd Master PTY file descriptor
 * @param buffer Output buffer
 * @param bufferSize Size of output buffer (must be at least 2)
 * @param timeoutMs Timeout in milliseconds (0 for no wait)
 * @return Bytes read, 0 if no data, -1 on error, -2 if session closed
 */
extern "C" int pty_read(int fd, char* buffer, int bufferSize, int timeoutMs) {
    if (fd < 0 || buffer == nullptr || bufferSize <= 1) {
        LOGE("Invalid read parameters: fd=%d, bufferSize=%d", fd, bufferSize);
        if (buffer && bufferSize > 0) {
            buffer[0] = '\0';
        }
        return -1;
    }
    
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        buffer[0] = '\0';
        return -2; // Session not found/closed
    }
    
    // Check if child is still alive
    int status;
    pid_t result = waitpid(sessions[sessionIdx].childPid, &status, WNOHANG);
    if (result > 0) {
        // Child exited
        LOGI("Child process %d exited with status %d", 
             sessions[sessionIdx].childPid, WEXITSTATUS(status));
        sessions[sessionIdx].isAlive = false;
        buffer[0] = '\0';
        return -2;
    }
    
    // Use select for timeout
    if (timeoutMs > 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        
        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        
        int selectResult = select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if (selectResult <= 0) {
            buffer[0] = '\0';
            return 0; // No data or error
        }
    }
    
    // Read with space for null terminator
    ssize_t bytesRead = read(fd, buffer, bufferSize - 1);
    
    if (bytesRead < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            buffer[0] = '\0';
            return 0; // No data available
        }
        LOGE("Read failed: %s", strerror(errno));
        buffer[0] = '\0';
        return -1;
    }
    
    if (bytesRead == 0) {
        // EOF - session closed
        LOGI("EOF on PTY fd=%d, session closing", fd);
        sessions[sessionIdx].isAlive = false;
        buffer[0] = '\0';
        return -2;
    }
    
    // Always null-terminate
    buffer[bytesRead] = '\0';
    return (int)bytesRead;
}

/**
 * Resize PTY window
 * 
 * @param fd Master PTY file descriptor
 * @param rows New row count
 * @param cols New column count
 * @return 0 on success, -1 on error
 */
/**
 * Resize PTY window
 * 
 * @param fd Master PTY file descriptor
 * @param rows New row count (1-9999)
 * @param cols New column count (1-9999)
 * @return 0 on success, -1 on error
 */
extern "C" int pty_resize(int fd, int rows, int cols) {
    // Validate parameters with reasonable bounds
    if (fd < 0 || rows <= 0 || rows > 9999 || cols <= 0 || cols > 9999) {
        LOGE("Invalid resize parameters: fd=%d, rows=%d, cols=%d", fd, rows, cols);
        return -1;
    }
    
    struct winsize ws;
    ws.ws_row = rows;
    ws.ws_col = cols;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    
    if (ioctl(fd, TIOCSWINSZ, &ws) < 0) {
        LOGE("ioctl TIOCSWINSZ failed: %s", strerror(errno));
        return -1;
    }
    
    LOGD("Resized PTY to %dx%d", cols, rows);
    return 0;
}

/**
 * Close PTY session
 * 
 * @param fd Master PTY file descriptor
 * @return 0 on success, -1 on error
 */
extern "C" int pty_close(int fd) {
    if (fd < 0) {
        return -1;
    }
    
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        // Just close the fd even if session not found
        close(fd);
        return 0;
    }
    
    PtySession* session = &sessions[sessionIdx];
    
    // Kill child process if still running
    if (session->childPid > 0) {
        kill(session->childPid, SIGHUP);
        usleep(100000); // 100ms
        
        int status;
        if (waitpid(session->childPid, &status, WNOHANG) == 0) {
            // Still running, force kill
            kill(session->childPid, SIGKILL);
            waitpid(session->childPid, &status, 0);
        }
        LOGI("Child process %d terminated", session->childPid);
    }
    
    // Close master FD
    close(fd);
    
    // Clear session
    session->masterFd = -1;
    session->childPid = -1;
    session->isAlive = false;
    
    LOGI("PTY session closed: fd=%d", fd);
    return 0;
}

/**
 * Check if session is alive
 * 
 * @param fd Master PTY file descriptor
 * @return 1 if alive, 0 if dead, -1 on error
 */
extern "C" int pty_is_alive(int fd) {
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        return -1;
    }
    
    PtySession* session = &sessions[sessionIdx];
    
    // Check child status
    int status;
    pid_t result = waitpid(session->childPid, &status, WNOHANG);
    
    if (result > 0) {
        session->isAlive = false;
        return 0;
    } else if (result == 0) {
        return 1; // Still running
    } else {
        return -1; // Error
    }
}

/**
 * Send signal to PTY child process
 * 
 * @param fd Master PTY file descriptor
 * @param signal Signal number
 * @return 0 on success, -1 on error
 */
extern "C" int pty_signal(int fd, int sig) {
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        return -1;
    }
    
    if (kill(sessions[sessionIdx].childPid, sig) < 0) {
        LOGE("Failed to send signal %d: %s", sig, strerror(errno));
        return -1;
    }
    
    LOGD("Sent signal %d to process %d", sig, sessions[sessionIdx].childPid);
    return 0;
}

/**
 * Get session info as JSON
 * 
 * @param fd Master PTY file descriptor
 * @return JSON string with session info (caller must free with pty_free_string)
 */
extern "C" char* pty_get_info(int fd) {
    int sessionIdx = findSessionByFd(fd);
    if (sessionIdx < 0) {
        return strdup("{\"success\":false,\"error\":\"Session not found\"}");
    }
    
    PtySession* session = &sessions[sessionIdx];
    
    // Get window size
    struct winsize ws;
    int rows = 0, cols = 0;
    if (ioctl(fd, TIOCGWINSZ, &ws) == 0) {
        rows = ws.ws_row;
        cols = ws.ws_col;
    }
    
    // Check if alive
    int alive = pty_is_alive(fd);
    
    char* resultBuffer = allocResultString(256);
    snprintf(resultBuffer, 256,
        "{\"success\":true,\"fd\":%d,\"pid\":%d,\"alive\":%s,\"rows\":%d,\"cols\":%d}",
        session->masterFd, session->childPid, 
        alive > 0 ? "true" : "false", rows, cols);
    
    return resultBuffer;
}
