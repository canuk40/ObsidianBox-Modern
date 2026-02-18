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

package com.obsidianbox.core.shell

import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * RootShell - libsu-based root command execution abstraction
 * 
 * Replaces raw ProcessBuilder calls with cached shell sessions for 10-100x performance improvement.
 * Based on industry-standard libsu library used by Magisk Manager and 100+ root apps.
 * 
 * Features:
 * - Singleton shell session (cached across calls)
 * - Automatic fallback chain: su --mount-master → su → sh
 * - Job API for command chaining
 * - Async execution patterns
 * - Thread-safe operations
 * 
 * @see <a href="https://github.com/topjohnwu/libsu">libsu documentation</a>
 */
@Singleton
class RootShell @Inject constructor() {
    
    companion object {
        private const val TAG = "RootShell"
        
        /**
         * Initialize libsu configuration.
         * Must be called once during app initialization (Application.onCreate).
         */
        fun initialize(isDebug: Boolean = false) {
            Shell.enableVerboseLogging = isDebug
            Shell.setDefaultBuilder(
                Shell.Builder.create()
                    .setFlags(Shell.FLAG_MOUNT_MASTER) // Try mount master first (Magisk)
                    .setTimeout(10) // 10 second timeout
            )
            Timber.tag(TAG).d("libsu initialized")
        }
    }
    
    /**
     * Check if root access is available and granted.
     * 
     * @return true if root shell available, false if non-root, null if undetermined
     */
    fun isRootAvailable(): Boolean? {
        return Shell.isAppGrantedRoot()
    }
    
    /**
     * Execute single command synchronously.
     * 
     * @param command Command to execute
     * @return Result containing exit code, stdout, and stderr
     */
    suspend fun execute(command: String): ShellResult = withContext(Dispatchers.IO) {
        executeInternal(listOf(command))
    }
    
    /**
     * Execute multiple commands synchronously (chained in same shell session).
     * 
     * Commands execute in order, sharing environment variables and CWD.
     * 
     * @param commands Commands to execute
     * @return Result containing combined output
     */
    suspend fun execute(vararg commands: String): ShellResult = withContext(Dispatchers.IO) {
        executeInternal(commands.toList())
    }
    
    /**
     * Execute command asynchronously with callback.
     * 
     * @param command Command to execute
     * @param callback Callback invoked on completion (runs on main thread)
     */
    fun executeAsync(command: String, callback: (ShellResult) -> Unit) {
        Shell.cmd(command).submit { result ->
            callback(result.toShellResult())
        }
    }
    
    /**
     * Execute commands asynchronously with callback.
     * 
     * @param commands Commands to execute
     * @param callback Callback invoked on completion
     */
    fun executeAsync(commands: List<String>, callback: (ShellResult) -> Unit) {
        Shell.cmd(*commands.toTypedArray()).submit { result ->
            callback(result.toShellResult())
        }
    }
    
    /**
     * Execute command with real-time output streaming.
     * 
     * @param command Command to execute
     * @param onOutput Called for each line of output (real-time)
     * @param onComplete Called when execution finishes
     */
    fun executeStreaming(
        command: String,
        onOutput: (String) -> Unit,
        onComplete: (ShellResult) -> Unit
    ) {
        val outputList = object : ArrayList<String>() {
            override fun add(element: String): Boolean {
                onOutput(element)
                return super.add(element)
            }
        }
        
        Shell.cmd(command)
            .to(outputList)
            .submit { result ->
                onComplete(result.toShellResult())
            }
    }
    
    /**
     * Check if command succeeded (exit code 0).
     * 
     * @param command Command to check
     * @return true if command succeeded
     */
    suspend fun isSuccess(command: String): Boolean = withContext(Dispatchers.IO) {
        ShellUtils.fastCmdResult(command)
    }
    
    /**
     * Execute command and return first line of output.
     * 
     * Optimized for single-line results (e.g., `whoami`, `id -u`).
     * 
     * @param command Command to execute
     * @return First line of stdout, or empty string if failed
     */
    suspend fun fastCmd(command: String): String = withContext(Dispatchers.IO) {
        ShellUtils.fastCmd(command) ?: ""
    }
    
    /**
     * Get cached shell instance.
     * 
     * Returns null if shell not yet initialized. Use getShell() to force initialization.
     * 
     * @return Cached shell or null
     */
    fun getCachedShell(): Shell? {
        return Shell.getCachedShell()
    }
    
    /**
     * Get shell instance, initializing if needed.
     * 
     * Blocks until shell is ready. For async initialization, use getShellAsync.
     * 
     * @return Shell instance
     */
    suspend fun getShell(): Shell = withContext(Dispatchers.IO) {
        Shell.getShell()
    }
    
    /**
     * Get shell instance asynchronously.
     * 
     * @param callback Called when shell is ready
     */
    fun getShellAsync(callback: (Shell) -> Unit) {
        Shell.getShell(callback)
    }
    
    /**
     * Internal execution logic.
     */
    private fun executeInternal(commands: List<String>): ShellResult {
        Timber.tag(TAG).d("Executing: ${commands.joinToString(" && ")}")
        
        val result = if (commands.size == 1) {
            Shell.cmd(commands[0]).exec()
        } else {
            Shell.cmd(*commands.toTypedArray()).exec()
        }
        
        val shellResult = result.toShellResult()
        
        if (!shellResult.isSuccess) {
            Timber.tag(TAG).w("Command failed (code ${shellResult.code}): ${commands.joinToString(" && ")}")
            Timber.tag(TAG).w("stderr: ${shellResult.err.joinToString("\n")}")
        }
        
        return shellResult
    }
    
    /**
     * Convert libsu Result to our ShellResult.
     */
    private fun Shell.Result.toShellResult(): ShellResult {
        return ShellResult(
            code = code,
            out = out ?: emptyList(),
            err = err ?: emptyList(),
            isSuccess = isSuccess
        )
    }
}

/**
 * Shell execution result.
 * 
 * @property code Exit code (0 = success)
 * @property out Stdout lines
 * @property err Stderr lines
 * @property isSuccess True if exit code is 0
 */
data class ShellResult(
    val code: Int,
    val out: List<String>,
    val err: List<String>,
    val isSuccess: Boolean
) {
    /**
     * Get stdout as single string.
     */
    fun outString(): String = out.joinToString("\n")
    
    /**
     * Get stderr as single string.
     */
    fun errString(): String = err.joinToString("\n")
    
    /**
     * Get first line of stdout, or empty string.
     */
    fun firstLine(): String = out.firstOrNull() ?: ""
}
