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

@file:OptIn(kotlinx.serialization.InternalSerializationApi::class)
package com.obsidianbox.data.nativebridge

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer
import timber.log.Timber
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * JNI bridge to Rust native library
 * All native operations return JSON strings for safe cross-boundary data transfer
 */
@Singleton
class NativeBridge @Inject constructor() {

    private val json = Json { 
        ignoreUnknownKeys = true 
        isLenient = true
    }

    companion object {
        private const val TAG = "NativeBridge"
        private var isNativeLibraryLoaded = false

        init {
            try {
                // Log system info for debugging
                Timber.i("Native library loading - System Info:")
                Timber.i("  ABI: ${System.getProperty("os.arch")}")
                Timber.i("  Supported ABIs: ${android.os.Build.SUPPORTED_ABIS.joinToString()}")
                Timber.i("  Primary ABI: ${android.os.Build.SUPPORTED_ABIS[0]}")

                // CRITICAL: Load the Rust native library FIRST - it contains all the JNI functions
                // The libobsidianbox_native.so is the Rust-compiled library with terminal, diagnostics, etc.
                try {
                    System.loadLibrary("obsidianbox_native")
                    Timber.i("✅ Loaded obsidianbox_native (Rust) library")
                    isNativeLibraryLoaded = true
                } catch (e: UnsatisfiedLinkError) {
                    Timber.w("obsidianbox_native not found, trying obsidianboxmodern")
                    // Fallback to the CMake-built library (may have Rust linked statically)
                    System.loadLibrary("obsidianboxmodern")
                    Timber.i("✅ Loaded obsidianboxmodern (CMake) library")
                    isNativeLibraryLoaded = true
                }

                Timber.i("Native library is ready for use")
            } catch (e: UnsatisfiedLinkError) {
                isNativeLibraryLoaded = false
                Timber.e(e, "❌ Failed to load native library - native features will be unavailable")
                Timber.e("Library search paths: ${System.getProperty("java.library.path")}")
            } catch (e: Exception) {
                isNativeLibraryLoaded = false
                Timber.e(e, "❌ Unexpected error loading native library")
            }
        }

        fun isNativeAvailable(): Boolean = isNativeLibraryLoaded
    }

    // Native function declarations (implemented in C++/Rust)
    private external fun nativeDetectPartitions(): String
    private external fun nativeInstallBusybox(targetPath: String, binaryData: ByteArray): String
    private external fun nativeCreateSymlinks(busyboxPath: String, symlinkDir: String, applets: String): String
    private external fun nativeRemoveSymlinks(symlinkDir: String): String
    private external fun nativePatchPermissions(path: String, mode: Int, recursive: Boolean): String
    private external fun nativeDetectSelinux(): String
    private external fun nativeDetectMagisk(): String
    private external fun nativeGetBusyboxInfo(path: String): String
    private external fun nativeCreateSnapshot(targetPath: String, snapshotName: String): String
    private external fun nativeRestoreSnapshot(snapshotPath: String, targetPath: String): String
    
    // Utility functions (implemented in Kotlin — no native symbol needed)
    fun getNativeVersion(): String = "1.0.0"
    fun isNativeReady(): Boolean = isNativeLibraryLoaded
    
    // Pipeline test (exported directly from Rust without native prefix)
    external fun testNative(): String
    
    // Installer functions (exported directly from Rust)
    private external fun detectObsidianBox(): String
    private external fun uninstallObsidianBox(targetDir: String): String
    private external fun createObsidianBoxSnapshot(targetPath: String): String
    private external fun restoreObsidianBoxSnapshot(snapshotId: String): String
    external fun listSnapshots(): String
    
    // Diagnostics functions (exported from Rust with native prefix)
    private external fun nativeRunSymlinkDiagnostics(): String
    private external fun nativeRunPathDiagnostics(): String
    private external fun nativeRunSelinuxDiagnostics(): String
    private external fun nativeRunMagiskDiagnostics(): String
    private external fun nativeRunObsidianBoxDiagnostics(): String
    private external fun nativeRunFullDiagnostics(): String
    
    // Enhanced SELinux & Cgroup functions (exported from Rust)
    private external fun nativeDetectSelinuxExtended(): String
    private external fun nativeGetAvcDenials(): String
    private external fun nativeDetectCgroups(): String
    
    /**
     * Terminal PTY functions (JNI → Rust)
     */
    private external fun nativeTerminalCreate(shell: String, rows: Int, cols: Int, useRoot: Boolean): String
    private external fun nativeTerminalWrite(fd: Int, data: String): String
    private external fun nativeTerminalRead(fd: Int, timeoutMs: Int): String
    private external fun nativeTerminalResize(fd: Int, rows: Int, cols: Int): String
    private external fun nativeTerminalClose(fd: Int): String
    private external fun nativeTerminalGetInfo(fd: Int): String

    // Magisk functions (JNI → Rust)
    private external fun nativeListMagiskModules(): String
    private external fun nativeDetectMagiskConflicts(): String

    /**
     * Helper method to safely call native functions
     * Returns an error result if native library is not loaded
     */
    private suspend inline fun <reified T : Any> safeNativeCall(
        operationName: String,
        crossinline nativeCall: suspend () -> String
    ): NativeResult<T> = withContext(Dispatchers.IO) {
        try {
            if (!isNativeLibraryLoaded) {
                Timber.w("Native library not loaded, cannot execute: $operationName")
                return@withContext NativeResult.Error("Native library not available. Please ensure the app is properly installed.")
            }
            val jsonResult = nativeCall()
            parseNativeResult<T>(jsonResult)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "$operationName failed - native method not found")
            NativeResult.Error("Native operation unavailable: ${e.message}")
        } catch (e: Exception) {
            Timber.e(e, "$operationName failed")
            NativeResult.Error(e.message ?: "Native call failed")
        }
    }

    /**
     * Test native pipeline - validates Kotlin → JNI → Rust connection
     */
    suspend fun runNativeTest(): NativeResult<TestData> = withContext(Dispatchers.IO) {
        try {
            if (!isNativeLibraryLoaded) {
                Timber.w("Native library not loaded, cannot execute runNativeTest")
                return@withContext NativeResult.Error("Native library not loaded. The native functions are unavailable.")
            }

            Timber.d("Running native pipeline test...")
            val result = testNative()
            Timber.d("Native test result: $result")
            parseNativeResult<TestData>(result)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "testNative failed - JNI function not implemented")
            NativeResult.Error("Native test function not implemented. This feature requires the native library to be fully built with Rust support.")
        } catch (e: Exception) {
            Timber.e(e, "runNativeTest failed")
            NativeResult.Error(e.message ?: "Native test failed")
        }
    }

    /**
     * Detect BusyBox installation by searching common paths
     */
    suspend fun detectBusyBoxInstallation(): NativeResult<DetectBusyBoxData> =
        safeNativeCall("detectBusyBoxInstallation") {
            Timber.d("Detecting BusyBox installation...")
            val result = detectObsidianBox()
            Timber.d("Detect result: $result")
            result
        }

    /**
     * Uninstall BusyBox from specified directory
     */
    suspend fun uninstallBusyBoxFromDir(targetDir: String): NativeResult<UninstallBusyBoxData> =
        safeNativeCall("uninstallBusyBoxFromDir") {
            Timber.d("Uninstalling BusyBox from: $targetDir")
            val result = uninstallObsidianBox(targetDir)
            Timber.d("Uninstall result: $result")
            result
        }

    /**
     * Create snapshot of BusyBox installation before making changes
     */
    suspend fun createInstallerSnapshot(targetPath: String): NativeResult<SnapshotData> =
        safeNativeCall("createInstallerSnapshot") {
            Timber.d("Creating snapshot of: $targetPath")
            val result = createObsidianBoxSnapshot(targetPath)
            Timber.d("Snapshot result: $result")
            result
        }

    /**
     * Restore BusyBox from snapshot
     */
    suspend fun restoreFromSnapshot(snapshotId: String): NativeResult<RestoreData> =
        safeNativeCall("restoreFromSnapshot") {
            Timber.d("Restoring from snapshot: $snapshotId")
            val result = restoreObsidianBoxSnapshot(snapshotId)
            Timber.d("Restore result: $result")
            result
        }

    /**
     * Get list of available snapshots
     */
    suspend fun getSnapshots(): NativeResult<List<SnapshotData>> =
        safeNativeCall("getSnapshots") {
            Timber.d("Listing snapshots...")
            val result = listSnapshots()
            Timber.d("Snapshots result: $result")
            result
        }

    /**
     * Detect available partitions for BusyBox installation
     */
    suspend fun detectPartitions(): NativeResult<List<PartitionData>> =
        safeNativeCall("detectPartitions") {
            nativeDetectPartitions()
        }

    /**
     * Install BusyBox binary to specified path
     */
    suspend fun installBusybox(targetPath: String, binaryData: ByteArray): NativeResult<InstallData> =
        safeNativeCall("installBusybox") {
            nativeInstallBusybox(targetPath, binaryData)
        }

    /**
     * Create symlinks for BusyBox applets
     */
    suspend fun createSymlinks(
        busyboxPath: String, 
        symlinkDir: String, 
        applets: List<String>
    ): NativeResult<SymlinkData> = safeNativeCall("createSymlinks") {
        val appletsJson = "[" + applets.joinToString(",") { "\"$it\"" } + "]"
        nativeCreateSymlinks(busyboxPath, symlinkDir, appletsJson)
    }

    /**
     * Remove all symlinks from directory
     */
    suspend fun removeSymlinks(symlinkDir: String): NativeResult<SymlinkData> =
        safeNativeCall("removeSymlinks") {
            nativeRemoveSymlinks(symlinkDir)
        }

    /**
     * Patch file/directory permissions
     */
    suspend fun patchPermissions(
        path: String,
        mode: Int,
        recursive: Boolean
    ): NativeResult<PermissionData> = safeNativeCall("patchPermissions") {
        nativePatchPermissions(path, mode, recursive)
    }

    /**
     * Detect SELinux mode and context
     */
    suspend fun detectSelinux(): NativeResult<SelinuxData> = safeNativeCall("detectSelinux") {
        nativeDetectSelinux()
    }

    /**
     * Extended SELinux detection: thread contexts, policy info, AVC stats, capabilities.
     * Inspired by SKRoot's selinux_procattr approach.
     */
    suspend fun detectSelinuxExtended(): NativeResult<SelinuxExtendedData> =
        safeNativeCall("detectSelinuxExtended") {
            nativeDetectSelinuxExtended()
        }

    /**
     * Get AVC (Access Vector Cache) denial log from dmesg.
     * Requires root for dmesg access on most devices.
     */
    suspend fun getAvcDenials(): NativeResult<List<AvcDenialData>> =
        safeNativeCall("getAvcDenials") {
            nativeGetAvcDenials()
        }

    /**
     * Detect cgroup state (v1/v2, cpuset, scheduling group).
     * Inspired by SKRoot's cgroup migration utilities.
     */
    suspend fun detectCgroups(): NativeResult<CgroupData> =
        safeNativeCall("detectCgroups") {
            nativeDetectCgroups()
        }

    /**
     * Detect Magisk environment
     */
    suspend fun detectMagisk(): NativeResult<MagiskData> = safeNativeCall("detectMagisk") {
        nativeDetectMagisk()
    }

    /**
     * Get BusyBox info from specified path
     */
    suspend fun getBusyboxInfo(path: String): NativeResult<BusyboxData> =
        safeNativeCall("getBusyboxInfo") {
            nativeGetBusyboxInfo(path)
        }

    /**
     * Create backup snapshot
     */
    suspend fun createSnapshot(targetPath: String, snapshotName: String): NativeResult<SnapshotData> =
        safeNativeCall("createSnapshot") {
            nativeCreateSnapshot(targetPath, snapshotName)
        }

    /**
     * Restore from snapshot
     */
    suspend fun restoreSnapshot(snapshotPath: String, targetPath: String): NativeResult<RestoreData> =
        safeNativeCall("restoreSnapshot") {
            nativeRestoreSnapshot(snapshotPath, targetPath)
        }

    // =============================================================================
    // Diagnostics Functions
    // =============================================================================

    /**
     * Run symlink diagnostics - checks for broken and missing symlinks
     */
    suspend fun runSymlinkDiagnosticsCheck(): NativeResult<DiagnosticCheckData> =
        safeNativeCall("runSymlinkDiagnostics") {
            Timber.d("Running symlink diagnostics...")
            val result = nativeRunSymlinkDiagnostics()
            Timber.d("Symlink diagnostics result: $result")
            result
        }

    /**
     * Run PATH diagnostics - checks PATH integrity
     */
    suspend fun runPathDiagnosticsCheck(): NativeResult<DiagnosticCheckData> =
        safeNativeCall("runPathDiagnostics") {
            Timber.d("Running PATH diagnostics...")
            val result = nativeRunPathDiagnostics()
            Timber.d("PATH diagnostics result: $result")
            result
        }

    /**
     * Run SELinux diagnostics - checks SELinux status and conflicts
     */
    suspend fun runSelinuxDiagnosticsCheck(): NativeResult<DiagnosticCheckData> =
        safeNativeCall("runSelinuxDiagnostics") {
            Timber.d("Running SELinux diagnostics...")
            val result = nativeRunSelinuxDiagnostics()
            Timber.d("SELinux diagnostics result: $result")
            result
        }

    /**
     * Run Magisk diagnostics - checks Magisk environment and conflicts
     */
    suspend fun runMagiskDiagnosticsCheck(): NativeResult<DiagnosticCheckData> =
        safeNativeCall("runMagiskDiagnostics") {
            Timber.d("Running Magisk diagnostics...")
            val result = nativeRunMagiskDiagnostics()
            Timber.d("Magisk diagnostics result: $result")
            result
        }

    /**
     * Run BusyBox diagnostics - checks BusyBox version
     */
    suspend fun runBusyBoxDiagnosticsCheck(): NativeResult<DiagnosticCheckData> =
        safeNativeCall("runBusyBoxDiagnostics") {
            Timber.d("Running BusyBox diagnostics...")
            val result = nativeRunObsidianBoxDiagnostics()
            Timber.d("BusyBox diagnostics result: $result")
            result
        }

    /**
     * Run full diagnostics - all checks combined
     */
    suspend fun runFullDiagnosticsCheck(): NativeResult<FullDiagnosticReportData> =
        safeNativeCall("runFullDiagnostics") {
            Timber.d("Running full diagnostics...")
            val result = nativeRunFullDiagnostics()
            Timber.d("Full diagnostics result: $result")
            result
        }

    // =============================================================================
    // Terminal PTY Functions
    // =============================================================================

    /**
     * Create a new terminal session
     * 
     * @param shell Path to shell executable (empty for default)
     * @param rows Initial terminal rows
     * @param cols Initial terminal columns
     * @param useRoot Whether to attempt root shell
     * @return Terminal session info or error
     */
    suspend fun terminalCreate(
        shell: String = "",
        rows: Int = 24,
        cols: Int = 80,
        useRoot: Boolean = true
    ): NativeResult<TerminalCreateData> = withContext(Dispatchers.IO) {
        try {
            if (!isNativeLibraryLoaded) {
                Timber.w("Native library not loaded, cannot create terminal")
                return@withContext NativeResult.Error("Native library not available. Terminal requires native support.")
            }

            Timber.d("Creating terminal session: shell=$shell, rows=$rows, cols=$cols, useRoot=$useRoot")
            val jsonResult = nativeTerminalCreate(shell, rows, cols, useRoot)
            Timber.d("Terminal create result: $jsonResult")
            
            val data = json.decodeFromString<TerminalCreateData>(jsonResult)
            if (data.success && data.session != null) {
                NativeResult.Success(data)
            } else {
                NativeResult.Error(data.error ?: "Failed to create terminal")
            }
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Terminal native function not implemented in library")
            NativeResult.Error("Terminal feature not available: native function missing")
        } catch (e: Exception) {
            Timber.e(e, "terminalCreate failed")
            NativeResult.Error(e.message ?: "Terminal creation failed")
        }
    }

    /**
     * Write data to terminal
     * 
     * @param fd Master PTY file descriptor
     * @param data UTF-8 data to write
     * @return Write result
     */
    suspend fun terminalWrite(fd: Int, data: String): NativeResult<TerminalWriteData> = 
        withContext(Dispatchers.IO) {
            try {
                if (!isNativeLibraryLoaded) {
                    return@withContext NativeResult.Error("Native library not available")
                }
                val jsonResult = nativeTerminalWrite(fd, data)
                val result = json.decodeFromString<TerminalWriteData>(jsonResult)
                if (result.success) {
                    NativeResult.Success(result)
                } else {
                    NativeResult.Error(result.error ?: "Write failed")
                }
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Terminal write native function not implemented")
                NativeResult.Error("Terminal write not available: native function missing")
            } catch (e: Exception) {
                Timber.e(e, "terminalWrite failed")
                NativeResult.Error(e.message ?: "Write failed")
            }
        }

    /**
     * Read data from terminal (non-blocking)
     * 
     * @param fd Master PTY file descriptor
     * @param timeoutMs Timeout in milliseconds (0 for no wait)
     * @return Read result with data
     */
    suspend fun terminalRead(fd: Int, timeoutMs: Int = 100): NativeResult<TerminalReadData> = 
        withContext(Dispatchers.IO) {
            try {
                if (!isNativeLibraryLoaded) {
                    return@withContext NativeResult.Error("Native library not available")
                }
                val jsonResult = nativeTerminalRead(fd, timeoutMs)
                val result = json.decodeFromString<TerminalReadData>(jsonResult)
                
                // bytesProcessed == -2 means session closed
                if (result.bytesProcessed == -2) {
                    NativeResult.Error("Session closed")
                } else if (result.success) {
                    NativeResult.Success(result)
                } else {
                    NativeResult.Error(result.error ?: "Read failed")
                }
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Terminal read native function not implemented")
                NativeResult.Error("Terminal read not available: native function missing")
            } catch (e: Exception) {
                Timber.e(e, "terminalRead failed")
                NativeResult.Error(e.message ?: "Read failed")
            }
        }

    /**
     * Resize terminal window
     * 
     * @param fd Master PTY file descriptor
     * @param rows New row count
     * @param cols New column count
     * @return Operation result
     */
    suspend fun terminalResize(fd: Int, rows: Int, cols: Int): NativeResult<TerminalOperationData> = 
        withContext(Dispatchers.IO) {
            try {
                if (!isNativeLibraryLoaded) {
                    return@withContext NativeResult.Error("Native library not available")
                }
                Timber.d("Resizing terminal: fd=$fd, rows=$rows, cols=$cols")
                val jsonResult = nativeTerminalResize(fd, rows, cols)
                val result = json.decodeFromString<TerminalOperationData>(jsonResult)
                if (result.success) {
                    NativeResult.Success(result)
                } else {
                    NativeResult.Error(result.error ?: "Resize failed")
                }
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Terminal resize native function not implemented")
                NativeResult.Error("Terminal resize not available: native function missing")
            } catch (e: Exception) {
                Timber.e(e, "terminalResize failed")
                NativeResult.Error(e.message ?: "Resize failed")
            }
        }

    /**
     * Close terminal session
     * 
     * @param fd Master PTY file descriptor
     * @return Operation result
     */
    suspend fun terminalClose(fd: Int): NativeResult<TerminalOperationData> = 
        withContext(Dispatchers.IO) {
            try {
                if (!isNativeLibraryLoaded) {
                    return@withContext NativeResult.Error("Native library not available")
                }
                Timber.d("Closing terminal: fd=$fd")
                val jsonResult = nativeTerminalClose(fd)
                val result = json.decodeFromString<TerminalOperationData>(jsonResult)
                if (result.success) {
                    NativeResult.Success(result)
                } else {
                    NativeResult.Error(result.error ?: "Close failed")
                }
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Terminal close native function not implemented")
                NativeResult.Error("Terminal close not available: native function missing")
            } catch (e: Exception) {
                Timber.e(e, "terminalClose failed")
                NativeResult.Error(e.message ?: "Close failed")
            }
        }

    /**
     * Get terminal session info
     *
     * @param fd Master PTY file descriptor
     * @return Session info
     */
    suspend fun terminalGetInfo(fd: Int): NativeResult<TerminalCreateData> =
        withContext(Dispatchers.IO) {
            try {
                if (!isNativeLibraryLoaded) {
                    return@withContext NativeResult.Error("Native library not available")
                }
                val jsonResult = nativeTerminalGetInfo(fd)
                val result = json.decodeFromString<TerminalCreateData>(jsonResult)
                if (result.success) {
                    NativeResult.Success(result)
                } else {
                    NativeResult.Error(result.error ?: "Session not found")
                }
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Terminal getInfo native function not implemented")
                NativeResult.Error("Terminal getInfo not available: native function missing")
            } catch (e: Exception) {
                Timber.e(e, "terminalGetInfo failed")
                NativeResult.Error(e.message ?: "Get info failed")
            }
        }

    // =========================================================================
    // Magisk Functions
    // =========================================================================

    /**
     * Detect Magisk environment with extended info
     * Returns comprehensive Magisk information including version, overlayfs, zygisk status
     */
    suspend fun detectMagiskInfo(): NativeResult<MagiskInfoData> = withContext(Dispatchers.IO) {
        try {
            val jsonResult = nativeDetectMagisk()
            Timber.d("Magisk detect result: $jsonResult")
            
            // Parse the nested structure
            val jsonElement = json.parseToJsonElement(jsonResult)
            val dataElement = jsonElement.jsonObject["data"]
            
            if (dataElement != null) {
                val data = json.decodeFromJsonElement<MagiskInfoData>(dataElement)
                NativeResult.Success(data)
            } else {
                // Try direct parse
                val data = json.decodeFromString<MagiskInfoData>(jsonResult)
                NativeResult.Success(data)
            }
        } catch (e: Exception) {
            Timber.e(e, "detectMagisk failed")
            NativeResult.Error(e.message ?: "Magisk detection failed")
        }
    }

    /**
     * List all Magisk modules with metadata
     * Returns module list with conflict flags for BusyBox
     */
    suspend fun listMagiskModules(): NativeResult<MagiskModuleListData> = withContext(Dispatchers.IO) {
        try {
            val jsonResult = nativeListMagiskModules()
            Timber.d("Magisk modules result: $jsonResult")
            
            // Parse the nested structure
            val jsonElement = json.parseToJsonElement(jsonResult)
            val dataElement = jsonElement.jsonObject["data"]
            
            if (dataElement != null) {
                val data = json.decodeFromJsonElement<MagiskModuleListData>(dataElement)
                NativeResult.Success(data)
            } else {
                val data = json.decodeFromString<MagiskModuleListData>(jsonResult)
                NativeResult.Success(data)
            }
        } catch (e: Exception) {
            Timber.e(e, "listMagiskModules failed")
            NativeResult.Error(e.message ?: "Failed to list modules")
        }
    }

    /**
     * Detect conflicts between Magisk modules and BusyBox
     * Returns conflict analysis with severity and suggestions
     */
    suspend fun detectMagiskConflicts(): NativeResult<MagiskConflictResultData> = withContext(Dispatchers.IO) {
        try {
            val jsonResult = nativeDetectMagiskConflicts()
            Timber.d("Magisk conflicts result: $jsonResult")
            
            // Parse the nested structure
            val jsonElement = json.parseToJsonElement(jsonResult)
            val dataElement = jsonElement.jsonObject["data"]
            
            if (dataElement != null) {
                val data = json.decodeFromJsonElement<MagiskConflictResultData>(dataElement)
                NativeResult.Success(data)
            } else {
                val data = json.decodeFromString<MagiskConflictResultData>(jsonResult)
                NativeResult.Success(data)
            }
        } catch (e: Exception) {
            Timber.e(e, "detectMagiskConflicts failed")
            NativeResult.Error(e.message ?: "Failed to detect conflicts")
        }
    }

    private inline fun <reified T> parseNativeResult(jsonString: String): NativeResult<T> {
        return try {
            val wrapper = json.decodeFromString<NativeResultWrapper<T>>(jsonString)
            if (wrapper.success) {
                NativeResult.Success(wrapper.data!!)
            } else {
                NativeResult.Error(wrapper.error ?: "Unknown error")
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse native result: $jsonString")
            NativeResult.Error("Parse error: ${e.message}")
        }
    }

    /**
     * Create a terminal session with BusyBox binary validation.
     */
    suspend fun createTerminalSession(shell: String, rows: Int, cols: Int, useRoot: Boolean): NativeResult<TerminalCreateData> =
        withContext(Dispatchers.IO) {
            try {
                val busyboxPath = "/data/user/0/com.obsidianbox.app.debug/files/busybox"

                // Validate BusyBox binary before creating terminal
                val busyboxFile = File(busyboxPath)
                if (!busyboxFile.exists() || !busyboxFile.canExecute()) {
                    Timber.e("BusyBox binary is missing or not executable at: $busyboxPath")
                    return@withContext NativeResult.Error("BusyBox binary is not ready for terminal session")
                }

                terminalCreate(shell, rows, cols, useRoot)
            } catch (e: Exception) {
                Timber.e(e, "createTerminalSession failed")
                NativeResult.Error(e.message ?: "Terminal session creation failed")
            }
        }
}

// Result wrapper types
sealed class NativeResult<out T> {
    data class Success<T>(val data: T) : NativeResult<T>()
    data class Error(val message: String) : NativeResult<Nothing>()

    fun getOrNull(): T? = (this as? Success)?.data
    fun errorOrNull(): String? = (this as? Error)?.message
}

@kotlinx.serialization.Serializable
data class NativeResultWrapper<T>(
    val success: Boolean,
    val data: T? = null,
    val error: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)

// Data classes for native responses
@kotlinx.serialization.Serializable
data class PartitionData(
    val path: String,
    val mountPoint: String,
    val filesystem: String,
    val writable: Boolean,
    val availableBytes: Long,
    val recommended: Boolean
)

@kotlinx.serialization.Serializable
data class InstallData(
    val installedPath: String,
    val size: Long,
    val permissions: String
)

@kotlinx.serialization.Serializable
data class SymlinkData(
    val created: Int,
    val removed: Int,
    val failed: List<String>
)

@kotlinx.serialization.Serializable
data class PermissionData(
    val path: String,
    val mode: String,
    val filesModified: Int
)

@kotlinx.serialization.Serializable
data class SelinuxData(
    val mode: String = "unknown",
    val context: String? = null,
    val enforcing: Boolean = false
)

@kotlinx.serialization.Serializable
data class SelinuxExtendedData(
    val mode: String = "unknown",
    val enforcing: Boolean = false,
    @kotlinx.serialization.SerialName("current_context")
    val currentContext: String? = null,
    @kotlinx.serialization.SerialName("exec_context")
    val execContext: String? = null,
    @kotlinx.serialization.SerialName("prev_context")
    val prevContext: String? = null,
    @kotlinx.serialization.SerialName("selinuxfs_mounted")
    val selinuxfsMounted: Boolean = false,
    @kotlinx.serialization.SerialName("policy_info")
    val policyInfo: SelinuxPolicyInfoData? = null,
    @kotlinx.serialization.SerialName("avc_stats")
    val avcStats: AvcCacheStatsData? = null,
    @kotlinx.serialization.SerialName("capability_info")
    val capabilityInfo: CapabilityInfoData? = null
)

@kotlinx.serialization.Serializable
data class SelinuxPolicyInfoData(
    @kotlinx.serialization.SerialName("policy_loaded")
    val policyLoaded: Boolean = false,
    @kotlinx.serialization.SerialName("policy_size_bytes")
    val policySizeBytes: Long? = null,
    @kotlinx.serialization.SerialName("object_class_count")
    val objectClassCount: Int? = null,
    val checkreqprot: Boolean? = null,
    @kotlinx.serialization.SerialName("deny_unknown")
    val denyUnknown: Boolean? = null
)

@kotlinx.serialization.Serializable
data class AvcCacheStatsData(
    val lookups: Long = 0,
    val hits: Long = 0,
    val misses: Long = 0,
    val allocations: Long = 0,
    val reclaims: Long = 0,
    val frees: Long = 0
)

@kotlinx.serialization.Serializable
data class AvcDenialData(
    val raw: String = "",
    val scontext: String? = null,
    val tcontext: String? = null,
    val tclass: String? = null,
    val permission: String? = null
)

@kotlinx.serialization.Serializable
data class CapabilityInfoData(
    @kotlinx.serialization.SerialName("cap_eff")
    val capEff: String = "",
    @kotlinx.serialization.SerialName("cap_prm")
    val capPrm: String = "",
    @kotlinx.serialization.SerialName("cap_inh")
    val capInh: String = "",
    @kotlinx.serialization.SerialName("cap_bnd")
    val capBnd: String = "",
    @kotlinx.serialization.SerialName("cap_amb")
    val capAmb: String = "",
    @kotlinx.serialization.SerialName("has_full_caps")
    val hasFullCaps: Boolean = false
)

@kotlinx.serialization.Serializable
data class CgroupData(
    @kotlinx.serialization.SerialName("v2_active")
    val v2Active: Boolean = false,
    @kotlinx.serialization.SerialName("v1_active")
    val v1Active: Boolean = false,
    val memberships: List<CgroupMembershipData> = emptyList(),
    val cpuset: CpusetInfoData? = null,
    @kotlinx.serialization.SerialName("scheduling_group")
    val schedulingGroup: String? = null,
    val frozen: Boolean = false
)

@kotlinx.serialization.Serializable
data class CgroupMembershipData(
    @kotlinx.serialization.SerialName("hierarchy_id")
    val hierarchyId: Int = 0,
    val controllers: String = "",
    val path: String = ""
)

@kotlinx.serialization.Serializable
data class CpusetInfoData(
    val cpus: String = "",
    val mems: String = "",
    @kotlinx.serialization.SerialName("cgroup_path")
    val cgroupPath: String = ""
)

@kotlinx.serialization.Serializable
data class MagiskData(
    val installed: Boolean = false,
    val version: String? = null,
    val versionCode: Int? = null,
    val path: String? = null,
    val suPath: String? = null,
    val modulesPath: String? = null,
    val overlayfs: Boolean = false,
    val zygiskEnabled: Boolean = false,
    val denylistEnabled: Boolean = false,
    val superuserStatus: String = "unknown",
    val notes: List<String> = emptyList()
)

@kotlinx.serialization.Serializable
data class BusyboxData(
    val version: String,
    val path: String,
    val applets: List<String>,
    val symlinks: Int,
    val brokenSymlinks: List<String>
)

@kotlinx.serialization.Serializable
data class SnapshotData(
    val id: String,
    val path: String,
    val timestamp: Long,
    val size: Long
)

@kotlinx.serialization.Serializable
data class RestoreData(
    val restored: Boolean,
    val filesRestored: Int,
    val errors: List<String>
)

@kotlinx.serialization.Serializable
data class TestData(
    val status: String,
    val message: String,
    val timestamp: Long = 0
)

// New installer data classes

@kotlinx.serialization.Serializable
data class DetectBusyBoxData(
    val found: Boolean,
    val info: ExtendedBusyBoxData? = null,
    val searchedPaths: List<String> = emptyList()
)

@kotlinx.serialization.Serializable
data class ExtendedBusyBoxData(
    val version: String,
    val path: String,
    val applets: List<String> = emptyList(),
    val symlinks: Int = 0,
    val brokenSymlinks: List<String> = emptyList(),
    val fileSize: Long = 0,
    val permissions: String = "",
    val isExecutable: Boolean = false
)

@kotlinx.serialization.Serializable
data class UninstallBusyBoxData(
    val uninstalled: Boolean,
    val binaryRemoved: Boolean,
    val symlinksRemoved: Int,
    val errors: List<String> = emptyList()
)

@kotlinx.serialization.Serializable
data class InstallBusyBoxData(
    val installed: Boolean,
    val installedPath: String,
    val size: Long = 0,
    val permissions: String = "755",
    val symlinkCount: Int = 0,
    val warnings: List<String> = emptyList(),
    val snapshotId: String? = null
)

// Diagnostics data classes

@kotlinx.serialization.Serializable
data class DiagnosticIssueData(
    val id: String,
    val severity: String,
    val title: String,
    val description: String,
    val affectedPath: String? = null,
    val canAutoFix: Boolean = false,
    val fixCommand: String? = null
)

@kotlinx.serialization.Serializable
data class DiagnosticCheckData(
    val type: String,
    val status: String,
    val summary: String,
    val issues: List<DiagnosticIssueData> = emptyList(),
    val details: kotlinx.serialization.json.JsonObject? = null
)

@kotlinx.serialization.Serializable
data class DiagnosticSummaryData(
    val totalChecks: Int,
    val passed: Int,
    val warnings: Int,
    val errors: Int,
    val critical: Int
)

@kotlinx.serialization.Serializable
data class FullDiagnosticReportData(
    val status: String,
    val timestamp: Long,
    val checks: List<DiagnosticCheckData>,
    val summary: DiagnosticSummaryData
)

// Terminal PTY data classes

@kotlinx.serialization.Serializable
data class TerminalSessionData(
    val fd: Int,
    val pid: Int,
    val rows: Int = 24,
    val cols: Int = 80,
    val alive: Boolean = true,
    val createdAt: Long = 0
)

@kotlinx.serialization.Serializable
data class TerminalCreateData(
    val success: Boolean,
    val session: TerminalSessionData? = null,
    val error: String? = null
)

@kotlinx.serialization.Serializable
data class TerminalReadData(
    val success: Boolean,
    val data: String? = null,
    val bytesProcessed: Int = 0,
    val error: String? = null
)

@kotlinx.serialization.Serializable
data class TerminalWriteData(
    val success: Boolean,
    val bytesProcessed: Int = 0,
    val error: String? = null
)

@kotlinx.serialization.Serializable
data class TerminalOperationData(
    val success: Boolean,
    val error: String? = null
)

// Magisk data classes

@kotlinx.serialization.Serializable
data class MagiskInfoData(
    val installed: Boolean,
    val version: String? = null,
    val versionCode: Int? = null,
    val path: String? = null,
    val suPath: String? = null,
    val modulesPath: String? = null,
    val overlayfs: Boolean = false,
    val zygiskEnabled: Boolean = false,
    val denylistEnabled: Boolean = false,
    val superuserStatus: String = "unknown",
    val notes: List<String> = emptyList()
)

@kotlinx.serialization.Serializable
data class MagiskModuleData(
    val id: String,
    val name: String,
    val version: String,
    val versionCode: Int = 0,
    val author: String = "",
    val description: String = "",
    val path: String,
    val enabled: Boolean,
    val remove: Boolean = false,
    val update: Boolean = false,
    val affectsBusyBox: Boolean = false,
    val affectsPath: Boolean = false
)

@kotlinx.serialization.Serializable
data class MagiskModuleListData(
    val success: Boolean,
    val moduleCount: Int = 0,
    val modules: List<MagiskModuleData> = emptyList(),
    val busyboxModules: List<String> = emptyList(),
    val warnings: List<String> = emptyList()
)

@kotlinx.serialization.Serializable
data class MagiskConflictData(
    val type: String,
    val severity: String,
    val moduleId: String? = null,
    val moduleName: String? = null,
    val path: String? = null,
    val description: String,
    val suggestion: String
)

@kotlinx.serialization.Serializable
data class MagiskConflictResultData(
    val success: Boolean,
    val severity: String = "ok",
    val conflictCount: Int = 0,
    val conflicts: List<MagiskConflictData> = emptyList(),
    val summary: String = "",
    val warnings: List<String> = emptyList()
)
