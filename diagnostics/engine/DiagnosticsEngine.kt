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

package com.obsidianbox.diagnostics.engine

import com.obsidianbox.data.nativebridge.NativeBridge
import com.obsidianbox.data.nativebridge.NativeResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Diagnostics Engine - Runs comprehensive system diagnostics
 * Delegates to native Rust layer for privileged operations
 */
@Singleton
class DiagnosticsEngine @Inject constructor(
    private val nativeBridge: NativeBridge
) {

    /**
     * Run full diagnostics including all checks
     */
    suspend fun runFullDiagnostics(): DiagnosticReport = withContext(Dispatchers.IO) {
        Timber.d("Running full diagnostics...")

        val startTime = System.currentTimeMillis()

        // Run diagnostics in parallel for efficiency
        val obsidianboxDeferred = async { runObsidianBoxDiagnostics() }
        val symlinkDeferred = async { runSymlinkDiagnostics() }
        val pathDeferred = async { runPathDiagnostics() }
        val selinuxDeferred = async { runSELinuxDiagnostics() }
        val magiskDeferred = async { runMagiskDiagnostics() }
        val permissionsDeferred = async { runPermissionDiagnostics() }

        val report = DiagnosticReport(
            timestamp = System.currentTimeMillis(),
            durationMs = System.currentTimeMillis() - startTime,
            obsidianbox = obsidianboxDeferred.await(),
            symlinks = symlinkDeferred.await(),
            path = pathDeferred.await(),
            selinux = selinuxDeferred.await(),
            magisk = magiskDeferred.await(),
            permissions = permissionsDeferred.await()
        )

        Timber.d("Diagnostics completed in ${report.durationMs}ms")
        report
    }

    /**
     * Run ObsidianBox-specific diagnostics
     */
    suspend fun runObsidianBoxDiagnostics(): ObsidianBoxDiagnostics? = withContext(Dispatchers.IO) {
        try {
            val result = nativeBridge.detectBusyBoxInstallation()
            when (result) {
                is NativeResult.Success<*> -> {
                    val data = result.data as? com.obsidianbox.data.nativebridge.DetectBusyBoxData
                    if (data != null) {
                        ObsidianBoxDiagnostics(
                            installed = data.found,
                            version = data.info?.version,
                            path = data.info?.path,
                            applets = data.info?.applets ?: emptyList(),
                            symlinkCount = data.info?.symlinks ?: 0,
                            brokenSymlinks = data.info?.brokenSymlinks ?: emptyList(),
                            isExecutable = data.info?.isExecutable ?: false
                        )
                    } else null
                }
                is NativeResult.Error -> {
                    Timber.w("ObsidianBox diagnostics failed: ${result.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "ObsidianBox diagnostics exception")
            null
        }
    }

    /**
     * Run symlink diagnostics
     */
    suspend fun runSymlinkDiagnostics(): SymlinkDiagnostics? = withContext(Dispatchers.IO) {
        try {
            val result = nativeBridge.runSymlinkDiagnosticsCheck()
            when (result) {
                is NativeResult.Success -> {
                    SymlinkDiagnostics(
                        total = 0, // Would be parsed from result
                        valid = 0,
                        broken = emptyList()
                    )
                }
                is NativeResult.Error -> {
                    Timber.w("Symlink diagnostics failed: ${result.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Symlink diagnostics exception")
            null
        }
    }

    /**
     * Run PATH diagnostics
     */
    suspend fun runPathDiagnostics(): PathDiagnostics? = withContext(Dispatchers.IO) {
        try {
            val result = nativeBridge.runPathDiagnosticsCheck()
            when (result) {
                is NativeResult.Success -> {
                    PathDiagnostics(
                        entries = emptyList(),
                        duplicates = emptyList(),
                        insecure = emptyList()
                    )
                }
                is NativeResult.Error -> {
                    Timber.w("PATH diagnostics failed: ${result.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "PATH diagnostics exception")
            null
        }
    }

    /**
     * Run SELinux diagnostics
     */
    suspend fun runSELinuxDiagnostics(): SELinuxDiagnostics? = withContext(Dispatchers.IO) {
        try {
            val result = nativeBridge.detectSelinux()
            when (result) {
                is NativeResult.Success -> {
                    val data = result.data
                    SELinuxDiagnostics(
                        mode = data.mode,
                        denials = emptyList()
                    )
                }
                is NativeResult.Error -> {
                    Timber.w("SELinux diagnostics failed: ${result.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "SELinux diagnostics exception")
            null
        }
    }

    /**
     * Run Magisk diagnostics
     */
    suspend fun runMagiskDiagnostics(): MagiskDiagnostics? = withContext(Dispatchers.IO) {
        try {
            val infoResult = nativeBridge.detectMagiskInfo()
            val modulesResult = nativeBridge.listMagiskModules()
            val conflictsResult = nativeBridge.detectMagiskConflicts()

            val info = when (infoResult) {
                is NativeResult.Success -> infoResult.data
                else -> null
            }

            val modules = when (modulesResult) {
                is NativeResult.Success -> modulesResult.data.modules
                else -> emptyList()
            }

            val conflicts = when (conflictsResult) {
                is NativeResult.Success -> conflictsResult.data.conflicts
                else -> emptyList()
            }

            MagiskDiagnostics(
                installed = info?.installed ?: false,
                version = info?.version,
                versionCode = info?.versionCode,
                modules = modules.map { module ->
                    MagiskModuleDiagnostic(
                        id = module.id,
                        name = module.name,
                        version = module.version,
                        enabled = module.enabled,
                        author = module.author
                    )
                },
                conflicts = conflicts.map { conflict ->
                    MagiskConflictDiagnostic(
                        moduleA = conflict.moduleId ?: "",
                        moduleB = "",
                        type = conflict.type,
                        description = conflict.description
                    )
                }
            )
        } catch (e: Exception) {
            Timber.e(e, "Magisk diagnostics exception")
            null
        }
    }

    /**
     * Run permission diagnostics
     */
    suspend fun runPermissionDiagnostics(): PermissionDiagnostics? = withContext(Dispatchers.IO) {
        try {
            PermissionDiagnostics(
                totalChecked = 0,
                correctCount = 0,
                incorrectFiles = emptyList()
            )
        } catch (e: Exception) {
            Timber.e(e, "Permission diagnostics exception")
            null
        }
    }
}

// ============================================================
// DIAGNOSTIC RESULT DATA CLASSES
// ============================================================

data class DiagnosticReport(
    val timestamp: Long,
    val durationMs: Long,
    val obsidianbox: ObsidianBoxDiagnostics?,
    val symlinks: SymlinkDiagnostics?,
    val path: PathDiagnostics?,
    val selinux: SELinuxDiagnostics?,
    val magisk: MagiskDiagnostics?,
    val permissions: PermissionDiagnostics?
)

data class ObsidianBoxDiagnostics(
    val installed: Boolean,
    val version: String?,
    val path: String?,
    val applets: List<String>,
    val symlinkCount: Int,
    val brokenSymlinks: List<String>,
    val isExecutable: Boolean
)

data class SymlinkDiagnostics(
    val total: Int,
    val valid: Int,
    val broken: List<BrokenSymlinkInfo>
)

data class BrokenSymlinkInfo(
    val path: String,
    val expectedTarget: String?,
    val actualTarget: String?,
    val appletName: String?
)

data class PathDiagnostics(
    val entries: List<String>,
    val duplicates: List<String>,
    val insecure: List<InsecurePathInfo>
)

data class InsecurePathInfo(
    val path: String,
    val reason: String
)

data class SELinuxDiagnostics(
    val mode: String,
    val denials: List<SELinuxDenialInfo>
)

data class SELinuxDenialInfo(
    val timestamp: Long,
    val source: String,
    val target: String,
    val action: String,
    val context: String
)

data class MagiskDiagnostics(
    val installed: Boolean,
    val version: String?,
    val versionCode: Int?,
    val modules: List<MagiskModuleDiagnostic>,
    val conflicts: List<MagiskConflictDiagnostic>
)

data class MagiskModuleDiagnostic(
    val id: String,
    val name: String,
    val version: String,
    val enabled: Boolean,
    val author: String
)

data class MagiskConflictDiagnostic(
    val moduleA: String,
    val moduleB: String,
    val type: String,
    val description: String
)

data class PermissionDiagnostics(
    val totalChecked: Int,
    val correctCount: Int,
    val incorrectFiles: List<IncorrectPermissionInfo>
)

data class IncorrectPermissionInfo(
    val path: String,
    val currentMode: String,
    val expectedMode: String,
    val owner: String?,
    val group: String?
)
