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

package com.obsidianbox.core.root

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import timber.log.Timber
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Implementation of [RootDetector] using shell commands.
 *
 * Detection strategy:
 * 1. Check if su binary exists in known locations
 * 2. Attempt to execute `su -c id` to verify root is granted
 * 3. Check for Magisk binary presence
 * 4. Read SELinux status from /sys/fs/selinux/enforce
 *
 * All operations are performed on IO dispatcher with appropriate timeouts.
 */
@Singleton
class RootDetectorImpl @Inject constructor() : RootDetector {

    private val cachedStatus = AtomicReference<RootStatus>(RootStatus.UNKNOWN)

    override suspend fun detectRootStatus(): RootStatus = withContext(Dispatchers.IO) {
        Timber.d("Starting root detection...")

        try {
            val suAvailable = checkSuBinaryExists()
            Timber.d("su binary available: $suAvailable")

            val rootGranted = if (suAvailable) {
                checkRootAccess()
            } else {
                false
            }
            Timber.d("Root granted: $rootGranted")

            val magiskDetected = checkMagiskPresent()
            Timber.d("Magisk detected: $magiskDetected")

            val kernelSuDetected = checkKernelSuPresent()
            Timber.d("KernelSU detected: $kernelSuDetected")

            val aPatchDetected = checkAPatchPresent()
            Timber.d("APatch detected: $aPatchDetected")

            val selinuxMode = getSelinuxMode(rootGranted)
            Timber.d("SELinux mode: $selinuxMode")

            // Zygisk & DenyList only meaningful when Magisk is detected and root is granted
            val zygiskEnabled = if (magiskDetected && rootGranted) checkZygiskEnabled() else false
            Timber.d("Zygisk enabled: $zygiskEnabled")

            val denyListEnabled = if (magiskDetected && rootGranted) checkDenyListEnabled() else false
            Timber.d("DenyList enabled: $denyListEnabled")

            val ramdiskDetected = checkRamdiskPresent()
            Timber.d("Ramdisk detected: $ramdiskDetected")

            // Hidden root detection (kernel-patched root like SKRoot)
            val hiddenRootDetected = checkHiddenRootPresent(rootGranted)
            Timber.d("Hidden root detected: $hiddenRootDetected")

            // SELinux integrity check
            val selinuxIntegrityCompromised = checkSelinuxIntegrity(selinuxMode, rootGranted)
            Timber.d("SELinux integrity compromised: $selinuxIntegrityCompromised")

            val status = RootStatus(
                suAvailable = suAvailable,
                rootGranted = rootGranted,
                magiskDetected = magiskDetected,
                kernelSuDetected = kernelSuDetected,
                aPatchDetected = aPatchDetected,
                zygiskEnabled = zygiskEnabled,
                denyListEnabled = denyListEnabled,
                ramdiskDetected = ramdiskDetected,
                selinuxMode = selinuxMode,
                hiddenRootDetected = hiddenRootDetected,
                selinuxIntegrityCompromised = selinuxIntegrityCompromised
            )

            cachedStatus.set(status)
            Timber.i("Root detection complete: ${status.summary}")

            status
        } catch (e: Exception) {
            Timber.e(e, "Root detection failed")
            RootStatus.NOT_ROOTED
        }
    }

    override suspend fun quickCheckSuPresent(): Boolean = withContext(Dispatchers.IO) {
        checkSuBinaryExists()
    }

    override fun getCachedStatus(maxAgeMs: Long): RootStatus {
        val cached = cachedStatus.get()
        return if (cached.isStale(maxAgeMs)) {
            RootStatus.UNKNOWN
        } else {
            cached
        }
    }

    override suspend fun getOrRefreshStatus(maxAgeMs: Long): RootStatus {
        val cached = cachedStatus.get()
        return if (cached.isStale(maxAgeMs)) {
            Timber.d("Root cache stale, refreshing...")
            detectRootStatus()
        } else {
            cached
        }
    }

    override fun clearCache() {
        cachedStatus.set(RootStatus.UNKNOWN)
    }

    /**
     * Check if su binary exists in any of the known locations.
     */
    private fun checkSuBinaryExists(): Boolean {
        // First check common paths
        for (path in RootDetector.SU_BINARY_PATHS) {
            val file = File(path)
            if (file.exists() && file.canExecute()) {
                Timber.d("Found su at: $path")
                return true
            }
        }

        // Also try which command as fallback
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.isNotEmpty() && File(result).exists()
        } catch (e: Exception) {
            Timber.d("'which su' failed: ${e.message}")
            false
        }
    }

    /**
     * Attempt to execute a root command to verify access is granted.
     */
    private suspend fun checkRootAccess(): Boolean {
        return try {
            withTimeout(RootDetector.ROOT_COMMAND_TIMEOUT_MS) {
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val output = reader.readText()
                val exitCode = process.waitFor()
                reader.close()

                // Check if output contains uid=0 (root)
                val isRoot = output.contains("uid=0") || output.contains("root")
                Timber.d("su -c id output: $output, exitCode: $exitCode, isRoot: $isRoot")

                isRoot && exitCode == 0
            }
        } catch (e: TimeoutCancellationException) {
            Timber.w("Root access check timed out - user may have denied permission")
            false
        } catch (e: Exception) {
            Timber.d("Root access check failed: ${e.message}")
            false
        }
    }

    /**
     * Check if Magisk is present on the device.
     */
    private fun checkMagiskPresent(): Boolean {
        // Check for magisk binary
        for (path in RootDetector.MAGISK_BINARY_PATHS) {
            if (File(path).exists()) {
                Timber.d("Found Magisk at: $path")
                return true
            }
        }

        // Check for magisk manager via which
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "magisk"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if KernelSU is present on the device.
     */
    private fun checkKernelSuPresent(): Boolean {
        val ksuPaths = listOf(
            "/data/adb/ksud",
            "/data/adb/ksu/",
        )
        for (path in ksuPaths) {
            if (File(path).exists()) {
                Timber.d("Found KernelSU at: $path")
                return true
            }
        }
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "ksud"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if APatch is present on the device.
     */
    private fun checkAPatchPresent(): Boolean {
        val apPaths = listOf(
            "/data/adb/ap/",
            "/data/adb/apd",
        )
        for (path in apPaths) {
            if (File(path).exists()) {
                Timber.d("Found APatch at: $path")
                return true
            }
        }
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "apd"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Read SELinux enforcement mode.
     */
    private fun getSelinuxMode(rootAvailable: Boolean = false): String? {
        return try {
            // Method 1: Read from sysfs (fastest, but blocked by SELinux on most devices)
            val enforceFile = File("/sys/fs/selinux/enforce")
            if (enforceFile.exists() && enforceFile.canRead()) {
                val value = enforceFile.readText().trim()
                return when (value) {
                    "1" -> "Enforcing"
                    "0" -> "Permissive"
                    else -> "Unknown"
                }
            }

            // Method 2: Use getenforce command (may also be blocked by SELinux)
            try {
                val process = Runtime.getRuntime().exec("getenforce")
                val result = process.inputStream.bufferedReader().readText().trim()
                process.waitFor()

                val mode = when (result.lowercase()) {
                    "enforcing" -> "Enforcing"
                    "permissive" -> "Permissive"
                    "disabled" -> "Disabled"
                    else -> null
                }
                if (mode != null) return mode
            } catch (_: Exception) {
                Timber.d("getenforce without root failed, trying with su")
            }

            // Method 3: Use su -c getenforce (requires root)
            if (rootAvailable) {
                try {
                    val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "getenforce"))
                    val result = process.inputStream.bufferedReader().readText().trim()
                    process.waitFor()

                    val mode = when (result.lowercase()) {
                        "enforcing" -> "Enforcing"
                        "permissive" -> "Permissive"
                        "disabled" -> "Disabled"
                        else -> result.ifEmpty { null }
                    }
                    if (mode != null) return mode
                } catch (e: Exception) {
                    Timber.d("su -c getenforce failed: ${e.message}")
                }
            }
            
            // All methods failed
            return null
        } catch (e: Exception) {
            Timber.d("Failed to get SELinux mode: ${e.message}")
            null
        }
    }

    /**
     * Check if Zygisk is enabled in Magisk settings.
     * Uses Magisk's own SQLite CLI (same approach as Magisk app reads ZYGISK_ENABLED env var).
     * Falls back to checking the /data/adb/magisk/zygisk file indicator.
     */
    private fun checkZygiskEnabled(): Boolean {
        // Method 1: Environment variable (set by magiskd, may only be in Magisk's process)
        try {
            val envVal = System.getenv("ZYGISK_ENABLED")
            if (envVal == "1") return true
            if (envVal == "0") return false
        } catch (_: Exception) { }

        // Method 2: Query Magisk SQLite database via CLI (5s timeout)
        try {
            val process = Runtime.getRuntime().exec(arrayOf(
                "su", "-c",
                "magisk --sqlite \"SELECT value FROM settings WHERE key='zygisk'\""
            ))
            val completed = process.waitFor(5, TimeUnit.SECONDS)
            if (completed) {
                val result = process.inputStream.bufferedReader().readText().trim()
                if (result.contains("value=1")) return true
                if (result.contains("value=0")) return false
            } else {
                process.destroyForcibly()
                Timber.d("Zygisk SQLite query timed out")
            }
        } catch (e: Exception) {
            Timber.d("Magisk SQLite zygisk query failed: ${e.message}")
        }

        // Method 3: Check file indicator via su
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "test -d /data/adb/magisk/zygisk && echo yes || echo no"))
            val completed = process.waitFor(3, TimeUnit.SECONDS)
            if (completed) {
                val result = process.inputStream.bufferedReader().readText().trim()
                if (result == "yes") return true
            } else {
                process.destroyForcibly()
            }
        } catch (_: Exception) { }

        return false
    }

    /**
     * Check if Magisk DenyList is enabled.
     * Uses Magisk's SQLite CLI to query the settings table.
     */
    private fun checkDenyListEnabled(): Boolean {
        try {
            val process = Runtime.getRuntime().exec(arrayOf(
                "su", "-c",
                "magisk --sqlite \"SELECT value FROM settings WHERE key='denylist'\""
            ))
            val completed = process.waitFor(5, TimeUnit.SECONDS)
            if (completed) {
                val result = process.inputStream.bufferedReader().readText().trim()
                if (result.contains("value=1")) return true
                if (result.contains("value=0")) return false
            } else {
                process.destroyForcibly()
                Timber.d("DenyList SQLite query timed out")
            }
        } catch (e: Exception) {
            Timber.d("Magisk SQLite denylist query failed: ${e.message}")
        }
        return false
    }

    /**
     * Check if the device boots with a ramdisk.
     * Mirrors Magisk's app_functions.sh logic:
     * - SYSTEM_AS_ROOT: grep ' / ' /proc/mounts | grep -qv 'rootfs'
     * - RAMDISKEXIST: A/B devices always have ramdisk; legacy SAR without A/B does not
     */
    private fun checkRamdiskPresent(): Boolean? {
        return try {
            // Check SYSTEM_AS_ROOT — if root is NOT rootfs, it's system-as-root
            val mounts = File("/proc/mounts").readText()
            val rootMount = mounts.lines().firstOrNull { it.contains(" / ") }

            if (rootMount != null) {
                val systemAsRoot = !rootMount.contains("rootfs")
                val legacySar = rootMount.contains("/dev/root")

                // Check if A/B device (has slot suffix)
                val cmdline = File("/proc/cmdline").readText()
                val isAB = cmdline.contains("androidboot.slot_suffix=") ||
                        cmdline.contains("androidboot.slot=")

                // Magisk logic: A/B always has ramdisk; legacy SAR without A/B does not
                when {
                    isAB -> true
                    legacySar -> false
                    !systemAsRoot -> true  // rootfs mount = has ramdisk
                    else -> true  // Modern system-as-root with ramdisk in boot.img
                }
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.d("Ramdisk detection failed: ${e.message}")
            null
        }
    }

    /**
     * Detect hidden/kernel-patched root solutions (e.g., SKRoot).
     *
     * SKRoot hides su binaries in /data/<hash>/ directories and patches the kernel
     * directly to bypass SELinux without touching policy files. Detection signals:
     * 1. Hidden su binaries in /data/ subdirectories with hash-like names
     * 2. Process has uid=0 capabilities without known root manager
     * 3. Abnormal /proc/self/status capability values for an unprivileged app
     */
    private fun checkHiddenRootPresent(rootGranted: Boolean): Boolean {
        try {
            // Signal 1: Look for hidden su binaries in /data/<hash>/ dirs
            // SKRoot stores su in /data/<first_16_chars_of_key>/su
            val dataDir = File("/data")
            if (dataDir.exists() && dataDir.canRead()) {
                val suspiciousDirs = dataDir.listFiles()?.filter { dir ->
                    dir.isDirectory &&
                    dir.name.length >= 16 &&
                    dir.name.matches(Regex("[a-f0-9]{16,}")) &&
                    File(dir, "su").exists()
                }
                if (!suspiciousDirs.isNullOrEmpty()) {
                    Timber.w("Found hidden su in hash-named directory: ${suspiciousDirs.first().name}")
                    return true
                }
            }

            // Signal 2: Check if process has unexpected capabilities
            // An untrusted_app should have CapEff=0, if we see high caps it's suspicious
            val status = File("/proc/self/status").readText()
            val capEff = status.lines()
                .firstOrNull { it.startsWith("CapEff:") }
                ?.substringAfter(":")?.trim() ?: "0"
            val capValue = capEff.toLongOrNull(16) ?: 0L
            // More than 5 capability bits set for an app process is suspicious
            if (capValue.countOneBits() > 5 && !rootGranted) {
                Timber.w("Suspicious CapEff for app process: $capEff")
                return true
            }

            // Signal 3: Check for SKRoot flag files
            if (rootGranted) {
                try {
                    val process = Runtime.getRuntime().exec(arrayOf("su", "-c",
                        "find /data -maxdepth 2 -name 'skroot' -type f 2>/dev/null | head -1"))
                    val result = process.inputStream.bufferedReader().readText().trim()
                    process.waitFor()
                    if (result.isNotEmpty()) {
                        Timber.w("Found SKRoot flag file: $result")
                        return true
                    }
                } catch (_: Exception) { }
            }
        } catch (e: Exception) {
            Timber.d("Hidden root detection failed: ${e.message}")
        }
        return false
    }

    /**
     * Check if SELinux enforcement integrity appears compromised.
     *
     * Inspired by SKRoot's AVC patching technique: if SELinux is "Enforcing"
     * but the process has root capabilities or no AVC denials are logged for
     * operations that should be denied, the enforcement may be bypassed at
     * the kernel level.
     */
    private fun checkSelinuxIntegrity(selinuxMode: String?, rootGranted: Boolean): Boolean {
        if (selinuxMode != "Enforcing") return false

        try {
            // Check 1: Read our own SELinux context — if it's an unexpected domain
            // (e.g., "u:r:magisk:s0" or custom domain) while claiming to be enforcing
            val context = try {
                File("/proc/self/attr/current").readText().trim().trimEnd('\u0000')
            } catch (_: Exception) { null }

            // An app should be in untrusted_app or similar. If we're in shell/magisk/su domain
            // without being launched via su, something is wrong
            if (context != null && !rootGranted) {
                val suspiciousDomains = listOf("u:r:su:", "u:r:magisk:", "u:r:init:", "u:r:kernel:")
                if (suspiciousDomains.any { context.startsWith(it) }) {
                    Timber.w("App running in suspicious SELinux domain: $context")
                    return true
                }
            }

            // Check 2: CapEff should be near-zero for an app process in enforcing mode
            val status = File("/proc/self/status").readText()
            val capEff = status.lines()
                .firstOrNull { it.startsWith("CapEff:") }
                ?.substringAfter(":")?.trim() ?: "0"
            val capValue = capEff.toLongOrNull(16) ?: 0L
            // Full capabilities (30+ bits) in enforcing mode for a non-root app = integrity issue
            if (capValue.countOneBits() >= 30 && !rootGranted) {
                Timber.w("Full capabilities in Enforcing mode without root grant: CapEff=$capEff")
                return true
            }
        } catch (e: Exception) {
            Timber.d("SELinux integrity check failed: ${e.message}")
        }
        return false
    }
}
