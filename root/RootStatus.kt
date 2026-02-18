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

/**
 * Represents the current root capability status of the device.
 *
 * This is obtained via [RootDetector] and can be used by:
 * - Automation modules to check if root is available before execution
 * - Terminal validator to warn about root-required commands
 * - UI components to show appropriate indicators
 * - Installer to enable/disable system installation options
 */
data class RootStatus(
    /**
     * True if the `su` binary is found in PATH (e.g., /system/bin/su, /system/xbin/su).
     * Does NOT guarantee root access is granted.
     */
    val suAvailable: Boolean,

    /**
     * True if root commands can be executed (i.e., `su -c id` returned uid=0).
     * This indicates the user has granted root permission to this app.
     */
    val rootGranted: Boolean,

    /**
     * True if Magisk is detected (via magisk binary or Magisk manager).
     * Useful for advanced features like systemless module management.
     */
    val magiskDetected: Boolean,

    /**
     * True if KernelSU is detected (via ksud binary or /data/adb/ksu/).
     */
    val kernelSuDetected: Boolean = false,

    /**
     * True if APatch is detected (via apd binary or /data/adb/ap/).
     */
    val aPatchDetected: Boolean = false,

    /**
     * True if Zygisk is enabled in Magisk settings.
     * Detected via Magisk SQLite: settings WHERE key="zygisk" value="1"
     */
    val zygiskEnabled: Boolean = false,

    /**
     * True if Magisk DenyList is enabled.
     * Detected via Magisk SQLite: settings WHERE key="denylist" value="1"
     */
    val denyListEnabled: Boolean = false,

    /**
     * Whether the device boots with a ramdisk. null = unknown/not checked.
     * Detected via /proc/mounts (Magisk's SYSTEM_AS_ROOT / RAMDISKEXIST logic).
     */
    val ramdiskDetected: Boolean? = null,

    /**
     * SELinux mode: "Enforcing", "Permissive", "Disabled", or null if unknown.
     * Some root operations behave differently based on SELinux mode.
     */
    val selinuxMode: String? = null,

    /**
     * True if a hidden/kernel-level root solution (e.g., SKRoot) is detected.
     * These solutions patch the kernel directly and hide from standard detection.
     */
    val hiddenRootDetected: Boolean = false,

    /**
     * True if SELinux integrity appears compromised — e.g., enforcing mode
     * but process has full capabilities, or AVC denials are being suppressed.
     */
    val selinuxIntegrityCompromised: Boolean = false,

    /**
     * Human-readable summary of root status for UI display.
     */
    val summary: String = buildSummary(rootGranted, suAvailable, magiskDetected, kernelSuDetected, aPatchDetected, zygiskEnabled, hiddenRootDetected),

    /**
     * Timestamp when this status was detected (epoch millis).
     * Useful for caching and freshness checks.
     */
    val detectedAt: Long = System.currentTimeMillis()
) {
    /**
     * Check if this status is older than the given duration in milliseconds.
     */
    fun isStale(maxAgeMs: Long): Boolean {
        return System.currentTimeMillis() - detectedAt > maxAgeMs
    }

    /**
     * Returns true if root is fully available and granted for operations.
     */
    fun canExecuteRootCommands(): Boolean = rootGranted

    /**
     * Returns a status level for UI indicators.
     */
    fun getStatusLevel(): RootStatusLevel = when {
        rootGranted -> RootStatusLevel.GRANTED
        suAvailable -> RootStatusLevel.AVAILABLE_NOT_GRANTED
        else -> RootStatusLevel.NOT_AVAILABLE
    }

    companion object {
        private fun buildSummary(
            rootGranted: Boolean,
            suAvailable: Boolean,
            magiskDetected: Boolean,
            kernelSuDetected: Boolean,
            aPatchDetected: Boolean,
            zygiskEnabled: Boolean,
            hiddenRootDetected: Boolean = false
        ): String {
            val zygiskSuffix = if (zygiskEnabled) " + Zygisk" else ""
            return when {
                rootGranted && hiddenRootDetected -> "Root granted (Kernel-patched)"
                rootGranted && magiskDetected -> "Root granted (Magisk$zygiskSuffix)"
                rootGranted && kernelSuDetected -> "Root granted (KernelSU)"
                rootGranted && aPatchDetected -> "Root granted (APatch)"
                rootGranted -> "Root granted"
                hiddenRootDetected -> "Hidden root detected"
                suAvailable -> "Root available but not granted"
                else -> "Root not available"
            }
        }

        /**
         * Default unknown/unchecked status.
         */
        val UNKNOWN = RootStatus(
            suAvailable = false,
            rootGranted = false,
            magiskDetected = false,
            selinuxMode = null,
            summary = "Not checked"
        )

        /**
         * Status indicating root is definitely not available.
         */
        val NOT_ROOTED = RootStatus(
            suAvailable = false,
            rootGranted = false,
            magiskDetected = false,
            selinuxMode = null,
            summary = "Root not available"
        )
    }
}

/**
 * Status levels for root availability, used for UI indicators.
 */
enum class RootStatusLevel {
    /**
     * Root is granted and available for use.
     * UI: Green indicator.
     */
    GRANTED,

    /**
     * su binary is present but permission has not been granted.
     * UI: Yellow/amber indicator.
     */
    AVAILABLE_NOT_GRANTED,

    /**
     * No su binary found, device appears to be non-rooted.
     * UI: Red/gray indicator.
     */
    NOT_AVAILABLE
}
