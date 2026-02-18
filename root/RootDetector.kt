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
 * Interface for detecting root capabilities on the device.
 *
 * Implementations should:
 * - Handle timeouts gracefully (root prompts may take time)
 * - Never crash if root is unavailable
 * - Cache results when appropriate
 *
 * Usage:
 * ```kotlin
 * val detector: RootDetector = RootDetectorImpl()
 * val status = detector.detectRootStatus()
 * if (status.rootGranted) {
 *     // Safe to execute root commands
 * }
 * ```
 */
interface RootDetector {

    /**
     * Performs a full root detection check.
     *
     * This may trigger a root permission prompt from Magisk/SuperSU,
     * so it should only be called when the user expects it (e.g., during
     * onboarding, installer setup, or explicit user action).
     *
     * @return [RootStatus] containing detection results
     */
    suspend fun detectRootStatus(): RootStatus

    /**
     * Performs a quick, non-intrusive check for su binary presence.
     *
     * This does NOT trigger a root prompt. It only checks if the su
     * binary exists in common locations.
     *
     * Useful for UI hints and pre-checks before offering root features.
     *
     * @return true if su binary is found
     */
    suspend fun quickCheckSuPresent(): Boolean

    /**
     * Returns the last cached [RootStatus], or [RootStatus.UNKNOWN] if
     * no detection has been performed yet.
     *
     * @param maxAgeMs Maximum age in milliseconds. If cached status is
     *                 older, returns [RootStatus.UNKNOWN].
     * @return Cached status or unknown
     */
    fun getCachedStatus(maxAgeMs: Long = DEFAULT_CACHE_AGE_MS): RootStatus

    /**
     * Returns cached status if fresh, otherwise performs a full detection.
     * Safe to call from repositories that need root status without worrying
     * about cache staleness.
     */
    suspend fun getOrRefreshStatus(maxAgeMs: Long = DEFAULT_CACHE_AGE_MS): RootStatus

    /**
     * Clears the cached status, forcing a fresh detection on next call.
     */
    fun clearCache()

    companion object {
        /**
         * Default cache duration: 60 minutes.
         * Root status only changes after a reboot (Magisk install/uninstall).
         */
        const val DEFAULT_CACHE_AGE_MS: Long = 60 * 60 * 1000L

        /**
         * Timeout for root commands (e.g., waiting for user to grant permission).
         */
        const val ROOT_COMMAND_TIMEOUT_MS: Long = 10_000L

        /**
         * Common locations where su binary may be found.
         */
        val SU_BINARY_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/su/bin/su",
            "/magisk/.core/bin/su"
        )

        /**
         * Common locations where Magisk binary may be found.
         */
        val MAGISK_BINARY_PATHS = listOf(
            "/sbin/magisk",
            "/system/bin/magisk",
            "/system/xbin/magisk",
            "/data/adb/magisk/magisk32",
            "/data/adb/magisk/magisk64"
        )

        /**
         * Common locations where KernelSU daemon may be found.
         */
        val KERNELSU_PATHS = listOf(
            "/data/adb/ksud",
            "/data/adb/ksu/"
        )

        /**
         * Common locations where APatch daemon may be found.
         */
        val APATCH_PATHS = listOf(
            "/data/adb/ap/",
            "/data/adb/apd"
        )
    }
}
