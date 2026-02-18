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

package com.obsidianbox.diagnostics

import android.app.ActivityManager
import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.StatFs
import android.os.Environment
import android.net.TrafficStats
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import java.io.RandomAccessFile
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.roundToInt

/**
 * System Information Data Models
 */
data class CpuInfo(
    val usagePercent: Float,
    val coreCount: Int,
    val currentFrequency: Long, // kHz
    val maxFrequency: Long // kHz
)

data class MemoryInfo(
    val totalRam: Long, // bytes
    val availableRam: Long, // bytes
    val usedRam: Long, // bytes
    val usagePercent: Float
)

data class StorageInfo(
    val totalSpace: Long, // bytes
    val freeSpace: Long, // bytes
    val usedSpace: Long, // bytes
    val usagePercent: Float
)

data class BatteryInfo(
    val level: Int, // percent
    val isCharging: Boolean,
    val temperature: Float, // celsius
    val health: String,
    val voltage: Int // millivolts
)

data class NetworkInfo(
    val bytesReceived: Long,
    val bytesSent: Long,
    val packetsReceived: Long,
    val packetsSent: Long
)

data class ProcessInfo(
    val name: String,
    val pid: Int,
    val memory: Long // bytes
)

data class SystemInfo(
    val cpu: CpuInfo,
    val memory: MemoryInfo,
    val storage: StorageInfo,
    val battery: BatteryInfo,
    val network: NetworkInfo,
    val timestamp: Long = System.currentTimeMillis()
)

/**
 * System Information Provider
 * Collects CPU, RAM, Storage, Battery, and Network stats
 * Works without root permissions
 */
@Singleton
class SystemInfoProvider @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val TAG = "SystemInfoProvider"
    }

    private val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    private val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager

    // Track previous CPU stats for calculating usage
    private var previousTotal: Long = 0
    private var previousIdle: Long = 0

    /**
     * Get complete system information
     */
    suspend fun getSystemInfo(): SystemInfo = withContext(Dispatchers.IO) {
        SystemInfo(
            cpu = getCpuInfo(),
            memory = getMemoryInfo(),
            storage = getStorageInfo(),
            battery = getBatteryInfo(),
            network = getNetworkInfo()
        )
    }

    /**
     * Get CPU usage information
     * Reads from /proc/stat (works without root)
     */
    suspend fun getCpuInfo(): CpuInfo = withContext(Dispatchers.IO) {
        try {
            val coreCount = Runtime.getRuntime().availableProcessors()
            val usage = calculateCpuUsage()
            val maxFreq = readCpuMaxFrequency()
            val currentFreq = readCpuCurrentFrequency()

            CpuInfo(
                usagePercent = usage,
                coreCount = coreCount,
                currentFrequency = currentFreq,
                maxFrequency = maxFreq
            )
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get CPU info")
            CpuInfo(0f, Runtime.getRuntime().availableProcessors(), 0, 0)
        }
    }

    /**
     * Calculate CPU usage percentage from /proc/stat
     */
    private fun calculateCpuUsage(): Float {
        return try {
            val stats = File("/proc/stat").readText().split("\n")[0].split("\\s+".toRegex())
            val user = stats[1].toLong()
            val nice = stats[2].toLong()
            val system = stats[3].toLong()
            val idle = stats[4].toLong()
            val iowait = stats[5].toLong()
            val irq = stats[6].toLong()
            val softirq = stats[7].toLong()

            val total = user + nice + system + idle + iowait + irq + softirq

            val diffTotal = total - previousTotal
            val diffIdle = idle - previousIdle

            previousTotal = total
            previousIdle = idle

            if (diffTotal == 0L) {
                0f
            } else {
                ((diffTotal - diffIdle).toFloat() / diffTotal.toFloat() * 100).coerceIn(0f, 100f)
            }
        } catch (e: Exception) {
            Timber.d("$TAG: CPU usage read skipped: ${e.message}")
            0f
        }
    }

    /**
     * Read CPU max frequency
     */
    private fun readCpuMaxFrequency(): Long {
        return try {
            File("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").readText().trim().toLong()
        } catch (e: Exception) {
            0L
        }
    }

    /**
     * Read CPU current frequency
     */
    private fun readCpuCurrentFrequency(): Long {
        return try {
            File("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").readText().trim().toLong()
        } catch (e: Exception) {
            0L
        }
    }

    /**
     * Get memory information using ActivityManager
     */
    suspend fun getMemoryInfo(): MemoryInfo = withContext(Dispatchers.IO) {
        try {
            val memInfo = ActivityManager.MemoryInfo()
            activityManager.getMemoryInfo(memInfo)

            val totalRam = memInfo.totalMem
            val availableRam = memInfo.availMem
            val usedRam = totalRam - availableRam
            val usagePercent = (usedRam.toFloat() / totalRam.toFloat() * 100).coerceIn(0f, 100f)

            MemoryInfo(
                totalRam = totalRam,
                availableRam = availableRam,
                usedRam = usedRam,
                usagePercent = usagePercent
            )
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get memory info")
            MemoryInfo(0, 0, 0, 0f)
        }
    }

    /**
     * Get storage information using StatFs
     */
    suspend fun getStorageInfo(): StorageInfo = withContext(Dispatchers.IO) {
        try {
            val path = Environment.getDataDirectory()
            val stat = StatFs(path.path)
            val blockSize = stat.blockSizeLong
            val totalBlocks = stat.blockCountLong
            val availableBlocks = stat.availableBlocksLong

            val totalSpace = totalBlocks * blockSize
            val freeSpace = availableBlocks * blockSize
            val usedSpace = totalSpace - freeSpace
            val usagePercent = (usedSpace.toFloat() / totalSpace.toFloat() * 100).coerceIn(0f, 100f)

            StorageInfo(
                totalSpace = totalSpace,
                freeSpace = freeSpace,
                usedSpace = usedSpace,
                usagePercent = usagePercent
            )
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get storage info")
            StorageInfo(0, 0, 0, 0f)
        }
    }

    /**
     * Get battery information using BatteryManager
     */
    suspend fun getBatteryInfo(): BatteryInfo = withContext(Dispatchers.IO) {
        try {
            val level = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            val status = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_STATUS)
            val isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                             status == BatteryManager.BATTERY_STATUS_FULL

            // Temperature and voltage require different approach
            val temperature = 0f // Requires BroadcastReceiver for ACTION_BATTERY_CHANGED
            val voltage = 0
            val health = "Unknown"

            BatteryInfo(
                level = level,
                isCharging = isCharging,
                temperature = temperature,
                health = health,
                voltage = voltage
            )
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get battery info")
            BatteryInfo(0, false, 0f, "Unknown", 0)
        }
    }

    /**
     * Get network statistics using TrafficStats
     */
    suspend fun getNetworkInfo(): NetworkInfo = withContext(Dispatchers.IO) {
        try {
            NetworkInfo(
                bytesReceived = TrafficStats.getTotalRxBytes(),
                bytesSent = TrafficStats.getTotalTxBytes(),
                packetsReceived = TrafficStats.getTotalRxPackets(),
                packetsSent = TrafficStats.getTotalTxPackets()
            )
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get network info")
            NetworkInfo(0, 0, 0, 0)
        }
    }

    /**
     * Get list of running processes (limited info without root)
     */
    suspend fun getRunningProcesses(): List<ProcessInfo> = withContext(Dispatchers.IO) {
        try {
            activityManager.runningAppProcesses?.map { process ->
                val memInfo = ActivityManager.MemoryInfo()
                activityManager.getMemoryInfo(memInfo)
                
                ProcessInfo(
                    name = process.processName,
                    pid = process.pid,
                    memory = 0 // Cannot get per-process memory without root
                )
            } ?: emptyList()
        } catch (e: Exception) {
            Timber.e(e, "$TAG: Failed to get running processes")
            emptyList()
        }
    }

    /**
     * Convert battery health code to string
     */
    private fun getHealthString(health: Int): String {
        return when (health) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "Good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "Overheat"
            BatteryManager.BATTERY_HEALTH_DEAD -> "Dead"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "Over Voltage"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "Unspecified Failure"
            BatteryManager.BATTERY_HEALTH_COLD -> "Cold"
            else -> "Unknown"
        }
    }

    /**
     * Format bytes to human-readable string
     */
    fun formatBytes(bytes: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var unitIndex = 0

        while (value >= 1024 && unitIndex < units.size - 1) {
            value /= 1024
            unitIndex++
        }

        return "%.2f %s".format(value, units[unitIndex])
    }

    /**
     * Format frequency to human-readable string
     */
    fun formatFrequency(khz: Long): String {
        return when {
            khz >= 1000000 -> "%.2f GHz".format(khz / 1000000.0)
            khz >= 1000 -> "%.2f MHz".format(khz / 1000.0)
            else -> "$khz kHz"
        }
    }
}
