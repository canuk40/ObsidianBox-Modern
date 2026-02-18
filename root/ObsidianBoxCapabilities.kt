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
 * Root requirement levels for ObsidianBox commands/applets.
 */
enum class CommandRequirement {
    /**
     * Command is safe to run without root.
     * Examples: ls, cat, echo, grep, sed, awk
     */
    SAFE,

    /**
     * Command works better with root but can function without.
     * Examples: ps (limited output), netstat (limited info)
     */
    ROOT_RECOMMENDED,

    /**
     * Command requires root to function properly.
     * Examples: mount, iptables, chmod on system files
     */
    ROOT_REQUIRED
}

/**
 * Represents a ObsidianBox applet's root requirement information.
 */
data class AppletCapability(
    val name: String,
    val requirement: CommandRequirement,
    val category: AppletCategory = AppletCategory.GENERAL,
    val notes: String? = null
)

/**
 * Categories for ObsidianBox applets.
 */
enum class AppletCategory {
    FILESYSTEM,
    NETWORK,
    PROCESS,
    SYSTEM,
    TEXT,
    ARCHIVE,
    SHELL,
    GENERAL
}

/**
 * Comprehensive map of ObsidianBox applet capabilities and root requirements.
 *
 * Based on:
 * - ObsidianBox BB_SUID_REQUIRE flags
 * - Common Android root usage patterns
 * - Typical permission requirements
 *
 * Statistics (auto-calculated):
 * - Total applets mapped: see [totalCount]
 * - Root required: see [rootRequiredCount]
 * - Root recommended: see [rootRecommendedCount]
 * - Safe (no root): see [safeCount]
 */
object ObsidianBoxCapabilities {

    /**
     * Map of command name to its root requirement.
     */
    val commandRequirements: Map<String, CommandRequirement> by lazy {
        appletCapabilities.associate { it.name to it.requirement }
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /** Total number of mapped applets */
    val totalCount: Int by lazy { appletCapabilities.size }

    /** Number of applets requiring root */
    val rootRequiredCount: Int by lazy {
        appletCapabilities.count { it.requirement == CommandRequirement.ROOT_REQUIRED }
    }

    /** Number of applets that work better with root */
    val rootRecommendedCount: Int by lazy {
        appletCapabilities.count { it.requirement == CommandRequirement.ROOT_RECOMMENDED }
    }

    /** Number of applets safe to run without root */
    val safeCount: Int by lazy {
        appletCapabilities.count { it.requirement == CommandRequirement.SAFE }
    }

    /** Count of applets per category */
    val countByCategory: Map<AppletCategory, Int> by lazy {
        appletCapabilities.groupingBy { it.category }.eachCount()
    }

    // ========================================================================
    // Query Functions
    // ========================================================================

    /**
     * Get requirement for a command (defaults to SAFE if unknown).
     */
    fun getRequirement(command: String): CommandRequirement {
        return commandRequirements[command.lowercase()] ?: CommandRequirement.SAFE
    }

    /**
     * Get full capability info for an applet.
     */
    fun getCapability(command: String): AppletCapability? {
        return appletCapabilities.find { it.name == command.lowercase() }
    }

    /**
     * Get all applets that require root.
     */
    fun getRootRequiredApplets(): List<AppletCapability> {
        return appletCapabilities.filter { it.requirement == CommandRequirement.ROOT_REQUIRED }
    }

    /**
     * Get all applets that recommend root.
     */
    fun getRootRecommendedApplets(): List<AppletCapability> {
        return appletCapabilities.filter { it.requirement == CommandRequirement.ROOT_RECOMMENDED }
    }

    /**
     * Get all safe applets (no root needed).
     */
    fun getSafeApplets(): List<AppletCapability> {
        return appletCapabilities.filter { it.requirement == CommandRequirement.SAFE }
    }

    /**
     * Get all applets by category.
     */
    fun getAppletsByCategory(category: AppletCategory): List<AppletCapability> {
        return appletCapabilities.filter { it.category == category }
    }

    /**
     * Check if a command is known in our capability map.
     */
    fun isKnownCommand(command: String): Boolean {
        return commandRequirements.containsKey(command.lowercase())
    }

    /**
     * Get all applet names as a set (for quick lookup).
     */
    val allAppletNames: Set<String> by lazy {
        appletCapabilities.map { it.name }.toSet()
    }

    /**
     * Get a summary string of capabilities.
     */
    fun getSummary(): String {
        return buildString {
            appendLine("ObsidianBox Applet Capabilities Summary")
            appendLine("====================================")
            appendLine("Total applets mapped: $totalCount")
            appendLine("- ROOT_REQUIRED: $rootRequiredCount")
            appendLine("- ROOT_RECOMMENDED: $rootRecommendedCount")
            appendLine("- SAFE: $safeCount")
            appendLine()
            appendLine("By Category:")
            countByCategory.forEach { (category, count) ->
                appendLine("- $category: $count")
            }
        }
    }

    /**
     * Full list of ObsidianBox applet capabilities.
     */
    val appletCapabilities: List<AppletCapability> = listOf(
        // ============================================================
        // STRICT ROOT REQUIRED (BB_SUID_REQUIRE in ObsidianBox source)
        // ============================================================
        AppletCapability("crontab", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),
        AppletCapability("login", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),
        AppletCapability("passwd", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),
        AppletCapability("su", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),
        AppletCapability("vlock", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),
        AppletCapability("wall", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "BB_SUID_REQUIRE"),

        // ============================================================
        // FILESYSTEM & DEVICE COMMANDS - ROOT REQUIRED
        // ============================================================
        AppletCapability("mount", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Mounting filesystems requires root"),
        AppletCapability("umount", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Unmounting filesystems requires root"),
        AppletCapability("fsck", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Filesystem check requires root"),
        AppletCapability("mkfs", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Creating filesystems requires root"),
        AppletCapability("mkfs.ext2", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),
        AppletCapability("mkfs.vfat", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),
        AppletCapability("losetup", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Loop device setup requires root"),
        AppletCapability("mknod", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Creating device nodes requires root"),
        AppletCapability("fdisk", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Partition editing requires root"),
        AppletCapability("swapon", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Enabling swap requires root"),
        AppletCapability("swapoff", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Disabling swap requires root"),
        AppletCapability("mkswap", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Creating swap requires root"),
        AppletCapability("blkid", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Reading block device info requires root"),
        AppletCapability("blockdev", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),
        AppletCapability("hdparm", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),
        AppletCapability("findfs", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),
        AppletCapability("fstrim", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM),

        // ============================================================
        // NETWORK COMMANDS - ROOT REQUIRED
        // ============================================================
        AppletCapability("ifconfig", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "Network interface config requires root"),
        AppletCapability("route", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "Routing table requires root"),
        AppletCapability("iptables", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "Firewall rules require root"),
        AppletCapability("ip", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "IP configuration requires root"),
        AppletCapability("ipaddr", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("iplink", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("iproute", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("iprule", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("iptunnel", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("ipneigh", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("udhcpc", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "DHCP client requires root"),
        AppletCapability("udhcpd", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "DHCP server requires root"),
        AppletCapability("brctl", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK, "Bridge control requires root"),
        AppletCapability("tunctl", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("vconfig", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("arp", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.NETWORK, "Viewing ARP table works without root, modification requires root"),
        AppletCapability("arping", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),
        AppletCapability("nameif", CommandRequirement.ROOT_REQUIRED, AppletCategory.NETWORK),

        // ============================================================
        // SYSTEM/PROCESS COMMANDS - ROOT REQUIRED
        // ============================================================
        AppletCapability("init", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("telinit", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("halt", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "System halt requires root"),
        AppletCapability("poweroff", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Power off requires root"),
        AppletCapability("reboot", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Reboot requires root"),
        AppletCapability("shutdown", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Shutdown or reboot the system (BusyBox)"),
        AppletCapability("killall5", CommandRequirement.ROOT_REQUIRED, AppletCategory.PROCESS),
        AppletCapability("crond", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Cron daemon requires root"),
        AppletCapability("syslogd", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("klogd", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("dmesg", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.SYSTEM, "Works without root on older Android, blocked on Android 13+"),
        AppletCapability("insmod", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Loading kernel modules requires root"),
        AppletCapability("rmmod", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Removing kernel modules requires root"),
        AppletCapability("modprobe", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("lsmod", CommandRequirement.SAFE, AppletCategory.SYSTEM, "Viewing loaded modules works without root"),
        AppletCapability("modinfo", CommandRequirement.SAFE, AppletCategory.SYSTEM, "Viewing module information works without root"),
        AppletCapability("depmod", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("pivot_root", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("switch_root", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("chroot", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Changing root requires root"),
        AppletCapability("sysctl", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.SYSTEM, "Reading kernel parameters works without root, writing requires root"),
        AppletCapability("setconsole", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("setkeycodes", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("loadkmap", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("hwclock", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Hardware clock access requires root"),

        // ============================================================
        // PERMISSIONS/OWNERSHIP - ROOT REQUIRED (on system files)
        // ============================================================
        AppletCapability("chmod", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.FILESYSTEM, "May require root for system files"),
        AppletCapability("chown", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Changing ownership requires root"),
        AppletCapability("chgrp", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.FILESYSTEM, "Works without root if you own the file and are in target group"),
        AppletCapability("chattr", CommandRequirement.ROOT_REQUIRED, AppletCategory.FILESYSTEM, "Changing file attributes requires root"),

        // ============================================================
        // USER MANAGEMENT - ROOT REQUIRED
        // ============================================================
        AppletCapability("adduser", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "User management requires root"),
        AppletCapability("deluser", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("addgroup", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("delgroup", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM),
        AppletCapability("useradd", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Create a new user account"),
        AppletCapability("usermod", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Modify a user account"),
        AppletCapability("chage", CommandRequirement.ROOT_REQUIRED, AppletCategory.SYSTEM, "Change user password expiry information"),
        AppletCapability("newgrp", CommandRequirement.SAFE, AppletCategory.SYSTEM, "Change current group ID during login session"),

        // ============================================================
        // ROOT RECOMMENDED (work better with root)
        // ============================================================
        AppletCapability("ps", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS, "Shows more processes with root"),
        AppletCapability("top", CommandRequirement.SAFE, AppletCategory.PROCESS, "Works fully without root on Android"),
        AppletCapability("netstat", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.NETWORK, "Shows more info with root"),
        AppletCapability("lsof", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS, "Shows more open files with root"),
        AppletCapability("fuser", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS),
        AppletCapability("kill", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS, "May need root for other users' processes"),
        AppletCapability("killall", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS),
        AppletCapability("pkill", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS),
        AppletCapability("nice", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS, "Negative nice values require root"),
        AppletCapability("renice", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS),
        AppletCapability("ionice", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS),
        AppletCapability("chrt", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.PROCESS, "Realtime scheduling requires root"),
        AppletCapability("dd", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.FILESYSTEM, "May need root for raw devices"),
        AppletCapability("ln", CommandRequirement.ROOT_RECOMMENDED, AppletCategory.FILESYSTEM, "Symlinks to system dirs need root"),
        AppletCapability("ping", CommandRequirement.SAFE, AppletCategory.NETWORK, "Modern Android (8+) allows ICMP without root"),
        AppletCapability("ping6", CommandRequirement.SAFE, AppletCategory.NETWORK, "Modern Android (8+) allows ICMP without root"),
        AppletCapability("traceroute", CommandRequirement.SAFE, AppletCategory.NETWORK, "Modern Android (8+) allows traceroute without root"),
        AppletCapability("traceroute6", CommandRequirement.SAFE, AppletCategory.NETWORK, "Modern Android (8+) allows traceroute without root"),
        AppletCapability("nslookup", CommandRequirement.SAFE, AppletCategory.NETWORK),

        // ============================================================
        // SAFE COMMANDS - No root required
        // ============================================================
        // Text processing
        AppletCapability("cat", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("echo", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("printf", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("grep", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("egrep", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("fgrep", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("sed", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("awk", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("cut", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("head", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("tail", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("sort", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("uniq", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("wc", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("tr", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("tee", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("rev", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("tac", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("paste", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("join", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("comm", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("diff", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("patch", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("expand", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("unexpand", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("fold", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("fmt", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("nl", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("od", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("hexdump", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("xxd", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("strings", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("cmp", CommandRequirement.SAFE, AppletCategory.TEXT, "Compare two files byte-by-byte"),

        // File operations (on accessible paths)
        AppletCapability("ls", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("cp", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("mv", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("rm", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("mkdir", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("rmdir", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("touch", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("stat", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("file", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("find", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("xargs", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("dirname", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("basename", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("readlink", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("realpath", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("pwd", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("du", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("df", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("sync", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("tree", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),
        AppletCapability("install", CommandRequirement.SAFE, AppletCategory.FILESYSTEM),

        // Archive/compression
        AppletCapability("tar", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("gzip", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("gunzip", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("zcat", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("bzip2", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("bunzip2", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("bzcat", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("xz", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("unxz", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("xzcat", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("lzma", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("unlzma", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("lzcat", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("unzip", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("cpio", CommandRequirement.SAFE, AppletCategory.ARCHIVE),
        AppletCapability("ar", CommandRequirement.SAFE, AppletCategory.ARCHIVE),

        // Shell utilities
        AppletCapability("sh", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("ash", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("bash", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("cd", CommandRequirement.SAFE, AppletCategory.SHELL, "Shell built-in for changing directory"),
        AppletCapability("alias", CommandRequirement.SAFE, AppletCategory.SHELL, "Shell built-in for creating command shortcuts"),
        AppletCapability("history", CommandRequirement.SAFE, AppletCategory.SHELL, "Shell built-in for viewing command history"),
        AppletCapability("test", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("[", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("[[", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("true", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("false", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("yes", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("sleep", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("usleep", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("env", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("printenv", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("export", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("set", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("unset", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("expr", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("seq", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("which", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("whoami", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("id", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("groups", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("logname", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("nohup", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("timeout", CommandRequirement.SAFE, AppletCategory.SHELL),
        AppletCapability("time", CommandRequirement.SAFE, AppletCategory.SHELL),

        // Date/time
        AppletCapability("date", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("cal", CommandRequirement.SAFE, AppletCategory.GENERAL),

        // Network (non-privileged)
        AppletCapability("wget", CommandRequirement.SAFE, AppletCategory.NETWORK),
        AppletCapability("nc", CommandRequirement.SAFE, AppletCategory.NETWORK, "Safe for non-privileged ports"),
        AppletCapability("telnet", CommandRequirement.SAFE, AppletCategory.NETWORK),
        AppletCapability("ftpget", CommandRequirement.SAFE, AppletCategory.NETWORK),
        AppletCapability("ftpput", CommandRequirement.SAFE, AppletCategory.NETWORK),
        AppletCapability("tftp", CommandRequirement.SAFE, AppletCategory.NETWORK),
        AppletCapability("hostname", CommandRequirement.SAFE, AppletCategory.NETWORK),

        // Editors/viewers
        AppletCapability("vi", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("less", CommandRequirement.SAFE, AppletCategory.TEXT),
        AppletCapability("more", CommandRequirement.SAFE, AppletCategory.TEXT),

        // Misc utilities
        AppletCapability("uname", CommandRequirement.SAFE, AppletCategory.SYSTEM),
        AppletCapability("uptime", CommandRequirement.SAFE, AppletCategory.SYSTEM),
        AppletCapability("free", CommandRequirement.SAFE, AppletCategory.SYSTEM),
        AppletCapability("clear", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("reset", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("watch", CommandRequirement.SAFE, AppletCategory.GENERAL, "Execute a program periodically"),
        AppletCapability("whereis", CommandRequirement.SAFE, AppletCategory.GENERAL, "Locate binary, source, and manual pages"),
        AppletCapability("whatis", CommandRequirement.SAFE, AppletCategory.GENERAL, "Display one-line command description"),
        AppletCapability("md5sum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("sha1sum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("sha256sum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("sha512sum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("cksum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("sum", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("base64", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("uuencode", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("uudecode", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("dc", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("bc", CommandRequirement.SAFE, AppletCategory.GENERAL),
        AppletCapability("factor", CommandRequirement.SAFE, AppletCategory.GENERAL),
    )
}
