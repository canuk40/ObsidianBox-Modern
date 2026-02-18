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

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Result of validating a terminal command for root requirements.
 */
data class CommandValidationResult(
    /**
     * The extracted command name (first token).
     */
    val command: String,

    /**
     * The root requirement for this command.
     */
    val requirement: CommandRequirement,

    /**
     * Whether the command can proceed based on current root status.
     */
    val canProceed: Boolean,

    /**
     * Warning message to show (if any).
     */
    val warningMessage: String? = null,

    /**
     * Detailed notes about the command's root requirements.
     */
    val notes: String? = null
)

/**
 * Validates terminal commands against root requirements.
 *
 * This validator:
 * - Extracts the command name from a full command line
 * - Looks up root requirements from ObsidianBoxCapabilities
 * - Checks against current root status
 * - Returns warnings/suggestions for root-required commands
 *
 * Usage:
 * ```kotlin
 * val validator = TerminalCommandValidator(rootDetector)
 * val result = validator.validateCommand("mount /dev/block/sda1 /mnt", rootStatus)
 * if (!result.canProceed) {
 *     showError(result.warningMessage)
 * } else if (result.warningMessage != null) {
 *     showWarning(result.warningMessage)
 * }
 * ```
 */
@Singleton
class TerminalCommandValidator @Inject constructor() {

    /**
     * Validate a command line against root requirements.
     *
     * @param commandLine The full command line to validate
     * @param rootStatus Current device root status
     * @param blockOnRootRequired If true, canProceed will be false for ROOT_REQUIRED commands without root
     * @return Validation result with warnings and proceed status
     */
    fun validateCommand(
        commandLine: String,
        rootStatus: RootStatus,
        blockOnRootRequired: Boolean = false
    ): CommandValidationResult {
        val command = extractCommand(commandLine)

        if (command.isBlank()) {
            return CommandValidationResult(
                command = "",
                requirement = CommandRequirement.SAFE,
                canProceed = true
            )
        }

        val capability = ObsidianBoxCapabilities.getCapability(command)
        val requirement = capability?.requirement ?: CommandRequirement.SAFE

        return when (requirement) {
            CommandRequirement.ROOT_REQUIRED -> {
                if (rootStatus.rootGranted) {
                    CommandValidationResult(
                        command = command,
                        requirement = requirement,
                        canProceed = true,
                        notes = capability?.notes
                    )
                } else {
                    val reason = if (!rootStatus.suAvailable) {
                        "This device does not have root access"
                    } else {
                        "Root permission not granted"
                    }
                    CommandValidationResult(
                        command = command,
                        requirement = requirement,
                        canProceed = !blockOnRootRequired,
                        warningMessage = "⚠️ '$command' requires root. $reason.",
                        notes = capability?.notes
                    )
                }
            }

            CommandRequirement.ROOT_RECOMMENDED -> {
                if (rootStatus.rootGranted) {
                    CommandValidationResult(
                        command = command,
                        requirement = requirement,
                        canProceed = true,
                        notes = capability?.notes
                    )
                } else {
                    CommandValidationResult(
                        command = command,
                        requirement = requirement,
                        canProceed = true,
                        warningMessage = "ℹ️ '$command' works better with root. Output may be limited.",
                        notes = capability?.notes
                    )
                }
            }

            CommandRequirement.SAFE -> {
                CommandValidationResult(
                    command = command,
                    requirement = requirement,
                    canProceed = true,
                    notes = capability?.notes
                )
            }
        }
    }

    /**
     * Quick check if a command requires root.
     */
    fun requiresRoot(commandLine: String): Boolean {
        val command = extractCommand(commandLine)
        return ObsidianBoxCapabilities.getRequirement(command) == CommandRequirement.ROOT_REQUIRED
    }

    /**
     * Quick check if a command recommends root.
     */
    fun recommendsRoot(commandLine: String): Boolean {
        val command = extractCommand(commandLine)
        val req = ObsidianBoxCapabilities.getRequirement(command)
        return req == CommandRequirement.ROOT_REQUIRED || req == CommandRequirement.ROOT_RECOMMENDED
    }

    /**
     * Get root requirement for a command.
     */
    fun getRequirement(commandLine: String): CommandRequirement {
        val command = extractCommand(commandLine)
        return ObsidianBoxCapabilities.getRequirement(command)
    }

    /**
     * Extract the command name from a command line.
     * Handles:
     * - Simple commands: "ls -la" -> "ls"
     * - Path prefixes: "/system/bin/ls -la" -> "ls"
     * - Environment variables: "VAR=value command arg" -> "command"
     * - sudo/su prefixes: "su -c 'mount ...'" -> "mount"
     */
    fun extractCommand(commandLine: String): String {
        val trimmed = commandLine.trim()
        if (trimmed.isBlank()) return ""

        // Split by whitespace
        val tokens = trimmed.split(Regex("\\s+"))
        if (tokens.isEmpty()) return ""

        var index = 0

        // Skip environment variable assignments (VAR=value)
        while (index < tokens.size && tokens[index].contains('=') && !tokens[index].startsWith('-')) {
            index++
        }

        if (index >= tokens.size) return ""

        var firstToken = tokens[index]

        // Handle su -c 'command' or sudo command
        if (firstToken == "su" && tokens.size > index + 2 && tokens[index + 1] == "-c") {
            // Extract command from su -c 'command args' or su -c "command args"
            val restOfCommand = tokens.drop(index + 2).joinToString(" ")
            val unquoted = restOfCommand.trim().removeSurrounding("'").removeSurrounding("\"")
            return extractCommand(unquoted)
        }

        if (firstToken == "sudo" && tokens.size > index + 1) {
            return extractCommand(tokens.drop(index + 1).joinToString(" "))
        }

        // Handle obsidianbox applet invocation: "obsidianbox ls" -> "ls"
        if (firstToken.endsWith("obsidianbox") || firstToken == "obsidianbox") {
            if (tokens.size > index + 1) {
                firstToken = tokens[index + 1]
            } else {
                return "obsidianbox"
            }
        }

        // Extract basename from path
        val command = firstToken.substringAfterLast('/')

        return command.lowercase()
    }

    companion object {
        /**
         * Common root-required command patterns for quick checking.
         */
        val ROOT_REQUIRED_PATTERNS = setOf(
            "mount", "umount", "fsck", "mkfs", "losetup", "mknod",
            "ifconfig", "route", "iptables", "ip",
            "insmod", "rmmod", "modprobe",
            "halt", "poweroff", "reboot",
            "chown", "chgrp", "chroot",
            "su", "passwd", "login"
        )
    }
}
