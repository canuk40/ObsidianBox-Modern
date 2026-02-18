# ObsidianBox Open-Core — Safety & Diagnostic Layer

**Version**: 1.0  
**License**: Apache 2.0  
**Purpose**: Transparency for root detection, shell sanitization, and native operations

---

## ⚠️ Important: This is NOT the Full Application

This repository contains **ONLY the safety and diagnostic layer** of ObsidianBox Modern.

**What's Included** (Open-Core):
- ✅ Root detection logic (Magisk, KernelSU, APatch)
- ✅ Shell command sanitization and validation
- ✅ Native PTY/SELinux operations (Rust/C++)
- ✅ System diagnostics (read-only information gathering)
- ✅ JNI bridge layer

**What's NOT Included** (Proprietary):
- ❌ User interface (UI/UX)
- ❌ Feature implementations (terminal, file manager, backup, etc.)
- ❌ System modification logic (build.prop editor, hosts editor, etc.)
- ❌ Automation framework
- ❌ AI agent system
- ❌ Plugin marketplace
- ❌ Monetization and billing
- ❌ Analytics

**The full application** is available on Google Play Store:  
[ObsidianBox Modern](https://play.google.com/store/apps/details?id=com.busyboxmodern.app)

---

## Why Open-Core?

**Transparency Where It Matters**:  
The root community deserves to know that root detection, shell execution, and native operations are safe and transparent. This repository provides that transparency.

**Protection Where It Matters**:  
Product features, UI/UX, and business logic remain proprietary to sustain development and ensure long-term viability.

---

## Repository Structure

```
publication/
├── root/                       # Root detection
│   ├── RootDetector.kt         # Root detection interface
│   ├── RootDetectorImpl.kt     # Magisk/KernelSU/APatch detection
│   ├── RootStatus.kt           # Root status data model
│   ├── ObsidianBoxCapabilities.kt  # Capability checking
│   └── TerminalCommandValidator.kt # Command safety validation
│
├── shell/                      # Shell sanitization & safety
│   ├── ShellSanitizer.kt       # Input validation, escaping
│   └── RootShell.kt            # Shell execution safety utilities
│
├── diagnostics/                # System diagnostics (read-only)
│   ├── SystemInfoProvider.kt  # Hardware/kernel info reading
│   └── engine/
│       └── DiagnosticsEngine.kt  # Diagnostic orchestration
│
└── native/                     # Native layer (Rust/C++/JNI)
    ├── rust/                   # Rust native code
    │   ├── lib.rs              # JNI exports
    │   ├── terminal.rs         # PTY implementation
    │   ├── selinux.rs          # SELinux operations
    │   ├── diagnostics.rs      # Native diagnostics
    │   ├── snapshot.rs         # Snapshot engine
    │   ├── magisk.rs           # Magisk integration
    │   ├── cgroup.rs           # Cgroup detection
    │   ├── partition.rs        # Partition operations
    │   ├── symlink.rs          # Symlink repair
    │   ├── obsidianbox.rs      # ObsidianBox integration
    │   ├── safety.rs           # Safety utilities
    │   ├── result.rs           # Result types
    │   ├── permission.rs       # Permission checking
    │   └── Cargo.toml          # Rust dependencies
    │
    ├── cpp/                    # C++ JNI bridge
    │   ├── obsidianbox_bridge.cpp  # JNI wrappers
    │   ├── terminal_pty.cpp    # PTY JNI operations
    │   └── CMakeLists.txt      # CMake build config
    │
    └── jni/                    # Kotlin JNI interface
        └── NativeBridge.kt     # JNI function declarations
```

---

## What Each Component Does

### 1. Root Detection (`root/`)

**Purpose**: Transparently detect root access and validate su binaries

**Key Files**:
- `RootDetector.kt` — Interface for root detection
- `RootDetectorImpl.kt` — Implementation (Magisk, KernelSU, APatch detection)
- `RootStatus.kt` — Root status data (granted, denied, method detected)
- `TerminalCommandValidator.kt` — Validates commands before execution

**Why Open-Core**: Shows the community that root detection is honest and doesn't hide anything.

---

### 2. Shell Sanitization (`shell/`)

**Purpose**: Prevent shell injection attacks, validate input

**Key Files**:
- `ShellSanitizer.kt` — Input validation, escaping, injection prevention
- `RootShell.kt` — Shell safety utilities

**Why Open-Core**: Security transparency — shows shell inputs are properly sanitized.

---

### 3. Diagnostics (`diagnostics/`)

**Purpose**: Read system information (CPU, RAM, storage, kernel, etc.)

**Key Files**:
- `SystemInfoProvider.kt` — Hardware/kernel info reading
- `DiagnosticsEngine.kt` — Diagnostic orchestration

**Why Open-Core**: Shows diagnostics are read-only (no backdoors or hidden data collection).

**Note**: This does NOT include modification logic (e.g., editing build.prop, modifying sysctl).

---

### 4. Native Pipeline (`native/`)

**Purpose**: Low-level PTY, SELinux, snapshot, and diagnostic operations

**Rust Code** (`native/rust/`):
- `terminal.rs` — PTY (pseudo-terminal) implementation
- `selinux.rs` — SELinux mode reading, context operations
- `diagnostics.rs` — Native system diagnostics
- `snapshot.rs` — Snapshot creation engine
- `magisk.rs` — Magisk module operations
- `cgroup.rs` — Cgroup detection
- `partition.rs` — Partition info reading
- `symlink.rs` — Symlink repair
- `safety.rs` — Safety utilities

**C++ Bridge** (`native/cpp/`):
- `obsidianbox_bridge.cpp` — JNI wrappers to Rust
- `terminal_pty.cpp` — PTY JNI operations

**Kotlin JNI Interface** (`native/jni/`):
- `NativeBridge.kt` — JNI function declarations

**Why Open-Core**: Shows native operations are transparent and safe.

---

## Building the Native Layer

**Prerequisites**:
- Rust 1.70+
- Android NDK r25c+
- CMake 3.22+

**Build Rust Library**:
```bash
cd native/rust
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target x86_64-linux-android --release
cargo build --target i686-linux-android --release
```

**Build C++ JNI Bridge**:
```bash
cd native/cpp
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-24 \
      .
make
```

**Note**: The full application has a complete build system. This is for reference only.

---

## Using These Components

**Important**: These files are **NOT a standalone application**. They are extracted components for transparency.

**If you want to use ObsidianBox**:
- Download the full app from Google Play Store
- Supports both Free and Pro versions
- Full terminal, file manager, automation, diagnostics, and more

**If you want to audit the code**:
- Review these files to understand root detection
- Verify shell sanitization is proper
- Inspect native operations for safety
- Contribute security improvements

---

## Contributing

**What You Can Contribute**:
- ✅ Security improvements to shell sanitization
- ✅ Bug fixes in root detection
- ✅ Performance improvements to native code
- ✅ Additional safety checks

**What You Cannot Contribute**:
- ❌ New features (those are in the proprietary app)
- ❌ UI changes (proprietary)
- ❌ Functionality changes (proprietary)

**How to Contribute**:
1. Fork this repository
2. Make your changes
3. Submit a pull request with:
   - Clear description of security improvement
   - Test cases
   - Explanation of why it's safer

---

## Security

**Reporting Security Issues**:  
If you find a security vulnerability in the open-core layer, please email:  
**security@obsidianbox.app**

**Do NOT open public issues for security vulnerabilities.**

---

## License

This open-core layer is licensed under **Apache 2.0**.

The full ObsidianBox Modern application contains proprietary code not included in this repository.

```
Copyright 2026 ObsidianBox Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## FAQ

**Q: Can I build a full app from this?**  
A: No. This is only the safety/diagnostic layer. The UI, features, and functionality are proprietary.

**Q: Why not open-source everything?**  
A: To sustain development and ensure long-term viability. The safety layer is open for trust; features remain proprietary for revenue.

**Q: Can I use this code in my app?**  
A: Yes, under Apache 2.0 terms. Attribution required.

**Q: Where's the UI?**  
A: Proprietary. Download the full app from Google Play Store.

**Q: Can I fork and add features?**  
A: You can fork the open-core layer, but features require the proprietary components.

**Q: Is this the full source code?**  
A: No. This is ~10% of the codebase (safety layer). 90% is proprietary.

---

## Full Application

**Download**: [Google Play Store](https://play.google.com/store/apps/details?id=com.busyboxmodern.app)

**Features** (in the full app):
- Advanced terminal with PTY support
- Root file manager
- Build.prop editor
- Hosts file editor
- Magisk module manager
- Kernel parameter tuner
- App debloater
- SELinux manager
- Automation framework
- AI diagnostic agent
- Plugin marketplace
- And much more...

---

**Thank you for trusting ObsidianBox!**
