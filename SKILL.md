# HexScan — Project Skill File

> **Read this first** before working on any HexScan code.
> This file explains the architecture, conventions, and how to navigate the codebase.

---

## What is HexScan?

HexScan (formerly CheatTurbine) is a **Linux memory scanner and editor** similar to Cheat Engine.
It can attach to a running process, scan/edit memory, set watchpoints, disassemble code, and patch instructions.

**Platform:** Linux only (uses `/proc/pid/mem`, `ptrace`, `process_vm_readv`)
**Language:** C++26, compiled with Clang
**GUI:** ImGui + Vulkan + GLFW
**Build:** CMake + vcpkg

---

## Repository Structure

```
CheatTurbine/
├── src/
│   ├── main.cpp                    # GUI entry point
│   ├── cli_main.cpp                # Headless CLI entry point
│   ├── backend/                    # Core logic (no GUI dependency ideally)
│   │   ├── virtualMemory/          # Read/Write process memory
│   │   ├── scanner/                # Memory scanning engine
│   │   ├── regions/                # /proc/pid/maps parser
│   │   ├── selectedProcess/        # Process attach/detach + observer pattern
│   │   ├── debugger/               # Hardware breakpoints + access tracker
│   │   ├── disassembler/           # Zydis-based x86-64 disassembler
│   │   ├── patch/                  # NOP patch + conditional jump inversion
│   │   ├── pointerMap/             # Reverse pointer lookup table
│   │   ├── pointerScan/            # Find pointer paths to target address
│   │   ├── pointerChain/           # Resolve multi-level pointer chains
│   │   ├── CTvalue/                # Value type system (i8..f64, string, AOB)
│   │   ├── starredAddress/         # Saved/bookmarked addresses with freeze
│   │   └── settings/               # Global settings
│   ├── gui/                        # ImGui windows
│   │   ├── gui.cpp                 # Main GUI loop + window management
│   │   ├── impl/                   # Vulkan + ImGui backend impl
│   │   ├── widgets/                # Shared ImGui widgets
│   │   └── windows/                # One subdirectory per window
│   └── config/                     # Build-time config (version, etc.)
├── examples/
│   ├── dummy_target.cpp            # Comprehensive test target ("fake game")
│   └── TEST_SPEC.md               # Detailed test specification
├── tests/
│   ├── scanner_tests.cpp           # Unit tests (GTest)
│   └── integration_test.sh         # End-to-end test script
├── external/                       # Git submodules
├── vcpkg/                          # Package manager
└── CMakeLists.txt                  # Build configuration
```

---

## Build Commands

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)

# Release build
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j$(nproc)

# Build specific target
cmake --build build --target DummyTarget
cmake --build build --target HexScanCLI
cmake --build build --target HexScan

# Run tests
cmake --build build --target ScannerTests
./build/ScannerTests
bash tests/integration_test.sh build
```

**Dependencies** (via vcpkg): imgui, Vulkan, glfw3, Fontconfig, Zydis (disassembler)

---

## Key Architecture Patterns

### 1. Memory I/O — `VirtualMemory` namespace
- `read()` → `/proc/pid/mem` with `pread()`, fallback `process_vm_readv()`
- `write()` → `/proc/pid/mem` with `pwrite()`, fallback `process_vm_writev()`
- `writeCode()` → `PTRACE_POKETEXT` for read-only code segments
- If `AccessTracker` is attached (ptrace active), writes go through tracker thread

### 2. Process Selection — `SelectedProcess` namespace
- Global `pid_t pid` shared by all modules
- Observer pattern: `subscribeToAttach()` / `subscribeToDetach()`
- Modules register callbacks to react to process changes

### 3. Scanning — `Scanner` class
- Template-based comparators: `getCommonComparator<T>()` for each numeric type
- Scans run in detached `std::thread`
- Progress tracked via `std::atomic` counters
- `ProcessSuspensionGuard` RAII class handles suspend/resume
- Mutex protects address list and latest values

### 4. Regions — `Regions` class
- Parses `/proc/pid/maps` into `std::vector<Region>`
- Binary search lookup by address
- Permission filtering with bitmask (`mustHavePerms` / `mustNotHavePerms`)

### 5. Value Type System — `CTvalue`
- Packed struct: `type` (8 bits) + `flags` (8 bits) + `stringLength` (16 bits) = 4 bytes
- Types: `i8, i16, i32, i64, f32, f64, string, byteArray, all`
- Flags: `isSigned`, `isNullTerminated`, `pchain`

### 6. GUI — ImGui windows
- Each window inherits from `Window` base class
- `Gui::getWindows<T>()` to find windows by type
- `Gui::log()` for logging (fmt-style formatting)

---

## Coding Conventions

- **C++26 standard** with Clang
- **Namespaces** for stateless modules: `VirtualMemory`, `HwBreakpoint`, `PatchManager`, `Disassembler`, `AccessTracker`
- **Classes** for stateful modules: `Scanner`, `Regions`, `PointerMap`, `PointerScan`, `PointerChain`
- **`extern "C"` + `noinline`** for functions meant to be disassembled/patched
- **`std::atomic`** for thread-shared state
- **`std::mutex`** for protecting data structures
- **RAII** for resource management (e.g., `ProcessSuspensionGuard`)
- Header guards: `#ifndef HEX_SCAN_MODULENAME_H`
- Logging: `Gui::log("format {}", args...)` (fmt-style)

---

## Testing

### DummyTarget (examples/dummy_target.cpp)
A "fake game" that exercises all features. See `examples/TEST_SPEC.md` for full details.

**Key test data:**
- 14 scannable values (all types including signed/unsigned)
- 4-level pointer chain: `g_world → currentRoom → player → inventory → gold`
- 5 patchable functions: `applyDamage`, `healPlayer`, `purchaseItem`, `calculateDamage`, `tickGameLoop`
- Background thread modifies values every second (watchpoint testing)
- 4 enemy entities (structure dissector array testing)
- 64-byte known AOB pattern

### Integration Test (tests/integration_test.sh)
Automated test that starts DummyTarget + HexScanCLI:
- i32 scan, f64 scan, all-type scan, string scan, AOB scan with wildcards
- Disassembly verification
- NOP patch verification

### Unit Tests (tests/scanner_tests.cpp)
GTest-based scanner comparator tests.

---

## Common Pitfalls

1. **Backend depends on GUI for logging**: `virtualMemory.cpp` includes `gui.h` for `Gui::log()`. The CLI workaround defines stub `Gui::logs` in `cli_main.cpp`.

2. **ptrace conflicts**: Only one thread can ptrace a process. If `AccessTracker` is attached, `VirtualMemory::writeCode()` must route writes through the tracker thread.

3. **ASLR**: Heap addresses change on every run. Use pointer chains with static base (BSS/data section) for persistence.

4. **Fast scan alignment**: `fastScanOffset` defaults to 4. Set to 1 for AOB scans or i8/i16 scans to avoid missing unaligned values.

5. **Float comparison**: Hardcoded epsilon of 0.001 in `getCommonComparator<T>()` for floating-point equality.
