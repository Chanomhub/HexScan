#ifndef HEX_SCAN_CODEINJECTION_H
#define HEX_SCAN_CODEINJECTION_H

#include <cstdint>
#include <vector>
#include <string>
#include <map>

/**
 * CodeInjection — Allocate executable memory and install trampoline hooks
 * in a remote process via ptrace syscall injection.
 *
 * Workflow:
 *   1. allocateRemote(size) → get RWX page in target process
 *   2. writeToRemote(cave, data) → write shellcode/data to the cave
 *   3. installHook(target, cave) → replace target instruction with JMP to cave
 *   4. removeHook(target) → restore original bytes
 *   5. freeRemote(cave) → release the allocated memory
 *
 * The trampoline layout in the code cave:
 *   [custom code bytes]
 *   [original displaced instruction(s)]
 *   [JMP back to target + displaced_length]
 */

struct CodeCave {
    uint64_t address;       // Remote address of allocated memory
    uint64_t size;          // Size of allocation
    bool     inUse;         // Whether it has active hooks
    std::string description;
};

struct TrampolineHook {
    uint64_t targetAddress;         // Where the hook is installed
    uint64_t caveAddress;           // Where the trampoline code lives
    std::vector<uint8_t> originalBytes;  // Original displaced bytes
    size_t   displacedLength;       // How many bytes were displaced (>= 5 for near jmp, >= 14 for far)
    bool     isActive;
    std::string description;
};

namespace CodeInjection {
    // ── Remote memory management ───────────────────────────────────────
    
    // Allocate RWX memory in the target process via ptrace + mmap syscall injection.
    // Returns the remote address, or 0 on failure.
    // Requires: process must NOT be ptraced by AccessTracker simultaneously.
    uint64_t allocateRemote(size_t size, const std::string& description = "");
    
    // Free previously allocated remote memory via ptrace + munmap syscall injection.
    bool freeRemote(uint64_t address);
    
    // Write arbitrary bytes to a remote code cave.
    bool writeToRemote(uint64_t remoteAddress, const uint8_t* data, size_t length);
    
    // Read bytes from remote address for verification.
    bool readFromRemote(uint64_t remoteAddress, uint8_t* buffer, size_t length);
    
    // ── Trampoline hooks ───────────────────────────────────────────────
    
    // Install a trampoline hook:
    //   - Disassembles instruction(s) at targetAddress (min 5 bytes for near JMP)
    //   - Copies displaced instructions to code cave
    //   - Appends JMP back to targetAddress + displaced_length
    //   - Overwrites targetAddress with JMP to code cave
    //   - customCode (optional) is prepended before the displaced instructions
    bool installHook(uint64_t targetAddress, const std::vector<uint8_t>& customCode = {},
                     const std::string& description = "");
    
    // Remove a previously installed hook, restoring original bytes.
    bool removeHook(uint64_t targetAddress);
    
    // ── Query ──────────────────────────────────────────────────────────
    
    // Get all allocated code caves.
    const std::map<uint64_t, CodeCave>& getCaves();
    
    // Get all active hooks.
    const std::map<uint64_t, TrampolineHook>& getHooks();
    
    // Check if address has an active hook.
    bool isHooked(uint64_t address);
}

#endif //HEX_SCAN_CODEINJECTION_H
