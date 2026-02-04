#ifndef HEX_SCAN_PATCHMANAGER_H
#define HEX_SCAN_PATCHMANAGER_H

#include <vector>
#include <string>
#include <map>
#include <cstdint>

struct Patch {
    void* address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> patchedBytes;
    std::string description;
    bool isActive;
};

namespace PatchManager {
    // Apply NOP patch to an instruction
    bool nopInstruction(void* address, size_t length, const std::string& description = "");
    
    // Restore original bytes
    bool restorePatch(void* address);
    
    // Get all tracked patches
    const std::map<void*, Patch>& getPatches();
    
    // Check if an address is currently patched
    bool isPatched(void* address);
}

#endif //HEX_SCAN_PATCHMANAGER_H
