#include "patchManager.h"
#include "../virtualMemory/virtualMemory.h"
#include "../disassembler/disassembler.h"
#include "../../gui/gui.h"

namespace PatchManager {

    std::map<void*, Patch> patches;

    bool nopInstruction(void* address, size_t length, const std::string& description) {
        if (length == 0) return false;

        // If already patched, do nothing or re-apply?
        // Let's assume we want to ensure it's patched.
        if (patches.count(address) && patches[address].isActive) {
            return true;
        }

        Patch patch;
        patch.address = address;
        patch.description = description;

        // Read original bytes
        patch.originalBytes.resize(length);
        if (!VirtualMemory::read(address, patch.originalBytes.data(), length)) {
            Gui::log("PatchManager: Failed to read original bytes at {:p}", address);
            return false;
        }

        // Create NOP bytes
        patch.patchedBytes = Disassembler::createNOP(length);

        // Apply patch using writeCode (PTRACE_POKETEXT) for executable memory
        if (VirtualMemory::writeCode(patch.patchedBytes.data(), address, length)) {
            patch.isActive = true;
            patches[address] = patch;
            Gui::log("PatchManager: Applied NOP patch at {:p}", address);
            return true;
        } else {
            Gui::log("PatchManager: Failed to write patch at {:p}", address);
            return false;
        }
    }

    bool restorePatch(void* address) {
        auto it = patches.find(address);
        if (it == patches.end()) return false;

        Patch& patch = it->second;
        if (!patch.isActive) return true; // Already restored

        if (VirtualMemory::writeCode(patch.originalBytes.data(), address, patch.originalBytes.size())) {
            patch.isActive = false;
            Gui::log("PatchManager: Restored original bytes at {:p}", address);
            return true;
        } else {
            Gui::log("PatchManager: Failed to restore patch at {:p}", address);
            return false;
        }
    }

    const std::map<void*, Patch>& getPatches() {
        return patches;
    }

    bool isPatched(void* address) {
        auto it = patches.find(address);
        return it != patches.end() && it->second.isActive;
    }
    
    // Helper: Check if opcode is a conditional jump and return the byte offset to invert
    // Short conditional jumps: 0x70-0x7F (Jcc rel8)
    // Near conditional jumps: 0x0F 0x80-0x8F (Jcc rel32)
    // Returns: offset of the byte to XOR with 0x01, or -1 if not a conditional jump
    static int getConditionalJumpOffset(const uint8_t* bytes, size_t length) {
        if (length == 0 || !bytes) return -1;
        
        // Short conditional jump: 0x70-0x7F
        if (bytes[0] >= 0x70 && bytes[0] <= 0x7F) {
            return 0;
        }
        
        // Near conditional jump: 0x0F 0x80-0x8F
        if (length >= 2 && bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F) {
            return 1;
        }
        
        return -1;
    }
    
    bool isConditionalJump(void* address, size_t length) {
        if (length == 0) return false;
        
        std::vector<uint8_t> bytes(length);
        if (!VirtualMemory::read(address, bytes.data(), length)) {
            return false;
        }
        
        return getConditionalJumpOffset(bytes.data(), length) >= 0;
    }
    
    bool invertConditionalJump(void* address, size_t length, const std::string& description) {
        if (length == 0) return false;
        
        // If already patched, we need to handle differently
        // For simplicity, let's not allow inverting already-patched instructions
        if (patches.count(address) && patches[address].isActive) {
            Gui::log("PatchManager: Address {:p} already has an active patch. Restore first.", address);
            return false;
        }
        
        Patch patch;
        patch.address = address;
        patch.description = description.empty() ? "Inverted conditional jump" : description;
        
        // Read original bytes
        patch.originalBytes.resize(length);
        if (!VirtualMemory::read(address, patch.originalBytes.data(), length)) {
            Gui::log("PatchManager: Failed to read original bytes at {:p}", address);
            return false;
        }
        
        // Find the offset of the conditional byte
        int offset = getConditionalJumpOffset(patch.originalBytes.data(), length);
        if (offset < 0) {
            Gui::log("PatchManager: Instruction at {:p} is not a conditional jump", address);
            return false;
        }
        
        // Create patched bytes by XORing the condition byte with 0x01
        // This inverts the condition: jz(0x74)↔jnz(0x75), je↔jne, jl↔jge, etc.
        patch.patchedBytes = patch.originalBytes;
        patch.patchedBytes[offset] ^= 0x01;
        
        // Apply the patch
        if (VirtualMemory::writeCode(patch.patchedBytes.data(), address, length)) {
            patch.isActive = true;
            patches[address] = patch;
            
            // Log what we changed
            const char* oldJump = "";
            const char* newJump = "";
            uint8_t oldByte = patch.originalBytes[offset];
            uint8_t newByte = patch.patchedBytes[offset];
            
            // Common jump mnemonics for logging
            switch (offset == 0 ? oldByte : oldByte) {
                case 0x74: case 0x84: oldJump = "jz/je"; newJump = "jnz/jne"; break;
                case 0x75: case 0x85: oldJump = "jnz/jne"; newJump = "jz/je"; break;
                case 0x7C: case 0x8C: oldJump = "jl/jnge"; newJump = "jge/jnl"; break;
                case 0x7D: case 0x8D: oldJump = "jge/jnl"; newJump = "jl/jnge"; break;
                case 0x7E: case 0x8E: oldJump = "jle/jng"; newJump = "jg/jnle"; break;
                case 0x7F: case 0x8F: oldJump = "jg/jnle"; newJump = "jle/jng"; break;
                case 0x72: case 0x82: oldJump = "jb/jc"; newJump = "jnb/jnc"; break;
                case 0x73: case 0x83: oldJump = "jnb/jnc"; newJump = "jb/jc"; break;
                case 0x76: case 0x86: oldJump = "jbe/jna"; newJump = "ja/jnbe"; break;
                case 0x77: case 0x87: oldJump = "ja/jnbe"; newJump = "jbe/jna"; break;
                default: oldJump = "jcc"; newJump = "jcc(inverted)"; break;
            }
            
            Gui::log("PatchManager: Inverted {} -> {} at {:p}", oldJump, newJump, address);
            return true;
        } else {
            Gui::log("PatchManager: Failed to write inverted jump at {:p}", address);
            return false;
        }
    }
}
