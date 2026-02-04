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
}
