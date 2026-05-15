#include "codeInjection.h"
#include "../selectedProcess/selectedProcess.h"
#include "../virtualMemory/virtualMemory.h"
#include "../disassembler/disassembler.h"
#include "../debugger/accessTracker.h"
#include "../../gui/gui.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <cerrno>
#include <cstring>
#include <algorithm>


namespace CodeInjection {

    static std::map<uint64_t, CodeCave> caves;
    static std::map<uint64_t, TrampolineHook> hooks;

    // ═══════════════════════════════════════════════════════════════════
    //  PTRACE SYSCALL INJECTION — Core mechanism
    // ═══════════════════════════════════════════════════════════════════
    //
    //  To call mmap/munmap in the target process:
    //  1. PTRACE_ATTACH + wait
    //  2. PTRACE_GETREGS → save original registers
    //  3. Read bytes at current RIP → save them
    //  4. Write `syscall` instruction (0x0F 0x05) at RIP
    //  5. Set registers for the desired syscall
    //  6. PTRACE_SINGLESTEP → execute the syscall
    //  7. PTRACE_GETREGS → read RAX (return value)
    //  8. Restore original bytes at RIP
    //  9. Restore original registers
    // 10. PTRACE_DETACH
    // ═══════════════════════════════════════════════════════════════════

    struct PtraceSession {
        pid_t pid;
        struct user_regs_struct savedRegs;
        uint64_t savedRIP;
        long savedWord;  // Original 8 bytes at RIP
        bool attached = false;

        bool attach() {
            pid = SelectedProcess::pid;
            if (pid == detached) {
                Gui::log("CodeInjection: No process attached");
                return false;
            }
            
            // Check if AccessTracker already has ptrace attached
            if (AccessTracker::isAttached()) {
                Gui::log("CodeInjection: Cannot inject while AccessTracker is active. Stop it first.");
                return false;
            }

            if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
                Gui::log("CodeInjection: Failed to attach: {}", strerror(errno));
                return false;
            }

            int status;
            if (waitpid(pid, &status, 0) == -1) {
                Gui::log("CodeInjection: waitpid failed: {}", strerror(errno));
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                return false;
            }

            // Save registers
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &savedRegs) == -1) {
                Gui::log("CodeInjection: Failed to get registers: {}", strerror(errno));
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                return false;
            }

            savedRIP = savedRegs.rip;

            // Save original bytes at RIP (8 bytes)
            errno = 0;
            savedWord = ptrace(PTRACE_PEEKTEXT, pid, savedRIP, nullptr);
            if (errno != 0) {
                Gui::log("CodeInjection: Failed to read at RIP: {}", strerror(errno));
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                return false;
            }

            attached = true;
            return true;
        }

        void detach() {
            if (!attached) return;

            // Restore original bytes at RIP
            ptrace(PTRACE_POKETEXT, pid, savedRIP, savedWord);

            // Restore all registers
            ptrace(PTRACE_SETREGS, pid, nullptr, &savedRegs);

            // Detach
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            attached = false;
        }

        // Execute a syscall with given arguments. Returns RAX (result).
        int64_t executeSyscall(uint64_t sysno, uint64_t arg1 = 0, uint64_t arg2 = 0,
                               uint64_t arg3 = 0, uint64_t arg4 = 0,
                               uint64_t arg5 = 0, uint64_t arg6 = 0) {
            if (!attached) return -1;

            // Write `syscall` instruction at RIP: 0x0F 0x05
            // We write it as part of an 8-byte word to avoid partial writes
            long syscallWord = savedWord;
            uint8_t* bytes = reinterpret_cast<uint8_t*>(&syscallWord);
            bytes[0] = 0x0F;  // syscall opcode byte 1
            bytes[1] = 0x05;  // syscall opcode byte 2

            if (ptrace(PTRACE_POKETEXT, pid, savedRIP, syscallWord) == -1) {
                Gui::log("CodeInjection: Failed to write syscall at RIP: {}", strerror(errno));
                return -1;
            }

            // Set syscall arguments
            struct user_regs_struct regs = savedRegs;
            regs.rip = savedRIP;
            regs.rax = sysno;
            regs.rdi = arg1;
            regs.rsi = arg2;
            regs.rdx = arg3;
            regs.r10 = arg4;
            regs.r8  = arg5;
            regs.r9  = arg6;

            if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
                Gui::log("CodeInjection: Failed to set registers: {}", strerror(errno));
                return -1;
            }

            // Single-step to execute the syscall
            if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
                Gui::log("CodeInjection: SINGLESTEP failed: {}", strerror(errno));
                return -1;
            }

            int status;
            if (waitpid(pid, &status, 0) == -1) {
                Gui::log("CodeInjection: waitpid after singlestep failed: {}", strerror(errno));
                return -1;
            }

            // Read result from RAX
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
                Gui::log("CodeInjection: Failed to read result registers: {}", strerror(errno));
                return -1;
            }

            return static_cast<int64_t>(regs.rax);
        }
    };


    // ═══════════════════════════════════════════════════════════════════
    //  REMOTE MEMORY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════

    uint64_t allocateRemote(size_t size, const std::string& description) {
        // Round up to page size
        size_t pageSize = 4096;
        size = (size + pageSize - 1) & ~(pageSize - 1);

        PtraceSession session;
        if (!session.attach()) return 0;

        // mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        int64_t result = session.executeSyscall(
            SYS_mmap,
            0,                                          // addr = NULL (kernel chooses)
            size,                                       // length
            PROT_READ | PROT_WRITE | PROT_EXEC,        // prot = RWX
            MAP_PRIVATE | MAP_ANONYMOUS,                // flags
            (uint64_t)-1,                               // fd = -1
            0                                           // offset = 0
        );

        session.detach();

        if (result < 0 || result == (int64_t)MAP_FAILED) {
            Gui::log("CodeInjection: mmap failed (result=0x{:x})", (uint64_t)result);
            return 0;
        }

        uint64_t addr = static_cast<uint64_t>(result);

        CodeCave cave;
        cave.address = addr;
        cave.size = size;
        cave.inUse = false;
        cave.description = description;
        caves[addr] = cave;

        Gui::log("CodeInjection: Allocated {} bytes at {:p}", size, (void*)addr);
        return addr;
    }


    bool freeRemote(uint64_t address) {
        auto it = caves.find(address);
        if (it == caves.end()) {
            Gui::log("CodeInjection: Unknown cave at {:p}", (void*)address);
            return false;
        }

        // Check no active hooks are using this cave
        for (const auto& [_, hook] : hooks) {
            if (hook.isActive && hook.caveAddress == address) {
                Gui::log("CodeInjection: Cannot free cave — active hook at {:p}", (void*)hook.targetAddress);
                return false;
            }
        }

        PtraceSession session;
        if (!session.attach()) return false;

        // munmap(address, size)
        int64_t result = session.executeSyscall(
            SYS_munmap,
            address,
            it->second.size
        );

        session.detach();

        if (result != 0) {
            Gui::log("CodeInjection: munmap failed (result={})", result);
            return false;
        }

        caves.erase(it);
        Gui::log("CodeInjection: Freed cave at {:p}", (void*)address);
        return true;
    }


    bool writeToRemote(uint64_t remoteAddress, const uint8_t* data, size_t length) {
        return VirtualMemory::writeCode((void*)data, (void*)remoteAddress, length);
    }


    bool readFromRemote(uint64_t remoteAddress, uint8_t* buffer, size_t length) {
        return VirtualMemory::read((void*)remoteAddress, buffer, length);
    }


    // ═══════════════════════════════════════════════════════════════════
    //  JMP ENCODING HELPERS
    // ═══════════════════════════════════════════════════════════════════

    // Near JMP (E9 + 4-byte relative offset) — works if offset fits in int32
    static std::vector<uint8_t> encodeNearJmp(uint64_t from, uint64_t to) {
        int64_t offset = (int64_t)to - (int64_t)from - 5;  // -5 for instruction length
        std::vector<uint8_t> jmp(5);
        jmp[0] = 0xE9;
        std::memcpy(&jmp[1], &offset, 4);
        return jmp;
    }

    // Far JMP (FF 25 00 00 00 00 + 8-byte absolute address) — always works
    static std::vector<uint8_t> encodeFarJmp(uint64_t to) {
        std::vector<uint8_t> jmp(14);
        jmp[0] = 0xFF; jmp[1] = 0x25;
        jmp[2] = 0x00; jmp[3] = 0x00; jmp[4] = 0x00; jmp[5] = 0x00;
        std::memcpy(&jmp[6], &to, 8);
        return jmp;
    }

    // Choose the smallest JMP encoding that reaches the target
    static std::vector<uint8_t> encodeJmp(uint64_t from, uint64_t to) {
        int64_t offset = (int64_t)to - (int64_t)from - 5;
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            return encodeNearJmp(from, to);
        }
        return encodeFarJmp(to);
    }

    // Minimum bytes needed for a JMP from `from` to `to`
    static size_t jmpSize(uint64_t from, uint64_t to) {
        int64_t offset = (int64_t)to - (int64_t)from - 5;
        return (offset >= INT32_MIN && offset <= INT32_MAX) ? 5 : 14;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  TRAMPOLINE HOOKS
    // ═══════════════════════════════════════════════════════════════════

    bool installHook(uint64_t targetAddress, const std::vector<uint8_t>& customCode,
                     const std::string& description) {
        
        if (hooks.count(targetAddress) && hooks[targetAddress].isActive) {
            Gui::log("CodeInjection: Hook already active at {:p}", (void*)targetAddress);
            return false;
        }

        Disassembler::init();

        // Step 1: Read enough bytes from target to disassemble full instructions
        //         We need at least 5 bytes (near JMP) or 14 bytes (far JMP)
        uint8_t readBuf[32];
        if (!VirtualMemory::read((void*)targetAddress, readBuf, sizeof(readBuf))) {
            Gui::log("CodeInjection: Failed to read target at {:p}", (void*)targetAddress);
            return false;
        }

        // Disassemble instructions until we have enough bytes displaced
        // We'll determine JMP size after we know the cave address
        // For now, assume we need at least 5 bytes (optimistic near JMP)
        size_t displaced = 0;
        size_t offset = 0;
        while (displaced < 5 && offset < sizeof(readBuf)) {
            auto inst = Disassembler::disassemble(readBuf + offset, sizeof(readBuf) - offset, targetAddress + offset);
            if (!inst.valid) {
                Gui::log("CodeInjection: Cannot disassemble at {:p}+{}", (void*)targetAddress, offset);
                return false;
            }
            displaced += inst.length;
            offset += inst.length;
        }

        if (displaced < 5) {
            Gui::log("CodeInjection: Not enough space for hook at {:p} (need 5, got {})", (void*)targetAddress, displaced);
            return false;
        }

        // Step 2: Allocate code cave for: customCode + displaced instructions + JMP back
        //         Far JMP back is 14 bytes max
        size_t caveSize = customCode.size() + displaced + 14;
        uint64_t caveAddr = allocateRemote(caveSize, "Hook cave: " + description);
        if (caveAddr == 0) {
            Gui::log("CodeInjection: Failed to allocate cave for hook");
            return false;
        }

        // Now check if we actually need a far JMP to reach the cave from the target
        size_t neededJmpSize = jmpSize(targetAddress, caveAddr);
        if (neededJmpSize > displaced) {
            // Re-disassemble to get enough displaced bytes for a far JMP
            displaced = 0;
            offset = 0;
            while (displaced < neededJmpSize && offset < sizeof(readBuf)) {
                auto inst = Disassembler::disassemble(readBuf + offset, sizeof(readBuf) - offset, targetAddress + offset);
                if (!inst.valid) break;
                displaced += inst.length;
                offset += inst.length;
            }
            if (displaced < neededJmpSize) {
                Gui::log("CodeInjection: Not enough space for far JMP (need {}, got {})", neededJmpSize, displaced);
                freeRemote(caveAddr);
                return false;
            }
        }

        // Step 3: Build cave content
        //   [custom code]
        //   [original displaced instruction(s)]
        //   [JMP back to target + displaced]
        std::vector<uint8_t> caveContent;
        caveContent.reserve(customCode.size() + displaced + 14);

        // Prepend custom code
        caveContent.insert(caveContent.end(), customCode.begin(), customCode.end());

        // Copy displaced instructions
        caveContent.insert(caveContent.end(), readBuf, readBuf + displaced);

        // Append JMP back
        uint64_t returnAddr = targetAddress + displaced;
        uint64_t jmpBackFrom = caveAddr + caveContent.size();
        auto jmpBack = encodeJmp(jmpBackFrom, returnAddr);
        caveContent.insert(caveContent.end(), jmpBack.begin(), jmpBack.end());

        // Step 4: Write cave content to allocated memory
        if (!writeToRemote(caveAddr, caveContent.data(), caveContent.size())) {
            Gui::log("CodeInjection: Failed to write cave content");
            freeRemote(caveAddr);
            return false;
        }

        // Step 5: Build the JMP at target → cave, padded with NOPs
        auto jmpToCave = encodeJmp(targetAddress, caveAddr);
        std::vector<uint8_t> hookPatch(displaced, 0x90); // Fill with NOPs
        std::memcpy(hookPatch.data(), jmpToCave.data(), jmpToCave.size());

        // Step 6: Save original bytes and install the hook
        TrampolineHook hook;
        hook.targetAddress = targetAddress;
        hook.caveAddress = caveAddr;
        hook.originalBytes.assign(readBuf, readBuf + displaced);
        hook.displacedLength = displaced;
        hook.isActive = true;
        hook.description = description;

        if (!VirtualMemory::writeCode(hookPatch.data(), (void*)targetAddress, displaced)) {
            Gui::log("CodeInjection: Failed to write hook JMP at {:p}", (void*)targetAddress);
            freeRemote(caveAddr);
            return false;
        }

        // Mark cave as in use
        caves[caveAddr].inUse = true;

        hooks[targetAddress] = hook;
        Gui::log("CodeInjection: Hook installed at {:p} → cave {:p} (displaced {} bytes)",
                 (void*)targetAddress, (void*)caveAddr, displaced);
        return true;
    }


    bool removeHook(uint64_t targetAddress) {
        auto it = hooks.find(targetAddress);
        if (it == hooks.end() || !it->second.isActive) {
            Gui::log("CodeInjection: No active hook at {:p}", (void*)targetAddress);
            return false;
        }

        TrampolineHook& hook = it->second;

        // Restore original bytes
        if (!VirtualMemory::writeCode(hook.originalBytes.data(), (void*)targetAddress, hook.originalBytes.size())) {
            Gui::log("CodeInjection: Failed to restore original bytes at {:p}", (void*)targetAddress);
            return false;
        }

        hook.isActive = false;

        // Free the code cave
        if (caves.count(hook.caveAddress)) {
            caves[hook.caveAddress].inUse = false;
            freeRemote(hook.caveAddress);
        }

        Gui::log("CodeInjection: Hook removed at {:p}", (void*)targetAddress);
        return true;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  QUERY
    // ═══════════════════════════════════════════════════════════════════

    const std::map<uint64_t, CodeCave>& getCaves() { return caves; }
    const std::map<uint64_t, TrampolineHook>& getHooks() { return hooks; }
    bool isHooked(uint64_t address) {
        auto it = hooks.find(address);
        return it != hooks.end() && it->second.isActive;
    }
}
