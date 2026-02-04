#include "accessTracker.h"
#include "../selectedProcess/selectedProcess.h"
#include "../virtualMemory/virtualMemory.h"
#include "../../gui/gui.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cerrno>
#include <cstring>

namespace {
    std::atomic<bool> tracking{false};
    std::atomic<bool> shouldStop{false};
    std::thread trackerThread;
    
    void* trackedAddress = nullptr;
    BreakpointType trackedType = BreakpointType::DataReadWrite;
    
    std::mutex recordsMutex;
    std::map<void*, AccessRecord> recordsMap;
    
    constexpr int INSTRUCTION_BYTES_TO_CAPTURE = 16;
    
    // Set hardware breakpoint directly (inline, no detach)
    bool setHwBreakpointDirect(pid_t pid, void* address, BreakpointType type) {
        constexpr size_t DR_OFFSET = offsetof(struct user, u_debugreg);
        
        // Set address in DR0
        if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET, address) == -1) {
            fprintf(stderr, "AccessTracker: Failed to set DR0: %s\n", strerror(errno));
            // Gui::log("AccessTracker: Failed to set DR0: {}", strerror(errno));
            return false;
        }
        
        // Read current DR7
        errno = 0;
        long dr7 = ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET + 7 * sizeof(long), nullptr);
        if (errno != 0) {
            fprintf(stderr, "AccessTracker: Failed to read DR7: %s\n", strerror(errno));
            // Gui::log("AccessTracker: Failed to read DR7: {}", strerror(errno));
            return false;
        }
        
        // Enable local breakpoint for slot 0 (bit 0)
        dr7 |= 1L;
        
        // Set condition (bits 16-17 for DR0)
        dr7 &= ~(0b11L << 16);
        dr7 |= (static_cast<long>(type) << 16);
        
        // Set length to 4 bytes (bits 18-19 for DR0)
        dr7 &= ~(0b11L << 18);
        dr7 |= (0b11L << 18);  // 0b11 = 4 bytes
        
        // Write DR7
        if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET + 7 * sizeof(long), dr7) == -1) {
            fprintf(stderr, "AccessTracker: Failed to write DR7: %s\n", strerror(errno));
            // Gui::log("AccessTracker: Failed to write DR7: {}", strerror(errno));
            return false;
        }
        
        fprintf(stderr, "AccessTracker: Hardware breakpoint set at %p\n", address);
        // Gui::log("AccessTracker: Hardware breakpoint set at {:p}", address);
        return true;
    }
    
    // Clear DR6 status register
    void clearDR6(pid_t pid) {
        constexpr size_t DR_OFFSET = offsetof(struct user, u_debugreg);
        ptrace(PTRACE_POKEUSER, pid, DR_OFFSET + 6 * sizeof(long), 0);
    }
    
    void trackerLoop() {
        fprintf(stderr, "DEBUG: trackerLoop started (fprintf)\n"); // Raw fprintf to bypass C++ streams
        pid_t pid = SelectedProcess::pid;
        fprintf(stderr, "DEBUG: Got PID: %d\n", pid);

        if (pid == detached) {
            fprintf(stderr, "DEBUG: trackerLoop: No process attached\n");
            // Gui::log("AccessTracker: No process attached");
            tracking = false;
            return;
        }
        
        // Gui::log("AccessTracker: Starting trace on PID {}", pid);
        fprintf(stderr, "DEBUG: Attaching to PID %d\n", pid);
        
        // Attach to process
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            fprintf(stderr, "DEBUG: Failed to attach: %s\n", strerror(errno));
            // Gui::log("AccessTracker: Failed to attach: {}", strerror(errno));
            tracking = false;
            return;
        }
        
        fprintf(stderr, "DEBUG: Waiting for initial stop\n");
        // Wait for initial stop
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            fprintf(stderr, "DEBUG: waitpid failed: %s\n", strerror(errno));
            // Gui::log("AccessTracker: waitpid failed");
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            tracking = false;
            return;
        }
        
        fprintf(stderr, "DEBUG: Setting HW breakpoint\n");
        // Set hardware breakpoint NOW (while attached)
        if (!setHwBreakpointDirect(pid, trackedAddress, trackedType)) {
            fprintf(stderr, "DEBUG: Failed to set breakpoint\n");
            // Gui::log("AccessTracker: Failed to set breakpoint");
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            tracking = false;
            return;
        }
        
        fprintf(stderr, "DEBUG: Breakpoint set, entering loop\n");
        // Gui::log("AccessTracker: Breakpoint active, waiting for hits...");
        
        // Main tracking loop
        while (!shouldStop.load()) {
            // Continue the process
            if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
                fprintf(stderr, "AccessTracker: PTRACE_CONT failed\n");
                // Gui::log("AccessTracker: PTRACE_CONT failed");
                break;
            }
            
            // Wait for signal
            int result = waitpid(pid, &status, 0);  // Blocking wait
            
            if (result == -1) {
                if (errno == EINTR && shouldStop.load()) {
                    break;
                }
                fprintf(stderr, "AccessTracker: waitpid error: %s\n", strerror(errno));
                // Gui::log("AccessTracker: waitpid error: {}", strerror(errno));
                break;
            }
            
            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                
                if (sig == SIGTRAP) {
                    // Hardware breakpoint hit!
                    struct user_regs_struct regs;
                    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
                        void* rip = reinterpret_cast<void*>(regs.rip);
                        
                        // Read instruction bytes
                        std::vector<uint8_t> instrBytes(INSTRUCTION_BYTES_TO_CAPTURE);
                        bool readOk = true;
                        
                        // Read using PTRACE_PEEKDATA (more reliable while attached)
                        for (int i = 0; i < INSTRUCTION_BYTES_TO_CAPTURE; i += sizeof(long)) {
                            errno = 0;
                            long data = ptrace(PTRACE_PEEKDATA, pid, 
                                             reinterpret_cast<char*>(rip) + i, nullptr);
                            if (errno != 0) {
                                readOk = false;
                                break;
                            }
                            memcpy(&instrBytes[i], &data, 
                                   std::min(sizeof(long), static_cast<size_t>(INSTRUCTION_BYTES_TO_CAPTURE - i)));
                        }
                        
                        if (readOk) {
                            std::unique_lock<std::mutex> lock(recordsMutex);
                            
                            auto it = recordsMap.find(rip);
                            if (it != recordsMap.end()) {
                                it->second.accessCount++;
                            } else {
                                AccessRecord record;
                                record.instructionAddress = rip;
                                record.instructionBytes = instrBytes;
                                record.accessCount = 1;
                                record.isWrite = false;
                                recordsMap[rip] = record;
                                
                                fprintf(stderr, "AccessTracker: New access from %p\n", rip);
                                // Gui::log("AccessTracker: New access from {:p}", rip);
                            }
                        }
                    }
                    
                    // Clear DR6
                    clearDR6(pid);
                    
                } else if (sig == SIGSTOP) {
                    // We might have sent this to stop tracking
                    if (shouldStop.load()) {
                        break;
                    }
                    // Otherwise continue
                } else {
                    // Pass other signals to the process
                    ptrace(PTRACE_CONT, pid, nullptr, sig);
                    continue;
                }
            }
            
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                fprintf(stderr, "AccessTracker: Target process terminated\n");
                // Gui::log("AccessTracker: Target process terminated");
                break;
            }
        }
        
        // Clear breakpoint before detaching
        constexpr size_t DR_OFFSET = offsetof(struct user, u_debugreg);
        ptrace(PTRACE_POKEUSER, pid, DR_OFFSET, nullptr);  // Clear DR0
        long dr7 = ptrace(PTRACE_PEEKUSER, pid, DR_OFFSET + 7 * sizeof(long), nullptr);
        dr7 &= ~1L;  // Disable slot 0
        ptrace(PTRACE_POKEUSER, pid, DR_OFFSET + 7 * sizeof(long), dr7);
        
        // Detach from process
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        
        tracking = false;
        Gui::log("AccessTracker: Stopped");
    }
}

bool AccessTracker::startTracking(void* address, BreakpointType type) {
    if (tracking.load()) {
        Gui::log("AccessTracker: Already tracking");
        return false;
    }
    
    if (SelectedProcess::pid == detached) {
        Gui::log("AccessTracker: No process selected");
        return false;
    }
    
    trackedAddress = address;
    trackedType = type;
    shouldStop = false;
    tracking = true;
    
    // Clear previous records
    {
        std::unique_lock<std::mutex> lock(recordsMutex);
        recordsMap.clear();
    }
    
    // Start tracker thread
    trackerThread = std::thread(trackerLoop);
    
    Gui::log("AccessTracker: Started tracking {:p}", address);
    return true;
}

void AccessTracker::stopTracking() {
    if (!tracking.load()) {
        return;
    }
    
    shouldStop = true;
    
    // Send SIGSTOP to interrupt waitpid
    if (SelectedProcess::pid != detached) {
        kill(SelectedProcess::pid, SIGSTOP);
    }
    
    // Wait for thread to finish
    if (trackerThread.joinable()) {
        trackerThread.join();
    }
    
    trackedAddress = nullptr;
    tracking = false;
}

bool AccessTracker::isTracking() {
    return tracking.load();
}

bool AccessTracker::isAttached() {
    return tracking.load();
}

std::vector<AccessRecord> AccessTracker::getRecords() {
    std::unique_lock<std::mutex> lock(recordsMutex);
    
    std::vector<AccessRecord> result;
    result.reserve(recordsMap.size());
    
    for (const auto& [addr, record] : recordsMap) {
        result.push_back(record);
    }
    
    // Sort by access count (descending)
    std::sort(result.begin(), result.end(), [](const AccessRecord& a, const AccessRecord& b) {
        return a.accessCount > b.accessCount;
    });
    
    return result;
}

void AccessTracker::clearRecords() {
    std::unique_lock<std::mutex> lock(recordsMutex);
    recordsMap.clear();
}

uint64_t AccessTracker::getTotalAccessCount() {
    std::unique_lock<std::mutex> lock(recordsMutex);
    uint64_t total = 0;
    for (const auto& [addr, record] : recordsMap) {
        total += record.accessCount;
    }
    return total;
}

std::string AccessTracker::getAOBString(const AccessRecord& record) {
    std::ostringstream oss;
    
    for (size_t i = 0; i < record.instructionBytes.size(); ++i) {
        if (i > 0) oss << " ";
        oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(record.instructionBytes[i]);
    }
    
    return oss.str();
}

void* AccessTracker::getTrackedAddress() {
    return trackedAddress;
}
