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

namespace {
    std::atomic<bool> tracking{false};
    std::atomic<bool> shouldStop{false};
    std::thread trackerThread;
    
    int breakpointSlot = -1;
    void* trackedAddress = nullptr;
    
    std::mutex recordsMutex;
    std::map<void*, AccessRecord> recordsMap;  // Keyed by instruction address
    
    // Number of instruction bytes to capture for AOB signature
    constexpr int INSTRUCTION_BYTES_TO_CAPTURE = 16;
    
    void trackerLoop() {
        pid_t pid = SelectedProcess::pid;
        if (pid == detached) {
            tracking = false;
            return;
        }
        
        Gui::log("AccessTracker: Starting trace on PID {}", pid);
        
        // Attach to process
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            Gui::log("AccessTracker: Failed to attach");
            tracking = false;
            return;
        }
        
        // Wait for initial stop
        int status;
        waitpid(pid, &status, 0);
        
        // Continue and wait for breakpoint hits
        while (!shouldStop.load()) {
            // Continue the process
            ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            
            // Wait for signal (with timeout to check shouldStop)
            int result = waitpid(pid, &status, WNOHANG);
            
            if (result == 0) {
                // No event yet, sleep briefly and check again
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            
            if (result == -1) {
                // Error or process exited
                Gui::log("AccessTracker: Process exited or error");
                break;
            }
            
            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                
                if (sig == SIGTRAP) {
                    // Hardware breakpoint hit!
                    
                    // Get registers to find RIP
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
                    
                    void* rip = reinterpret_cast<void*>(regs.rip);
                    
                    // The instruction that caused the trap is at RIP
                    // (or RIP-1 for some cases, but for data breakpoints it's usually at RIP)
                    
                    // Read instruction bytes
                    std::vector<uint8_t> instrBytes(INSTRUCTION_BYTES_TO_CAPTURE);
                    if (VirtualMemory::read(rip, instrBytes.data(), INSTRUCTION_BYTES_TO_CAPTURE)) {
                        std::lock_guard<std::mutex> lock(recordsMutex);
                        
                        auto it = recordsMap.find(rip);
                        if (it != recordsMap.end()) {
                            it->second.accessCount++;
                        } else {
                            AccessRecord record;
                            record.instructionAddress = rip;
                            record.instructionBytes = instrBytes;
                            record.accessCount = 1;
                            record.isWrite = false;  // We can't easily tell read vs write
                            recordsMap[rip] = record;
                            
                            Gui::log("AccessTracker: New access from {:p}", rip);
                        }
                    }
                    
                    // Clear DR6 to re-arm the breakpoint
                    HwBreakpoint::clearStatus();
                    
                } else if (sig == SIGSTOP) {
                    // Ignore SIGSTOP (we may have sent it)
                    continue;
                } else {
                    // Pass other signals to the process
                    ptrace(PTRACE_CONT, pid, nullptr, sig);
                    continue;
                }
            }
            
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                // Process terminated
                Gui::log("AccessTracker: Target process terminated");
                break;
            }
        }
        
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
    
    // Set hardware breakpoint
    breakpointSlot = HwBreakpoint::set(address, type, BreakpointSize::Byte4);
    if (breakpointSlot < 0) {
        Gui::log("AccessTracker: Failed to set breakpoint");
        return false;
    }
    
    trackedAddress = address;
    shouldStop = false;
    tracking = true;
    
    // Clear previous records
    {
        std::lock_guard<std::mutex> lock(recordsMutex);
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
    
    // Clear the breakpoint
    if (breakpointSlot >= 0) {
        HwBreakpoint::clear(breakpointSlot);
        breakpointSlot = -1;
    }
    
    trackedAddress = nullptr;
    tracking = false;
}

bool AccessTracker::isTracking() {
    return tracking.load();
}

std::vector<AccessRecord> AccessTracker::getRecords() {
    std::lock_guard<std::mutex> lock(recordsMutex);
    
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
    std::lock_guard<std::mutex> lock(recordsMutex);
    recordsMap.clear();
}

uint64_t AccessTracker::getTotalAccessCount() {
    std::lock_guard<std::mutex> lock(recordsMutex);
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
