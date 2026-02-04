#include "hwBreakpoint.h"
#include "../selectedProcess/selectedProcess.h"
#include "../../gui/gui.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstring>

// Debug register offsets in user struct (in bytes, divide by 8 for index)
// On x86_64: offsetof(struct user, u_debugreg) gives the start
// DR0 is at index 0, DR1 at 1, ..., DR7 at 7
namespace {
    // Slot usage tracking
    bool slots[4] = {false, false, false, false};
    void* watchedAddresses[4] = {nullptr, nullptr, nullptr, nullptr};
    
    // Get offset for debug register N in user struct
    constexpr size_t getDROffset(int n) {
        return offsetof(struct user, u_debugreg) + n * sizeof(long);
    }
    
    // Attach to process for ptrace operations if not already attached
    bool ensureAttached() {
        pid_t pid = SelectedProcess::pid;
        if (pid == detached) {
            Gui::log("HwBreakpoint: No process selected");
            return false;
        }
        
        // Try to attach with ptrace
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            if (errno == EPERM) {
                Gui::log("HwBreakpoint: Permission denied. Run as root.");
                return false;
            }
            // Already attached is OK (errno == EPERM sometimes)
            // Or process might be our child (errno == ESRCH means dead)
        }
        
        // Wait for process to stop
        int status;
        waitpid(pid, &status, 0);
        
        return true;
    }
    
    // Continue the process after ptrace operation
    void continueProcess() {
        pid_t pid = SelectedProcess::pid;
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    }
}

int HwBreakpoint::set(void* address, BreakpointType type, BreakpointSize size) {
    // Find available slot
    int slot = -1;
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (!slots[i]) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        Gui::log("HwBreakpoint: All 4 slots in use");
        return -1;
    }
    
    pid_t pid = SelectedProcess::pid;
    if (pid == detached) {
        Gui::log("HwBreakpoint: No process selected");
        return -1;
    }
    
    if (!ensureAttached()) {
        return -1;
    }
    
    // Set address in DR0-DR3
    if (ptrace(PTRACE_POKEUSER, pid, getDROffset(slot), address) == -1) {
        Gui::log("HwBreakpoint: Failed to set DR{}: {}", slot, strerror(errno));
        continueProcess();
        return -1;
    }
    
    // Read current DR7
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, pid, getDROffset(7), nullptr);
    if (errno != 0) {
        Gui::log("HwBreakpoint: Failed to read DR7: {}", strerror(errno));
        continueProcess();
        return -1;
    }
    
    // Enable local breakpoint for this slot
    // Local enable bits: 0, 2, 4, 6 for DR0-DR3
    dr7 |= (1L << (slot * 2));
    
    // Set condition (breakpoint type)
    // Condition bits: 16-17 for DR0, 20-21 for DR1, 24-25 for DR2, 28-29 for DR3
    int condBits = 16 + slot * 4;
    dr7 &= ~(0b11L << condBits);  // Clear existing condition
    dr7 |= (static_cast<long>(type) << condBits);
    
    // Set length
    // Length bits: 18-19 for DR0, 22-23 for DR1, 26-27 for DR2, 30-31 for DR3
    int lenBits = 18 + slot * 4;
    dr7 &= ~(0b11L << lenBits);  // Clear existing length
    dr7 |= (static_cast<long>(size) << lenBits);
    
    // Write DR7
    if (ptrace(PTRACE_POKEUSER, pid, getDROffset(7), dr7) == -1) {
        Gui::log("HwBreakpoint: Failed to write DR7: {}", strerror(errno));
        continueProcess();
        return -1;
    }
    
    slots[slot] = true;
    watchedAddresses[slot] = address;
    
    continueProcess();
    
    Gui::log("HwBreakpoint: Set breakpoint {} at {:p}", slot, address);
    return slot;
}

bool HwBreakpoint::clear(int slot) {
    if (slot < 0 || slot >= MAX_BREAKPOINTS || !slots[slot]) {
        return false;
    }
    
    pid_t pid = SelectedProcess::pid;
    if (pid == detached) {
        // Just clear our tracking, no process to update
        slots[slot] = false;
        watchedAddresses[slot] = nullptr;
        return true;
    }
    
    if (!ensureAttached()) {
        return false;
    }
    
    // Clear address in DR
    ptrace(PTRACE_POKEUSER, pid, getDROffset(slot), nullptr);
    
    // Read DR7 and disable this breakpoint
    long dr7 = ptrace(PTRACE_PEEKUSER, pid, getDROffset(7), nullptr);
    dr7 &= ~(1L << (slot * 2));  // Clear local enable bit
    ptrace(PTRACE_POKEUSER, pid, getDROffset(7), dr7);
    
    slots[slot] = false;
    watchedAddresses[slot] = nullptr;
    
    continueProcess();
    
    Gui::log("HwBreakpoint: Cleared breakpoint {}", slot);
    return true;
}

void HwBreakpoint::clearAll() {
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (slots[i]) {
            clear(i);
        }
    }
}

bool HwBreakpoint::hasAvailableSlot() {
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (!slots[i]) return true;
    }
    return false;
}

int HwBreakpoint::activeCount() {
    int count = 0;
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (slots[i]) ++count;
    }
    return count;
}

int HwBreakpoint::getTriggeredSlot() {
    pid_t pid = SelectedProcess::pid;
    if (pid == detached) return -1;
    
    // Read DR6 (status register)
    errno = 0;
    long dr6 = ptrace(PTRACE_PEEKUSER, pid, getDROffset(6), nullptr);
    if (errno != 0) return -1;
    
    // Check which breakpoint triggered (bits 0-3)
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (dr6 & (1L << i)) {
            return i;
        }
    }
    
    return -1;
}

void HwBreakpoint::clearStatus() {
    pid_t pid = SelectedProcess::pid;
    if (pid == detached) return;
    
    // Clear DR6
    ptrace(PTRACE_POKEUSER, pid, getDROffset(6), 0);
}

void* HwBreakpoint::getWatchedAddress(int slot) {
    if (slot < 0 || slot >= MAX_BREAKPOINTS) return nullptr;
    return watchedAddresses[slot];
}

bool HwBreakpoint::isSlotActive(int slot) {
    if (slot < 0 || slot >= MAX_BREAKPOINTS) return false;
    return slots[slot];
}
