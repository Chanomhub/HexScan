#ifndef HEX_SCAN_HWBREAKPOINT_H
#define HEX_SCAN_HWBREAKPOINT_H

#include <cstdint>
#include <vector>
#include <string>

enum class BreakpointType : uint8_t {
    Execute = 0b00,       // Break on instruction execution
    DataWrite = 0b01,     // Break on data write only
    IOReadWrite = 0b10,   // Break on I/O read/write (rarely used)
    DataReadWrite = 0b11  // Break on data read or write
};

enum class BreakpointSize : uint8_t {
    Byte1 = 0b00,
    Byte2 = 0b01,
    Byte4 = 0b11,
    Byte8 = 0b10  // Only valid in 64-bit mode
};

// Record of an instruction that accessed a watched address
struct AccessRecord {
    void* instructionAddress;               // RIP when breakpoint triggered
    std::vector<uint8_t> instructionBytes;  // Bytes at RIP (up to 16 bytes for AOB)
    uint64_t accessCount;                   // Number of times this instruction accessed
    bool isWrite;                           // true = write, false = read (best guess)
    
    AccessRecord() : instructionAddress(nullptr), accessCount(0), isWrite(false) {}
};

namespace HwBreakpoint {
    // Maximum number of hardware breakpoints (x86/x64 limit)
    constexpr int MAX_BREAKPOINTS = 4;
    
    // Set hardware breakpoint on address (uses DR0-DR3)
    // Returns breakpoint slot (0-3) or -1 on failure
    int set(void* address, BreakpointType type, BreakpointSize size);
    
    // Clear breakpoint by slot
    bool clear(int slot);
    
    // Clear all breakpoints
    void clearAll();
    
    // Check if any slot is available
    bool hasAvailableSlot();
    
    // Get number of active breakpoints
    int activeCount();
    
    // Check which slot is triggered (from DR6)
    int getTriggeredSlot();
    
    // Clear DR6 status after handling breakpoint
    void clearStatus();
    
    // Get the address being watched in a slot
    void* getWatchedAddress(int slot);
    
    // Check if slot is active
    bool isSlotActive(int slot);
}

#endif //HEX_SCAN_HWBREAKPOINT_H
