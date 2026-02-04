#ifndef HEX_SCAN_ACCESSTRACKER_H
#define HEX_SCAN_ACCESSTRACKER_H

#include "hwBreakpoint.h"
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>

namespace AccessTracker {
    // Start tracking accesses to an address
    // type: DataWrite for writes only, DataReadWrite for both
    bool startTracking(void* address, BreakpointType type = BreakpointType::DataReadWrite);
    
    // Stop tracking and release the breakpoint
    void stopTracking();
    
    // Check if tracking is active
    bool isTracking();
    
    // Check if we are currently attached to the process (ptrace active)
    // Used by VirtualMemory to decide how to read memory
    bool isAttached();
    
    // Get recorded accesses (thread-safe copy)
    std::vector<AccessRecord> getRecords();
    
    // Clear all recorded accesses
    void clearRecords();
    
    // Get total number of accesses recorded
    uint64_t getTotalAccessCount();
    
    // Get instruction bytes formatted as AOB string
    std::string getAOBString(const AccessRecord& record);
    
    // Get the address being tracked
    void* getTrackedAddress();
}

#endif //HEX_SCAN_ACCESSTRACKER_H
