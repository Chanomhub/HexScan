#ifndef HEX_SCAN_ACCESSTRACKERWINDOW_H
#define HEX_SCAN_ACCESSTRACKERWINDOW_H

#include "../generic/window.h"
#include "../../../backend/debugger/hwBreakpoint.h"
#include <vector>
#include <string>

struct DisplayRecord {
    AccessRecord record;
    std::string mnemonic;
    std::string operands;
    std::string fullInstruction;
    size_t instructionLength = 0;
};

class AccessTrackerWindow final : public Window {
    void* watchAddress = nullptr;
    std::vector<DisplayRecord> cachedRecords;
    
    void drawControls();
    void drawResults();
    
public:
    void draw() override;
    
    // Start watching an address (called from Starred Addresses context menu)
    void startWatch(void* address, BreakpointType type = BreakpointType::DataReadWrite);
    void stopWatch();
    
    AccessTrackerWindow() { name = "Access Tracker"; }
};

#endif //HEX_SCAN_ACCESSTRACKERWINDOW_H
