#ifndef HEX_SCAN_DISASSEMBLERWINDOW_H
#define HEX_SCAN_DISASSEMBLERWINDOW_H

#include "../generic/window.h"
#include "../../../backend/disassembler/disassembler.h"
#include <vector>

class DisassemblerWindow : public Window {
private:
    uint64_t currentAddress;
    uint64_t baseAddress;
    
    struct DisassembledLine {
        uint64_t address;
        std::string bytes;
        std::string mnemonic;
        std::string operands;
        std::string fullText;
        size_t length;
    };
    
    std::vector<DisassembledLine> instructions;
    
    void refreshInstructions();
    void drawMenuBar();
    void drawTable();

public:
    explicit DisassemblerWindow(uint64_t startAddress = 0);
    void draw() override;
    
    void goToAddress(uint64_t address);
};

#endif //HEX_SCAN_DISASSEMBLERWINDOW_H
