#ifndef HEX_SCAN_DISASSEMBLER_H
#define HEX_SCAN_DISASSEMBLER_H

#include <string>
#include <vector>
#include <cstdint>

namespace Disassembler {
    struct Instruction {
        std::string mnemonic;      // e.g. "mov"
        std::string operands;      // e.g. "[rbx+0x120], eax"
        std::string fullText;      // e.g. "mov [rbx+0x120], eax"
        size_t length;             // instruction length in bytes
        bool isWrite;              // is it writing to memory?
        bool isRead;               // is it reading from memory?
        bool valid;                // successfully disassembled
    };
    
    // Initialize Zydis decoder/formatter if needed
    void init();
    
    // Disassemble bytes into an instruction
    Instruction disassemble(const uint8_t* bytes, size_t size, uint64_t address);
    
    // Create NOP bytes of specified length
    std::vector<uint8_t> createNOP(size_t length);
}

#endif //HEX_SCAN_DISASSEMBLER_H
