#include "disassembler.h"
#include <Zydis/Zydis.h>
#include <cstring>
#include <algorithm>

namespace Disassembler {

    // NOP (0x90)
    constexpr uint8_t NOP_BYTE = 0x90;

    // Remove static instances/init
    // We will initialize on stack per-call to avoid memory issues

    void init() {
        // No-op now
        fprintf(stderr, "DEBUG: Disassembler::init() - No-op (Stack Mode)\n");
    }

    Instruction disassemble(const uint8_t* bytes, size_t size, uint64_t address) {
        Instruction result = {};
        result.valid = false;
        result.length = 0;
        
        if (!bytes || size == 0) return result;

        // Stack allocation - Verified to work
        ZydisDecoder decoder;
        ZydisFormatter formatter;
        
        // Initialize Decoder
        if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            return result;
        }

        // Initialize Formatter
        if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
             return result;
        }
        
        // Note: ZydisFormatterSetProperty caused segfaults, so we use default settings.
        // ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_HEX_PREFIX, ZYAN_TRUE);
        
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes, size, &instruction, operands))) {
            char buffer[256];
            
            if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                                           instruction.operand_count_visible, 
                                                           buffer, sizeof(buffer), address, ZYAN_NULL))) {
                result.fullText = buffer;
                result.mnemonic = ZydisMnemonicGetString(instruction.mnemonic);
                
                // Extract operands
                if (result.fullText.length() > result.mnemonic.length()) {
                    size_t start = result.mnemonic.length();
                    while (start < result.fullText.length() && result.fullText[start] == ' ') start++;
                    result.operands = result.fullText.substr(start);
                }
                
                result.length = instruction.length;
                result.valid = true;
                
                result.isRead = false;
                result.isWrite = false;
                
                for (int i = 0; i < instruction.operand_count; ++i) {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        if (op.actions & ZYDIS_OPERAND_ACTION_READ) result.isRead = true;
                        if (op.actions & ZYDIS_OPERAND_ACTION_WRITE) result.isWrite = true;
                    }
                }
            }
        }
        
        return result;
    }


    std::vector<uint8_t> createNOP(size_t length) {
        return std::vector<uint8_t>(length, NOP_BYTE);
    }
}
