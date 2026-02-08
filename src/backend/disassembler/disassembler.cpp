#include "disassembler.h"
#include <Zydis/Zydis.h>
#include <Zydis/Utils.h>
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
                
                // Calculate branch target
                uint64_t target = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, operands, address, &target))) {
                     result.targetAddress = target;
                } else {
                    result.targetAddress = 0;
                }

                // Check meta info
                result.isBranch = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR || 
                                   instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                                   instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                                   instruction.meta.category == ZYDIS_CATEGORY_RET);
                                   
                result.isConditional = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR);
            }
        }
        
        return result;
    }


    std::vector<uint8_t> createNOP(size_t length) {
        return std::vector<uint8_t>(length, NOP_BYTE);
    }
    
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> createWildcardAOB(const uint8_t* bytes, size_t size, uint64_t address) {
        std::vector<uint8_t> outBytes;
        std::vector<uint8_t> outMask;
        
        if (!bytes || size == 0) return {outBytes, outMask};
        
        // Initialize decoder
        ZydisDecoder decoder;
        if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            return {outBytes, outMask};
        }
        
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        
        // Use DecodeFull to get operands and raw info
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes, size, &instruction, operands))) {
            outBytes.resize(instruction.length);
            outMask.resize(instruction.length, 0xFF); // Default: match everything
            
            // Copy raw bytes
            std::memcpy(outBytes.data(), bytes, instruction.length);
            
            // Mask relative displacement
            if (instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM) {
                 if (instruction.raw.disp.size > 0 && instruction.raw.disp.offset > 0) {
                     // Check if rip-relative memory operand
                     for(int i=0; i<instruction.operand_count; ++i) {
                         if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                             operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                             // Mask displacement bytes
                             for (int j = 0; j < instruction.raw.disp.size / 8; ++j) {
                                 size_t offset = instruction.raw.disp.offset / 8 + j;
                                 if (offset < outMask.size()) outMask[offset] = 0x00;
                             }
                             break;
                         }
                     }
                 }
            }
            
            // Mask relative immediate (e.g. JZA, CALL)
            // Usually branch instructions with immediate operand
            if (instruction.meta.category == ZYDIS_CATEGORY_COND_BR || 
                instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR || 
                instruction.meta.category == ZYDIS_CATEGORY_CALL) {
                
                for(int i=0; i<instruction.operand_count; ++i) {
                     if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
                         // Find immediate offset in raw instruction
                         // Zydis puts immediate info in instruction.raw.imm[i]
                         // But we need to match operand index to imm index?
                         // Usually imm[0] corresponds to the immediate operand.
                         
                         // Iterate raw imms
                         for(int k=0; k<2; ++k) {
                             if (instruction.raw.imm[k].size > 0 && instruction.raw.imm[k].is_relative) {
                                  for (int j = 0; j < instruction.raw.imm[k].size / 8; ++j) {
                                     size_t offset = instruction.raw.imm[k].offset / 8 + j;
                                     if (offset < outMask.size()) outMask[offset] = 0x00;
                                 }
                             }
                         }
                     }
                }
            }
        }
        
        return {outBytes, outMask};
    }
}
