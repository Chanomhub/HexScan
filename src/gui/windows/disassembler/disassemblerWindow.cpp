#include "disassemblerWindow.h"
#include "../../../backend/virtualMemory/virtualMemory.h"
#include "../../../backend/selectedProcess/selectedProcess.h"
#include "../../../backend/patch/patchManager.h"
#include "../../gui.h"

#include <imgui.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

DisassemblerWindow::DisassemblerWindow(uint64_t startAddress) : currentAddress(startAddress) {
    name = "Disassembler";
    baseAddress = SelectedProcess::getBaseAddress();
    if (currentAddress == 0) {
        currentAddress = baseAddress;
    }
}

void DisassemblerWindow::goToAddress(uint64_t address) {
    currentAddress = address;
    refreshInstructions();
}

void DisassemblerWindow::refreshInstructions() {
    instructions.clear();
    
    if (SelectedProcess::pid == -1) return;
    
    // Read a chunk of memory
    constexpr size_t BUFFER_SIZE = 1024;
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    
    // We read a bit more to handle variable length instructions
    if (!VirtualMemory::read((void*)currentAddress, buffer.data(), BUFFER_SIZE)) {
        // Failed to read, maybe invalid page
        return;
    }
    
    size_t offset = 0;
    uint64_t addr = currentAddress;
    
    // Disassemble roughly 50 instructions or until buffer end
    for (int i = 0; i < 50 && offset < BUFFER_SIZE; i++) {
        auto instr = Disassembler::disassemble(buffer.data() + offset, BUFFER_SIZE - offset, addr);
        
        if (!instr.valid) {
            // If invalid, just skip 1 byte (db)
            DisassembledLine line;
            line.address = addr;
            
            std::ostringstream hex;
            hex << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[offset];
            line.bytes = hex.str();
            
            line.mnemonic = "??";
            line.operands = "";
            line.fullText = "??";
            line.length = 1;
            
            instructions.push_back(line);
            
            offset += 1;
            addr += 1;
        } else {
            DisassembledLine line;
            line.address = addr;
            
            // Format bytes
            std::ostringstream hex;
            for (size_t b = 0; b < instr.length; b++) {
                if (b > 0) hex << " ";
                hex << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[offset + b];
            }
            line.bytes = hex.str();
            
            line.mnemonic = instr.mnemonic;
            line.operands = instr.operands;
            line.fullText = instr.fullText;
            line.length = instr.length;
            
            instructions.push_back(line);
            
            offset += instr.length;
            addr += instr.length;
        }
    }
}

void DisassemblerWindow::drawMenuBar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Refresh")) {
                refreshInstructions();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

void DisassemblerWindow::drawTable() {
    // Top bar: Address navigation
    ImGui::Text("Address:");
    ImGui::SameLine();
    
    char addrBuf[32];
    snprintf(addrBuf, sizeof(addrBuf), "%lx", currentAddress);
    ImGui::PushItemWidth(150);
    if (ImGui::InputText("##addrInput", addrBuf, sizeof(addrBuf), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
        try {
            uint64_t newAddr = std::stoull(addrBuf, nullptr, 16);
            goToAddress(newAddr);
        } catch (...) {}
    }
    ImGui::PopItemWidth();
    
    ImGui::SameLine();
    if (ImGui::Button("Go")) {
         try {
            uint64_t newAddr = std::stoull(addrBuf, nullptr, 16);
            goToAddress(newAddr);
        } catch (...) {}
    }

    // Main Table
    if (ImGui::BeginTable("DisasmTable", 4, 
        ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter)) {
        
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        
        for (const auto& line : instructions) {
            ImGui::TableNextRow();
            
            // Address
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "%p", (void*)line.address);
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                 ImGui::SetClipboardText(std::to_string(line.address).c_str()); // Or hex string
            }
            
            // Bytes
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%s", line.bytes.c_str());
            
            // Mnemonic
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%s", line.mnemonic.c_str());
            
            // Operands
            ImGui::TableNextColumn();
            ImGui::Text("%s", line.operands.c_str());
        }
        
        ImGui::EndTable();
    }
}

void DisassemblerWindow::draw() {
    if (!ImGui::Begin(name.c_str(), &pOpen, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }
    
    drawMenuBar();
    
    // Auto-refresh if empty
    if (instructions.empty() && SelectedProcess::pid != -1) {
        refreshInstructions();
    }
    
    drawTable();
    
    ImGui::End();
}
