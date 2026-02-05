#include "disassemblerWindow.h"
#include "../../../backend/virtualMemory/virtualMemory.h"
#include "../../../backend/selectedProcess/selectedProcess.h"
#include "../../../backend/patch/patchManager.h"
#include "../../../backend/debugger/accessTracker.h"
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
            line.isBranch = instr.isBranch;
            line.isConditional = instr.isConditional;
            line.targetAddress = instr.targetAddress;
            
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
    if (ImGui::BeginTable("DisasmTable", 5, 
        ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter)) {
        
        ImGui::TableSetupColumn("Flow", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImDrawList* drawList = ImGui::GetWindowDrawList();
        std::unordered_map<uint64_t, float> addrY;
        float xBase = 0.0f; // X position of the Flow column
        
        for (const auto& line : instructions) {
            ImGui::TableNextRow();
            
            // Flow Column
            ImGui::TableNextColumn();
            float currY = ImGui::GetCursorScreenPos().y + ImGui::GetTextLineHeight() / 2.0f;
            addrY[line.address] = currY;
            xBase = ImGui::GetCursorScreenPos().x;

            // Address
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "%p", (void*)line.address);
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                 ImGui::SetClipboardText(std::to_string(line.address).c_str()); 
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

            // ... Context Menu ...
            if (ImGui::BeginPopupContextItem(std::to_string(line.address).c_str())) {
                if (ImGui::MenuItem("Copy Address")) {
                    ImGui::SetClipboardText(std::format("{:x}", line.address).c_str());
                }
                if (ImGui::MenuItem("Copy Bytes")) {
                    ImGui::SetClipboardText(line.bytes.c_str());
                }
                
                bool isPatched = PatchManager::isPatched((void*)line.address);
                if (isPatched) {
                    if (ImGui::MenuItem("Restore Original Code")) {
                        PatchManager::restorePatch((void*)line.address);
                    }
                } else {
                    if (ImGui::MenuItem("NOP Instruction")) {
                        if (AccessTracker::isTracking()) {
                            AccessTracker::stopTracking();
                            Gui::log("Access Tracker stopped for safe patching.");
                        }
                        PatchManager::nopInstruction((void*)line.address, line.length, line.fullText);
                        refreshInstructions();
                    }
                }
                ImGui::EndPopup();
            }
        }
        
        // Draw Lines (Overlay)
        // We draw *after* the loop so we have all Y positions
        for (const auto& line : instructions) {
            if (line.isBranch && line.targetAddress != 0) {
                float y1 = addrY[line.address];
                float x = xBase + 20.0f; // Center of Flow column

                ImU32 col = line.isConditional ? IM_COL32(0, 255, 255, 255) : IM_COL32(200, 200, 200, 255);
                
                if (addrY.count(line.targetAddress)) {
                    // Target is visible
                    float y2 = addrY[line.targetAddress];
                    
                    // Simple bracket shape
                    drawList->AddLine(ImVec2(x, y1), ImVec2(x - 5, y1), col);
                    drawList->AddLine(ImVec2(x - 5, y1), ImVec2(x - 5, y2), col);
                    drawList->AddLine(ImVec2(x - 5, y2), ImVec2(x, y2), col);
                    
                    // Arrow head at target
                    drawList->AddTriangleFilled(
                        ImVec2(x, y2),
                        ImVec2(x - 4, y2 - 3),
                        ImVec2(x - 4, y2 + 3),
                        col
                    );
                } else {
                    // Target not visible - Point Up/Down
                    bool isUp = line.targetAddress < line.address;
                    float y2 = isUp ? y1 - 10 : y1 + 10;
                    
                    drawList->AddLine(ImVec2(x, y1), ImVec2(x - 5, y1), col);
                    drawList->AddLine(ImVec2(x - 5, y1), ImVec2(x - 5, y2), col);
                    
                    // Arrow head pointing off-screen
                    // (Optional)
                }
            }
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
