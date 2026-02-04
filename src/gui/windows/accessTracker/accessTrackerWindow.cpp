#include "accessTrackerWindow.h"
#include "../../../backend/debugger/accessTracker.h"
#include "../../../backend/disassembler/disassembler.h"
#include "../../../backend/patch/patchManager.h"
#include "../../gui.h"

#include <imgui.h>
#include <sstream>
#include <iomanip>
#include <iostream>

void AccessTrackerWindow::startWatch(void* address, BreakpointType type) {
    std::cerr << "DEBUG: startWatch called for " << address << std::endl;
    stopWatch();  // Stop any existing watch
    
    watchAddress = address;
    std::cerr << "DEBUG: Calling AccessTracker::startTracking" << std::endl;
    if (AccessTracker::startTracking(address, type)) {
        Gui::log("Access Tracker: Watching {:p}", address);
        std::cerr << "DEBUG: startTracking success" << std::endl;
    } else {
        watchAddress = nullptr;
        Gui::log("Access Tracker: Failed to start");
    }
}

void AccessTrackerWindow::stopWatch() {
    if (AccessTracker::isTracking()) {
        AccessTracker::stopTracking();
    }
    watchAddress = nullptr;
    cachedRecords.clear();
}

void AccessTrackerWindow::drawControls() {
    bool isTracking = AccessTracker::isTracking();
    
    if (isTracking) {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "● Tracking");
        ImGui::SameLine();
        ImGui::Text("Address: %p", watchAddress);
        
        ImGui::SameLine();
        if (ImGui::Button("Stop")) {
            stopWatch();
        }
        
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            AccessTracker::clearRecords();
            cachedRecords.clear();
        }
        
        // Refresh cached records periodically
        static int frameCount = 0;
        if (++frameCount % 30 == 0) {  // Every 30 frames
            std::vector<AccessRecord> rawRecords = AccessTracker::getRecords();
            
            std::vector<DisplayRecord> newRecords;
            newRecords.reserve(rawRecords.size());
            
            for (const auto& raw : rawRecords) {
                DisplayRecord display;
                display.record = raw;
                
                // Disassemble
                auto instr = Disassembler::disassemble(raw.instructionBytes.data(), 
                                                     raw.instructionBytes.size(), 
                                                     reinterpret_cast<uint64_t>(raw.instructionAddress));
                
                if (instr.valid) {
                    display.mnemonic = instr.mnemonic;
                    display.operands = instr.operands;
                    display.fullInstruction = instr.fullText;
                    display.instructionLength = instr.length;
                } else {
                    display.fullInstruction = "??";
                    display.instructionLength = 0;
                }
                
                newRecords.push_back(display);
            }
            
            cachedRecords = std::move(newRecords);
        }
    } else {
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "○ Not tracking");
        ImGui::SameLine();
        ImGui::TextDisabled("Right-click an address in Starred Addresses to start");
    }
    
    ImGui::Separator();
    
    // Show stats
    ImGui::Text("Unique instructions: %zu | Total accesses: %llu",
                cachedRecords.size(),
                static_cast<unsigned long long>(AccessTracker::getTotalAccessCount()));
}

void AccessTrackerWindow::drawResults() {
    if (ImGui::BeginTable("AccessRecords", 4, 
            ImGuiTableFlags_Resizable | 
            ImGuiTableFlags_RowBg | 
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Sortable)) {
        
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableHeadersRow();
        
        for (size_t i = 0; i < cachedRecords.size(); ++i) {
            const auto& item = cachedRecords[i];
            const auto& record = item.record;
            
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));
            
            // Count
            ImGui::TableNextColumn();
            ImGui::Text("%llu", static_cast<unsigned long long>(record.accessCount));
            
            // Address
            ImGui::TableNextColumn();
            ImGui::Text("%p", record.instructionAddress);
            
            // Instruction
            ImGui::TableNextColumn();
            if (!item.fullInstruction.empty()) {
                ImGui::TextUnformatted(item.fullInstruction.c_str());
            } else {
                ImGui::TextDisabled("?");
            }
            
            // Tooltip with AOB details
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("Mnemonic: %s", item.mnemonic.c_str());
                ImGui::Text("Operands: %s", item.operands.c_str());
                ImGui::Text("Bytes: %s", AccessTracker::getAOBString(record).c_str());
                ImGui::EndTooltip();
            }
            
            // Actions
            ImGui::TableNextColumn();
            
            // NOP / Restore
            bool isPatched = PatchManager::isPatched(record.instructionAddress);
            
            if (isPatched) {
                if (ImGui::Button("Restore")) {
                     PatchManager::restorePatch(record.instructionAddress);
                }
            } else {
                if (item.instructionLength > 0) {
                     if (ImGui::Button("NOP")) {
                         PatchManager::nopInstruction(record.instructionAddress, item.instructionLength, item.fullInstruction);
                     }
                } else {
                    ImGui::BeginDisabled();
                    ImGui::Button("NOP");
                    ImGui::EndDisabled();
                }
            }
            
            ImGui::SameLine();
            
            if (ImGui::Button("Copy AOB")) {
                ImGui::SetClipboardText(AccessTracker::getAOBString(record).c_str());
                Gui::log("Copied AOB to clipboard");
            }
            
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
}

void AccessTrackerWindow::draw() {
    if (!ImGui::Begin(name.c_str(), &pOpen)) {
        ImGui::End();
        return;
    }
    
    drawControls();
    drawResults();
    
    ImGui::End();
}
