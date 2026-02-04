#include "accessTrackerWindow.h"
#include "../../../backend/debugger/accessTracker.h"
#include "../../gui.h"

#include <imgui.h>
#include <sstream>
#include <iomanip>

void AccessTrackerWindow::startWatch(void* address, BreakpointType type) {
    stopWatch();  // Stop any existing watch
    
    watchAddress = address;
    if (AccessTracker::startTracking(address, type)) {
        Gui::log("Access Tracker: Watching {:p}", address);
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
            cachedRecords = AccessTracker::getRecords();
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
        ImGui::TableSetupColumn("Bytes (AOB)", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableHeadersRow();
        
        for (size_t i = 0; i < cachedRecords.size(); ++i) {
            const auto& record = cachedRecords[i];
            
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));
            
            // Count
            ImGui::TableNextColumn();
            ImGui::Text("%llu", static_cast<unsigned long long>(record.accessCount));
            
            // Address
            ImGui::TableNextColumn();
            ImGui::Text("%p", record.instructionAddress);
            
            // Bytes as hex string
            ImGui::TableNextColumn();
            std::string aobStr = AccessTracker::getAOBString(record);
            
            // Show first ~30 chars with ellipsis if too long
            if (aobStr.length() > 40) {
                ImGui::TextUnformatted((aobStr.substr(0, 40) + "...").c_str());
            } else {
                ImGui::TextUnformatted(aobStr.c_str());
            }
            
            // Tooltip with full AOB
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushTextWrapPos(400.0f);
                ImGui::TextUnformatted(aobStr.c_str());
                ImGui::PopTextWrapPos();
                ImGui::EndTooltip();
            }
            
            // Actions
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Copy")) {
                ImGui::SetClipboardText(aobStr.c_str());
                Gui::log("Copied AOB to clipboard: {}", aobStr.substr(0, 30));
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
