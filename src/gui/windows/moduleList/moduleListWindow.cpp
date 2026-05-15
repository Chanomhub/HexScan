#include "moduleListWindow.h"
#include "../../gui.h"
#include "../windows.h"

#include <imgui.h>
#include <format>
#include <cstring>
#include <algorithm>

void ModuleListWindow::draw() {
    ImGui::Begin(name.c_str(), &pOpen);
    
    // Refresh modules periodically (every ~120 frames)
    if (refreshCounter++ >= 120 || modules.empty()) {
        modules = ModuleList::getModules();
        refreshCounter = 0;
    }
    
    // Filter input
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Refresh").x - ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().ItemSpacing.x);
    ImGui::InputTextWithHint("##filter", "Filter modules...", filterBuf, sizeof(filterBuf));
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) {
        modules = ModuleList::getModules();
    }
    
    ImGui::Text("%zu modules loaded", modules.size());
    ImGui::Separator();
    
    if (ImGui::BeginTable("ModuleTable", 4, 
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | 
            ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV)) {
        
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort);
        ImGui::TableSetupColumn("Base Address");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Path");
        ImGui::TableHeadersRow();
        
        // Sort
        if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs()) {
            if (sortSpecs->SpecsDirty) {
                auto spec = sortSpecs->Specs[0];
                std::sort(modules.begin(), modules.end(), [&](const Module& a, const Module& b) {
                    bool result = false;
                    switch (spec.ColumnIndex) {
                        case 0: result = a.name < b.name; break;
                        case 1: result = a.baseAddress < b.baseAddress; break;
                        case 2: result = a.size < b.size; break;
                        case 3: result = a.path < b.path; break;
                    }
                    return spec.SortDirection == ImGuiSortDirection_Ascending ? result : !result;
                });
                sortSpecs->SpecsDirty = false;
            }
        }
        
        std::string filterStr(filterBuf);
        
        for (const auto& mod : modules) {
            // Apply filter
            if (!filterStr.empty()) {
                if (mod.name.find(filterStr) == std::string::npos && 
                    mod.path.find(filterStr) == std::string::npos)
                    continue;
            }
            
            ImGui::TableNextRow();
            
            ImGui::TableNextColumn();
            bool selected = false;
            if (ImGui::Selectable(mod.name.c_str(), &selected, ImGuiSelectableFlags_SpanAllColumns)) {
                // On click: open memory editor at base address
                Gui::addWindow(new MemoryEditorWindow(mod.baseAddress));
            }
            
            // Context menu
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Open in memory editor"))
                    Gui::addWindow(new MemoryEditorWindow(mod.baseAddress));
                if (ImGui::MenuItem("Open in disassembler"))
                    Gui::showDisassembler(mod.baseAddress);
                if (ImGui::MenuItem("Copy base address"))
                    ImGui::SetClipboardText(std::format("0x{:x}", mod.baseAddress).c_str());
                if (ImGui::MenuItem("Copy path"))
                    ImGui::SetClipboardText(mod.path.c_str());
                ImGui::EndPopup();
            }
            
            ImGui::TableNextColumn();
            ImGui::Text("0x%lx", mod.baseAddress);
            
            ImGui::TableNextColumn();
            if (mod.size >= 1024 * 1024)
                ImGui::Text("%.1f MB", mod.size / (1024.0 * 1024.0));
            else if (mod.size >= 1024)
                ImGui::Text("%.1f KB", mod.size / 1024.0);
            else
                ImGui::Text("%lu B", mod.size);
            
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(mod.path.c_str());
        }
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}
