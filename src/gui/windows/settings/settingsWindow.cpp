#include "settingsWindow.h"
#include "../../../backend/settings/settings.h"
#include <imgui.h>

void SettingsWindow::draw() {
    ImGui::Begin(name.c_str(), &pOpen);
    
    if (ImGui::CollapsingHeader("Scan Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::TreeNode("All Scan Type Configuration")) {
            ImGui::Checkbox("int64", &Settings::allScanI64);
            ImGui::Checkbox("int32", &Settings::allScanI32);
            ImGui::Checkbox("int16", &Settings::allScanI16);
            ImGui::Checkbox("int8", &Settings::allScanI8);
            ImGui::Checkbox("float64 (double)", &Settings::allScanF64);
            ImGui::Checkbox("float32 (float)", &Settings::allScanF32);
            ImGui::Checkbox("string", &Settings::allScanString);
            ImGui::TreePop();
        }
    }
    
    ImGui::End();
}
