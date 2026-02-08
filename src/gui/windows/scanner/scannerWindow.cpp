#include "scannerWindow.h"
#include "../../widgets/widgets.h"
#include "../../../backend/virtualMemory/virtualMemory.h"
#include "../../../backend/scanner/aobUtils.h"
#include "../../gui.h"
#include "../memoryEditor/memoryEditorWindow.h"
#include "../starredAddresses/starredAddressesWindow.h"
#include "../../../backend/disassembler/disassembler.h"

#include <imgui.h>
#include <format>
#include <iostream>

void ScannerWindow::scanControls() {
    const bool isScanRunning = scanner.isRunning();
    const bool isScannerReset = scanner.hasBeenReset();

    ImGui::BeginGroup();

    if (isScanRunning)
        ImGui::BeginDisabled();
    const ScanType type = scanner.getScanType();
    const bool shouldDisable = type == ScanType::Unchanged || 
                              type == ScanType::Changed || 
                              type == ScanType::Unknown || 
                              type == ScanType::Increased || 
                              type == ScanType::Decreased;

    if (shouldDisable)
        ImGui::BeginDisabled(true);
    if (scanner.getScanType() == ScanType::Range) {
        ImGui::SetNextItemWidth(ImGui::GetWindowWidth() / 4 - ImGui::GetStyle().FramePadding.x);
        Widgets::valueInputTrueOnEditing(scanner.getValueType(), scanner.getValueBytesRef().data());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetWindowWidth() / 4 - ImGui::GetStyle().FramePadding.x);
        Widgets::valueInputTrueOnEditing(scanner.getValueType(), scanner.getValueBytesSecondRef().data());
    } else if (scanner.getValueType().type == byteArray) {
        // AOB uses text input for hex pattern
        ImGui::SetNextItemWidth(ImGui::GetWindowWidth() / 2);
        ImGui::InputTextWithHint("##AOBInput", "48 8B ?? 00 AA", aobInputBuffer, sizeof(aobInputBuffer));
    } else {
        ImGui::SetNextItemWidth(ImGui::GetWindowWidth() / 2);
        Widgets::valueInputTrueOnEditing(scanner.getValueType(), scanner.getValueBytesRef().data(), 256);
    }
    if (shouldDisable)
        ImGui::EndDisabled();

    if (isScanRunning)
        ImGui::EndDisabled();

    if (scanner.hasBeenReset()) {
        if (isScanRunning) ImGui::BeginDisabled();
        if (ImGui::Button("New")) {
            // Handle AOB parsing before scan
            if (scanner.getValueType().type == byteArray) {
                auto parseResult = ParseAOBString(aobInputBuffer);
                if (parseResult.success) {
                    scanner.setValue(parseResult.bytes);
                    scanner.setValueMask(parseResult.mask);
                    
                    auto vt = scanner.getValueType();
                    vt.stringLength = parseResult.bytes.size();
                    scanner.setValueType(vt);
                    
                    scanner.setFastScanOffset(1);  // Force byte-aligned scanning for AOB
                    scanner.setScanType(ScanType::Equal);    // AOB only supports equal
                    scanner.newScan();
                } else {
                    Gui::log("AOB Parse Error: {}", parseResult.errorMessage);
                }
            } else {
                scanner.newScan();
            }
        }
        
        ImGui::SameLine();
        bool liveScan = scanner.getLiveScan();
        if (ImGui::Checkbox("Live", &liveScan))
            scanner.setLiveScan(liveScan);
        if (ImGui::IsItemHovered())
             ImGui::SetTooltip("Keep scanning until result found (Good for JIT/Late loading)");

        if (isScanRunning) ImGui::EndDisabled();
        
        if (isScanRunning) {
            ImGui::SameLine();
            if (ImGui::Button("Stop"))
                scanner.cancelScan();
        }
    } else {
        if (isScanRunning) ImGui::BeginDisabled();
        
        if (ImGui::Button("Reset"))
            scanner.reset();

        ImGui::SameLine();
        if (ImGui::Button("Next"))
            scanner.nextScan();
            
        if (isScanRunning) ImGui::EndDisabled();

        ImGui::SameLine();
        bool autoNext = scanner.getIsAutonextEnabled();
        if (ImGui::Checkbox("auto", &autoNext))
            scanner.setIsAutonextEnabled(autoNext);
            
        if (scanner.getIsAutonextEnabled() and !scanner.isRunning())
            scanner.nextScan();
            
        if (isScanRunning) {
            ImGui::SameLine();
            if (ImGui::Button("Stop"))
                scanner.cancelScan();
        }
    }

    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();

    if (!isScannerReset)
        ImGui::BeginDisabled();

    ImGui::SetNextItemWidth(-1);
    
    // Modify valueType
    {
        auto vt = scanner.getValueType();
        Widgets::valueTypeSelector(vt, false);
        vt.stringLength = 256;
        scanner.setValueType(vt);
    }
    
    scanner.getValueBytesRef().resize(scanner.getValueType().getSize());
    scanner.getValueBytesSecondRef().resize(scanner.getValueType().getSize());

    if (!isScannerReset)
        ImGui::EndDisabled();

    ImGui::SetNextItemWidth(-1);
    if (isScannerReset) {
        if (scanner.getValueType().type == string) {
            constexpr std::array indexMapping{ScanType::Equal, ScanType::Unknown};
            const char* items[]{"Equal", "Unknown"};
            int currentItem = 0;
            for (int i = 0; i < 2; ++i)
                if (indexMapping[i] == scanner.getScanType())
                    currentItem = i;

            if ((unsigned)currentItem > 2) {
                currentItem = 0;
                scanner.setScanType(ScanType::Equal);
            } else if (indexMapping[currentItem] != scanner.getScanType()) {
                scanner.setScanType(ScanType::Equal);
            }
            if (ImGui::Combo("##My Combo", &currentItem, items, IM_ARRAYSIZE(items)))
                scanner.setScanType(indexMapping[currentItem]);
        } else if (scanner.getValueType().type == byteArray) {
            // AOB only supports Equal scan type
            scanner.setScanType(ScanType::Equal);
            ImGui::BeginDisabled();
            int dummy = 0;
            const char* items[]{"Equal"};
            ImGui::Combo("##AOB Scan Type", &dummy, items, 1);
            ImGui::EndDisabled();
        } else {
            constexpr std::array indexMapping{ScanType::Equal, ScanType::Bigger, ScanType::Smaller, ScanType::Range, ScanType::Unknown};
            const char* items[]{"Equal", "Bigger than", "Smaller than", "Range", "Unknown"};
            int currentItem = 0;
            for (int i = 0; i < 5; ++i)
                if (indexMapping[i] == scanner.getScanType())
                    currentItem = i;
            if (ImGui::Combo("##My Combo", &currentItem, items, IM_ARRAYSIZE(items)))
                scanner.setScanType(indexMapping[currentItem]);
        }
    } else {
        if (scanner.getScanType() >= ScanType::Unknown)
             scanner.setScanType(ScanType::Equal);
             
        // Safe casting for combo box not possible directly with enum class, need manual mapping or assumption
        // Assuming the order matches for simple cases, but since ScanType is enum class, we can't just cast address.
        // We must use a local int.
        
        int currentType = (int)scanner.getScanType();
        
        if (scanner.getValueType().type == string) {
            // "Equal\0Changed\0Unchanged\0\0" -> 0, 8, 9 ? No.
            // Combo returns index 0, 1, 2.
            // Mapping: 0->Equal, 1->Changed, 2->Unchanged.
            int item = 0;
            if (scanner.getScanType() == ScanType::Changed) item = 1;
            else if (scanner.getScanType() == ScanType::Unchanged) item = 2;
            
            if (ImGui::Combo("##scanner_scan_type", &item, "Equal\0Changed\0Unchanged\0\0")) {
                if (item == 0) scanner.setScanType(ScanType::Equal);
                else if (item == 1) scanner.setScanType(ScanType::Changed);
                else if (item == 2) scanner.setScanType(ScanType::Unchanged);
            }
        }
        else if (scanner.getValueType().type == byteArray) {
            // AOB only supports Equal
            scanner.setScanType(ScanType::Equal);
            ImGui::BeginDisabled();
            int dummy = 0;
            ImGui::Combo("##scanner_scan_type", &dummy, "Equal\0\0");
            ImGui::EndDisabled();
        } else {
             // "Equal\0Bigger than\0Smaller than\0Range\0Increased\0Increased by\0Decreased\0Decreased by\0Changed\0Unchanged\0\0"
             // Indices match ScanType order?
             // Equal=0, Bigger=1, Smaller=2, Range=3, Increased=4, IncreasedBy=5, Decreased=6, DecreasedBy=7, Changed=8, Unchanged=9.
             // ScanType enum: Equal, Bigger, Smaller, Range, Increased, IncreasedBy, Decreased, DecreasedBy, Changed, Unchanged, Unknown.
             // The order matches perfectly!
             
             if (ImGui::Combo("##scanner_scan_type", &currentType, "Equal\0Bigger than\0Smaller than\0Range\0Increased\0Increased by\0Decreased\0Decreased by\0Changed\0Unchanged\0\0")) {
                 scanner.setScanType((ScanType)currentType);
             }
        }
    }

    ImGui::EndGroup();

    static int regionPermR = 2, regionPermW = 1, regionPermX = 1, regionPermP = 1;
    if (ImGui::TreeNode("Settings")) {
        Widgets::tristateCheckbox("r", &regionPermR);
        ImGui::SameLine();
        Widgets::tristateCheckbox("w", &regionPermW);
        ImGui::SameLine();
        Widgets::tristateCheckbox("x", &regionPermX);
        ImGui::SameLine();
        Widgets::tristateCheckbox("p", &regionPermP);
        ImGui::SameLine();
        ImGui::TextUnformatted("Region permissions");

        ImGui::SetNextItemWidth(40);
        if (!isScannerReset)
            ImGui::BeginDisabled(true);
        unsigned fOffset = scanner.getFastScanOffset();
        if (ImGui::InputScalar("Fast scan offset", ImGuiDataType_U32, &fOffset))
            scanner.setFastScanOffset(fOffset);
        if (!isScannerReset)
            ImGui::EndDisabled();
            
        bool suspend = scanner.getShouldSuspendWhileScanning();
        if (ImGui::Checkbox("Suspend while scanning", &suspend))
             scanner.setShouldSuspendWhileScanning(suspend);
             
        ImGui::TreePop();
    }
    
    auto& regions = scanner.getRegions();
    regions.mustHavePerms = regionPermR == 2 ? RegionPerms(regions.mustHavePerms | r) : RegionPerms(regions.mustHavePerms & ~r);
    regions.mustHavePerms = regionPermW == 2 ? RegionPerms(regions.mustHavePerms | w) : RegionPerms(regions.mustHavePerms & ~w);
    regions.mustHavePerms = regionPermX == 2 ? RegionPerms(regions.mustHavePerms | x) : RegionPerms(regions.mustHavePerms & ~x);
    regions.mustHavePerms = regionPermP == 2 ? RegionPerms(regions.mustHavePerms | p) : RegionPerms(regions.mustHavePerms & ~p);

    regions.mustNotHavePerms = regionPermR == 0 ? RegionPerms(regions.mustNotHavePerms | r) : RegionPerms(regions.mustNotHavePerms & ~r);
    regions.mustNotHavePerms = regionPermW == 0 ? RegionPerms(regions.mustNotHavePerms | w) : RegionPerms(regions.mustNotHavePerms & ~w);
    regions.mustNotHavePerms = regionPermX == 0 ? RegionPerms(regions.mustNotHavePerms | x) : RegionPerms(regions.mustNotHavePerms & ~x);
    regions.mustNotHavePerms = regionPermP == 0 ? RegionPerms(regions.mustNotHavePerms | p) : RegionPerms(regions.mustNotHavePerms & ~p);




    ImGui::NewLine();

    if (isScannerReset)
        ImGui::BeginDisabled(true);
    char buf[64];
    sprintf(buf, "%llu/%llu", scanner.getScannedAddresses(), scanner.getTotalAddresses());
    const float progress = scanner.getScannedAddresses() == 0 ? 0.0 : (float)scanner.getScannedAddresses() / scanner.getTotalAddresses();
    ImGui::ProgressBar(progress, ImVec2(-(ImGui::CalcTextSize("Add all").x + ImGui::GetStyle().FramePadding.x * 2 + ImGui::GetStyle().ItemSpacing.x), 0.0f), buf);

    ImGui::SameLine();
    if (ImGui::Button("Add all")) {
        const auto starredAddressesWindow = Gui::getWindows<StarredAddressesWindow>().front();
        const auto addresses = scanner.getAddresses();
        for (const auto row: addresses)
            starredAddressesWindow->addAddress("New address", (void*)row, scanner.getValueType());
    }
    if (isScannerReset)
        ImGui::EndDisabled();
}

void ScannerWindow::scanResults() {
    if (scanner.isRunning())
        return;
        
    const auto addresses = scanner.getAddresses();
    if (addresses.empty())
        return;
        
    if (ImGui::BeginTable("CurrentAddresses", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("Previous");
        ImGui::TableHeadersRow();

        static std::vector<char> currentRowAddressValueBytes;
        currentRowAddressValueBytes.resize(scanner.getValueBytesRef().size());

        ImGui::PushStyleColor(ImGuiCol_FrameBg, 0);
        ImGuiListClipper clipper;
        // Use addresses.size() to avoid out of bounds access
        const size_t addrSize = addresses.size();
        const int displayCount = static_cast<int>(addrSize);
        clipper.Begin(displayCount);
        
        // Fetch values for display
        const auto latestValues = scanner.getLatestValues();
        const size_t valueSize = scanner.getValueBytesRef().size();
        
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd && static_cast<size_t>(row) < addrSize; row++) {
                ImGui::TableNextRow();
                ImGui::PushID(row);
                ImGui::TableNextColumn();
                ImGui::AlignTextToFramePadding();
                
                // Bounds check before accessing addresses
                if (static_cast<size_t>(row) >= addrSize) {
                    ImGui::PopID();
                    break;
                }
                
                // Address is uintptr_t in vector, need casting if needed or void*
                void* currentAddr = (void*)addresses[row];
                
                if (scanner.getRegions().isStaticAddress(currentAddr)) {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%p", currentAddr);
                } else {
                    ImGui::Text("%p", currentAddr);
                }


                ImGui::TableNextColumn();
                ImGui::SetNextItemWidth(-1);


                VirtualMemory::read(currentAddr, currentRowAddressValueBytes.data(), currentRowAddressValueBytes.size());

                if (Widgets::valueInputTrueOnDeactivation(scanner.getValueType(), currentRowAddressValueBytes.data())) {
                    if (VirtualMemory::write(currentRowAddressValueBytes.data(), currentAddr, currentRowAddressValueBytes.size()))
                        Gui::log("Wrote {} to {:p}", scanner.getValueType().format(currentRowAddressValueBytes.data(), false), currentAddr);
                }


                ImGui::TableNextColumn();
                if (valueSize > 0 && (row * valueSize < latestValues.size())) {
                    Widgets::valueText(scanner.getValueType(), (char*)latestValues.data() + row * valueSize);
                }


                ImGui::AlignTextToFramePadding();
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, 0);
                ImGui::Selectable("##Selectable", false, ImGuiSelectableFlags_SpanAllColumns);
                ImGui::PopStyleColor();
                if (ImGui::BeginPopupContextItem("##Popup")) {
                    if (ImGui::BeginMenu("Add to starred")) {
                        for (const auto starredAddressesWindow: Gui::getWindows<StarredAddressesWindow>()) {
                            if (ImGui::MenuItem(starredAddressesWindow->name.c_str()))
                                starredAddressesWindow->addAddress("New address", currentAddr, scanner.getValueType());
                        }

                        ImGui::EndMenu();
                    }
                    
                    if (ImGui::Selectable("Copy Wildcard AOB")) {
                        uint8_t buffer[16];
                        if (VirtualMemory::read(currentAddr, buffer, 16)) {
                            auto [bytes, mask] = Disassembler::createWildcardAOB(buffer, 16, (uint64_t)currentAddr);
                            if (!bytes.empty()) {
                                std::string aob;
                                for(size_t i=0; i<bytes.size(); ++i) {
                                    if (mask[i] == 0x00) {
                                        aob += "?? ";
                                    } else {
                                        aob += std::format("{:02X} ", bytes[i]);
                                    }
                                }
                                if (!aob.empty()) aob.pop_back();
                                ImGui::SetClipboardText(aob.c_str());
                                Gui::log("Copied Wildcard AOB: {}", aob);
                            }
                        }
                    }

                    ImGui::EndPopup();
                }

                if (ImGui::IsItemHovered() and ImGui::IsMouseDoubleClicked(0)) {
                    for (const auto starredAddressesWindow: Gui::getWindows<StarredAddressesWindow>()) {
                        starredAddressesWindow->addAddress("New address", currentAddr, scanner.getValueType());
                        break;
                    }
                }

                ImGui::PopID();
            }
        }
        ImGui::PopStyleColor();
        ImGui::EndTable();
    }
}


void ScannerWindow::draw() {
    if (ImGui::Begin(name.c_str(), &pOpen)) {
        scanControls();
        scanResults();
    }
    ImGui::End();
}
