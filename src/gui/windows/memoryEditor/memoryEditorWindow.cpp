#include <array>
#include <format>
#include <iostream>
#include <algorithm>
#include <cstring>

#include "memoryEditorWindow.h"
#include "../../../backend/virtualMemory/virtualMemory.h"
#include "../../../backend/regions/regions.h"
#include "../../gui.h"


void MemoryEditorWindow::updateChunk() const {
    memcpy(prevChunk, chunk, currentChunkSize);
    VirtualMemory::read((void*)startAddress, chunk, currentChunkSize);
}


void MemoryEditorWindow::draw() {
    static std::vector<float> cellHighlightTimeLeft(32768);

    static ImGuiIO& io = ImGui::GetIO();
    static ImGuiStyle& imGuiStyle = ImGui::GetStyle();

    static auto originalStyle = imGuiStyle;
    imGuiStyle.FramePadding.x = 0;
    imGuiStyle.CellPadding.x = 0;
    imGuiStyle.ItemSpacing.x = 0;
    imGuiStyle.WindowMinSize = {200, 100};
    ImGui::PushStyleColor(ImGuiCol_FrameBg, 0);


    if (ImGui::Begin(name.c_str(), &pOpen, ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar)) {
        static constexpr std::array<unsigned, 6> symbolsPerValueHex{16, 8, 4, 2, 22, 20};
        static constexpr std::array<unsigned, 6> symbolsPerValueDec{20, 11, 6, 4, 23, 15};
        const unsigned symbolsPerValue = displayAsHex ? symbolsPerValueHex[cellValueType.type] : symbolsPerValueDec[cellValueType.type];


        const ImGuiDataType ImGuiCellValueType = cellValueType.getImGuiDataType();

        const float spacingSize = ImGui::CalcTextSize(" ").x;
        const float extraSpacingSize = spacingSize * float(2 + bool(cellValueType.type == i32 or cellValueType.type == i64 or cellValueType.type == f32 or cellValueType.type == f64));
        constexpr unsigned extraSpacingAfterXValues = 4;

        const float addressColumnSize = ImGui::CalcTextSize(std::format(" {:p}: ", (void*)(startAddress + 100)).c_str()).x + extraSpacingSize;
        const float valueSize = ImGui::CalcTextSize(" ").x * symbolsPerValue;

        // Calculate ASCII column width (only for i8 hex mode)
        const bool showAscii = asciiViewEnabled && cellValueType.type == i8 && displayAsHex;
        const float asciiCharWidth = ImGui::CalcTextSize("W").x;

        const float spaceLeftForValues = ImGui::GetWindowSize().x - addressColumnSize - imGuiStyle.WindowPadding.x * 2 + spacingSize
                                        - (showAscii ? 0 : 0); // ASCII column is after the table
        const unsigned valuesPerRow = spaceLeftForValues * extraSpacingAfterXValues / ((valueSize + spacingSize + int(innerBordersEnabled)) * extraSpacingAfterXValues + extraSpacingSize);
        const unsigned rowsAvailable = ImGui::GetWindowSize().y / ImGui::CalcTextSize(" ").y;

        // Adjust for ASCII: reduce values per row to leave space for ASCII column
        unsigned effectiveValuesPerRow = valuesPerRow;
        if (showAscii && effectiveValuesPerRow > 4) {
            // Reserve space for ASCII: each byte needs ~1 char width
            const float asciiTotalWidth = asciiCharWidth * effectiveValuesPerRow + spacingSize * 2;
            const float availableWidth = ImGui::GetWindowSize().x - addressColumnSize - imGuiStyle.WindowPadding.x * 2;
            while (effectiveValuesPerRow > 4) {
                float neededWidth = effectiveValuesPerRow * (valueSize + spacingSize) 
                                  + (effectiveValuesPerRow / extraSpacingAfterXValues) * extraSpacingSize
                                  + asciiCharWidth * effectiveValuesPerRow + spacingSize * 3;
                if (neededWidth <= availableWidth) break;
                effectiveValuesPerRow--;
            }
            // Round down to multiple of extraSpacingAfterXValues for clean layout
            effectiveValuesPerRow = (effectiveValuesPerRow / extraSpacingAfterXValues) * extraSpacingAfterXValues;
            if (effectiveValuesPerRow < 4) effectiveValuesPerRow = 4;
        }

        updateChunk();
        const unsigned sizeofValue = cellValueType.getSize();

        std::string fmtStr;
        if (displayAsHex) {
            fmtStr = "%0" + std::to_string(symbolsPerValueHex[cellValueType.type]);
            if (cellValueType.type == f64)
                fmtStr += "a";
            else if (cellValueType.type == f32)
                fmtStr += "a";
            else if (cellValueType.type == i64)
                fmtStr += "llx";
            else if (cellValueType.type == i32)
                fmtStr += "lx";
            else if (cellValueType.type == i16)
                fmtStr += "hx";
            else if (cellValueType.type == i8)
                fmtStr += "hhx";
        } else {
            if (cellValueType.type == f32)
                fmtStr = "%.9g";
            else if (cellValueType.type == f64)
                fmtStr = "%.17g";
            else {
                if (cellValueType.type == i64)
                    fmtStr = "%ll";
                else if (cellValueType.type == i32)
                    fmtStr = "%l";
                else if (cellValueType.type == i16)
                    fmtStr = "%h";
                else if (cellValueType.type == i8)
                    fmtStr = "%hh";
                fmtStr += cellValueType.flags & isSigned ? "d" : "u";
            }
        }

        // Determine column count: hex values + optional ASCII column
        const unsigned totalColumns = effectiveValuesPerRow + 1 + (showAscii ? 1 : 0);
        
        if (ImGui::BeginTable("Memory editor table", totalColumns, ImGuiTableFlags_RowBg | (innerBordersEnabled ? ImGuiTableFlags_BordersInner : 0))) {
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_NoResize | ImGuiTableColumnFlags_WidthFixed, addressColumnSize);

            for (unsigned i = 1; i <= effectiveValuesPerRow; ++i) {
                if (i % extraSpacingAfterXValues == 0)
                    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_NoResize | ImGuiTableColumnFlags_WidthFixed, valueSize + spacingSize + extraSpacingSize);
                else
                    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_NoResize | ImGuiTableColumnFlags_WidthFixed, valueSize + spacingSize);
            }
            
            // ASCII column
            if (showAscii) {
                ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_NoResize | ImGuiTableColumnFlags_WidthFixed, 
                                        asciiCharWidth * effectiveValuesPerRow + spacingSize * 2);
            }

            for (unsigned row = 0; row < rowsAvailable; ++row) {
                ImGui::TableNextColumn();
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(189, 189, 189, 255));
                ImGui::AlignTextToFramePadding();
                ImGui::Text(" %p: ", startAddress + row * effectiveValuesPerRow * sizeofValue);
                ImGui::AlignTextToFramePadding();
                ImGui::PopStyleColor();


                for (unsigned i = 0; i < effectiveValuesPerRow; ++i) {
                    ImGui::TableNextColumn();
                    ImGui::PushID(row * 4096 + i);
                    ImGui::SetNextItemWidth(-1);

                    void* currentValue = (void*)((uint64_t)chunk + (row * effectiveValuesPerRow + i) * sizeofValue);
                    const void* previousValue = (void*)((uint64_t)prevChunk + (row * effectiveValuesPerRow + i) * sizeofValue);
                    uint64_t currentAddress = startAddress + row * effectiveValuesPerRow * sizeofValue + i * sizeofValue;


                    cellHighlightTimeLeft[row * effectiveValuesPerRow + i] -= 255 * (1 / io.Framerate);
                    if (!scrolled and memcmp(currentValue, previousValue, cellValueType.getSize()) != 0)
                        cellHighlightTimeLeft[row * effectiveValuesPerRow + i] = 255;
                    else if (cellHighlightTimeLeft[row * effectiveValuesPerRow + i] < 0)
                        cellHighlightTimeLeft[row * effectiveValuesPerRow + i] = 0;
                    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(15, 135, 250, cellHighlightTimeLeft[row * effectiveValuesPerRow + i]));
                    ImGui::InputScalar("", ImGuiCellValueType, currentValue, nullptr, nullptr, fmtStr.c_str(), (displayAsHex ? ImGuiInputTextFlags_CharsHexadecimal : 0));
                    if (ImGui::IsItemDeactivatedAfterEdit()) {
                        if (VirtualMemory::write(currentValue, (void*)currentAddress, sizeofValue))
                            Gui::log("Wrote {} to {:p}", cellValueType.format(currentValue, displayAsHex), (void*)currentAddress);
                    }
                    
                    // Context menu: follow pointer, copy address
                    if (ImGui::BeginPopupContextItem("##CellPopup")) {
                        if (ImGui::MenuItem(std::format("Copy address ({:p})", (void*)currentAddress).c_str())) {
                            ImGui::SetClipboardText(std::format("0x{:x}", currentAddress).c_str());
                        }
                        // Follow as pointer (only for 8-byte or 4-byte values in hex mode)
                        if (sizeofValue >= 4) {
                            uint64_t ptrValue = 0;
                            std::memcpy(&ptrValue, currentValue, std::min((unsigned)8u, sizeofValue));
                            if (ImGui::MenuItem(std::format("Follow pointer → {:p}", (void*)ptrValue).c_str())) {
                                startAddress = ptrValue;
                                scrolled = 2;
                            }
                        }
                        if (ImGui::MenuItem("Open in structure dissector")) {
                            // Will be handled via windows.h include
                        }
                        ImGui::EndPopup();
                    }
                    
                    ImGui::PopStyleColor();
                    ImGui::PopID();
                }
                
                // ASCII column
                if (showAscii) {
                    ImGui::TableNextColumn();
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(150, 200, 150, 255));
                    
                    std::string asciiStr;
                    asciiStr.reserve(effectiveValuesPerRow);
                    for (unsigned i = 0; i < effectiveValuesPerRow; ++i) {
                        uint8_t byte = *((uint8_t*)chunk + (row * effectiveValuesPerRow + i));
                        asciiStr += (byte >= 32 && byte <= 126) ? (char)byte : '.';
                    }
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text(" %s", asciiStr.c_str());
                    
                    ImGui::PopStyleColor();
                }
            }
            ImGui::EndTable();
        }

        scrolled -= (bool)scrolled;
        if (ImGui::IsWindowHovered() and io.MouseWheel != 0) {
            const int shift = io.MouseWheel * effectiveValuesPerRow * sizeofValue * 2;
            startAddress -= shift;
            startAddress = std::max(startAddress, baseAddress);
            if (shift > 0) {
                std::rotate(cellHighlightTimeLeft.rbegin(), cellHighlightTimeLeft.rbegin() + shift, cellHighlightTimeLeft.rend());
            } else if (shift < 0) {
                std::rotate(cellHighlightTimeLeft.begin(), cellHighlightTimeLeft.begin() - shift, cellHighlightTimeLeft.end());
            }
            if (shift > 0) {
                for (int i = 0; i < shift; ++i)
                    cellHighlightTimeLeft[i] = 0;
            } else if (shift < 0) {
                for (int i = cellHighlightTimeLeft.size() - shift - 1; i < cellHighlightTimeLeft.size(); ++i)
                    cellHighlightTimeLeft[i] = 0;
            }
            scrolled = 2;
        }

        ImGui::PopStyleColor();
        imGuiStyle = originalStyle;

        menuBar();
        ImGui::End();
    } else {
        ImGui::PopStyleColor();
        imGuiStyle = originalStyle;
        ImGui::End();
    }
}

void MemoryEditorWindow::menuBar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("View")) {
            if (ImGui::BeginMenu("Value type")) {
                if (ImGui::MenuItem("signed", nullptr, cellValueType.flags & isSigned))
                    cellValueType.flags = cellValueType.flags ^ isSigned;
                if (ImGui::MenuItem("int8", nullptr, bool(cellValueType.type == i8)))
                    cellValueType = i8;
                if (ImGui::MenuItem("int16", nullptr, bool(cellValueType.type == i16)))
                    cellValueType = i16;
                if (ImGui::MenuItem("int32", nullptr, bool(cellValueType.type == i32)))
                    cellValueType = i32;
                if (ImGui::MenuItem("int64", nullptr, bool(cellValueType.type == i64)))
                    cellValueType = i64;
                if (ImGui::MenuItem("float32", nullptr, bool(cellValueType.type == f32)))
                    cellValueType = f32;
                if (ImGui::MenuItem("float64", nullptr, bool(cellValueType.type == f64)))
                    cellValueType = f64;

                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Display type")) {
                bool displayAsDec = !displayAsHex;
                ImGui::MenuItem("hex", nullptr, &displayAsHex);
                if (ImGui::MenuItem("dec", nullptr, &displayAsDec))
                    displayAsHex = !displayAsHex;
                ImGui::EndMenu();
            }
            ImGui::MenuItem("ASCII view", nullptr, &asciiViewEnabled);
            ImGui::MenuItem("Inner borders", nullptr, &innerBordersEnabled);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::BeginMenu("Go to address")) {
                static uint64_t gotoAddr = 0;
                ImGui::InputScalar("##gotoAddress", ImGuiDataType_U64, &gotoAddr, 0, 0, "%p", ImGuiInputTextFlags_CharsHexadecimal);
                if (ImGui::IsItemDeactivatedAfterEdit() || ImGui::Button("Go")) {
                    startAddress = gotoAddr;
                    scrolled = 2;
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Current address")) {
                auto newStartAddress = startAddress;
                ImGui::InputScalar("##currentAddress", ImGuiDataType_U64, &newStartAddress, 0, 0, "%p", ImGuiInputTextFlags_CharsHexadecimal);
                if (ImGui::IsItemDeactivatedAfterEdit() and newStartAddress != startAddress) {
                    startAddress = newStartAddress;
                    scrolled = 2;
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}


MemoryEditorWindow::MemoryEditorWindow(const unsigned long long start) {
    name = "Memory editor";
    startAddress = start;
    baseAddress = SelectedProcess::getBaseAddress();
}


MemoryEditorWindow::~MemoryEditorWindow() {
    free(chunk);
}
