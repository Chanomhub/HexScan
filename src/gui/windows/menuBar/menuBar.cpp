#include "menuBar.h"
#include "../../gui.h"
#include "../../../backend/selectedProcess/selectedProcess.h"
#include "../../../backend/cheatTable/cheatTable.h"
#include "../windows.h"

#include <imgui_stdlib.h>
#include <cstdio>
#include <array>


// ─── Native file dialog via zenity/kdialog ──────────────────────────────────

static std::string openFileDialog(const char* title, const char* filter, bool save) {
    // Try zenity first (GNOME), then kdialog (KDE)
    std::string cmd;
    if (save) {
        cmd = std::format(
            "zenity --file-selection --save --confirm-overwrite --title='{}' --file-filter='{}' 2>/dev/null "
            "|| kdialog --getsavefilename . '{}' --title '{}' 2>/dev/null",
            title, filter, filter, title
        );
    } else {
        cmd = std::format(
            "zenity --file-selection --title='{}' --file-filter='{}' 2>/dev/null "
            "|| kdialog --getopenfilename . '{}' --title '{}' 2>/dev/null",
            title, filter, filter, title
        );
    }

    std::array<char, 1024> buf;
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buf.data(), buf.size(), pipe) != nullptr)
        result += buf.data();
    pclose(pipe);

    // Remove trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();

    return result;
}


void MenuBarWindow::draw() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("Project")) {
            if (ImGui::MenuItem("Open")) {
                std::string path = openFileDialog("Open Cheat Table", "*.hxt", false);
                if (!path.empty()) {
                    std::string errorMsg;
                    auto loaded = CheatTable::load(path, errorMsg);
                    if (!loaded.empty()) {
                        // Find or create a StarredAddressesWindow to put entries in
                        auto starredWindows = Gui::getWindows<StarredAddressesWindow>();
                        StarredAddressesWindow* targetWindow;
                        if (starredWindows.empty()) {
                            targetWindow = new StarredAddressesWindow();
                            Gui::addWindow(targetWindow);
                        } else {
                            targetWindow = starredWindows.front();
                        }
                        for (auto& addr : loaded) {
                            targetWindow->addresses.push_back(std::move(addr));
                        }
                        Gui::log("Loaded {} entries from {}", loaded.size(), path);
                    } else {
                        Gui::log("Failed to load cheat table: {}", errorMsg);
                    }
                }
            }
            if (ImGui::MenuItem("Save")) {
                // Collect all addresses from all StarredAddressesWindows
                std::vector<StarredAddress> allAddresses;
                for (auto* window : Gui::getWindows<StarredAddressesWindow>()) {
                    for (auto& addr : window->addresses) {
                        allAddresses.push_back(addr);
                    }
                }
                if (allAddresses.empty()) {
                    Gui::log("Nothing to save — no starred addresses.");
                } else {
                    std::string path = openFileDialog("Save Cheat Table", "*.hxt", true);
                    if (!path.empty()) {
                        // Auto-add .hxt extension if missing
                        if (path.size() < 4 || path.substr(path.size() - 4) != ".hxt")
                            path += ".hxt";
                        CheatTable::save(path, allAddresses);
                    }
                }
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Settings"))
                Gui::addWindow(new SettingsWindow());
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Windows")) {
            if (ImGui::BeginMenu("Opened")) {
                for (const auto& window : Gui::windows) {
                    if (window->name.substr(0, 14) != "Unnamed window") {
                        if (ImGui::BeginMenu(window->name.c_str())) {
                            if (ImGui::BeginMenu("Rename")) {
                                std::string newName = window->name;
                                ImGui::SetNextItemWidth(ImGui::GetStyle().FramePadding.x * 2 + ImGui::CalcTextSize(newName.c_str()).x);
                                if (ImGui::InputText("##windowname", &newName, ImGuiInputTextFlags_EnterReturnsTrue))
                                    window->name = newName;
                                ImGui::EndMenu();
                            }
                            if (ImGui::MenuItem("Focus"))
                                window->shouldBringToFront = true;
                            if (ImGui::MenuItem("Close"))
                                window->pOpen = false;

                            ImGui::EndMenu();
                        }
                    }
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("New")) {
                if (ImGui::MenuItem("Scanner"))
                    Gui::addWindow(new ScannerWindow());
                if (ImGui::MenuItem("Memory editor"))
                    Gui::addWindow(new MemoryEditorWindow());
                if (ImGui::MenuItem("Settings"))
                    Gui::addWindow(new SettingsWindow());
                if (ImGui::MenuItem("Starred addresses"))
                    Gui::addWindow(new StarredAddressesWindow());
                if (ImGui::MenuItem("Logs"))
                    Gui::addWindow(new LogsWindow());
                if (ImGui::MenuItem("ImGui demo"))
                    Gui::addWindow(new ImguiDemoWindow());
                if (ImGui::MenuItem("Pointer scan"))
                    Gui::addWindow(new PointerScanWindow());
                if (ImGui::MenuItem("Pointermap manager"))
                    Gui::addWindow(new PointerMapManagerWindow());
                if (ImGui::MenuItem("Structure dissector"))
                    Gui::addWindow(new StructureDissectorWindow());
                if (ImGui::MenuItem("Disassembler"))
                    Gui::addWindow(new DisassemblerWindow());
                if (ImGui::MenuItem("Module list"))
                    Gui::addWindow(new ModuleListWindow());
                ImGui::EndMenu();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Process")) {
            if (ImGui::MenuItem("Select another"))
                SelectedProcess::detach();

            if (ImGui::MenuItem("Terminate"))
                SelectedProcess::terminate();

            if (ImGui::MenuItem("Kill"))
                SelectedProcess::kill();

            if (SelectedProcess::isSuspended()) {
                if (ImGui::MenuItem("Resume"))
                    SelectedProcess::resume();
            } else {
                if (ImGui::MenuItem("Suspend"))
                    SelectedProcess::suspend();
            }


            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }
}
