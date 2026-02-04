#include "gui.h"
#include "impl/imgui/imguiImpl.h"
#include "windows/windows.h"
#include "../backend/debugger/hwBreakpoint.h"
#include "../backend/debugger/accessTracker.h"
#include <map>


namespace Gui {
    std::list<std::unique_ptr<Window>> windows;
    std::list<std::pair<std::string, int>> logs;
    std::mutex logsMutex;
}


void Gui::mainLoop() {
    ImGuiImpl::init();

    log("Welcome to HexScan!");

    addWindow(new MenuBarWindow());
    addWindow(new DockSpaceWindow());
    addWindow(new LogBarWindow());
    addWindow(new ProcessSelectorWindow());
    addWindow(new StarredAddressesWindow());
    addWindow(new ScannerWindow());

    SelectedProcess::subscribeToAttach([] {
        log("Attached to {}", SelectedProcess::pid);
        if (getuid())
            log("It looks like HexScan is not running as root. If you are unsure of what you are doing, restart it as root.");
    });
    SelectedProcess::subscribeToDetach([] { addWindow(new ProcessSelectorWindow()); });
    SelectedProcess::subscribeToDetach([] { log("Detached from {}", SelectedProcess::pid); });

    while (!ImGuiImpl::shouldClose()) {
        ImGuiImpl::newFrame();
        for (auto it = windows.begin(); it != windows.end();) {
            if (const auto window = it->get(); !window->pOpen) {
                it = windows.erase(it);
            } else {
                window->operator()();
                ++it;
            }
        }

        ImGuiImpl::render();
    }

    // Cleanup debugger resources before closing to prevent game crashes
    // Hardware breakpoints must be cleared or the game will crash when accessing watched memory
    AccessTracker::stopTracking();
    HwBreakpoint::clearAll();

    ImGuiImpl::destroy();
}

void Gui::addWindow(Window* window) {
    static std::map<std::string, int> totalWindows;
    if (totalWindows[window->name] != 0) {
        totalWindows[window->name]++;
        window->name = std::format("{} {}", window->name, totalWindows[window->name]);
    } else {
        totalWindows[window->name]++;
    }
    // std::cout << "Opened " << window->name << std::endl;
    windows.emplace_back(window);
}
