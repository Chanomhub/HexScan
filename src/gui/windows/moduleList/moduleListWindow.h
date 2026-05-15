#ifndef HEX_SCAN_MODULELISTWINDOW_H
#define HEX_SCAN_MODULELISTWINDOW_H

#include "../generic/window.h"
#include "../../../backend/moduleList/moduleList.h"
#include <vector>

class ModuleListWindow final : public Window {
    std::vector<Module> modules;
    int refreshCounter = 0;
    char filterBuf[128] = "";
    
public:
    void draw() override;
    ModuleListWindow() { name = "Module list"; }
};

#endif //HEX_SCAN_MODULELISTWINDOW_H
