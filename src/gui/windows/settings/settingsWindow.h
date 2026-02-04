#ifndef HEX_SCAN_SETTINGSWINDOW_H
#define HEX_SCAN_SETTINGSWINDOW_H

#include "../generic/window.h"


class SettingsWindow final : public Window {
public:
    void draw() override;

    SettingsWindow() { name = "Settings"; }
};


#endif //HEX_SCAN_SETTINGSWINDOW_H
