#ifndef HEX_SCAN_PROCESSSELECTORWINDOW_H
#define HEX_SCAN_PROCESSSELECTORWINDOW_H

#include "../generic/window.h"


class ProcessSelectorWindow final : public Window {
public:
    void draw() override;

    ProcessSelectorWindow() { name = "Process selector"; }
};


#endif //HEX_SCAN_PROCESSSELECTORWINDOW_H
