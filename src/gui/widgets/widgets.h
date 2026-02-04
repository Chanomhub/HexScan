#ifndef HEX_SCAN_WIDGETS_H
#define HEX_SCAN_WIDGETS_H

#include "../../backend/CTvalue/CTvalue.h"


namespace Widgets {
    bool valueInputTrueOnEditing(const CTvalue& valueType, void* to, int bufSize=256);
    bool valueInputTrueOnDeactivation(const CTvalue& valueType, void* to, bool hex=false, int bufSize=256, bool pointer=false);
    void valueText(const CTvalue& valueType, void* value);
    void valueTypeSelector(CTvalue& valueType, bool enablePchain=true);
    bool tristateCheckbox(const char* label, int* state);
}

#endif //HEX_SCAN_WIDGETS_H
