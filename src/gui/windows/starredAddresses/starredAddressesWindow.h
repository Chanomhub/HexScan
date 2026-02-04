#ifndef HEX_SCAN_STARREDADDRESSESWINDOW_H
#define HEX_SCAN_STARREDADDRESSESWINDOW_H

#include "../generic/window.h"
#include "../../../backend/starredAddress/starredAddress.h"
#include <vector>


class StarredAddressesWindow final : public Window {
    void addAddressPopup(bool& pOpen);
public:
    std::vector<StarredAddress> addresses;

    void draw() override;

    void addAddress(const std::string& name, void* address, CTvalue valueType);
    void addAddress(const std::string& name, void* address, CTvalue valueType, PointerChain pointerChain);
    void getAddresses();

    StarredAddressesWindow() { name = "Starred"; }
};


#endif //HEX_SCAN_STARREDADDRESSESWINDOW_H
