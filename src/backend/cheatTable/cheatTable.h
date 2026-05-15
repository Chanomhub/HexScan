#ifndef HEX_SCAN_CHEATTABLE_H
#define HEX_SCAN_CHEATTABLE_H

#include "../starredAddress/starredAddress.h"
#include <string>
#include <vector>

/**
 * CheatTable — Save/Load starred addresses to/from XML file.
 *
 * XML Format:
 * <HexScanTable version="1">
 *   <Entry>
 *     <Name>Player HP</Name>
 *     <Address>0x7f1234</Address>
 *     <ValueType>i32</ValueType>
 *     <Flags>signed</Flags>
 *     <DisplayType>dec</DisplayType>
 *     <Frozen>false</Frozen>
 *     <PointerChain>
 *       <Module>/path/to/binary</Module>
 *       <RegionOffset>0x0</RegionOffset>
 *       <Offsets>0x0,0x20</Offsets>
 *     </PointerChain>
 *   </Entry>
 * </HexScanTable>
 */
namespace CheatTable {
    // Save all addresses to XML file. Returns true on success.
    bool save(const std::string& filepath, const std::vector<StarredAddress>& addresses);
    
    // Load addresses from XML file. Returns loaded addresses.
    // On failure, returns empty vector and sets errorMsg.
    std::vector<StarredAddress> load(const std::string& filepath, std::string& errorMsg);
}

#endif //HEX_SCAN_CHEATTABLE_H
