#ifndef HEX_SCAN_MODULELIST_H
#define HEX_SCAN_MODULELIST_H

#include <string>
#include <vector>
#include <cstdint>

struct Module {
    std::string name;       // basename (e.g. "libfoo.so")
    std::string path;       // full path
    uint64_t baseAddress;   // lowest mapped address
    uint64_t endAddress;    // highest mapped address end
    uint64_t size;          // total mapped size
};

namespace ModuleList {
    // Parse /proc/pid/maps and extract loaded modules
    std::vector<Module> getModules();
    
    // Find module containing an address
    const Module* findModule(const std::vector<Module>& modules, uint64_t address);
    
    // Format address as module+offset string (e.g. "libfoo.so+0x1234")
    std::string formatAddress(const std::vector<Module>& modules, uint64_t address);
}

#endif //HEX_SCAN_MODULELIST_H
