#include "moduleList.h"
#include "../selectedProcess/selectedProcess.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <filesystem>

std::vector<Module> ModuleList::getModules() {
    std::vector<Module> modules;
    
    if (SelectedProcess::pid == detached) return modules;
    
    std::ifstream maps("/proc/" + std::to_string(SelectedProcess::pid) + "/maps");
    if (!maps.is_open()) return modules;
    
    // Group regions by path to merge into single module entries
    std::unordered_map<std::string, Module> moduleMap;
    
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        std::string addrRange, perms, offset, dev, inode, path;
        
        iss >> addrRange >> perms >> offset >> dev >> inode;
        std::getline(iss, path);
        
        // Trim whitespace
        path.erase(0, path.find_first_not_of(' '));
        path.erase(path.find_last_not_of(' ') + 1);
        
        // Skip anonymous mappings, [stack], [heap], [vdso] etc.
        if (path.empty() || path[0] == '[') continue;
        
        // Skip /dev/ mappings
        if (path.rfind("/dev/", 0) == 0) continue;
        
        // Parse address range
        auto dashPos = addrRange.find('-');
        if (dashPos == std::string::npos) continue;
        
        uint64_t start = 0, end = 0;
        try {
            start = std::stoull(addrRange.substr(0, dashPos), nullptr, 16);
            end = std::stoull(addrRange.substr(dashPos + 1), nullptr, 16);
        } catch (...) { continue; }
        
        auto it = moduleMap.find(path);
        if (it == moduleMap.end()) {
            Module mod;
            mod.path = path;
            mod.name = std::filesystem::path(path).filename().string();
            mod.baseAddress = start;
            mod.endAddress = end;
            mod.size = end - start;
            moduleMap[path] = mod;
        } else {
            it->second.baseAddress = std::min(it->second.baseAddress, start);
            it->second.endAddress = std::max(it->second.endAddress, end);
            it->second.size = it->second.endAddress - it->second.baseAddress;
        }
    }
    
    modules.reserve(moduleMap.size());
    for (auto& [_, mod] : moduleMap) {
        modules.push_back(std::move(mod));
    }
    
    // Sort by base address
    std::sort(modules.begin(), modules.end(), [](const Module& a, const Module& b) {
        return a.baseAddress < b.baseAddress;
    });
    
    return modules;
}

const Module* ModuleList::findModule(const std::vector<Module>& modules, uint64_t address) {
    for (const auto& mod : modules) {
        if (address >= mod.baseAddress && address < mod.endAddress)
            return &mod;
    }
    return nullptr;
}

std::string ModuleList::formatAddress(const std::vector<Module>& modules, uint64_t address) {
    const Module* mod = findModule(modules, address);
    if (mod) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s+0x%lx", mod->name.c_str(), address - mod->baseAddress);
        return buf;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", address);
    return buf;
}
