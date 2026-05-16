#include "backend/scanner/scanner.h"
#include "backend/scanner/aobUtils.h"
#include "backend/selectedProcess/selectedProcess.h"
#include "backend/virtualMemory/virtualMemory.h"
#include "backend/disassembler/disassembler.h"
#include "backend/patch/patchManager.h"
#include "backend/codeInjection/codeInjection.h"
#include "backend/moduleList/moduleList.h"
#include "backend/pointerChain/pointerChain.h"
#include "backend/regions/regions.h"
#include "backend/debugger/accessTracker.h"
#include "backend/starredAddress/starredAddress.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <list>

/**
 * Headless CLI for HexScan
 * This allows the agent and users to perform scans without the ImGui frontend.
 */

// Satisfy Gui::log externs without including full GUI
namespace Gui {
    std::mutex logsMutex;
    std::list<std::pair<std::string, int>> logs;
}

void printUsage() {
    std::cout << "Usage: HexScanCLI <pid> <command> [args...]" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  scan <type> <value> [scan_type]" << std::endl;
    std::cout << "  disasm <address> [length]" << std::endl;
    std::cout << "  patch <address> <length> (NOPs the instruction)" << std::endl;
    std::cout << "  invertjmp <address> <length> (invert conditional jump)" << std::endl;
    std::cout << "  restore <address> (restore patched bytes)" << std::endl;
    std::cout << "  read <address> <type> (read value at address)" << std::endl;
    std::cout << "  pchain <base_addr> <off1> [off2] ... (resolve pointer chain)" << std::endl;
    std::cout << "  regions <address> (show region info)" << std::endl;
    std::cout << "  freeze <address> <type> <value> <duration_sec> (freeze value)" << std::endl;
    std::cout << "  watch <address> [duration_sec] [write|rw] (hw watchpoint)" << std::endl;
    std::cout << "  alloc <size> (allocate RWX memory in target)" << std::endl;
    std::cout << "  hook <address> (install trampoline hook)" << std::endl;
    std::cout << "  unhook <address> (remove trampoline hook)" << std::endl;
    std::cout << "  modules (list loaded modules)" << std::endl;
    std::cout << "Types: i8, i16, i32, i64, f32, f64, string, all" << std::endl;
}

// Helper to parse CTvalue type from string
static CTvalue parseType(const std::string& typeStr) {
    if (typeStr == "i8") return {i8, isSigned};
    if (typeStr == "i16") return {i16, isSigned};
    if (typeStr == "i32") return {i32, isSigned};
    if (typeStr == "i64") return {i64, isSigned};
    if (typeStr == "u8") return {i8};
    if (typeStr == "u16") return {i16};
    if (typeStr == "u32") return {i32};
    if (typeStr == "u64") return {i64};
    if (typeStr == "f32") return {f32};
    if (typeStr == "f64") return {f64};
    if (typeStr == "string") return {string};
    return {i32, isSigned};
}

static void drainLogs() {
    std::lock_guard<std::mutex> lock(Gui::logsMutex);
    while (!Gui::logs.empty()) {
        std::cout << "[LOG] " << Gui::logs.front().first << std::endl;
        Gui::logs.pop_front();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage();
        return 1;
    }

    int pid;
    try {
        pid = std::stoi(argv[1]);
    } catch (...) {
        std::cerr << "Invalid PID: " << argv[1] << std::endl;
        return 1;
    }

    std::string cmd = argv[2];

    SelectedProcess::attach(pid);
    if (SelectedProcess::pid == detached) {
        std::cerr << "Failed to attach to PID " << pid << std::endl;
        return 1;
    }

    if (cmd == "scan") {
        if (argc < 5) { printUsage(); return 1; }
        std::string typeStr = argv[3];
        std::string valStr = argv[4];
        int scanTypeInt = (argc > 5) ? std::stoi(argv[5]) : 0;

        Scanner scanner("CLIScanner");
        scanner.getRegions().mustHavePerms = (RegionPerms)0;
        scanner.getRegions().mustNotHavePerms = (RegionPerms)0;
        
        CTvalue vt;
        if (typeStr == "i8") vt = {i8, isSigned};
        else if (typeStr == "i16") vt = {i16, isSigned};
        else if (typeStr == "i32") vt = {i32, isSigned};
        else if (typeStr == "i64") vt = {i64, isSigned};
        else if (typeStr == "f32") vt = {f32};
        else if (typeStr == "f64") vt = {f64};
        else if (typeStr == "string") {
            vt = {string};
            vt.stringLength = valStr.length();
        }
        else if (typeStr == "aob") vt = {byteArray};
        else if (typeStr == "all") vt = {all};
        else return 1;

        scanner.setValueType(vt);
        scanner.setScanType((ScanType)scanTypeInt);

        if (typeStr == "string") {
            std::vector<uint8_t> bytes(valStr.begin(), valStr.end());
            scanner.setValue(bytes);
        } else if (typeStr == "aob") {
            auto aob = ParseAOBString(valStr);
            if (!aob.success) {
                std::cerr << "Invalid AOB string: " << aob.errorMessage << std::endl;
                return 1;
            }
            std::cout << "Parsed AOB: " << aob.bytes.size() << " bytes" << std::endl;
            scanner.setValue(aob.bytes);
            scanner.setValueMask(aob.mask);
            scanner.setFastScanOffset(1); // AOB should use offset 1
        } else if (typeStr == "all" || typeStr == "f32" || typeStr == "f64") {
            double dval = std::stod(valStr);
            std::vector<uint8_t> bytes(8);
            std::memcpy(bytes.data(), &dval, 8);
            scanner.setValue(bytes);
        } else {
            long long lval = std::stoll(valStr);
            std::vector<uint8_t> bytes(8);
            std::memcpy(bytes.data(), &lval, 8);
            scanner.setValue(bytes);
        }

        scanner.newScan();
        while (scanner.isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::lock_guard<std::mutex> lock(Gui::logsMutex);
            while (!Gui::logs.empty()) {
                std::cout << "[LOG] " << Gui::logs.front().first << std::endl;
                Gui::logs.pop_front();
            }
        }
        
        // Final log check
        {
            std::lock_guard<std::mutex> lock(Gui::logsMutex);
            while (!Gui::logs.empty()) {
                std::cout << "[LOG] " << Gui::logs.front().first << std::endl;
                Gui::logs.pop_front();
            }
        }
        
        auto addresses = scanner.getAddresses();
        std::cout << "Scan finished. Found " << addresses.size() << " addresses." << std::endl;
        int count = 0;
        for (auto addr : addresses) {
            if (count++ >= 1000) break;
            std::cout << "Found: 0x" << std::hex << addr << std::dec << std::endl;
        }
    } 
    else if (cmd == "disasm") {
        if (argc < 4) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        size_t len = (argc > 4) ? std::stoul(argv[4]) : 32;
        
        std::vector<uint8_t> bytes(len);
        if (VirtualMemory::read((void*)addr, bytes.data(), len)) {
            size_t offset = 0;
            Disassembler::init();
            while (offset < len) {
                auto inst = Disassembler::disassemble(bytes.data() + offset, len - offset, addr + offset);
                if (!inst.valid) break;
                std::cout << "0x" << std::hex << addr + offset << ": " << inst.fullText << std::dec << std::endl;
                offset += inst.length;
            }
        }
    }
    else if (cmd == "patch") {
        if (argc < 5) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        size_t len = std::stoul(argv[4]);
        
        if (PatchManager::nopInstruction((void*)addr, len, "CLI Patch")) {
            std::cout << "Successfully patched at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cout << "Failed to patch." << std::endl;
        }
    }
    else if (cmd == "alloc") {
        if (argc < 4) { printUsage(); return 1; }
        size_t size = std::stoul(argv[3]);
        uint64_t addr = CodeInjection::allocateRemote(size, "CLI alloc");
        if (addr) {
            std::cout << "Allocated at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cout << "Failed to allocate." << std::endl;
        }
    }
    else if (cmd == "hook") {
        if (argc < 4) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        if (CodeInjection::installHook(addr, {}, "CLI hook")) {
            std::cout << "Hook installed at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cout << "Failed to install hook." << std::endl;
        }
    }
    else if (cmd == "unhook") {
        if (argc < 4) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        if (CodeInjection::removeHook(addr)) {
            std::cout << "Hook removed at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cout << "Failed to remove hook." << std::endl;
        }
    }
    else if (cmd == "modules") {
        auto modules = ModuleList::getModules();
        std::cout << modules.size() << " modules loaded:" << std::endl;
        for (const auto& mod : modules) {
            std::cout << "  0x" << std::hex << mod.baseAddress << std::dec
                      << "  " << mod.size << " bytes"
                      << "  " << mod.name
                      << "  (" << mod.path << ")" << std::endl;
        }
    }
    else if (cmd == "read") {
        if (argc < 5) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        std::string typeStr = argv[4];
        CTvalue vt = parseType(typeStr);
        
        std::vector<uint8_t> buf(vt.getSize());
        if (VirtualMemory::read((void*)addr, buf.data(), vt.getSize())) {
            if (typeStr == "i8") std::cout << (int)*reinterpret_cast<int8_t*>(buf.data()) << std::endl;
            else if (typeStr == "i16") std::cout << *reinterpret_cast<int16_t*>(buf.data()) << std::endl;
            else if (typeStr == "i32") std::cout << *reinterpret_cast<int32_t*>(buf.data()) << std::endl;
            else if (typeStr == "i64") std::cout << *reinterpret_cast<int64_t*>(buf.data()) << std::endl;
            else if (typeStr == "u8") std::cout << (unsigned)*reinterpret_cast<uint8_t*>(buf.data()) << std::endl;
            else if (typeStr == "u16") std::cout << *reinterpret_cast<uint16_t*>(buf.data()) << std::endl;
            else if (typeStr == "u32") std::cout << *reinterpret_cast<uint32_t*>(buf.data()) << std::endl;
            else if (typeStr == "u64") std::cout << *reinterpret_cast<uint64_t*>(buf.data()) << std::endl;
            else if (typeStr == "f32") std::cout << *reinterpret_cast<float*>(buf.data()) << std::endl;
            else if (typeStr == "f64") std::cout << *reinterpret_cast<double*>(buf.data()) << std::endl;
            else std::cout << "(unsupported type)" << std::endl;
        } else {
            std::cerr << "Failed to read." << std::endl; return 1;
        }
    }
    else if (cmd == "pchain") {
        if (argc < 5) { std::cerr << "Usage: pchain <base_hex> <off1> [off2] ..." << std::endl; return 1; }
        uint64_t base = std::stoull(argv[3], nullptr, 16);
        std::vector<int> offsets;
        for (int a = 4; a < argc; a++) {
            offsets.push_back((int)std::stol(argv[a], nullptr, 0));
        }
        PointerChain pc("", (void*)base, offsets, 0);
        void* tail = pc.getTail();
        std::cout << "Base: 0x" << std::hex << base << std::dec << std::endl;
        std::cout << "Offsets:";
        for (auto o : offsets) std::cout << " 0x" << std::hex << o;
        std::cout << std::dec << std::endl;
        std::cout << "Tail: 0x" << std::hex << (uint64_t)tail << std::dec << std::endl;
        std::cout << "Valid: " << (pc.isValid ? "true" : "false") << std::endl;
        if (pc.isValid) {
            int32_t val = 0;
            if (VirtualMemory::read(tail, &val, 4))
                std::cout << "Value(i32): " << val << std::endl;
        }
    }
    else if (cmd == "regions") {
        if (argc < 4) { std::cerr << "Usage: regions <address_hex>" << std::endl; return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        Regions regions;
        regions.mustHavePerms = (RegionPerms)0;
        regions.mustNotHavePerms = (RegionPerms)0;
        regions.parse();
        auto region = regions.get((void*)addr);
        if (region.has_value()) {
            auto& r = region.value();
            std::cout << "Address: 0x" << std::hex << addr << std::dec << std::endl;
            std::cout << "Region: 0x" << std::hex << (uint64_t)r.start << "-0x" << (uint64_t)r.end << std::dec << std::endl;
            std::cout << "Path: " << (r.path.empty() ? "(anonymous)" : r.path) << std::endl;
            std::cout << "Inode: " << r.inodeID << std::endl;
            std::cout << "Perms: " << ((r.mode & RegionPerms::r) ? 'r' : '-') << ((r.mode & w) ? 'w' : '-') << ((r.mode & x) ? 'x' : '-') << std::endl;
            bool isStatic = regions.isStaticAddress((void*)addr);
            std::cout << "Static: " << (isStatic ? "true" : "false") << std::endl;
        } else {
            std::cerr << "Address not found in any region." << std::endl; return 1;
        }
    }
    else if (cmd == "invertjmp") {
        if (argc < 5) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        size_t len = std::stoul(argv[4]);
        if (PatchManager::invertConditionalJump((void*)addr, len, "CLI invertjmp")) {
            std::cout << "Inverted jump at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cerr << "Failed to invert jump." << std::endl; return 1;
        }
    }
    else if (cmd == "restore") {
        if (argc < 4) { printUsage(); return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        if (PatchManager::restorePatch((void*)addr)) {
            std::cout << "Restored patch at 0x" << std::hex << addr << std::dec << std::endl;
        } else {
            std::cerr << "Failed to restore (no patch found)." << std::endl; return 1;
        }
    }
    else if (cmd == "freeze") {
        if (argc < 7) { std::cerr << "Usage: freeze <addr_hex> <type> <value> <duration_sec>" << std::endl; return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        std::string typeStr = argv[4];
        std::string valStr = argv[5];
        int duration = std::stoi(argv[6]);
        
        CTvalue vt = parseType(typeStr);
        StarredAddress sa("CLIFreeze", vt, (void*)addr);
        
        // Read current value first
        VirtualMemory::read((void*)addr, sa.valueBytes.data(), vt.getSize());
        
        // Set the freeze value
        if (typeStr == "i32" || typeStr == "u32") {
            int32_t v = std::stoi(valStr); memcpy(sa.valueBytes.data(), &v, 4);
        } else if (typeStr == "f32") {
            float v = std::stof(valStr); memcpy(sa.valueBytes.data(), &v, 4);
        } else if (typeStr == "f64") {
            double v = std::stod(valStr); memcpy(sa.valueBytes.data(), &v, 8);
        } else if (typeStr == "i64" || typeStr == "u64") {
            int64_t v = std::stoll(valStr); memcpy(sa.valueBytes.data(), &v, 8);
        }
        
        sa.isFrozen = true;
        std::cout << "Freezing 0x" << std::hex << addr << std::dec << " = " << valStr << " for " << duration << "s" << std::endl;
        
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(duration)) {
            sa.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        // Unfreeze and read back
        sa.isFrozen = false;
        sa.update();
        if (typeStr == "i32") std::cout << "Final: " << *reinterpret_cast<int32_t*>(sa.valueBytes.data()) << std::endl;
        else if (typeStr == "f32") std::cout << "Final: " << *reinterpret_cast<float*>(sa.valueBytes.data()) << std::endl;
        else std::cout << "Final: (done)" << std::endl;
    }
    else if (cmd == "watch") {
        if (argc < 4) { std::cerr << "Usage: watch <addr_hex> [duration_sec] [write|rw]" << std::endl; return 1; }
        uint64_t addr = std::stoull(argv[3], nullptr, 16);
        int duration = (argc > 4) ? std::stoi(argv[4]) : 3;
        BreakpointType bpType = BreakpointType::DataWrite;
        if (argc > 5 && std::string(argv[5]) == "rw") bpType = BreakpointType::DataReadWrite;
        
        std::cout << "Watching 0x" << std::hex << addr << std::dec << " for " << duration << "s" << std::endl;
        if (!AccessTracker::startTracking((void*)addr, bpType)) {
            std::cerr << "Failed to start tracking." << std::endl;
            drainLogs();
            return 1;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        AccessTracker::stopTracking();
        
        auto records = AccessTracker::getRecords();
        std::cout << "Recorded " << records.size() << " unique access(es):" << std::endl;
        for (const auto& rec : records) {
            std::cout << "  RIP=0x" << std::hex << (uint64_t)rec.instructionAddress << std::dec
                      << "  count=" << rec.accessCount
                      << "  AOB=" << AccessTracker::getAOBString(rec) << std::endl;
        }
    }

    return 0;
}
