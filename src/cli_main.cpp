#include "backend/scanner/scanner.h"
#include "backend/scanner/aobUtils.h"
#include "backend/selectedProcess/selectedProcess.h"
#include "backend/virtualMemory/virtualMemory.h"
#include <iostream>
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
    std::cout << "Types: i8, i16, i32, i64, f32, f64, string, all" << std::endl;
}

#include "backend/disassembler/disassembler.h"
#include "backend/patch/patchManager.h"

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

    return 0;
}
