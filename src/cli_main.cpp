#include "backend/scanner/scanner.h"
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
    
    void log(const std::string_view rt_fmt_str, auto&&... args) {
        std::string str = std::vformat(rt_fmt_str, std::make_format_args(args...));
        std::cout << "[LOG] " << str << std::endl;
    }
}

void printUsage() {
    std::cout << "Usage: HexScanCLI <pid> <type> <value> [scan_type]" << std::endl;
    std::cout << "Types: i8, i16, i32, i64, f32, f64, string, all" << std::endl;
    std::cout << "Scan Types: 0=Equal, 1=Bigger, 2=Smaller, 3=Range, 10=Unknown" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
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

    std::string typeStr = argv[2];
    std::string valStr = argv[3];
    int scanTypeInt = (argc > 4) ? std::stoi(argv[4]) : 0;

    SelectedProcess::attach(pid);
    if (SelectedProcess::pid == detached) {
        std::cerr << "Failed to attach to PID " << pid << std::endl;
        return 1;
    }

    std::cout << "Attached to PID " << pid << std::endl;

    Scanner scanner("CLIScanner");
    scanner.getRegions().mustHavePerms = (RegionPerms)0;
    scanner.getRegions().mustNotHavePerms = (RegionPerms)0;
    
    // Set Value Type
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
    else if (typeStr == "all") vt = {all};
    else {
        std::cerr << "Unknown type: " << typeStr << std::endl;
        return 1;
    }
    scanner.setValueType(vt);
    scanner.setScanType((ScanType)scanTypeInt);

    // Set Value
    if (typeStr == "string") {
        std::vector<uint8_t> bytes(valStr.begin(), valStr.end());
        scanner.setValue(bytes);
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

    std::cout << "Starting New Scan..." << std::endl;
    scanner.newScan();

    // Wait for scan to complete
    while (scanner.isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto addresses = scanner.getAddresses();
    std::cout << "Scan finished. Found " << addresses.size() << " addresses." << std::endl;

    // Show first 20 results
    int count = 0;
    for (auto addr : addresses) {
        if (count++ >= 20) break;
        std::cout << "Found: 0x" << std::hex << addr << std::dec << std::endl;
    }

    return 0;
}
