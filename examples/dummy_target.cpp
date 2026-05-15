#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <iomanip>
#include <cstdint>

/**
 * DummyTarget - A controlled application for testing memory scanners.
 * It provides known addresses and values that can be modified via CLI.
 */

int main() {
    // Variables on stack/data section to scan
    int32_t val_i32 = 1234;
    int64_t val_i64 = 567890;
    float val_f32 = 123.456f;
    double val_f64 = 987.654;
    char val_str[32] = "CheatTurbine";

    std::cout << "========================================" << std::endl;
    std::cout << "   HexScan Dummy Test Target Started    " << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Process ID (PID): " << getpid() << std::endl;
    std::cout << std::endl;
    std::cout << "Memory Addresses to Scan:" << std::endl;
    std::cout << std::left << std::setw(10) << "Type" << std::setw(18) << "Address" << "Value" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << std::setw(10) << "int32"  << std::setw(18) << (void*)&val_i32 << val_i32 << std::endl;
    std::cout << std::setw(10) << "int64"  << std::setw(18) << (void*)&val_i64 << val_i64 << std::endl;
    std::cout << std::setw(10) << "float"  << std::setw(18) << (void*)&val_f32 << val_f32 << std::endl;
    std::cout << std::setw(10) << "double" << std::setw(18) << (void*)&val_f64 << val_f64 << std::endl;
    std::cout << std::setw(10) << "string" << std::setw(18) << (void*)val_str  << val_str  << std::endl;
    std::cout << "========================================" << std::endl;

    char cmd;
    while (true) {
        std::cout << "\nWaiting for command ([c]hange, [i]ncrease, [d]ecrease, [r]eset, [q]uit): ";
        if (!(std::cin >> cmd)) break;

        if (cmd == 'q') break;

        switch (cmd) {
            case 'c':
                val_i32 = 9999;
                val_i64 = 9999999;
                val_f32 = 999.9f;
                val_f64 = 9999.99;
                std::cout << ">> Values changed to '9999' patterns." << std::endl;
                break;
            case 'i':
                val_i32 += 10;
                val_i64 += 100;
                val_f32 += 1.5f;
                val_f64 += 2.5;
                std::cout << ">> Values increased." << std::endl;
                break;
            case 'd':
                val_i32 -= 5;
                val_i64 -= 50;
                val_f32 -= 0.5f;
                val_f64 -= 1.0;
                std::cout << ">> Values decreased." << std::endl;
                break;
            case 'r':
                val_i32 = 1234;
                val_i64 = 567890;
                val_f32 = 123.456f;
                val_f64 = 987.654;
                std::cout << ">> Values reset to defaults." << std::endl;
                break;
            default:
                std::cout << "Unknown command!" << std::endl;
                continue;
        }

        // Print current state for verification
        std::cout << "Current values: i32=" << val_i32 << ", i64=" << val_i64 
                  << ", f32=" << val_f32 << ", f64=" << val_f64 << std::endl;
    }

    std::cout << "Target application exiting..." << std::endl;
    return 0;
}
