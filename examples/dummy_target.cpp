#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <iomanip>
#include <cstdint>

// Global pointer chain for testing
struct Entity {
    int32_t health;
    int32_t padding[4];
    int32_t mana;
};

struct GameState {
    Entity* localPlayer;
};

GameState* g_state = nullptr;

// A simple function that we can try to patch/disassemble
extern "C" {
    void __attribute__((noinline)) dummy_function(int* val) {
        if (*val > 100) {
            *val -= 10;
        } else {
            *val += 5;
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    // Initialize pointer chain
    g_state = new GameState();
    g_state->localPlayer = new Entity();
    g_state->localPlayer->health = 100;
    g_state->localPlayer->mana = 50;

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
    std::cout << std::left << std::setw(12) << "Type" << std::setw(18) << "Address" << "Value" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << std::setw(12) << "int32"  << std::setw(18) << (void*)&val_i32 << val_i32 << std::endl;
    std::cout << std::setw(12) << "int64"  << std::setw(18) << (void*)&val_i64 << val_i64 << std::endl;
    std::cout << std::setw(12) << "float"  << std::setw(18) << (void*)&val_f32 << val_f32 << std::endl;
    std::cout << std::setw(12) << "double" << std::setw(18) << (void*)&val_f64 << val_f64 << std::endl;
    std::cout << std::setw(12) << "string" << std::setw(18) << (void*)val_str  << val_str  << std::endl;

    std::cout << std::setw(12) << "ptr_base" << std::setw(18) << (void*)&g_state << " (g_state)" << std::endl;
    std::cout << std::setw(12) << "ptr_health" << std::setw(18) << (void*)&g_state->localPlayer->health << g_state->localPlayer->health << std::endl;
    std::cout << std::setw(12) << "func_dummy" << std::setw(18) << (void*)&dummy_function << " (noinline)" << std::endl;

    std::cout << "========================================" << std::endl;

    char cmd;
    while (true) {
        std::cout << "\nWaiting for command ([c]hange, [i]ncrease, [d]ecrease, [r]eset, [q]uit): ";
        std::string input;
        if (!(std::cin >> input)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        cmd = input[0];

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
