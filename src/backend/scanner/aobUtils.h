#ifndef AOB_UTILS_H
#define AOB_UTILS_H

#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
#include <sstream>

// AOB parsing result structure
struct AOBParseResult {
    bool success = false;
    std::string errorMessage;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

inline AOBParseResult ParseAOBString(const std::string& input) {
    AOBParseResult result;
    std::stringstream ss(input);
    std::string token;
    
    while (ss >> token) {
        if (token == "?" || token == "??") {
            result.bytes.push_back(0x00);
            result.mask.push_back(0x00);
        } else if (token == "*" || token == "**") {
            result.bytes.push_back(0x00);
            result.mask.push_back(0x00);
        } else {
            // Must be even length if not a single-byte wildcard
            if (token.length() % 2 != 0) {
                 result.errorMessage = "Invalid AOB token: " + token + " (odd length)";
                 return result;
            }
            
            for (size_t i = 0; i < token.length(); i += 2) {
                uint8_t byte = 0;
                uint8_t mask = 0xFF;
                
                char c1 = token[i];
                char c2 = token[i+1];
                
                // Process high nibble
                if (c1 == '?' || c1 == '*') {
                    mask &= 0x0F;
                } else if (std::isxdigit(static_cast<unsigned char>(c1))) {
                    std::string s(1, c1);
                    byte |= (static_cast<uint8_t>(std::stoul(s, nullptr, 16)) << 4);
                } else {
                    result.errorMessage = "Invalid hex char: " + std::string(1, c1);
                    return result;
                }
                
                // Process low nibble
                if (c2 == '?' || c2 == '*') {
                    mask &= 0xF0;
                } else if (std::isxdigit(static_cast<unsigned char>(c2))) {
                    std::string s(1, c2);
                    byte |= static_cast<uint8_t>(std::stoul(s, nullptr, 16));
                } else {
                    result.errorMessage = "Invalid hex char: " + std::string(1, c2);
                    return result;
                }
                
                result.bytes.push_back(byte);
                result.mask.push_back(mask);
            }
        }
    }
    
    if (result.bytes.empty()) {
        result.errorMessage = "Empty AOB string";
        return result;
    }
    
    result.success = true;
    return result;
}

#endif //AOB_UTILS_H
