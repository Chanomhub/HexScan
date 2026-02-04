#ifndef AOB_UTILS_H
#define AOB_UTILS_H

#include <string>
#include <vector>
#include <cstdint>
#include <cctype>

// AOB parsing result structure
struct AOBParseResult {
    bool success = false;
    std::string errorMessage;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

inline AOBParseResult ParseAOBString(const std::string& input) {
    AOBParseResult result;
    
    std::string clean;
    // Remove all whitespace
    for (char c : input) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }
    
    // Must have even number of chars
    if (clean.length() % 2 != 0) {
        result.errorMessage = "Invalid AOB string: odd number of characters";
        return result;
    }
    
    if (clean.empty()) {
        result.errorMessage = "Empty AOB string";
        return result;
    }
    
    for (size_t i = 0; i < clean.length(); i += 2) {
        std::string byteStr = clean.substr(i, 2);
        
        if (byteStr == "??" || byteStr == "**") {
            // Wildcard byte
            result.bytes.push_back(0x00);
            result.mask.push_back(0x00);
        } else {
            // Validate hex characters
            if (!std::isxdigit(static_cast<unsigned char>(byteStr[0])) || 
                !std::isxdigit(static_cast<unsigned char>(byteStr[1]))) {
                result.errorMessage = "Invalid character in AOB string at position " + std::to_string(i);
                return result;
            }
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
            result.bytes.push_back(byte);
            result.mask.push_back(0xFF);
        }
    }
    
    result.success = true;
    return result;
}

#endif //AOB_UTILS_H
