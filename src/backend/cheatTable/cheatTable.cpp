#include "cheatTable.h"
#include "../../gui/gui.h"

#include <fstream>
#include <sstream>
#include <format>
#include <cstdint>


// ─── Simple XML writer helpers ───────────────────────────────────────────────

static std::string xmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;
        }
    }
    return out;
}

static std::string valueTypeToString(CTValueType type) {
    switch (type) {
        case i64:       return "i64";
        case i32:       return "i32";
        case i16:       return "i16";
        case i8:        return "i8";
        case f64:       return "f64";
        case f32:       return "f32";
        case string:    return "string";
        case byteArray: return "byteArray";
        case all:       return "all";
    }
    return "i32";
}

static CTValueType stringToValueType(const std::string& s) {
    if (s == "i64")       return i64;
    if (s == "i32")       return i32;
    if (s == "i16")       return i16;
    if (s == "i8")        return i8;
    if (s == "f64")       return f64;
    if (s == "f32")       return f32;
    if (s == "string")    return string;
    if (s == "byteArray") return byteArray;
    if (s == "all")       return all;
    return i32;
}

static std::string flagsToString(CTValueFlags flags) {
    std::string result;
    if (flags & isSigned)         result += "signed,";
    if (flags & isNullTerminated) result += "nullterm,";
    if (flags & pchain)           result += "pchain,";
    if (!result.empty()) result.pop_back(); // remove trailing comma
    return result.empty() ? "none" : result;
}

static CTValueFlags stringToFlags(const std::string& s) {
    CTValueFlags flags = none;
    if (s.find("signed") != std::string::npos)   flags = flags | isSigned;
    if (s.find("nullterm") != std::string::npos)  flags = flags | isNullTerminated;
    if (s.find("pchain") != std::string::npos)    flags = flags | pchain;
    return flags;
}


// ─── Simple XML tag parser (no external dependency) ──────────────────────────

static std::string getTagContent(const std::string& xml, const std::string& tag) {
    std::string openTag = "<" + tag + ">";
    std::string closeTag = "</" + tag + ">";
    auto start = xml.find(openTag);
    if (start == std::string::npos) return "";
    start += openTag.length();
    auto end = xml.find(closeTag, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

static std::vector<std::string> getAllTagBlocks(const std::string& xml, const std::string& tag) {
    std::vector<std::string> blocks;
    std::string openTag = "<" + tag + ">";
    std::string closeTag = "</" + tag + ">";
    size_t pos = 0;
    while (true) {
        auto start = xml.find(openTag, pos);
        if (start == std::string::npos) break;
        start += openTag.length();
        auto end = xml.find(closeTag, start);
        if (end == std::string::npos) break;
        blocks.push_back(xml.substr(start, end - start));
        pos = end + closeTag.length();
    }
    return blocks;
}

static std::string xmlUnescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            if (s.substr(i, 4) == "&lt;")        { out += '<';  i += 3; }
            else if (s.substr(i, 4) == "&gt;")    { out += '>';  i += 3; }
            else if (s.substr(i, 5) == "&amp;")   { out += '&';  i += 4; }
            else if (s.substr(i, 6) == "&quot;")  { out += '"';  i += 5; }
            else if (s.substr(i, 6) == "&apos;")  { out += '\''; i += 5; }
            else out += s[i];
        } else {
            out += s[i];
        }
    }
    return out;
}


// ─── Save ────────────────────────────────────────────────────────────────────

bool CheatTable::save(const std::string& filepath, const std::vector<StarredAddress>& addresses) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        Gui::log("CheatTable: Failed to open file for writing: {}", filepath);
        return false;
    }

    file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    file << "<HexScanTable version=\"1\">\n";

    for (const auto& addr : addresses) {
        file << "  <Entry>\n";
        file << "    <Name>" << xmlEscape(addr.name) << "</Name>\n";
        file << std::format("    <Address>0x{:x}</Address>\n", (uint64_t)addr.address);
        file << "    <ValueType>" << valueTypeToString(addr.valueType.type) << "</ValueType>\n";
        file << "    <Flags>" << flagsToString(addr.valueType.flags) << "</Flags>\n";
        file << "    <StringLength>" << addr.valueType.stringLength << "</StringLength>\n";
        file << "    <DisplayType>" << (addr.displayType == hex ? "hex" : "dec") << "</DisplayType>\n";
        file << "    <Frozen>" << (addr.isFrozen ? "true" : "false") << "</Frozen>\n";

        // Save pointer chain if present
        if (addr.valueType.flags & pchain) {
            file << "    <PointerChain>\n";
            file << "      <Module>" << xmlEscape(addr.pchain.path) << "</Module>\n";
            file << std::format("      <RegionOffset>0x{:x}</RegionOffset>\n", addr.pchain.regionOffset);
            file << "      <Offsets>";
            for (size_t i = 0; i < addr.pchain.offsets.size(); ++i) {
                if (i > 0) file << ",";
                file << std::format("0x{:x}", addr.pchain.offsets[i]);
            }
            file << "</Offsets>\n";
            file << "    </PointerChain>\n";
        }

        // Save frozen value bytes if frozen
        if (addr.isFrozen && !addr.valueBytes.empty()) {
            file << "    <FrozenValue>";
            for (size_t i = 0; i < addr.valueBytes.size(); ++i) {
                if (i > 0) file << " ";
                file << std::format("{:02X}", addr.valueBytes[i]);
            }
            file << "</FrozenValue>\n";
        }

        file << "  </Entry>\n";
    }

    file << "</HexScanTable>\n";
    file.close();

    Gui::log("CheatTable: Saved {} entries to {}", addresses.size(), filepath);
    return true;
}


// ─── Load ────────────────────────────────────────────────────────────────────

std::vector<StarredAddress> CheatTable::load(const std::string& filepath, std::string& errorMsg) {
    std::vector<StarredAddress> result;

    std::ifstream file(filepath);
    if (!file.is_open()) {
        errorMsg = "Failed to open file: " + filepath;
        return result;
    }

    std::string xml((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Verify version
    std::string table = getTagContent(xml, "HexScanTable");
    if (table.empty()) {
        errorMsg = "Not a valid HexScan table file (missing <HexScanTable>)";
        return result;
    }

    auto entries = getAllTagBlocks(table, "Entry");
    for (const auto& entry : entries) {
        std::string name = xmlUnescape(getTagContent(entry, "Name"));
        std::string addrStr = getTagContent(entry, "Address");
        std::string typeStr = getTagContent(entry, "ValueType");
        std::string flagsStr = getTagContent(entry, "Flags");
        std::string strLenStr = getTagContent(entry, "StringLength");
        std::string dispStr = getTagContent(entry, "DisplayType");
        std::string frozenStr = getTagContent(entry, "Frozen");

        if (name.empty() && addrStr.empty()) continue;

        uint64_t addr = 0;
        try { addr = std::stoull(addrStr, nullptr, 16); } catch (...) {}

        CTValueType vtype = stringToValueType(typeStr);
        CTValueFlags vflags = stringToFlags(flagsStr);
        unsigned strLen = 0;
        try { strLen = std::stoul(strLenStr); } catch (...) {}

        CTvalue valueType(vtype, vflags, strLen);
        StarredAddress sa(name, valueType, (void*)addr);
        sa.displayType = (dispStr == "hex") ? hex : dec;
        sa.isFrozen = (frozenStr == "true");

        // Load pointer chain
        std::string pchainBlock = getTagContent(entry, "PointerChain");
        if (!pchainBlock.empty()) {
            std::string module = xmlUnescape(getTagContent(pchainBlock, "Module"));
            std::string regOffStr = getTagContent(pchainBlock, "RegionOffset");
            std::string offsetsStr = getTagContent(pchainBlock, "Offsets");

            uint64_t regOff = 0;
            try { regOff = std::stoull(regOffStr, nullptr, 16); } catch (...) {}

            std::vector<int> offsets;
            if (!offsetsStr.empty()) {
                std::stringstream ss(offsetsStr);
                std::string tok;
                while (std::getline(ss, tok, ',')) {
                    try { offsets.push_back((int)std::stol(tok, nullptr, 16)); } catch (...) {}
                }
            }

            sa.pchain = PointerChain(module, nullptr, offsets, regOff);
            
            // Resolve head from current process memory map
            Regions regions;
            regions.parse();
            sa.pchain.updateHead(regions);
        }

        // Load frozen value
        std::string frozenVal = getTagContent(entry, "FrozenValue");
        if (!frozenVal.empty() && sa.isFrozen) {
            std::stringstream ss(frozenVal);
            std::string tok;
            sa.valueBytes.clear();
            while (ss >> tok) {
                try { sa.valueBytes.push_back((uint8_t)std::stoul(tok, nullptr, 16)); } catch (...) {}
            }
        }

        result.push_back(std::move(sa));
    }

    Gui::log("CheatTable: Loaded {} entries from {}", result.size(), filepath);
    return result;
}
