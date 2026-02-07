#include "scanner.h"
#include "aobUtils.h"

#include <cmath>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <thread>

#include "../selectedProcess/selectedProcess.h"
#include "../virtualMemory/virtualMemory.h"
#include "../../gui/gui.h"

// RAII helper class for process suspension
class ProcessSuspensionGuard {
    bool shouldResume;
    
public:
    ProcessSuspensionGuard(bool shouldSuspend) : shouldResume(false) {
        if (shouldSuspend && !SelectedProcess::isSuspended()) {
            SelectedProcess::suspend();
            shouldResume = true;
        }
    }
    
    ~ProcessSuspensionGuard() {
        if (shouldResume) {
            SelectedProcess::resume();
        }
    }
    
    ProcessSuspensionGuard(const ProcessSuspensionGuard&) = delete;
    ProcessSuspensionGuard& operator=(const ProcessSuspensionGuard&) = delete;
};

Scanner::Scanner(std::string_view name) : name(name) {
    latestValues.reserve(256);
    valueBytes.reserve(32);
    valueBytesSecond.reserve(32);
    reset();
}

template<typename T>
std::function<bool(const void*)> Scanner::getCommonComparator() const {
    switch (scanType) {
        case ScanType::Equal:
            if constexpr (std::is_floating_point_v<T>) {
                return [this](const void* mem) {
                    return std::abs(*static_cast<const T*>(mem) - 
                                  *reinterpret_cast<const T*>(valueBytes.data())) < static_cast<T>(0.001);
                };
            }
            return [this](const void* mem) {
                return *static_cast<const T*>(mem) == 
                       *reinterpret_cast<const T*>(valueBytes.data());
            };
            
        case ScanType::Bigger:
            return [this](const void* mem) {
                return *static_cast<const T*>(mem) > 
                       *reinterpret_cast<const T*>(valueBytes.data());
            };
            
        case ScanType::Smaller:
            return [this](const void* mem) {
                return *static_cast<const T*>(mem) < 
                       *reinterpret_cast<const T*>(valueBytes.data());
            };
            
        case ScanType::Range:
            return [this](const void* mem) {
                const T val = *static_cast<const T*>(mem);
                const T min = *reinterpret_cast<const T*>(valueBytes.data());
                const T max = *reinterpret_cast<const T*>(valueBytesSecond.data());
                return val > min && val < max;
            };
            
        case ScanType::Increased: {
            const size_t valueSize = sizeof(T);
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                return *static_cast<const T*>(mem) > 
                       *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
            };
        }
            
        case ScanType::IncreasedBy: {
            const size_t valueSize = sizeof(T);
            if constexpr (std::is_floating_point_v<T>) {
                return [this, valueSize](const void* mem) {
                    const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                    if (idx * valueSize >= latestValues.size()) return false;
                    const T current = *static_cast<const T*>(mem);
                    const T previous = *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
                    const T expected = *reinterpret_cast<const T*>(valueBytes.data());
                    return std::abs(current - previous - expected) < static_cast<T>(0.001);
                };
            }
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                const T current = *static_cast<const T*>(mem);
                const T previous = *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
                const T expected = *reinterpret_cast<const T*>(valueBytes.data());
                return current - previous == expected;
            };
        }
            
        case ScanType::Decreased: {
            const size_t valueSize = sizeof(T);
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                return *static_cast<const T*>(mem) < 
                       *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
            };
        }
            
        case ScanType::DecreasedBy: {
            const size_t valueSize = sizeof(T);
            if constexpr (std::is_floating_point_v<T>) {
                return [this, valueSize](const void* mem) {
                    const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                    if (idx * valueSize >= latestValues.size()) return false;
                    const T current = *static_cast<const T*>(mem);
                    const T previous = *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
                    const T expected = *reinterpret_cast<const T*>(valueBytes.data());
                    return std::abs(previous - current - expected) < static_cast<T>(0.001);
                };
            }
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                const T current = *static_cast<const T*>(mem);
                const T previous = *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
                const T expected = *reinterpret_cast<const T*>(valueBytes.data());
                return previous - current == expected;
            };
        }
            
        case ScanType::Changed: {
            const size_t valueSize = sizeof(T);
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                return *static_cast<const T*>(mem) != 
                       *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
            };
        }
            
        case ScanType::Unchanged: {
            const size_t valueSize = sizeof(T);
            return [this, valueSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * valueSize >= latestValues.size()) return false;
                return *static_cast<const T*>(mem) == 
                       *reinterpret_cast<const T*>(latestValues.data() + idx * valueSize);
            };
        }
            
        case ScanType::Unknown:
            return [](const void*) {
                return true;
            };
    }
    
    throw std::runtime_error("Invalid scan type");
}

std::function<bool(const void*)> Scanner::getStringComparator() const {
    const size_t stringSize = valueBytes.size();
    
    switch (scanType) {
        case ScanType::Equal:
            return [this, stringSize](const void* mem) {
                return std::memcmp(mem, valueBytes.data(), stringSize) == 0;
            };
            
        case ScanType::Changed: {
            return [this, stringSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * stringSize >= latestValues.size()) return false;
                return std::memcmp(mem, latestValues.data() + idx * stringSize, stringSize) != 0;
            };
        }
            
        case ScanType::Unchanged: {
            return [this, stringSize](const void* mem) {
                const size_t idx = scannedAddresses.load(std::memory_order_relaxed);
                if (idx * stringSize >= latestValues.size()) return false;
                return std::memcmp(mem, latestValues.data() + idx * stringSize, stringSize) == 0;
            };
        }
            
        case ScanType::Unknown:
            return [](const void* mem) {
                const auto* p = static_cast<const uint8_t*>(mem);
                // Check if first two bytes are printable ASCII
                return (p[0] >= ' ' && p[0] <= '~') && (p[1] >= ' ' && p[1] <= '~');
            };
            
        default:
            throw std::runtime_error("Unsupported scan type for string");
    }
}

std::function<bool(const void*)> Scanner::getAOBComparator() const {
    const size_t patternSize = valueBytes.size();
    
    return [this, patternSize](const void* mem) {
        const auto* memPtr = static_cast<const uint8_t*>(mem);
        const uint8_t* patternPtr = valueBytes.data();
        const uint8_t* maskPtr = valueMask.data();
        
        for (size_t i = 0; i < patternSize; ++i) {
            if ((memPtr[i] & maskPtr[i]) != (patternPtr[i] & maskPtr[i])) {
                return false;
            }
        }
        return true;
    };
}

std::function<bool(const void*)> Scanner::getTypeSpecificComparator() const {
    switch (valueType.type) {
        case i64:
            if (valueType.flags & isSigned)
                return getCommonComparator<int64_t>();
            return getCommonComparator<uint64_t>();
            
        case i32:
            if (valueType.flags & isSigned)
                return getCommonComparator<int32_t>();
            return getCommonComparator<uint32_t>();
            
        case i16:
            if (valueType.flags & isSigned)
                return getCommonComparator<int16_t>();
            return getCommonComparator<uint16_t>();
            
        case i8:
            if (valueType.flags & isSigned)
                return getCommonComparator<int8_t>();
            return getCommonComparator<uint8_t>();
            
        case f64:
            return getCommonComparator<double>();
            
        case f32:
            return getCommonComparator<float>();
            
        case string:
            return getStringComparator();
            
        case byteArray:
            return getAOBComparator();
    }
    
    throw std::runtime_error("Invalid value type");
}

void Scanner::newScan() {
    if (isScanRunning.load(std::memory_order_acquire)) {
        throw std::runtime_error("Scan is already running");
    }
    
    isScanRunning.store(true, std::memory_order_release);
    scannedAddresses.store(0, std::memory_order_release);
    
    std::thread([this]() {
        try {
            performNewScan(getTypeSpecificComparator());
        } catch (const std::exception& e) {
            Gui::log("{}: Error during scan: {}", name, e.what());
            isScanRunning.store(false, std::memory_order_release);
        }
    }).detach();
}

void Scanner::nextScan() {
    if (isScanRunning.load(std::memory_order_acquire)) {
        throw std::runtime_error("Scan is already running");
    }
    
    if (isReset.load(std::memory_order_acquire)) {
        throw std::runtime_error("No previous scan exists, use newScan() first");
    }
    
    isScanRunning.store(true, std::memory_order_release);
    scannedAddresses.store(0, std::memory_order_release);
    
    std::thread([this]() {
        try {
            performNextScan(getTypeSpecificComparator());
        } catch (const std::exception& e) {
            Gui::log("{}: Error during scan: {}", name, e.what());
            isScanRunning.store(false, std::memory_order_release);
        }
    }).detach();
}

void Scanner::performNewScan(std::function<bool(const void*)> cmp) {
    ProcessSuspensionGuard guard(shouldSuspendWhileScanning);
    
    std::lock_guard<std::mutex> lock(scanMutex);
    
    uint64_t matchingAddresses = 0;
    uint64_t totalScannedAddresses = 0;
    
    regions.parse();
    
    // Calculate total addresses
    for (const auto& region : regions.regions) {
        const auto regionSize = static_cast<const uint8_t*>(region.end) - 
                               static_cast<const uint8_t*>(region.start);
        totalScannedAddresses += regionSize / fastScanOffset;
    }
    totalAddresses.store(totalScannedAddresses, std::memory_order_release);
    
    // Pre-allocate vectors
    std::vector<uintptr_t> newAddresses;
    std::vector<uint8_t> newLatestValues;
    newAddresses.reserve(std::min(totalScannedAddresses, uint64_t(1000000)));
    newLatestValues.reserve(std::min(totalScannedAddresses * valueBytes.size(), size_t(100000000)));
    
    // Allocate memory buffer
    std::vector<uint8_t> memory(regions.largestRegionSize);
    
    for (const auto& [start, end, mode, offset, device, inodeID, fname] : regions.regions) {
        const size_t regionSize = static_cast<const uint8_t*>(end) - 
                                 static_cast<const uint8_t*>(start);
        
        if (!VirtualMemory::read(start, memory.data(), regionSize)) {
            continue;
        }
        
        Gui::log("{}: Scanning region {:p} - {:p}", name, start, end);
        
        for (size_t i = 0; i + valueBytes.size() <= regionSize; i += fastScanOffset) {
            if (cmp(memory.data() + i)) {
                const uintptr_t address = reinterpret_cast<uintptr_t>(start) + i;
                newAddresses.push_back(address);
                
                // Store latest value
                newLatestValues.insert(newLatestValues.end(), 
                                      memory.data() + i, 
                                      memory.data() + i + valueBytes.size());
                matchingAddresses++;
            }
            scannedAddresses.fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    Gui::log("{}: Scan completed, {} addresses scanned, {} match", 
             name, scannedAddresses.load(), matchingAddresses);
    
    // Update state
    addresses = std::move(newAddresses);
    latestValues = std::move(newLatestValues);
    totalAddresses.store(matchingAddresses, std::memory_order_release);
    scannedAddresses.store(matchingAddresses, std::memory_order_release);
    
    isReset.store(false, std::memory_order_release);
    isScanRunning.store(false, std::memory_order_release);
}

void Scanner::performNextScan(std::function<bool(const void*)> cmp) {
    ProcessSuspensionGuard guard(shouldSuspendWhileScanning);
    
    std::lock_guard<std::mutex> lock(scanMutex);
    
    regions.parse();
    
    uint64_t resAddrIdx = 0;
    uint64_t matchingAddresses = 0;
    uint64_t currentScanIdx = 0;
    
    std::vector<uintptr_t> newAddresses;
    std::vector<uint8_t> newLatestValues;
    newAddresses.reserve(addresses.size());
    newLatestValues.reserve(latestValues.size());
    
    std::vector<uint8_t> memory(regions.largestRegionSize);
    
    for (const auto& [start, end, mode, offset, device, inodeID, fname] : regions.regions) {
        const size_t regionSize = static_cast<const uint8_t*>(end) - 
                                 static_cast<const uint8_t*>(start);
        
        if (!VirtualMemory::read(start, memory.data(), regionSize)) {
            continue;
        }
        
        Gui::log("{}: Scanning region {:p} - {:p}", name, start, end);
        
        const uintptr_t regionStart = reinterpret_cast<uintptr_t>(start);
        const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(end) - valueBytes.size();
        
        // Skip addresses before this region
        while (currentScanIdx < addresses.size() && addresses[currentScanIdx] < regionStart) {
            currentScanIdx++;
        }
        
        // Scan addresses in this region
        while (currentScanIdx < addresses.size() && addresses[currentScanIdx] <= regionEnd) {
            const uintptr_t addr = addresses[currentScanIdx];
            const size_t offsetInRegion = addr - regionStart;
            
            if (offsetInRegion + valueBytes.size() <= regionSize) {
                if (cmp(memory.data() + offsetInRegion)) {
                    newAddresses.push_back(addr);
                    newLatestValues.insert(newLatestValues.end(),
                                          memory.data() + offsetInRegion,
                                          memory.data() + offsetInRegion + valueBytes.size());
                    matchingAddresses++;
                }
            }
            
            currentScanIdx++;
            scannedAddresses.fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    Gui::log("{}: Scan completed, {} addresses scanned, {} match", 
             name, scannedAddresses.load(), matchingAddresses);
    
    // Update state
    addresses = std::move(newAddresses);
    latestValues = std::move(newLatestValues);
    totalAddresses.store(matchingAddresses, std::memory_order_release);
    scannedAddresses.store(matchingAddresses, std::memory_order_release);
    
    isScanRunning.store(false, std::memory_order_release);
}

void Scanner::reset() {
    std::lock_guard<std::mutex> lock(scanMutex);
    
    valueBytes.clear();
    valueBytesSecond.clear();
    valueMask.clear();
    addresses.clear();
    latestValues.clear();
    
    totalAddresses.store(0, std::memory_order_release);
    scannedAddresses.store(0, std::memory_order_release);
    isAutonextEnabled = false;
    isReset.store(true, std::memory_order_release);
    scanType = ScanType::Equal;
    regions = Regions();
    
    Gui::log("{}: Scanner reset", name);
}