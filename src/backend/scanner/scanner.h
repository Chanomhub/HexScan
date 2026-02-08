#ifndef HEX_SCAN_SCANNER_H
#define HEX_SCAN_SCANNER_H

#include "../regions/regions.h"
#include "../CTvalue/CTvalue.h"
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <memory>
#include <cstdint>

/**
 * Scan types for memory scanning operations
 */
enum class ScanType : uint8_t {
    Equal,
    Bigger,
    Smaller,
    Range,
    Increased,
    IncreasedBy,
    Decreased,
    DecreasedBy,
    Changed,
    Unchanged,
    Unknown
};

/**
 * Scanner class for memory scanning operations
 * Thread-safe for concurrent reads, but only one scan at a time is allowed
 */
class Scanner {
private:
    // Core data
    std::string name;
    std::vector<uintptr_t> addresses;
    std::vector<uint8_t> latestValues;
    
    // Thread-safe state
    std::atomic<uint64_t> totalAddresses{0};
    std::atomic<uint64_t> scannedAddresses{0};
    std::atomic<bool> isScanRunning{false};
    std::atomic<bool> isReset{true};
    mutable std::mutex scanMutex;
    
    // Scan configuration
    Regions regions;
    ScanType scanType = ScanType::Equal;
    CTvalue valueType = i32;
    unsigned fastScanOffset = 4;
    bool shouldSuspendWhileScanning = false;
    bool isAutonextEnabled = false;
    bool isLiveScan = false;
    std::atomic<bool> shouldCancelScan{false};
    
    // Scan data
    std::vector<uint8_t> valueBytes;
    std::vector<uint8_t> valueBytesSecond;
    std::vector<uint8_t> valueMask;
    
    // Private helper methods
    template<typename T>
    std::function<bool(const void*)> getCommonComparator() const;
    
    std::function<bool(const void*)> getStringComparator() const;
    std::function<bool(const void*)> getAOBComparator() const;
    std::function<bool(const void*)> getTypeSpecificComparator() const;
    
    void performNewScan(std::function<bool(const void*)> cmp);
    void performNextScan(std::function<bool(const void*)> cmp);

public:
    /**
     * Constructor
     * @param name Scanner name for logging
     */
    explicit Scanner(std::string_view name);
    
    /**
     * Destructor
     */
    ~Scanner() = default;
    
    // Disable copy and move (because of std::atomic)
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
    Scanner(Scanner&&) = delete;
    Scanner& operator=(Scanner&&) = delete;
    
    /**
     * Performs a new scan across all memory regions
     * @throws std::runtime_error if scan is already running
     */
    void newScan();
    
    /**
     * Rescans existing addresses from previous scan
     * @throws std::runtime_error if no previous scan exists or scan is running
     */
    void nextScan();
    
    /**
     * Resets scanner state
     */
    void reset();
    
    // Getters
    const std::string& getName() const { return name; }
    uint64_t getTotalAddresses() const { return totalAddresses.load(std::memory_order_acquire); }
    uint64_t getScannedAddresses() const { return scannedAddresses.load(std::memory_order_acquire); }
    bool isRunning() const { return isScanRunning.load(std::memory_order_acquire); }
    bool hasBeenReset() const { return isReset.load(std::memory_order_acquire); }
    
    std::vector<uintptr_t> getAddresses() const {
        std::lock_guard<std::mutex> lock(scanMutex);
        return addresses;
    }
    
    std::vector<uint8_t> getLatestValues() const {
        std::lock_guard<std::mutex> lock(scanMutex);
        return latestValues;
    }
    
    ScanType getScanType() const { return scanType; }
    CTvalue getValueType() const { return valueType; }
    unsigned getFastScanOffset() const { return fastScanOffset; }
    bool getShouldSuspendWhileScanning() const { return shouldSuspendWhileScanning; }
    bool getIsAutonextEnabled() const { return isAutonextEnabled; }
    
    // Regions access
    Regions& getRegions() { return regions; }
    const Regions& getRegions() const { return regions; }
    
    // Setters with validation
    void setScanType(ScanType type) { 
        scanType = type; 
    }
    
    void setValueType(CTvalue type) { 
        valueType = type; 
    }
    
    void setFastScanOffset(unsigned offset) { 
        if (offset > 0) {
            fastScanOffset = offset;
        }
    }
    
    void setShouldSuspendWhileScanning(bool suspend) { 
        shouldSuspendWhileScanning = suspend; 
    }
    
    void setIsAutonextEnabled(bool enabled) { 
        isAutonextEnabled = enabled; 
    }

    void setLiveScan(bool enabled) {
        isLiveScan = enabled;
    }
    
    bool getLiveScan() const { return isLiveScan; }
    
    void cancelScan() {
        shouldCancelScan.store(true, std::memory_order_release);
    }
    
    // Value configuration - return pointers for direct modification
    std::vector<uint8_t>& getValueBytesRef() { 
        return valueBytes; 
    }
    
    std::vector<uint8_t>& getValueBytesSecondRef() { 
        return valueBytesSecond; 
    }
    
    std::vector<uint8_t>& getValueMaskRef() { 
        return valueMask; 
    }
    
    const std::vector<uint8_t>& getValueBytes() const { return valueBytes; }
    const std::vector<uint8_t>& getValueBytesSecond() const { return valueBytesSecond; }
    const std::vector<uint8_t>& getValueMask() const { return valueMask; }
    
    // Direct setters
    void setValue(std::vector<uint8_t> bytes) { 
        std::lock_guard<std::mutex> lock(scanMutex);
        valueBytes = std::move(bytes); 
    }
    
    void setValueSecond(std::vector<uint8_t> bytes) { 
        std::lock_guard<std::mutex> lock(scanMutex);
        valueBytesSecond = std::move(bytes); 
    }
    
    void setValueMask(std::vector<uint8_t> mask) { 
        std::lock_guard<std::mutex> lock(scanMutex);
        valueMask = std::move(mask); 
    }
};

#endif // HEX_SCAN_SCANNER_H