#ifndef HEX_SCAN_VIRTUALMEMORY_H
#define HEX_SCAN_VIRTUALMEMORY_H


namespace VirtualMemory {
    bool read(void* from, void* to, unsigned long long length);
    bool write(void* from, void* to, unsigned long long length);
    
    // Write to executable memory using PTRACE_POKETEXT (for code patching)
    // This works even on read-only code segments
    bool writeCode(void* from, void* to, unsigned long long length);
}

#endif //HEX_SCAN_VIRTUALMEMORY_H
