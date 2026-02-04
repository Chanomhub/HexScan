#ifndef HEX_SCAN_VIRTUALMEMORY_H
#define HEX_SCAN_VIRTUALMEMORY_H


namespace VirtualMemory {
    bool read(void* from, void* to, unsigned long long length);
    bool write(void* from, void* to, unsigned long long length);
}

#endif //HEX_SCAN_VIRTUALMEMORY_H
