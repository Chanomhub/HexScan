#include "virtualMemory.h"
#include "../selectedProcess/selectedProcess.h"

#include <cstdio>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <algorithm>

#include "../../gui/gui.h"
#include "../debugger/accessTracker.h"

// Helper to open /proc/pid/mem
static int openMemFd(pid_t pid, int flags) {
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    return open(path.c_str(), flags);
}

bool VirtualMemory::read(void* from, void* to, const unsigned long long length) {
    if (SelectedProcess::pid == -1) return false;

    // Use /proc/pid/mem which works even if process is ptraced by another thread
    int fd = openMemFd(SelectedProcess::pid, O_RDONLY);
    if (fd == -1) {
        // Fallback to process_vm_readv if open fails (though sudo should prevent this)
         const iovec local[1] = {{to, length}};
         const iovec remote[1] = {{from, length}};
         const ssize_t nread = process_vm_readv(SelectedProcess::pid, local, 1, remote, 1, 0);
         return nread > 0;
    }

    // pread reads from specific offset without changing file cursor
    ssize_t nread = pread(fd, to, length, reinterpret_cast<off_t>(from));
    close(fd);

    return nread == static_cast<ssize_t>(length);
}


bool VirtualMemory::write(void* from, void* to, const unsigned long long length) {
    if (SelectedProcess::pid == -1) return false;

    // Use /proc/pid/mem for writing too
    int fd = openMemFd(SelectedProcess::pid, O_WRONLY);
    if (fd == -1) {
         const iovec local[1] = {{from, length}};
         const iovec remote[1] = {{to, length}};
         const ssize_t nwrote = process_vm_writev(SelectedProcess::pid, local, 1, remote, 1, 0);
         return nwrote > 0;
    }

    ssize_t nwrote = pwrite(fd, from, length, reinterpret_cast<off_t>(to));
    close(fd);

    return nwrote == static_cast<ssize_t>(length);
}

bool VirtualMemory::writeCode(void* from, void* to, const unsigned long long length) {
    if (SelectedProcess::pid == -1) return false;
    
    // If AccessTracker is attached, we MUST write through the tracker thread
    if (AccessTracker::isAttached()) {
        return AccessTracker::writeMemory(to, from, length);
    }
    
    pid_t pid = SelectedProcess::pid;
    uint8_t* src = static_cast<uint8_t*>(from);
    uint8_t* dst = static_cast<uint8_t*>(to);
    
    // PTRACE_POKETEXT writes one word (8 bytes on x64) at a time
    // and can write to read-only memory regions
    
    for (unsigned long long offset = 0; offset < length; offset += sizeof(long)) {
        long word = 0;
        size_t remaining = length - offset;
        size_t chunk = std::min(remaining, sizeof(long));
        
        // If we're not writing a full word, we need to read first to preserve other bytes
        if (chunk < sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKTEXT, pid, dst + offset, nullptr);
            if (errno != 0) {
                Gui::log("VirtualMemory::writeCode: PEEKTEXT failed at {:p}: {}", 
                         static_cast<void*>(dst + offset), strerror(errno));
                return false;
            }
        }
        
        // Copy the source bytes into the word
        std::memcpy(&word, src + offset, chunk);
        
        // Write the word
        if (ptrace(PTRACE_POKETEXT, pid, dst + offset, word) == -1) {
            Gui::log("VirtualMemory::writeCode: POKETEXT failed at {:p}: {}", 
                     static_cast<void*>(dst + offset), strerror(errno));
            return false;
        }
    }
    
    return true;
}
