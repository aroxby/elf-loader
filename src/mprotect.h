#ifndef __INC_MPROTECT_H_
#define __INC_MPROTECT_H_

#ifdef _WIN32

#include <windows.h>

void unprotect(const void *address, size_t length) {
    DWORD dummy;
    BOOL bRet = VirtualProtect((void*)address, length, PAGE_EXECUTE_READWRITE, &dummy);
    if(!bRet) {
        throw "Error handling not implemented";
    }
}


#else

#include <sys/mman.h>
#include <iostream>

void unprotect(const void *address, size_t length) {
    constexpr int PAGE_SIZE = 0x1000;
    size_t page = (size_t)address / PAGE_SIZE * PAGE_SIZE;
    address = (const void *)page;
    
    int iRet = mprotect((void*)address, length, PROT_READ|PROT_WRITE|PROT_EXEC);
    if(iRet) {
        throw "Error handling not implemented";
    }
}

#endif

#endif//__INC_MPROTECT_H_
