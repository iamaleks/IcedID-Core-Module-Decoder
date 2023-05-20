#pragma once

#include <Windows.h>
#include <immintrin.h>

struct PEHeader {
    ULONGLONG ImageBase;
    DWORD SizeOfImage;
    DWORD AddressOfEntryPoint;
    DWORD IATRva;
    DWORD BaseRelocationRVA;
    DWORD BaseRelocationSize;
    DWORD NumberOfSections;
};

struct SectionHeader {
    DWORD VirtualAddress;
    DWORD VirtualSize;
    DWORD PointerToRawData;
    DWORD SizeOfRawData;
    BYTE SectionPageProtection;
};