#define _CRT_SECURE_NO_WARNINGS // Prevent warning about fopen being unsafe - Its a POC, lets live dangerously...

#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <tuple>
#include "Header.h"

/// <summary>
/// Align an address based on a specfic alignment requirement.
/// </summary>
/// <param name="addressToAlign">Address to align.</param>
/// <param name="alignmentRequirement">Alignment requirement.</param>
/// <returns>Aligned address</returns>
DWORD AlignAddress(DWORD addressToAlign, DWORD alignmentRequirement) {

    // Check if already aligned
    if ((addressToAlign % alignmentRequirement) == 0) {
        return addressToAlign;
    }

    int remainder = addressToAlign % alignmentRequirement;
    return addressToAlign + alignmentRequirement - remainder;
}

/// <summary>
/// This will return a PEHeader struct that matches the header format used by the licence.dat file within IcedID.
/// </summary>
/// <param name="pCoreModule">Decoded licence.dat file.</param>
/// <returns>PEHeader struct.</returns>
PEHeader* ParsePEHeader(PBYTE pCoreModule) {

    PEHeader* pPEHeader = (PEHeader*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEHeader));
    if (pPEHeader == NULL) {
        return NULL;
    }

    memcpy(pPEHeader, pCoreModule, sizeof(PEHeader));

    return pPEHeader;

}

std::tuple<PBYTE, DWORD> ReconstructPEFile(PBYTE pCoreModule) {

    PBYTE pBeginningOfHeadlessPE = pCoreModule + 0x81; // Skip the first 0x81 bytes of the file as those are not used.
    PEHeader* pParsedHeadlessPEHeader = ParsePEHeader(pBeginningOfHeadlessPE);

    DWORD size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER);
    PBYTE pReconstructedPEFile = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (pReconstructedPEFile == NULL) {
        return { NULL, 0 };
    }

    /*
        Reconstruct the IMAGE_DOS_HEADER

        All values left as zeros expect the following two:
    */
    ((PIMAGE_DOS_HEADER)pReconstructedPEFile)->e_magic = 'ZM';
    ((PIMAGE_DOS_HEADER)pReconstructedPEFile)->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    /*
        Reconstruct the IMAGE_NT_HEADERS
    */
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(pReconstructedPEFile + ((PIMAGE_DOS_HEADER)pReconstructedPEFile)->e_lfanew);
    pNtHeaders->Signature = 'EP';

    /*
        Reconstruct the IMAGE_FILE_HEADER
    */
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
    pFileHeader->Machine = IMAGE_FILE_MACHINE_AMD64;
    pFileHeader->NumberOfSections = (WORD)pParsedHeadlessPEHeader->NumberOfSections;
    pFileHeader->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

    /*
        Reconstruct the IMAGE_OPTIONAL_HEADER
    */
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = &pNtHeaders->OptionalHeader;
    pOptionalHeader->Magic = 0x20b;
    pOptionalHeader->AddressOfEntryPoint = pParsedHeadlessPEHeader->AddressOfEntryPoint;
    pOptionalHeader->ImageBase = pParsedHeadlessPEHeader->ImageBase;
    pOptionalHeader->SectionAlignment = 0x1000;
    pOptionalHeader->FileAlignment = 0x200;
    pOptionalHeader->SizeOfImage = pParsedHeadlessPEHeader->SizeOfImage;
    pOptionalHeader->SizeOfHeaders = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER);
    pOptionalHeader->Subsystem = 0x2;
    pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pParsedHeadlessPEHeader->IATRva;
    pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pParsedHeadlessPEHeader->BaseRelocationRVA;
    pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = pParsedHeadlessPEHeader->BaseRelocationSize;

    /*
        Allocate enough space to fit the section headers
    */
    size = size + (pFileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    PBYTE pReconstructedPEFileNew = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pReconstructedPEFile, size);
    if (pReconstructedPEFileNew == NULL) {
        return { NULL, 0 };
    }
    else {
        pReconstructedPEFile = pReconstructedPEFileNew;
    }

    /*
        Reconstruct Section Headers
    */

    PIMAGE_SECTION_HEADER pCurrentReconstructedSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    // Used to keep track of the previous sections PointerToRawDataSize
    // This helps to understand what the next PointerToRawData should be, by adding the previous sections PointerToRawData
    // 
    // The inital value of previousPointerToRawData is the total size of the headers, this is because the first section header 
    // in the reconstructed file will be right after all the PE headers.
    DWORD previousPointerToRawData = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER);
    DWORD previousSizeOfRawData = 0;

    for (DWORD currentSectionCount = 0; currentSectionCount < pParsedHeadlessPEHeader->NumberOfSections; currentSectionCount++) {

        // The parsedHeadlessSectionHeader will contain a copy of the section header from the headless PE file
        SectionHeader parsedHeadlessSectionHeader = { 0 };

        // The first section in the headless PE file is 0x20 bytes from the beginning of the file.
        // Each section is 0x11 bytes in size, so for each section we multiply by 0x11 to index into all the section headers.
        PBYTE pCurrentHeadlessSectionPointer = (pBeginningOfHeadlessPE + 0x20) + (0x11 * currentSectionCount);
        memcpy(&parsedHeadlessSectionHeader, pCurrentHeadlessSectionPointer, 0x11);

        // The VirtualSize and VirtualAddress will be kept the same as what is hardcoded in the headless PE file.
        pCurrentReconstructedSectionHeader->VirtualAddress = parsedHeadlessSectionHeader.VirtualAddress;
        pCurrentReconstructedSectionHeader->Misc.VirtualSize = parsedHeadlessSectionHeader.VirtualSize;

        if (parsedHeadlessSectionHeader.SectionPageProtection == PAGE_EXECUTE_READ) {
            pCurrentReconstructedSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        }
        else if (parsedHeadlessSectionHeader.SectionPageProtection == PAGE_READWRITE) {
            pCurrentReconstructedSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        }

        // The PointerToRawData and SizeOfRawData will be aligned based on OptionalHeader->FileAlignment
        // This is because we are storing the sections in a new format ourselves, so we can do whatever we want.
        DWORD newPointerToRawData = previousPointerToRawData + previousSizeOfRawData + 1;
        pCurrentReconstructedSectionHeader->PointerToRawData = AlignAddress(newPointerToRawData, pOptionalHeader->FileAlignment);
        previousPointerToRawData = pCurrentReconstructedSectionHeader->PointerToRawData;

        pCurrentReconstructedSectionHeader->SizeOfRawData = AlignAddress(parsedHeadlessSectionHeader.SizeOfRawData, pOptionalHeader->FileAlignment);
        previousSizeOfRawData = pCurrentReconstructedSectionHeader->SizeOfRawData;

        // Increment to next section header to reconstruct
        pCurrentReconstructedSectionHeader++;

    }


    // Calculate the new size of all the section data, and reallocate enough space
    DWORD additionalSize = (previousPointerToRawData + previousSizeOfRawData) - (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER) + 1);

    size = size + additionalSize;
    pReconstructedPEFileNew = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pReconstructedPEFile, size);
    if (pReconstructedPEFileNew == NULL) {
        return { NULL, 0 };
    }
    else {
        pReconstructedPEFile = pReconstructedPEFileNew;
    }

    /*
        Copy over the section data into the reconstructed file.
    */
    pCurrentReconstructedSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    for (DWORD currentSectionCount = 0; currentSectionCount < pParsedHeadlessPEHeader->NumberOfSections; currentSectionCount++) {

        // The parsedHeadlessSectionHeader will contain a copy of the section header from the headless PE file
        SectionHeader parsedHeadlessSectionHeader = { 0 };

        // The first section in the headless PE file is 0x20 bytes from the beginning of the file.
        // Each section is 0x11 bytes in size, so for each section we multiply by 0x11 to index into all the section headers.
        PBYTE pCurrentHeadlessSectionPointer = (pBeginningOfHeadlessPE + 0x20) + (0x11 * currentSectionCount);
        memcpy(&parsedHeadlessSectionHeader, pCurrentHeadlessSectionPointer, 0x11);

        PBYTE pSourceSectionAddress = parsedHeadlessSectionHeader.PointerToRawData + pBeginningOfHeadlessPE;
        PBYTE pDestinationSectionAddress = pCurrentReconstructedSectionHeader->PointerToRawData + pReconstructedPEFile;
        memcpy(pDestinationSectionAddress, pSourceSectionAddress, parsedHeadlessSectionHeader.SizeOfRawData);

        // Increment to next section header to reconstruct
        pCurrentReconstructedSectionHeader++;
    }

    return { pReconstructedPEFile, size };
}

/// <summary>
/// This function will parse the IcedID licence.dat file and decode it.
/// </summary>
/// <param name="pSecondStage">Encoded licence.dat file, this same buffer will be decoded.</param>
/// <param name="sizeOfSecondStage">Size of the file</param>
/// <returns></returns>
int DecodeRoutine(PBYTE pSecondStage, DWORD sizeOfSecondStage) {

    DWORD sizeOfSecondStageMinusXORBytes = sizeOfSecondStage - 0x10;
    PDWORD pXORBytes = (PDWORD)((PBYTE)pSecondStage + sizeOfSecondStageMinusXORBytes);

    for (DWORD i = 0; i < sizeOfSecondStageMinusXORBytes; i++) {

        DWORD xorBytesIndex1 = i & 3;
        DWORD xorBytesIndex2 = (i + 1) & 3;

        BYTE xorByte = *((PBYTE)&pXORBytes[xorBytesIndex1]) + *((PBYTE)&pXORBytes[xorBytesIndex2]);

        pSecondStage[i] = pSecondStage[i] ^ xorByte;

        BYTE rollNumber = *((PBYTE)&pXORBytes[xorBytesIndex2]) & 0x7;
        DWORD bytesToRoll = pXORBytes[xorBytesIndex1];

        __asm {
            push ecx
            push ebx

            mov cl, rollNumber
            mov ebx, bytesToRoll

            ror ebx, cl
            mov bytesToRoll, ebx


            pop ecx
            pop ebx
        }

        pXORBytes[xorBytesIndex1] = ++bytesToRoll;

        rollNumber = bytesToRoll & 0x7;
        bytesToRoll = pXORBytes[xorBytesIndex2];

        __asm {
            push ecx
            push ebx

            mov cl, rollNumber
            mov ebx, bytesToRoll

            ror ebx, cl
            mov bytesToRoll, ebx


            pop ecx
            pop ebx
        }

        pXORBytes[xorBytesIndex2] = ++bytesToRoll;

    }

    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::printf("[-] IcedID licence.dat file missing.\n");
        std::printf("[-] Try running: %s C:\\path\\to\\licence.dat\n", argv[0]);
        return 0;
    }
    else {
        std::printf("[+] Opening and parsing %s\n", argv[1]);
    }

    // Read in the licence.dat file
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    PBYTE pIcedIDPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (pIcedIDPayload == NULL) {
        return 0;
    }

    if (file.read((char*)pIcedIDPayload, size))
    {
        // Decode and reconstruct the encoded file
        DecodeRoutine(pIcedIDPayload, size);
        auto [pReconstructedFile, reconstructedFileSize] = ReconstructPEFile(pIcedIDPayload);

        if (pReconstructedFile == NULL || reconstructedFileSize == 0) {
            std::printf("[-] An error occured during decoding for reconstruction.");
            return 0;
        }
        else {
            std::printf("[+] Decoding and reconstruction looks to be a success!\n");
        }

        // Output path of reconstructed file will be the same path this program was run from.
        std::filesystem::path outputFileName = std::filesystem::current_path() / "IcedIDCoreModule.dat";

        // Write out for debugging.
        FILE* pFile;
        pFile = fopen(outputFileName.string().c_str(), "wb");
        fwrite(pReconstructedFile, 1, (size_t)reconstructedFileSize, pFile);
        fclose(pFile);

        std::printf("[+] Reconstructed file has been written to %s\n", outputFileName.string().c_str());
        HeapFree(GetProcessHeap(), NULL, pReconstructedFile);

        return 0;
    }
}