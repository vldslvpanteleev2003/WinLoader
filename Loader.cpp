#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>
#include <format>
#include "headers.h"
#include "RelocSection.h"

int main()
{
    std::ifstream file("C:\\Users\\admin\\Desktop\\MessageBoxDLL.dll", std::ifstream::binary);
    if (!file)
    {
        MessageBoxW(NULL, (LPCWSTR)L"File reading failed", (LPCWSTR)L"Error", MB_DEFBUTTON1);
        exit(1);
    }
    file.seekg(0, file.end);
    int length = file.tellg();
    file.seekg(0, file.beg);

    std::vector<uint8_t> Buffer(length);
    file.read(reinterpret_cast<char*>(Buffer.data()), length);

    IMAGE_DOS_HEADER* dos{ reinterpret_cast<IMAGE_DOS_HEADER*>(Buffer.data()) };

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << std::format("File is not pe") << std::endl;
    }

    IMAGE_NT_HEADERS* nt{ reinterpret_cast<IMAGE_NT_HEADERS*>(Buffer.data() + dos->e_lfanew) };

    IMAGE_FILE_HEADER* fileHeader{ &nt->FileHeader };

    IMAGE_OPTIONAL_HEADER* optionalHeader{ &nt->OptionalHeader };
    
    DWORD imageSize{ optionalHeader->SizeOfImage };

    DWORD headerSize{ optionalHeader->SizeOfHeaders };

    WORD numberOfSec{ fileHeader->NumberOfSections };

    BYTE* ImageBase{ reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) };

    IMAGE_SECTION_HEADER* section{ IMAGE_FIRST_SECTION(nt) };

    memcpy(ImageBase, Buffer.data(), headerSize);

    for (int i = 0; i < numberOfSec; i++)
    {
        void* dst{ ImageBase + section[i].VirtualAddress };

        const void* src{ Buffer.data() + section[i].PointerToRawData };

        memcpy(dst, src, section[i].SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY importDir{ optionalHeader->DataDirectory[1] };

    DWORD importDirRva{ importDir.VirtualAddress };

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor{ reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ImageBase + importDirRva) };

    /*IAT резолвинг*/
    for (; importDescriptor->Name != 0; importDescriptor++)
    {
        const char* dllname{ reinterpret_cast<const char*>(ImageBase + importDescriptor->Name) };
        std::cout << dllname << std::endl;
        DWORD OriginalFirstThunkRva{ importDescriptor->OriginalFirstThunk };
        DWORD FirstThunkRva{ importDescriptor->FirstThunk };
        uint64_t* IATFunctionAddress{ reinterpret_cast<uint64_t*>(ImageBase + FirstThunkRva) };
        std::cout << std::format("OriginalFirstThunk: {:x}\n\n\n", OriginalFirstThunkRva);
        HMODULE module{ LoadLibraryA(dllname) };
        for (uint64_t* rvaFunction{ reinterpret_cast<uint64_t*>(ImageBase + OriginalFirstThunkRva) }; *rvaFunction != 0; rvaFunction = rvaFunction + 1, IATFunctionAddress = IATFunctionAddress + 1)
        {
            /*Поиск адресов по FunctionName*/
            if (!(*rvaFunction & 0x8000000000000000)) /*Проверка на флаг ordinal*/
            {
                std::cout << std::format("rvaFunction: {:x}\n\n", *rvaFunction);
                NameFunction* functionName{ reinterpret_cast<NameFunction*>(ImageBase + *rvaFunction) };
                std::cout << std::format("FunctionName: {}\n\n", functionName->structFunctionName);
                FARPROC proc{ GetProcAddress(module, functionName->structFunctionName) };
                uint64_t functionAddress{ reinterpret_cast<uint64_t>(proc) };
                std::cout << std::format("FunctionAddress: {:x}\n\n\n", functionAddress);
                *IATFunctionAddress = functionAddress;
            }
            /*Поиск адресов ordinal*/
            else 
            {   
                WORD ordinal{ static_cast<WORD>(*rvaFunction) };
                std::cout << std::format("Ordinal: {}\n\n", ordinal);
                FARPROC proc{ GetProcAddress(module, reinterpret_cast<LPCSTR>(ordinal)) };
                uint64_t functionAddress{ reinterpret_cast<uint64_t>(proc) };
                std::cout << std::format("FunctionAddress: {:x}\n\n\n", functionAddress);
                *IATFunctionAddress = functionAddress;
            }
        }

    }
    /*IAT резолвинг*/

    /*relocations резолвинг*/
    IMAGE_DATA_DIRECTORY relocDir{ optionalHeader->DataDirectory[5] };
    if (DWORD relocDirRva{ relocDir.VirtualAddress })
    {
        uint64_t blockSize = 0;
        do
        {
            StructRelocSection* relocSection = reinterpret_cast<StructRelocSection*>(ImageBase + relocDir.VirtualAddress + blockSize);
            DWORD count = (relocSection->SizeOfBlock - sizeof(StructRelocSection::VirtualAddress) - sizeof(StructRelocSection::SizeOfBlock)) / sizeof(WORD);
            if (!relocSection->SizeOfBlock)
            {
                break;
            }
            std::cout << std::format("{}\n", count);
            uint64_t delta = reinterpret_cast<uint64_t>(ImageBase) - optionalHeader->ImageBase;
            std::cout << std::format("Delta: {:x}\nImageBase: {:x}\nActualImageBase: {:x}\n\n", delta, optionalHeader->ImageBase, reinterpret_cast<uint64_t>(ImageBase));
            for (int i{ 0 }; i < count; i++)
            {
                if (relocSection->TypeOffset[i])
                {
                    WORD entry{ relocSection->TypeOffset[i] };
                    WORD type = entry >> 12;
                    WORD offset = entry & 0x0FFF;
                    std::cout << std::format("Type: {:x}\n", type);
                    std::cout << std::format("Ofsset: {:x}\n", offset);
                    uintptr_t* relocAddress = reinterpret_cast<uint64_t*>(ImageBase + relocSection->VirtualAddress + offset);
                    std::cout << std::format("Reloc address: {:x}\n", reinterpret_cast<uintptr_t>(relocAddress));
                    std::cout << std::format("Reloc before: {:x}\n", *relocAddress);
                    *relocAddress = *relocAddress + delta;
                    std::cout << std::format("Reloc after: {:x}\n", *relocAddress);
                }
            }
            blockSize += relocSection->SizeOfBlock;

        } while (true);
    }
    else
    {
        std::cout << std::format("Section .reloc wasn't found.\n");
    }
    /*relocations резолвинг*/

    /*Вызов DLLmain*/
    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    DllMain_t dllMain = reinterpret_cast<DllMain_t>(ImageBase + optionalHeader->AddressOfEntryPoint);

    dllMain((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, nullptr);

    /*Вызов DLLmain*/
}
