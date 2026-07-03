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

    std::vector<uint8_t> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);

    IMAGE_DOS_HEADER* dos{ reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data()) };

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << std::format("File is not pe") << std::endl;
    }

    IMAGE_NT_HEADERS* nt{ reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew) };

    IMAGE_FILE_HEADER* fileHeader{ &nt->FileHeader };

    IMAGE_OPTIONAL_HEADER* optionalHeader{ &nt->OptionalHeader };
    
    DWORD imageSize{ optionalHeader->SizeOfImage };

    DWORD headerSize{ optionalHeader->SizeOfHeaders };

    WORD numberOfSec{ fileHeader->NumberOfSections };

    BYTE* imageBase{ reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) };

    IMAGE_SECTION_HEADER* sectionHeader{ IMAGE_FIRST_SECTION(nt) }; /*Section Headers*/

    memcpy(imageBase, buffer.data(), headerSize); /*копируем заголовок файла*/

    for (int i = 0; i < numberOfSec; i++) /*копируем секции*/
    {
        void* dst{ imageBase + sectionHeader[i].VirtualAddress };

        const void* src{ buffer.data() + sectionHeader[i].PointerToRawData };

        memcpy(dst, src, sectionHeader[i].SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY importDir{ optionalHeader->DataDirectory[1] };

    DWORD importDirRva{ importDir.VirtualAddress };

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor{ reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(imageBase + importDirRva) };

    /*IAT резолвинг*/
    for (; importDescriptor->Name != 0; importDescriptor++)
    {
        const char* dllName{ reinterpret_cast<const char*>(imageBase + importDescriptor->Name) };
        DWORD originalFirstThunkRva{ importDescriptor->OriginalFirstThunk };
        DWORD firstThunkRva{ importDescriptor->FirstThunk };
        uintptr_t* IATFunctionAddress{ reinterpret_cast<uintptr_t*>(imageBase + firstThunkRva) };
        HMODULE module{ LoadLibraryA(dllName) };
        for (uintptr_t* rvaFunction{ reinterpret_cast<uintptr_t*>(imageBase + originalFirstThunkRva) }; *rvaFunction != 0; rvaFunction = rvaFunction + 1, IATFunctionAddress = IATFunctionAddress + 1)
        {
            /*Поиск адресов по FunctionName*/
            if (!(*rvaFunction & 0x8000000000000000)) /*Проверка на флаг ordinal*/
            {
                NameFunction* functionName{ reinterpret_cast<NameFunction*>(imageBase + *rvaFunction) };
                FARPROC proc{ GetProcAddress(module, functionName->structFunctionName) };
                uintptr_t functionAddress{ reinterpret_cast<uintptr_t>(proc) };
                *IATFunctionAddress = functionAddress;
            }
            /*Поиск адресов ordinal*/
            else 
            {   
                WORD ordinal{ static_cast<WORD>(*rvaFunction) };
                FARPROC proc{ GetProcAddress(module, reinterpret_cast<LPCSTR>(ordinal)) };
                uintptr_t functionAddress{ reinterpret_cast<uintptr_t>(proc) };
                *IATFunctionAddress = functionAddress;
            }
        }

    }
    /*IAT резолвинг*/

    /*relocations резолвинг*/
    IMAGE_DATA_DIRECTORY relocDir{ optionalHeader->DataDirectory[5] };
    if (DWORD relocDirRva{ relocDir.VirtualAddress }) /*провека на наличие reloc секции*/
    {
        uintptr_t blockSize = 0;
        do
        {
            StructRelocSection* relocSection = reinterpret_cast<StructRelocSection*>(imageBase + relocDir.VirtualAddress + blockSize);
            DWORD count = (relocSection->SizeOfBlock - sizeof(StructRelocSection::VirtualAddress) - sizeof(StructRelocSection::SizeOfBlock)) / sizeof(WORD); /*считаем количество записей в одном блоке, которые указывают на места с релокациями*/
            if (!relocSection->SizeOfBlock) /*проверка sizeOfblock параметра у блока*/
            {
                break;
            }
            uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - optionalHeader->ImageBase;
            for (int i{ 0 }; i < count; i++)
            {
                if (relocSection->TypeOffset[i]) /*расчитываем адрес значения требующее релокации и меняем значение*/
                {
                    WORD entry{ relocSection->TypeOffset[i] };
                    WORD type = entry >> 12;
                    WORD offset = entry & 0x0FFF;
                    uintptr_t* relocAddress = reinterpret_cast<uint64_t*>(imageBase + relocSection->VirtualAddress + offset);
                    *relocAddress = *relocAddress + delta;
                }
            }
            blockSize += relocSection->SizeOfBlock;

        } while (true);
    }
    /*relocations резолвинг*/

    /*Вызов DLLmain*/

    std::cout << std::format("Calling dllMain\n");

    using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

    DllMain_t dllMain = reinterpret_cast<DllMain_t>(imageBase + optionalHeader->AddressOfEntryPoint);

    dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr);

    /*Вызов DLLmain*/
}
