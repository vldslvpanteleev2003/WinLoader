#pragma once

#pragma pack(push, 1)
struct StructRelocSection
{
	DWORD VirtualAddress;
	DWORD SizeOfBlock;
	WORD TypeOffset[1];
};
#pragma pack(pop)
