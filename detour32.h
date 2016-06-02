/* http://research.microsoft.com/pubs/68568/huntusenixnt99.pdf */
#pragma once
#include <Windows.h>

BOOL DetourProc(IN OUT PVOID Target, IN PVOID Detour, int ByteOffset);
BOOL RetourProc(IN OUT PVOID TargetOrDetour);

#define MAX_DETOURS (32) //TODO: try change this to 64
#define MAX_DETOUR_SIZE (128)
#define TRAMP_NEEDLE (0xDEADBEEF)
#define DetourTrampoline(Type, Conv) ((Type (Conv *)())TRAMP_NEEDLE)

struct DetourInfo {
	PVOID Target, Detour;
};

// .Text trampoline buffer 
__declspec(naked) void __DetourTrampolineBuffer()
{
#define NULL_SHORT	__asm add [eax], al
#define NULL_QWORD	NULL_SHORT NULL_SHORT NULL_SHORT NULL_SHORT
#define NULL_32		NULL_QWORD NULL_QWORD NULL_QWORD NULL_QWORD

	// 8 * 32 * 16 = 4096 bytes
#define TRAMP_BUFFER_SIZE (4096)
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32
	NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32 NULL_32

	// Must be divisible to partition trampoline buffer correctly
	C_ASSERT(TRAMP_BUFFER_SIZE % MAX_DETOURS == 0);

#undef NULL_32
#undef NULL_QWORD
#undef NULL_SHORT
}

BOOL DetourProc(IN OUT PVOID Target, IN PVOID Detour, int ByteOffset)
{
	DWORD dwOldProtect, dwIgnoreProtect;

	static int TrampolineSize = TRAMP_BUFFER_SIZE / MAX_DETOURS;
	static int InfoSize = sizeof(struct DetourInfo);
	if (ByteOffset > TrampolineSize - InfoSize)
		return FALSE;

	PVOID Trampoline = NULL;
	struct DetourInfo *DetourInfo = (PVOID)__DetourTrampolineBuffer;

	// Get pointer to trampoline buffer
	for (size_t i = 0; i < MAX_DETOURS; i++, DetourInfo += TrampolineSize)
	{
		// Select the first empty trampoline
		if (DetourInfo->Target == NULL)
		{
			if (VirtualProtect(DetourInfo, InfoSize, PAGE_EXECUTE_READWRITE, &dwIgnoreProtect))
			{
				Trampoline = (PVOID)(DetourInfo + InfoSize);
				break;
			}
			else
				return FALSE;
		}
	}

	// Create trampoline
	{
		PBYTE pbTrampoline = (PBYTE)Trampoline;
		if (!VirtualProtect(Trampoline, TrampolineSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			return FALSE;

		// Populate detour info
		DetourInfo->Target = Target;
		DetourInfo->Detour = Detour;

		// Copy bytes from target
		for (USHORT i = 0; i < ByteOffset; i++)
			*(pbTrampoline++) = ((PBYTE)Target)[i];

		// Jump to target
		*(pbTrampoline++) = '\xe9';		// jmp
		*(PDWORD)pbTrampoline = ((PBYTE)Target + ByteOffset) - (pbTrampoline + 4);

		if (!VirtualProtect(Trampoline, TrampolineSize, dwOldProtect, &dwIgnoreProtect))
			return FALSE;
	}

	// Replace trampoline needle in detour
	{
		if (!VirtualProtect(Detour, MAX_DETOUR_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			return FALSE;

		PBYTE Haystack = (PBYTE)Detour;
		for (size_t i = 0; i < MAX_DETOUR_SIZE; i++)
		{
			if (*(PDWORD)&Haystack[i] == TRAMP_NEEDLE)
				*(PDWORD)&Haystack[i] = (DWORD)Trampoline;
		}

		if (!VirtualProtect(Detour, MAX_DETOUR_SIZE, dwOldProtect, &dwIgnoreProtect))
			return FALSE;
	}

	// Detour target
	{
		PBYTE pbTarget = (PBYTE)Target;
		if (!VirtualProtect(Target, 1 + 4, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			return FALSE;

		// Jump to detour
		*(pbTarget++) = '\xe9';			// jmp
		*(PDWORD)pbTarget = (PBYTE)Detour - (pbTarget + 4);

		if (!VirtualProtect(Target, 1 + 4, dwOldProtect, &dwIgnoreProtect))
			return FALSE;
	}

	FlushInstructionCache(GetCurrentProcess(), NULL, 0);
	return TRUE;
}

BOOL RetourProc(IN OUT PVOID TargetOrDetour)
{
	// TODO
}