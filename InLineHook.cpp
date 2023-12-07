#include "InLineHook.h"
InLineHook64::InLineHook64() {
	BYTE OldCode[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE NewCode[12] = { 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0 };
	RtlMoveMemory(this->NewBytes, NewCode, 12);
	RtlZeroMemory(this->OldBytes, 12);
	this->FunctionAddress = NULL;
}
InLineHook64::~InLineHook64() {
	this->FunctionAddress = NULL;
	RtlZeroMemory(this->OldBytes, 12);
	RtlZeroMemory(this->NewBytes, 12);
}
BOOL InLineHook64::Init(LPCWSTR ModuleName, LPCSTR FuncName, LPVOID FuncAddr) {
	HMODULE ModuleBase = GetModuleHandleW(ModuleName);
	if (ModuleBase == NULL) return FALSE;
	this->FunctionAddress = GetProcAddress(ModuleBase, FuncName);
	if (this->FunctionAddress == NULL) return FALSE;
	DWORD Protection = 0;
	VirtualProtect(this->FunctionAddress, 12, PAGE_READWRITE, &Protection);
	RtlCopyMemory(this->OldBytes, this->FunctionAddress, 12);
	RtlCopyMemory(this->NewBytes + 2, &FuncAddr, 8);
	RtlCopyMemory(this->FunctionAddress, this->NewBytes, 12);
	VirtualProtect(this->FunctionAddress, 12, Protection, &Protection);
	return TRUE;
}
BOOL InLineHook64::Exit() {
	DWORD Protection = 0;
	VirtualProtect(this->FunctionAddress, 12, PAGE_EXECUTE_READWRITE, &Protection);
	RtlCopyMemory(this->FunctionAddress, OldBytes, 12);
	VirtualProtect(this->FunctionAddress, 12, Protection, &Protection);
	return TRUE;
}

InLineHook32::InLineHook32() {
	BYTE OldCode[5] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE NewCode[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
	RtlMoveMemory(this->NewBytes, NewCode, 5);
	RtlZeroMemory(this->OldBytes, 5);
	this->FunctionAddress = NULL;
}
InLineHook32::~InLineHook32() {
	this->FunctionAddress = NULL;
	RtlZeroMemory(this->OldBytes, 5);
	RtlZeroMemory(this->NewBytes, 5);
}
BOOL InLineHook32::Init(LPCWSTR ModuleName, LPCSTR FuncName, LPVOID FuncAddr) {
	HMODULE ModuleBase = GetModuleHandleW(ModuleName);
	if (ModuleBase == NULL) return FALSE;
	this->FunctionAddress = GetProcAddress(ModuleBase, FuncName);
	if (this->FunctionAddress == NULL) return FALSE;
	DWORD Protection = 0;
	VirtualProtect(this->FunctionAddress, 5, PAGE_READWRITE, &Protection);
	RtlCopyMemory(this->OldBytes, this->FunctionAddress, 5);
	DWORD dwFuncAddr = (DWORD)FuncAddr - (DWORD)this->FunctionAddress - 5;
	RtlCopyMemory(this->NewBytes + 1, &dwFuncAddr, 4);
	RtlCopyMemory(this->FunctionAddress, this->NewBytes, 5);
	VirtualProtect(this->FunctionAddress, 5, Protection, &Protection);
	return TRUE;
}
BOOL InLineHook32::Exit() {
	DWORD Protection = 0;
	VirtualProtect(this->FunctionAddress, 5, PAGE_EXECUTE_READWRITE, &Protection);
	RtlCopyMemory(this->FunctionAddress, OldBytes, 5);
	VirtualProtect(this->FunctionAddress, 5, Protection, &Protection);
	return TRUE;
}
