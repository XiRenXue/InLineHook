#pragma once
#include <Windows.h>
//64位下的内联钩子
class InLineHook64 {
    // 12 bytes
    public:
        FARPROC FunctionAddress;
        BYTE OldBytes[12];
        BYTE NewBytes[12];
    public:
        InLineHook64();
        ~InLineHook64();
        BOOL Init(LPCWSTR ModuleName, LPCSTR FuncName, LPVOID FuncAddr);
        BOOL Exit();
};
//32位下的内联钩子
class InLineHook32 {
	// 5 bytes
	public:
		FARPROC FunctionAddress;
		BYTE OldBytes[5];
		BYTE NewBytes[5];
	public:
		InLineHook32();
		~InLineHook32();
		BOOL Init(LPCWSTR ModuleName, LPCSTR FuncName, LPVOID FuncAddr);
		BOOL Exit();
};
