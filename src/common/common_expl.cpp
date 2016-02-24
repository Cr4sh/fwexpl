#include "stdafx.h"
//--------------------------------------------------------------------------------------
PVOID KernelGetModuleBase(char *lpszModuleName)
{
    PVOID ModuleBase = NULL;
    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        if (strcmp(lpszModuleName, "ntoskrnl.exe"))
        {
            for (ULONG i = 0; i < Info->NumberOfModules; i++)
            {
                char *lpszCurrentModuleName = _strlwr(
                    (char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
                );

                // match image file name
                if (!strcmp(lpszModuleName, lpszCurrentModuleName))
                {
                    ModuleBase = (PVOID)Info->Modules[i].ImageBase;
                    break;
                }
            }
        }
        else
        {
            // return kernel image base
            ModuleBase = (PVOID)Info->Modules[0].ImageBase;
        }

        LocalFree(Info);
    }

    return ModuleBase;
}
//--------------------------------------------------------------------------------------
PVOID KernelGetProcAddr(char *lpszProcName)
{
    PVOID Addr = NULL;
    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        // get kernel address and file name
        PVOID KernelBase = Info->Modules[0].ImageBase;
        char *lpszKernelName = (char *)Info->Modules[0].FullPathName + Info->Modules[0].OffsetToFileName;

        // load kernel image as dynamic library
        HMODULE hKrnl = LoadLibraryExA(lpszKernelName, 0, DONT_RESOLVE_DLL_REFERENCES);
        if (hKrnl)
        {
            // get address of target function
            Addr = GetProcAddress(hKrnl, lpszProcName);
            if (Addr)
            {
                // calculate REAL address of this function
                Addr = (PVOID)((PUCHAR)Addr - (PUCHAR)hKrnl + (PUCHAR)KernelBase);
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "GetProcAddress() ERROR %d\n", GetLastError());
            }

            FreeLibrary(hKrnl);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\n", GetLastError());
        }

        LocalFree(Info);
    }

    return Addr;
}
//--------------------------------------------------------------------------------------
// EoF
