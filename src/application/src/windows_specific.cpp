#include "stdafx.h"
//--------------------------------------------------------------------------------------
#ifdef _AMD64_

#define IS_CANONICAL_ADDR(_addr_) (((DWORD_PTR)(_addr_) & 0xfffff80000000000) == 0xfffff80000000000)

#define IS_EFI_DXE_ADDR(_addr_) (((DWORD_PTR)(_addr_) & 0xffffffff00000000) == 0 && \
                                 ((DWORD_PTR)(_addr_) & 0x00000000ffffffff) != 0)

#else

#error x64 only

#endif

char *m_szHalNames[] =
{
    "hal.dll",      // Non-ACPI PIC HAL 
    "halacpi.dll",  // ACPI PIC HAL
    "halapic.dll",  // Non-ACPI APIC UP HAL
    "halmps.dll",   // Non-ACPI APIC MP HAL
    "halaacpi.dll", // ACPI APIC UP HAL
    "halmacpi.dll", // ACPI APIC MP HAL
    NULL
};

unsigned long long win_get_efi_boot_services(void)
{
    unsigned long long Ret = 0;

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        PVOID HalAddr = NULL;
        char *lpszHalName = NULL;

        // enumerate loaded kernel modules
        for (DWORD i = 0; i < Info->NumberOfModules; i += 1)
        {            
            char *lpszName = (char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName;

            // match by all of the possible HAL names
            for (DWORD i_n = 0; m_szHalNames[i_n] != NULL; i_n += 1)
            {                
                if (!strcmp(strlwr(lpszName), m_szHalNames[i_n]))
                {
                    // get HAL address and path
                    HalAddr = Info->Modules[i].ImageBase;
                    lpszHalName = lpszName;
                    break;
                }
            }       

            if (lpszHalName)
            {
                break;
            }
        }
        
        if (HalAddr && lpszHalName)
        {
            // load HAL as dynamic library
            HMODULE hModule = LoadLibraryExA(lpszHalName, 0, DONT_RESOLVE_DLL_REFERENCES);
            if (hModule)
            {
                PVOID pHalEfiRuntimeServicesTable = NULL;
                PVOID EfiRuntimeImageAddr = NULL;
                DWORD dwEfiRuntimeImageSize = 0;

                PVOID Func = GetProcAddress(hModule, "HalGetEnvironmentVariableEx");
                if (Func)
                {                    
                    for (DWORD i = 0; i < 0x40; i += 1)
                    {
                        PUCHAR Ptr = RVATOVA(Func, i), Addr = NULL;

                        /*
                            Check for the following code of hal!HalGetEnvironmentVariableEx():
                            
                                cmp     cs:HalFirmwareTypeEfi, 0

                                ...

                                HalEfiRuntimeServicesTable dq ?
                                HalFirmwareTypeEfi db ?
                        */
                        if (*(PUSHORT)Ptr == 0x3d80 /* CMP */)
                        {
                            // get address of hal!HalEfiRuntimeServicesTable
                            Addr = Ptr + *(PLONG)(Ptr + 2) - 1;
                        }
                        else if (*(PUSHORT)(Ptr + 0) == 0x3844 && *(Ptr + 2) == 0x2d /* CMP */)
                        {
                            // get address of hal!HalEfiRuntimeServicesTable
                            Addr = Ptr + *(PLONG)(Ptr + 3) - 1;
                        }

                        if (Addr)
                        {                            
                            // calculate a real kernel address
                            pHalEfiRuntimeServicesTable = (PVOID)RVATOVA(HalAddr, Addr - (PUCHAR)hModule);
                            break;
                        }
                    }
                }

                if (IS_CANONICAL_ADDR(pHalEfiRuntimeServicesTable))
                {
                    PVOID HalEfiRuntimeServicesTable = NULL;

                    DbgMsg(
                        __FILE__, __LINE__, "hal!HalEfiRuntimeServicesTable is at "IFMT"\n", 
                        pHalEfiRuntimeServicesTable
                    );

                    // read hal!HalEfiRuntimeServicesTable value
                    if (uefi_expl_virt_mem_read(
                        (unsigned long long)pHalEfiRuntimeServicesTable, 
                        sizeof(PVOID), (unsigned char *)&HalEfiRuntimeServicesTable))
                    {
                        DbgMsg(
                            __FILE__, __LINE__, "hal!HalEfiRuntimeServicesTable value is "IFMT"\n",
                            HalEfiRuntimeServicesTable
                        );

                        if (IS_CANONICAL_ADDR(HalEfiRuntimeServicesTable))
                        {
                            PVOID EfiGetVariable = NULL;

                            // read EFI_RUNTIME_SERVICES.GetVariable() address
                            if (uefi_expl_virt_mem_read(
                                (unsigned long long)HalEfiRuntimeServicesTable + (sizeof(DWORD_PTR) * 3),
                                sizeof(PVOID), (unsigned char *)&EfiGetVariable))
                            {
                                DbgMsg(
                                    __FILE__, __LINE__, "EFI_RUNTIME_SERVICES.GetVariable() is at "IFMT"\n",
                                    EfiGetVariable
                                );

                                if (IS_CANONICAL_ADDR(EfiGetVariable))
                                {
                                    PUCHAR Addr = (PUCHAR)XALIGN_DOWN((DWORD_PTR)EfiGetVariable, PAGE_SIZE);
                                    DWORD dwMaxSize = 0;

                                    // find EFI image load address by EFI_RUNTIME_SERVICES.GetVariable() address
                                    while (dwMaxSize < PAGE_SIZE * 4)
                                    {
                                        UCHAR Buff[PAGE_SIZE];

                                        // read memory page of EFI image
                                        if (!uefi_expl_virt_mem_read((unsigned long long)Addr, PAGE_SIZE, Buff))
                                        {
                                            break;
                                        }

                                        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)&Buff;

                                        // check for valid DOS header
                                        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && 
                                            pDosHeader->e_lfanew < PAGE_SIZE - sizeof(IMAGE_NT_HEADERS))
                                        {
                                            PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)
                                                RVATOVA(pDosHeader, pDosHeader->e_lfanew);

                                            // check for valid NT header
                                            if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
                                            {                                                
                                                EfiRuntimeImageAddr = Addr;
                                                dwEfiRuntimeImageSize = pNtHeader->OptionalHeader.SizeOfImage;
                                                break;
                                            }
                                        }

                                        Addr -= PAGE_SIZE;
                                        dwMaxSize += PAGE_SIZE;
                                    }
                                }                                
                            }
                        }
                    }
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        __FUNCTION__"() ERROR: Unable to locate hal!HalEfiRuntimeServicesTable\n"
                    );
                }

                if (IS_CANONICAL_ADDR(EfiRuntimeImageAddr) && dwEfiRuntimeImageSize > 0)
                {
                    DbgMsg(
                        __FILE__, __LINE__, "EFI image is at "IFMT" (%d bytes)\n", 
                        EfiRuntimeImageAddr, dwEfiRuntimeImageSize
                    );

                    PUCHAR Image = (PUCHAR)M_ALLOC(dwEfiRuntimeImageSize);
                    if (Image)
                    {
                        // dump EFI runtime image from memory
                        if (uefi_expl_virt_mem_read(
                            (unsigned long long)EfiRuntimeImageAddr, 
                            dwEfiRuntimeImageSize, Image))
                        {
                            PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
                                RVATOVA(Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

                            for (DWORD i = 0; i < 0x100; i += 1)
                            {
                                PUCHAR Ptr = RVATOVA(Image, pHeaders->OptionalHeader.AddressOfEntryPoint + i);

                                /*
                                    Check for the following code at entry point of EFI driver:

                                        mov     rax, cs:qword_AA8DCE98      ; get EFI_BOOT_SERVICES address
                                        call    qword ptr [rax+140h]        ; call LocateProtocol function
                                */
                                if (*(Ptr + 0x00) == 0x48 && *(Ptr + 0x01) == 0x8b && *(Ptr + 0x02) == 0x05 &&
                                    *(Ptr + 0x07) == 0xff && *(Ptr + 0x08) == 0x90 && *(PDWORD)(Ptr + 0x09) == 0x140)
                                {
                                    // get address of variable that points to EFI_BOOT_SERVICES
                                    PVOID *pEfiBootServices = (PVOID *)(Ptr + *(PLONG)(Ptr + 3) + 7);                                                                                

                                    if (IS_EFI_DXE_ADDR(*pEfiBootServices))
                                    {                                            
                                        DbgMsg(
                                            __FILE__, __LINE__,
                                            "EFI_BOOT_SERVICES address is "IFMT"\n", *pEfiBootServices
                                        );

                                        Ret = (unsigned long long)*pEfiBootServices;
                                    }
                                        
                                    break;
                                }
                            }

                            if (Ret == 0)
                            {
                                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to locate EFI_BOOT_SERVICES\n");
                            }                                                       
                        }

                        M_FREE(Image);
                    }
                }

                FreeLibrary(hModule);
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\n", GetLastError());
            }
        } 
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to locate HAL.DLL\n");
        }

        M_FREE(Info);
    }

    return Ret;
}
//--------------------------------------------------------------------------------------
DWORD WINAPI s3_sleep_thread(LPVOID lpParam)
{
    Sleep(300);

    // put computer into the sleep
    SetSuspendState(FALSE, TRUE, FALSE);
    
    return 0;
}

int s3_sleep_with_timeout(int seconds)
{
    int ret = -1;
    SYSTEM_POWER_CAPABILITIES PowerCapabilities;

    if (!GetPwrCapabilities(&PowerCapabilities))
    {
        DbgMsg(__FILE__, __LINE__, "GetPwrCapabilities() ERROR %d\n", GetLastError());
        return -1;
    }

    if (!PowerCapabilities.SystemS3)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: S3 sleep is not supoprted on this system\n");
        return -1;
    }

    // create waitable timer to wake up computer from sleep
    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (hTimer)
    {        
        char szMessage[0x100];

        sprintf(
            szMessage, 
            "System is going to S3 sleep for %d seconds.\n"
            "Press the power button if it will not wake up atomatically.\n", seconds);

        MessageBox(0, szMessage, "Warning", MB_ICONWARNING);

        LARGE_INTEGER Time;
        Time.QuadPart = seconds * -1 * 1000 * 1000 * 10;

        if (SetWaitableTimer(hTimer, &Time, 0, NULL, NULL, TRUE))
        {
            HANDLE hThread = CreateThread(NULL, 0, s3_sleep_thread, NULL, 0, NULL);
            if (hThread)
            {
                HANDLE Events[] = { hTimer, hThread };

                // wait till wakeup
                WaitForMultipleObjects(2, Events, FALSE, INFINITE);                
                CloseHandle(hThread);

                ret = 0;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n", GetLastError());
            }
        }       
        else
        {
            DbgMsg(__FILE__, __LINE__, "SetWaitableTimer() ERROR %d\n", GetLastError());
        }

        CloseHandle(hTimer);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateWaitableTimer() ERROR %d\n", GetLastError());
    }
        
    return ret;
}
//--------------------------------------------------------------------------------------
// EoF
