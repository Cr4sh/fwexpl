#include "stdafx.h"

PVOID m_DriverBase = NULL;
PDEVICE_OBJECT m_DeviceObject = NULL;
UNICODE_STRING m_usDosDeviceName, m_usDeviceName;
//--------------------------------------------------------------------------------------
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS ns = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG InSize = 0, OutSize = 0;

    Irp->IoStatus.Status = ns;
    Irp->IoStatus.Information = 0;

    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) 
    {
        // get IOCTL parameters
        ULONG Code = stack->Parameters.DeviceIoControl.IoControlCode;                
        PREQUEST_BUFFER Buff = (PREQUEST_BUFFER)Irp->AssociatedIrp.SystemBuffer;

        InSize = stack->Parameters.DeviceIoControl.InputBufferLength;
        OutSize = stack->Parameters.DeviceIoControl.OutputBufferLength;

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IRP_MJ_DEVICE_CONTROL 0x%.8x\n", Code);

        // check buffer length
        if (InSize >= sizeof(REQUEST_BUFFER) && OutSize >= sizeof(REQUEST_BUFFER))
        {
            switch (Code)
            {
            case IOCTL_DRV_CONTROL:
                {
                    switch (Buff->Code)
                    {
                    case DRV_CTL_NONE:
                        {
                            // do nothing, just return successful status
                            ns = STATUS_SUCCESS;
                            break;
                        }

                    case DRV_CTL_PHYS_MEM_READ:
                        {
                            if (InSize >= sizeof(REQUEST_BUFFER) + Buff->PhysMemRead.Size)
                            {
                                // read physical memory
                                ns = HwPhysMemRead(
                                    Buff->PhysMemRead.Address,
                                    Buff->PhysMemRead.Size, 
                                    Buff->PhysMemRead.Data
                                );
                            }
                            
                            break;
                        }

                    case DRV_CTL_PHYS_MEM_WRITE:
                        {
                            if (InSize >= sizeof(REQUEST_BUFFER) + Buff->PhysMemWrite.Size)
                            {
                                // write physical memory
                                ns = HwPhysMemWrite(
                                    Buff->PhysMemWrite.Address,
                                    Buff->PhysMemWrite.Size,
                                    Buff->PhysMemWrite.Data
                                );
                            }

                            break;
                        }

                    case DRV_CTL_PORT_READ:
                        {
                            // read I/O port value
                            ns = HwPortRead(Buff->PortRead.Port, Buff->PortRead.Size, &Buff->PortRead.Val);
                            break;
                        }

                    case DRV_CTL_PORT_WRITE:
                        {
                            // write value to I/O port
                            ns = HwPortWrite(Buff->PortWrite.Port, Buff->PortWrite.Size, Buff->PortWrite.Val);
                            break;
                        }

                    case DRV_CTL_PCI_READ:
                        {
                            // read PCI config space register value
                            ns = HwPciRead(Buff->PciRead.Address, Buff->PciRead.Size, &Buff->PciRead.Val);
                            break;
                        }

                    case DRV_CTL_PCI_WRITE:
                        {
                            // write value to PCI config space egister
                            ns = HwPciWrite(Buff->PciWrite.Address, Buff->PciWrite.Size, Buff->PciWrite.Val);
                            break;
                        }

                    case DRV_CTL_SMI_INVOKE:
                        {
                            // invoke SMI via APMC I/O port
                            ns = HwSmiInvoke(Buff->SmiInvoke.Code);                            
                            break;
                        }

                    case DRV_CTL_MEM_ALLOC:
                        {
                            // allocate memory
                            if ((ns = HwMemAlloc(&Buff->MemAlloc.Address, Buff->MemAlloc.Size)) == STATUS_SUCCESS)
                            {
                                // get physical address by virtual
                                ns = HwGetPhysAddr(Buff->MemAlloc.Address, &Buff->MemAlloc.PhysicalAddress);
                            }

                            break;
                        }

                    case DRV_CTL_MEM_FREE:
                        {
                            // free allocated memory
                            ns = HwMemFree(Buff->MemFree.Address);
                            break;
                        }

                    case DRV_CTL_PHYS_ADDR:
                        {
                            // get physical address by virtual
                            ns = HwGetPhysAddr(Buff->PhysAddr.Address, &Buff->PhysAddr.PhysicalAddress);
                            break;
                        }

                    case DRV_CTL_MSR_GET:
                        {
                            // get MSR value
                            ns = HwMsrGet(Buff->MsrGet.Register, &Buff->MsrGet.Value);
                            break;
                        }

                    case DRV_CTL_MSR_SET:
                        {
                            // set MSR value
                            ns = HwMsrSet(Buff->MsrSet.Register, Buff->MsrSet.Value);
                            break;
                        }
#ifdef USE_DSE_BYPASS

                    case DRV_CTL_RESTORE_CR4:
                        {
                            // get bitmask of active processors
                            KAFFINITY ActiveProcessors = KeQueryActiveProcessors();
                            ULONG cr4_val = 0, cr4_current = 0;

                            // enumerate active processors starting from 2-nd
                            for (KAFFINITY i = 1; i < sizeof(KAFFINITY) * 8; i++)
                            {
                                KAFFINITY Mask = 1 << i;

                                if (ActiveProcessors & Mask)
                                {
                                    // bind thread to specific processor
                                    KeSetSystemAffinityThread(Mask);

                                    // read CR4 register of other CPU
                                    cr4_val = _cr4_get();
                                    break;
                                }
                            }

                            if (cr4_val != 0)
                            {
                                // bind thread to first processor
                                KeSetSystemAffinityThread(0x00000001);

                                if ((cr4_current = _cr4_get()) != cr4_val)
                                {
                                    DbgMsg(__FILE__, __LINE__, "Restoring CR4 value from 0x%.8x to 0x%.8x\n", cr4_current, cr4_val);

                                    // restore CR4 register of current CPU
                                    _cr4_set(cr4_val);
                                }
                                else
                                {
                                    DbgMsg(__FILE__, __LINE__, "CR4 is 0x%.8x\n", cr4_current);
                                }

                                ns = STATUS_SUCCESS;
                            }
                            else
                            {
                                DbgMsg(__FILE__, __LINE__, "ERROR: Unable to read CR4 value from 2-nd processor\n");
                            }

                            break;
                        }

#endif // USE_DSE_BYPASS

                    default:
                        {
                            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Unknown control code 0x%x\n", Code);
                            break;
                        }
                    }

                    break;
                }

            default:
                {
                    break;
                }
            }
        }        

        if (ns == STATUS_SUCCESS)
        {
            Irp->IoStatus.Information = InSize;
        }
    }
    else if (stack->MajorFunction == IRP_MJ_CREATE) 
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IRP_MJ_CREATE\n");

        ns = STATUS_SUCCESS;
    }
    else if (stack->MajorFunction == IRP_MJ_CLOSE) 
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IRP_MJ_CLOSE\n");

        ns = STATUS_SUCCESS;
    }

    if (ns != STATUS_PENDING)
    {        
        Irp->IoStatus.Status = ns;             

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return ns;
}
//--------------------------------------------------------------------------------------
void DriverUnload(PDRIVER_OBJECT DriverObject)
{   
    DbgMsg(__FILE__, __LINE__, "DriverUnload()\n");

    // delete device
    IoDeleteSymbolicLink(&m_usDosDeviceName);
    IoDeleteDevice(m_DeviceObject);
}
//--------------------------------------------------------------------------------------
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{

#ifdef USE_DSE_BYPASS

    // check if driver image was loaded by DSE bypass exploit
    if (RegistryPath == NULL && m_DriverBase)
    {
        if (GetKernelBase() == NULL)
        {
            return STATUS_UNSUCCESSFUL;
        }

        /*
            IMPORTANT:
            Here we need to process our own import table because image
            was loaded using libdsebypass instead of kernel PE loader.
        */
        if (!RuntimeProcessImports(m_DriverBase))
        {
            return STATUS_UNSUCCESSFUL;
        }

        // ok, now it's safe to use imported functions as usual
    }
    else

#endif // USE_DSE_BYPASS

    {
        DriverObject->DriverUnload = DriverUnload;
    }

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Driver loaded\n");    

    RtlInitUnicodeString(&m_usDeviceName, L"\\Device\\" DEVICE_NAME);
    RtlInitUnicodeString(&m_usDosDeviceName, L"\\DosDevices\\" DEVICE_NAME);    

    // create driver communication device
    NTSTATUS ns = IoCreateDevice(
        DriverObject, 
        0, 
        &m_usDeviceName, 
        FILE_DEVICE_UNKNOWN, 
        FILE_DEVICE_SECURE_OPEN, 
        FALSE, 
        &m_DeviceObject
    );
    if (NT_SUCCESS(ns))
    {
        for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            DriverObject->MajorFunction[i] = DriverDispatch;
        }

#ifdef USE_DSE_BYPASS

        /*
            This flag must be removed when the driver has been loaded
            by our own loader that using nt!IoCreateDriver().
        */
        m_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
#endif

        ns = IoCreateSymbolicLink(&m_usDosDeviceName, &m_usDeviceName);
        if (NT_SUCCESS(ns))
        {
            return STATUS_SUCCESS;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "IoCreateSymbolicLink() fails: 0x%.8x\n", ns);
        }

        IoDeleteDevice(m_DeviceObject);
    } 
    else 
    {
        DbgMsg(__FILE__, __LINE__, "IoCreateDevice() fails: 0x%.8x\n", ns);
    }

    return STATUS_UNSUCCESSFUL;
}
//--------------------------------------------------------------------------------------
// EoF
