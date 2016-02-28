#include "stdafx.h"
//--------------------------------------------------------------------------------------
NTSTATUS HwPhysMemRead(ULONG64 Address, ULONG Size, PUCHAR Data)
{        
    // address and size for MmMapIoSpace() must be aligned by page boundary
    ULONG64 MapAddress = XALIGN_DOWN(Address, PAGE_SIZE);
    ULONG MapSize = XALIGN_UP(Size, PAGE_SIZE);

    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = MapAddress;
    
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): address = 0x%llx, size = 0x%x\n", Address, Size);

    // map physical memory
    PVOID Mapped = MmMapIoSpace(PhysicalAddress, MapSize, MmCached);
    if (Mapped == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "MmMapIoSpace() fails\n");
        return STATUS_UNSUCCESSFUL;
    }

    // copy memory contents
    RtlCopyMemory(
        Data, 
        RVATOVA(Mapped, Address - MapAddress),
        Size
    );

    MmUnmapIoSpace(Mapped, MapSize);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwPhysMemWrite(ULONG64 Address, ULONG Size, PUCHAR Data)
{
    // address and size for MmMapIoSpace() must be aligned by page boundary
    ULONG64 MapAddress = XALIGN_DOWN(Address, PAGE_SIZE);
    ULONG MapSize = XALIGN_UP(Size, PAGE_SIZE);

    PHYSICAL_ADDRESS PhysicalAddress;
    PhysicalAddress.QuadPart = MapAddress;
    
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): address = 0x%llx, size = 0x%x\n", Address, Size);

    // map physical memory
    PVOID Mapped = MmMapIoSpace(PhysicalAddress, MapSize, MmCached);
    if (Mapped == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "MmMapIoSpace() fails\n");
        return STATUS_UNSUCCESSFUL;
    }

    // copy memory contents
    RtlCopyMemory(
        RVATOVA(Mapped, Address - MapAddress),
        Data,         
        Size
    );

    MmUnmapIoSpace(Mapped, MapSize);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwPortRead(USHORT Port, ULONG Size, PULONG64 Data)
{
    ULONG64 Val = 0;

    switch (Size)
    {
    case 1:

        Val |= __inbyte(Port);
        break;

    case 2:

        Val |= __inword(Port);
        break;

    case 4:

        Val |= __indword(Port);
        break;

    default:

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid size\n");
        return STATUS_UNSUCCESSFUL;
    }

    *Data = Val;

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwPortWrite(USHORT Port, ULONG Size, ULONG64 Data)
{
    switch (Size)
    {
    case 1:

        __outbyte(Port, (UCHAR)Data);
        break;

    case 2:

        __outword(Port, (USHORT)Data);
        break;

    case 4:

        __outdword(Port, (ULONG)Data);
        break;

    default:

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid size\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwPciRead(ULONG Address, ULONG Size, PULONG64 Data)
{
    ULONG64 Val = 0;

    #define SET_PCI_ADDR() __outdword(PCI_PORT_ADDR, Address)

    switch (Size)
    {
    case 1:

        SET_PCI_ADDR();
        Val |= __inbyte(PCI_PORT_DATA);
        break;

    case 2:

        SET_PCI_ADDR();
        Val |= __inword(PCI_PORT_DATA);
        break;

    case 4:

        SET_PCI_ADDR();
        Val |= __indword(PCI_PORT_DATA);
        break;

    default:

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid size\n");
        return STATUS_UNSUCCESSFUL;
    }

    *Data = Val;

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwPciWrite(ULONG Address, ULONG Size, ULONG64 Data)
{
    #define SET_PCI_ADDR() __outdword(PCI_PORT_ADDR, Address)

    switch (Size)
    {
    case 1:

        SET_PCI_ADDR();
        __outbyte(PCI_PORT_DATA, (UCHAR)Data);
        break;

    case 2:

        SET_PCI_ADDR();
        __outword(PCI_PORT_DATA, (USHORT)Data);
        break;

    case 4:

        SET_PCI_ADDR();
        __outdword(PCI_PORT_DATA, (ULONG)Data);
        break;

    default:

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid size\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwSmiInvoke(UCHAR Code)
{
    // invoke SMI using APMC I/O port
    __outbyte(APMC_PORT_CONTROL, Code);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwMemAlloc(PULONG64 Address, ULONG Size)
{
    PHYSICAL_ADDRESS Limit;
    Limit.QuadPart = 0xffffffff;

    // allocate contiguous memory range in lower 4 GB of physical memory space 
    PVOID Mem = MmAllocateContiguousMemory(Size, Limit);
    if (Mem == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "MmAllocateContiguousMemory() fails\n");
        return STATUS_UNSUCCESSFUL;
    }

    *Address = 0;
    *Address |= (ULONG_PTR)Mem;

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwMemFree(ULONG64 Address)
{
    PVOID Mem = (PVOID)Address;

    MmFreeContiguousMemory(Mem);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwGetPhysAddr(ULONG64 Address, PULONG64 PhysicalAddress)
{
    PVOID Mem = (PVOID)Address;
    PHYSICAL_ADDRESS Ret = MmGetPhysicalAddress(Mem);

    *PhysicalAddress = Ret.QuadPart;

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwMsrGet(ULONG Register, PULONG64 Value)
{   
    *Value = _msr_get(Register);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
NTSTATUS HwMsrSet(ULONG Register, ULONG64 Value)
{
    _msr_set(Register, Value);

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
