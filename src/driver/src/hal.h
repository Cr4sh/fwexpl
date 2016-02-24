
#define APMC_PORT_CONTROL 0x00b2
#define APMC_PORT_DATA    0x00b3

#define PCI_PORT_ADDR     0x0cf8
#define PCI_PORT_DATA     0x0cfc


NTSTATUS HwPhysMemRead(ULONG64 Address, ULONG Size, PUCHAR Data);
NTSTATUS HwPhysMemWrite(ULONG64 Address, ULONG Size, PUCHAR Data);

NTSTATUS HwPortRead(USHORT Port, ULONG Size, PULONG64 Data);
NTSTATUS HwPortWrite(USHORT Port, ULONG Size, ULONG64 Data);

NTSTATUS HwPciRead(ULONG Address, ULONG Size, PULONG64 Data);
NTSTATUS HwPciWrite(ULONG Address, ULONG Size, ULONG64 Data);

NTSTATUS HwSmiInvoke(UCHAR Code);

NTSTATUS HwMemAlloc(PULONG64 Address, ULONG Size);
NTSTATUS HwMemFree(ULONG64 Address);
NTSTATUS HwGetPhysAddr(ULONG64 Address, PULONG64 PhysicalAddress);
