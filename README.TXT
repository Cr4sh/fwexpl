
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

  --target <N> — Select known target where <N> is a target number.
  
  --target-list — Print all known targets information.

  --target-addr - Use manual address of EFI_BOOT_SERVICES.LocateProtocol field for SystemSmmAhciAspiLegacyRt exploit. This option will be ignored if --target was specified.

  --target-smi - Use manual SMI handler number for SystemSmmAhciAspiLegacyRt exploit. This option will be ignored if --target was specified. If --target-addr was specified without --target-smi — SystemSmmAhciAspiLegacyRt exploit will check all of the possible SMI handlers from 0 to 255.

  --smram-dump — Determinate current SMRAM address and dump it contents to file.
  
  --phys-mem-read <addr> — Read physical memory starting from specified address.
  
  --phys-mem-write <addr> — Write physical memory starting from specified address.
  
  --length <bytes> — Number of bytes to read or write for --phys-mem-read and --phys-mem-write.  
  
  --file <path> — Memory dump path to read or write, in case of --phys-mem-read this parameter is optional and when it's not specified — application will print a hex dump of physical memory to stdout. In case of --smram-dump this parameter is mandatory.
  
  --exec <addr> — Execute SMM code at specified physical memory address.

  --dse-bypass — Install and exploit Secret Net 7.4 driver to bypass Windows x64 DSE.  

  --test — Run some basic libfwexpl tests.

Please note, that --dse-bypass option requires sncc0.sys file (digitally signed vulnerable driver from Secret Net) in the same directory with fwexpl_app_amd64.exe, this file can be downloaded here: 

https://mega.nz/#!ydEnSabK!H63Yw44POR0dO02WAh-f1eqgHaWeeqlqP75_XwIzw_4


Usage examples:

  > fwexpl_app_amd64.exe --target 1 — Test run of SMM exploit without payload;

  > fwexpl_app_amd64.exe --target 1 --phys-mem-read 0x86000000 --size 0x1000 — Read 4096 bytes of physical memory starting from 0x86000000 and print it's hexadecimal dump to stdout.

  > fwexpl_app_amd64.exe --target 1 --phys-mem-write 0x86000000 --file mem.bin — Read data stored in mem.bin file and copy it to physical memory starting from 0x86000000.


To compile a whole project from the source code:

  1) Download and install WDK for Windows 7 or later.

  2) Open WDK build environment for 64-bit versions of Windows.

  3) Change current directory to src/ and run build_amd64.bat scenario.


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh

