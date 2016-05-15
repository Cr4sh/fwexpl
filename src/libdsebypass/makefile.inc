libdsebypass.obj: src/libdsebypass.cpp
    $(CC) $(CFLAGS) src/libdsebypass.cpp

shellcode.obj: src/shellcode.cpp
    $(CC) $(CFLAGS) src/shellcode.cpp

SNCC0_Sys_220010.obj: src/SNCC0_Sys_220010.cpp
    $(CC) $(CFLAGS) src/SNCC0_Sys_220010.cpp

debug.obj: ../common/debug.cpp
    $(CC) $(CFLAGS) ../common/debug.cpp

common.obj: ../common/common.cpp
    $(CC) $(CFLAGS) ../common/common.cpp

common_expl.obj: ../common/common_expl.cpp
    $(CC) $(CFLAGS) ../common/common_expl.cpp
	 
loader.obj: ../common/loader.cpp
    $(CC) $(CFLAGS) ../common/loader.cpp

service.obj: ../common/service.cpp
    $(CC) $(CFLAGS) ../common/service.cpp

service_inf.obj: ../common/service_inf.cpp
    $(CC) $(CFLAGS) ../common/service_inf.cpp

LLIBS = kernel32.lib user32.lib advapi32.lib shlwapi.lib version.lib

LOBJS = libdsebypass.obj shellcode.obj SNCC0_Sys_220010.obj debug.obj common.obj common_expl.obj loader.obj service.obj service_inf.obj
