libfwexpl.obj: src/libfwexpl.cpp
    $(CC) $(CFLAGS) src/libfwexpl.cpp

debug.obj: ../common/debug.cpp
    $(CC) $(CFLAGS) ../common/debug.cpp

common.obj: ../common/common.cpp
    $(CC) $(CFLAGS) ../common/common.cpp

service.obj: ../common/service.cpp
    $(CC) $(CFLAGS) ../common/service.cpp
	 
LLIBS = kernel32.lib user32.lib advapi32.lib shlwapi.lib version.lib

LOBJS = libfwexpl.obj debug.obj common.obj service.obj
