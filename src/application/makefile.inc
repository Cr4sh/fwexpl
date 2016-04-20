application.obj: src/application.cpp
    $(CC) $(CFLAGS) src/application.cpp

windows_specific.obj: src/windows_specific.cpp
    $(CC) $(CFLAGS) src/windows_specific.cpp

lenovo_SystemSmmAhciAspiLegacyRt.obj: src/lenovo_SystemSmmAhciAspiLegacyRt.cpp
    $(CC) $(CFLAGS) src/lenovo_SystemSmmAhciAspiLegacyRt.cpp
	 
hexdump.obj: ../common/hexdump.cpp
    $(CC) $(CFLAGS) ../common/hexdump.cpp

LLIBS = kernel32.lib user32.lib advapi32.lib shlwapi.lib version.lib

LOBJS = application.obj windows_specific.obj lenovo_SystemSmmAhciAspiLegacyRt.obj hexdump.obj
