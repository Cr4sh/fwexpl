application.obj: src/application.cpp
    $(CC) $(CFLAGS) src/application.cpp

lenovo_SystemSmmAhciAspiLegacyRt.obj: src/lenovo_SystemSmmAhciAspiLegacyRt.cpp
    $(CC) $(CFLAGS) src/lenovo_SystemSmmAhciAspiLegacyRt.cpp
	 
hexdump.obj: ../common/hexdump.cpp
    $(CC) $(CFLAGS) ../common/hexdump.cpp

LLIBS = kernel32.lib user32.lib advapi32.lib shlwapi.lib version.lib

LOBJS = application.obj lenovo_SystemSmmAhciAspiLegacyRt.obj hexdump.obj
