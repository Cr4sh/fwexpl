
driver.obj: src/driver.cpp
    $(CC) $(CFLAGS) src/driver.cpp

debug.obj: src/debug.cpp
    $(CC) $(CFLAGS) src/debug.cpp

common.obj: src/common.cpp
    $(CC) $(CFLAGS) src/common.cpp

hal.obj: src/hal.cpp
    $(CC) $(CFLAGS) src/hal.cpp

runtime.obj: src/runtime/runtime.cpp
    $(CC) $(CFLAGS) src/runtime/runtime.cpp

import.obj: src/runtime/import.cpp
    $(CC) $(CFLAGS) src/runtime/import.cpp

LLIBS = ntoskrnl.lib hal.lib

LOBJS = driver.obj debug.obj common.obj hal.obj runtime.obj import.obj
