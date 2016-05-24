#define _WIN32_WINNT  0x0501

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <conio.h>
#include <errno.h>
#include <sys/stat.h>

#include <windows.h>
#include <PowrProf.h>
#include <Shlwapi.h>

#include "../../common/TlHelp32.h"

#include "../../config.h"

#include "../../common/ntdll_defs.h"
#include "../../common/ntdll_undocnt.h"
#include "../../common/common.h"
#include "../../common/memory.h"
#include "../../common/common_expl.h"
#include "../../common/debug.h"
#include "../../common/hexdump.h"

#include "../../../include/libfwexpl.h"

#include "asm/common_asm.h"
#include "windows_specific.h"
#include "lenovo_SystemSmmAhciAspiLegacyRt.h"
