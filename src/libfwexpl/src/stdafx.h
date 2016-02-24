#define _WIN32_WINNT  0x0501

#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <windows.h>
#include <Shlwapi.h>

#include "../../common/TlHelp32.h"

#include "../../config.h"
#include "../../driver/src/drvcomm.h"

#include "../../common/ntdll_defs.h"
#include "../../common/ntdll_undocnt.h"
#include "../../common/common.h"
#include "../../common/service.h"
#include "../../common/debug.h"

#include "../../../include/libfwexpl.h"
