#define _WIN32_WINNT  0x0501

#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <windows.h>
#include <Shlwapi.h>

#include "../../common/TlHelp32.h"

#include "../../config.h"

#include "../../common/ntdll_defs.h"
#include "../../common/ntdll_undocnt.h"
#include "../../common/common.h"
#include "../../common/common_expl.h"
#include "../../common/debug.h"
#include "../../common/loader.h"
#include "../../common/service.h"
#include "../../common/service_inf.h"

#include "../../../include/libdsebypass.h"

#include "shellcode.h"
#include "SNCC0_Sys_220010.h"
