
/* #define USE_RWDRV */

#ifdef _X86_

#define DRIVER_DEFAULT_NAME "fwexpl_i386.sys"

#else _AMD64_

#define USE_DSE_BYPASS
#define DRIVER_DEFAULT_NAME "fwexpl_amd64.sys"

#endif

#ifdef USE_RWDRV

#ifdef USE_DSE_BYPASS
#undef USE_DSE_BYPASS
#endif

// device name to communicate with the driver
#define DEVICE_NAME L"RwDrv"

// driver server name
#define SERVICE_NAME "RwDrv"

// driver file name
#define DRIVER_FILE_NAME "RwDrv.sys"

#else

// device name to communicate with the driver
#define DEVICE_NAME L"fwexpl"

// driver server name
#define SERVICE_NAME "fwexpl"

// driver file name
#define DRIVER_FILE_NAME "fwexpl.sys"

#endif 