
#define USE_RWDRV

// name of the driver to install
#ifdef _X86_

#ifdef USE_RWDRV
#error RwDrv is x64 only
#else
#define DRIVER_DEFAULT_NAME "fwexpl_i386.sys"
#endif

#else _AMD64_

#ifdef USE_RWDRV
#define DRIVER_DEFAULT_NAME "RwDrv.sys"
#else
#define DRIVER_DEFAULT_NAME "fwexpl_amd64.sys"
#define USE_DSE_BYPASS
#endif

#endif

#ifdef USE_RWDRV

// device name to communicate with the driver
#define DEVICE_NAME L"RwDrv"

// driver server name
#define SERVICE_NAME "RwDrv"

// file name of installed driver that will be created in system32/drivers
#define DRIVER_FILE_NAME "RwDrv.sys"

#else

// device name to communicate with the driver
#define DEVICE_NAME L"fwexpl"

// driver server name
#define SERVICE_NAME "fwexpl"

// file name of installed driver that will be created in system32/drivers
#define DRIVER_FILE_NAME "fwexpl.sys"

#endif 