
#ifdef _X86_

#define DRIVER_DEFAULT_NAME "fwexpl_i386.sys"

#else _AMD64_

#define USE_DSE_BYPASS
#define DRIVER_DEFAULT_NAME "fwexpl_amd64.sys"

#endif

// device name to communicate with the driver
#define DEVICE_NAME L"fwexpl"

// driver server name
#define SERVICE_NAME "fwexpl"

// driver file name
#define DRIVER_FILE_NAME "fwexpl.sys"
