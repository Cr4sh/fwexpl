#include "stdafx.h"

#ifdef USE_DSE_BYPASS

#include "../../../include/libdsebypass.h"

#ifdef _AMD64_

#pragma comment(lib, "../../lib/libdsebypass_amd64.lib")

#endif
#endif // USE_DSE_BYPASS


#define DRV_REQUEST_INIT(_name_, _code_)                            \
                                                                    \
    REQUEST_BUFFER _name_;                                          \
    ZeroMemory(&_name_, sizeof(_name_));                            \
    _name_.Code = (_code_);


#define DRV_REQUEST_INIT_EX(_name_, _code_, _size_)                 \
                                                                    \
    PREQUEST_BUFFER _name_ = (PREQUEST_BUFFER)M_ALLOC((_size_));    \
    if (_name_)                                                     \
    {                                                               \
        ZeroMemory(_name_, (_size_));                               \
        _name_->Code = (_code_);                                    \
    }


static HANDLE m_hDevice = NULL; 
static BOOL m_bStopService = FALSE;
//--------------------------------------------------------------------------------------
BOOL uefi_drv_device_request(HANDLE hDevice, PREQUEST_BUFFER Request, DWORD dwRequestSize)
{
    BOOL bRet = FALSE;

#ifdef DBG_IOCTL

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Code = 0x%.2x\n", Request->Code);

#endif

    PREQUEST_BUFFER Response = (PREQUEST_BUFFER)M_ALLOC(dwRequestSize);
    if (Response)
    {
        DWORD dwBytes = 0;

        ZeroMemory(Response, dwRequestSize);

        // send request to driver
        if (DeviceIoControl(
            hDevice, IOCTL_DRV_CONTROL,
            Request, dwRequestSize,
            Response, dwRequestSize,
            &dwBytes, NULL))
        {
            memcpy(Request, Response, dwRequestSize);

            bRet = TRUE;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
        }

        M_FREE(Response);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_init(char *driver_path, bool use_dse_bypass)
{
    PWSTR lpszDeviceName = L"\\Device\\" DEVICE_NAME;

    if (driver_path == NULL)
    {
        // use default kernel driver file
        driver_path = DRIVER_DEFAULT_NAME;
    }

    if (m_hDevice)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Already initialized\n");
        return false;
    }

    m_bStopService = FALSE;

    // try to open device if service was already started
    if (DrvOpenDevice(lpszDeviceName, &m_hDevice))
    {
        return true;
    }

    BOOL bAsService = TRUE;    

#ifdef USE_DSE_BYPASS    

    if (use_dse_bypass)
    {
        PVOID Data = NULL;
        DWORD dwDataSize = 0;

        if (ReadFromFile(driver_path, &Data, &dwDataSize))
        {
            // load kernel driver with libdsebypass
            if (kernel_expl_load_driver(Data, dwDataSize))
            {
                bAsService = FALSE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't load driver using libdsebypass\n");
            }

            M_FREE(Data);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't read driver binary\n");
        }
    }
    else

#endif // USE_DSE_BYPASS

    {
        char szDestPath[MAX_PATH];
        GetSystemDirectory(szDestPath, sizeof(szDestPath));
        lstrcat(szDestPath, "\\drivers\\" DRIVER_FILE_NAME);

        // copy driver to the system directory
        if (!CopyFile(driver_path, szDestPath, FALSE))
        {
            DbgMsg(__FILE__, __LINE__, "CopyFile() ERROR %d\n", GetLastError());
        }

        // start service
        if (!(m_bStopService = DrvServiceStart(SERVICE_NAME, szDestPath, NULL)))
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Can't load driver using system service\n");
            return false;
        }
    }

    // open device
    if (DrvOpenDevice(lpszDeviceName, &m_hDevice))
    {

#ifdef USE_DSE_BYPASS

        if (use_dse_bypass && !bAsService)
        {
            /*
                Restore CR4 register value to prevent
                PatchGuard crash because of the SMEP bypass.
            */
            DRV_REQUEST_INIT(Request, DRV_CTL_RESTORE_CR4);

            uefi_drv_device_request(m_hDevice, &Request, sizeof(Request));
        }

#endif // USE_DSE_BYPASS

        return true;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Error while opening kernel driver device\n");
    }

    // cleanup
    if (m_bStopService)
    {
        DrvServiceStop(SERVICE_NAME);
        m_bStopService = FALSE;
    }

    m_hDevice = NULL;

    return false;
}
//--------------------------------------------------------------------------------------
void uefi_expl_uninit(void)
{
    if (m_hDevice)
    {
        CloseHandle(m_hDevice);
        m_hDevice = NULL;
    }

    if (m_bStopService)
    {
        DrvServiceStop(SERVICE_NAME);
        m_bStopService = FALSE;
    }
}
//--------------------------------------------------------------------------------------
bool uefi_expl_is_initialized(void)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_NONE);

    // send dummy control code to the driver
    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
static DWORD uefi_expl_data_size(data_width width)
{
    switch (width)
    {
    case U8: return 1;
    case U16: return 2;
    case U32: return 4;
    case U64: return 8;

    default:

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid data width %d\n", width);
        break;
    }

    return 0;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_phys_mem_read(unsigned long long address, int size, unsigned char *buff)
{
    bool bRet = false;
    DWORD dwRequestSize = sizeof(REQUEST_BUFFER) + size;

    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT_EX(pRequest, DRV_CTL_PHYS_MEM_READ, dwRequestSize);

    if (pRequest == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
        return false;
    }

    pRequest->PhysMemRead.Address = address;
    pRequest->PhysMemRead.Size = size;

    // send memory read request to the driver
    if (uefi_drv_device_request(m_hDevice, pRequest, dwRequestSize))
    {
        // copy data that was returned by driver
        memcpy(buff, &pRequest->PhysMemRead.Data, size);

        bRet = true;
    }

    M_FREE(pRequest);

    return bRet;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_phys_mem_write(unsigned long long address, int size, unsigned char *buff)
{
    bool bRet = false;
    DWORD dwRequestSize = sizeof(REQUEST_BUFFER) + size;

    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT_EX(pRequest, DRV_CTL_PHYS_MEM_WRITE, dwRequestSize);

    if (pRequest == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
        return false;
    }

    pRequest->PhysMemWrite.Address = address;
    pRequest->PhysMemWrite.Size = size;

    // pass memory data to the driver
    memcpy(&pRequest->PhysMemWrite.Data, buff, size);

    // send memory write request to the driver
    if (uefi_drv_device_request(m_hDevice, pRequest, dwRequestSize))
    {        
        bRet = true;
    }

    M_FREE(pRequest);

    return bRet;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_port_read(unsigned short port, data_width size, unsigned long long *val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_PORT_READ);

    Request.PortRead.Port = port;
    Request.PortRead.Size = uefi_expl_data_size(size);

    if (uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)))
    {
        if (val)
        {
            *val = Request.PortRead.Val;
        }

        return true;
    }

    return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_port_write(unsigned short port, data_width size, unsigned long long val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_PORT_WRITE);

    Request.PortWrite.Port = port;
    Request.PortWrite.Size = uefi_expl_data_size(size);
    Request.PortWrite.Val = val;

    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_pci_read(unsigned int address, data_width size, unsigned long long *val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_PCI_READ);

    Request.PciRead.Address = address;
    Request.PciRead.Size = uefi_expl_data_size(size);

    if (uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)))
    {
        if (val)
        {
            *val = Request.PciRead.Val;
        }

        return true;
    }

    return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_pci_write(unsigned int address, data_width size, unsigned long long val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_PCI_WRITE);

    Request.PciWrite.Address = address;
    Request.PciWrite.Size = uefi_expl_data_size(size);
    Request.PciWrite.Val = val;

    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_smi_invoke(unsigned char code)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_SMI_INVOKE);

    Request.SmiInvoke.Code = code;

    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_mem_alloc(int size, unsigned long long *addr, unsigned long long *phys_addr)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_MEM_ALLOC);

    Request.MemAlloc.Size = size;

    if (uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)))
    {
        if (addr)
        {
            *addr = Request.MemAlloc.Address;
        }

        if (phys_addr)
        {
            *phys_addr = Request.MemAlloc.PhysicalAddress;
        }

        return true;
    }

    return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_mem_free(unsigned long long addr)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_MEM_FREE);

    Request.MemFree.Address = addr;

    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_phys_addr(unsigned long long addr, unsigned long long *phys_addr)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_PHYS_ADDR);

    Request.PhysAddr.Address = addr;

    if (uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)))
    {
        if (phys_addr)
        {
            *phys_addr = Request.PhysAddr.PhysicalAddress;
        }

        return true;
    }

    return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_msr_get(unsigned int reg, unsigned long long *val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_MSR_GET);

    Request.MsrGet.Register = reg;

    if (uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)))
    {
        if (val)
        {
            *val = Request.MsrGet.Value;
        }

        return true;
    }

    return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_msr_set(unsigned int reg, unsigned long long val)
{
    if (m_hDevice == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return false;
    }

    // allocate driver request buffer
    DRV_REQUEST_INIT(Request, DRV_CTL_MSR_SET);

    Request.MsrSet.Register = reg;
    Request.MsrSet.Value = val;

    return uefi_drv_device_request(m_hDevice, &Request, sizeof(Request)) ? true : false;
}
//--------------------------------------------------------------------------------------
// EoF
