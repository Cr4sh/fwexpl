#ifdef __cplusplus

extern "C" 
{

#endif

VOID NTAPI _invlpg(ULONG_PTR Addr);

ULONG_PTR NTAPI _cr3_get(VOID);

VOID NTAPI _cr3_set(ULONG_PTR Val);

ULONG_PTR NTAPI _vmread(ULONG_PTR Code);

#ifdef __cplusplus

}

#endif
