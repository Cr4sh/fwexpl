#include "stdafx.h"

#define DBG_BUFF_SIZE 0x1000
//--------------------------------------------------------------------------------------
#ifdef DBG
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list mylist;

    char *lpszBuff = (char *)M_ALLOC(DBG_BUFF_SIZE);
    if (lpszBuff == NULL)
    {
        return;
    }

    char *lpszOutBuff = (char *)M_ALLOC(DBG_BUFF_SIZE);
    if (lpszOutBuff == NULL)
    {
        M_FREE(lpszBuff);
        return;
    }

    va_start(mylist, lpszMsg);
    vsprintf(lpszBuff, lpszMsg, mylist);	
    va_end(mylist);

    sprintf(lpszOutBuff, "%s(%d) : %s", GetNameFromFullPath(lpszFile), Line, lpszBuff);	

    DbgPrint(lpszOutBuff);


    M_FREE(lpszBuff);
    M_FREE(lpszOutBuff);
}
//--------------------------------------------------------------------------------------
#endif // DB
//--------------------------------------------------------------------------------------
// EoF
