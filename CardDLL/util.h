#include <winscard.h>


#ifndef UTIL_H_INCLUDE
#define UTIL_H_INCLUDE
	
    void printHexString(CHAR* sPrefix, LPBYTE baData, DWORD dataLen);
	INT cmpByte(LPBYTE array1,LPBYTE array2,INT len);
	void copyByte(LPBYTE des, LPBYTE src, INT len);
	CHAR*  sCardGetErrorString(LONG lRetValue);

#endif 