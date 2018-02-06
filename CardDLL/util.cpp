/*
Copyright (c) 2011, Gerhard H. Schalk (www.smartcard-magic.net)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*/
#include <windows.h>
#include <stdio.h>


void printHexString(CHAR* sPrefix, LPBYTE baData, DWORD dataLen)
{
	DWORD i;

	printf("%s", sPrefix);

	for(i = 0; i < dataLen;i++)		
	{
		printf("%02X ",baData[i]);
	}
	
	printf("\n");
}

INT cmpByte(LPBYTE array1,LPBYTE array2,INT len)
{
	INT i;

	for(i = 0; i < len; i++)
	{
		if(*array1++ != *array2++)
		{
			return i ? i: -1;
		}
	}
	return 0;
}

void copyByte(LPBYTE des, LPBYTE src, INT len)
{
	INT i;

	for(i = 0; i < len; i++)
	{
		*des++ = *src++;
	}
}

CHAR*  sCardGetErrorString(LONG lRetValue)
{

	switch(lRetValue)
	{
        case 0x0l:
                return "SCard OK";
                break;

        case 0x80100001:
                return "SCard internal error";
                break;

        case 0x80100002:
                return "SCard cancelled";
                break;

        case 0x80100003:
                return "SCard invalid handle";
                break;

        case 0x80100004:
                return "SCard invalid parameter";
                break;

        case 0x80100005:
                return "SCard invalid target";
                break;

        case 0x80100006:
                return "SCard no memory";
                break;

        case 0x80100007:
                return "SCard waited too long";
                break;

        case 0x80100008:
                return "SCard insufficient buffer";
                break;

        case 0x80100009:
                return "SCard unknown reader";
                break;

        case 0x8010000a:
                return "SCard timeout";
                break;

        case 0x8010000b:
                return "SCard sharing violation";
                break;

        case 0x8010000c:
                return "SCard no smartcard";
                break;

        case 0x8010000d:
                return "SCard unknown card";
                break;

        case 0x8010000e:
                return "SCard cant dispose";
                break;

        case 0x8010000f:
                return "SCard proto mismatch";
                break;

        case 0x80100010:
                return "SCard not ready";
                break;

        case 0x80100011:
                return "SCard invalid value";
                break;

        case 0x80100012:
                return "SCard system cancelled";
                break;

        case 0x80100013:
                return "SCard communications error";
                break;

        case 0x80100014:
                return "SCard unknown error";
                break;

        case 0x80100015:
                return "SCard invalid atr";
                break;

        case 0x80100016:
                return "SCard not transacted";
                break;

        case 0x80100017:
                return "SCard reader unavailable";
                break;

        case 0x80100018:
                return "SCard p shutdown";
                break;

        case 0x80100019:
                return "SCard pci too small";
                break;

        case 0x8010001a:
                return "SCard reader unsupported";
                break;

        case 0x8010001b:
                return "SCard duplicate reader";
                break;

        case 0x8010001c:
                return "SCard card unsupported";
                break;

        case 0x8010001d:
                return "SCard no service";
                break;

        case 0x8010001e:
                return "SCard service stopped";
                break;

        case 0x8010001f:
                return "SCard unexpected";
                break;

        case 0x80100020:
                return "SCard icc installation";
                break;

        case 0x80100021:
                return "SCard icc createorder";
                break;

        case 0x80100022:
                return "SCard unsupported feature";
                break;

        case 0x80100023:
                return "SCard dir not found";
                break;

        case 0x80100024:
                return "SCard file not  ound";
                break;

        case 0x80100025:
                return "SCard no dir";
                break;

        case 0x80100026:
                return "SCard no file";
                break;

        case 0x80100027:
                return "SCard no access";
                break;

        case 0x80100028:
                return "SCard write too many";
                break;

        case 0x80100029:
                return "SCard bad seek";
                break;

        case 0x8010002a:
                return "SCard invalid chv";
                break;

        case 0x8010002b:
                return "SCard unknown res mng";
                break;

        case 0x8010002c:
                return "SCard no such certificate";
                break;

        case 0x8010002d:
                return "SCard certificate unavailable";
                break;

        case 0x8010002e:
                return "SCard no readers available";
                break;

        case 0x80100065:
                return "SCard warning unsupported card";
                break;

        case 0x80100066:
                return "SCard warning unresponsive card";
                break;

        case 0x80100067:
                return "SCard warning unpowered card";
                break;

        case 0x80100068:
                return "SCard warning reset card";
                break;

        case 0x80100069:
                return "SCard warning removed card";
                break;

        case 0x8010006a:
                return "SCard warning security violation";
                break;

        case 0x8010006b:
                return "SCard warning wrong chv";
                break;

        case 0x8010006c:
                return "SCard warning chv blocked";
                break;

        case 0x8010006d:
                return "SCard warning eof";
                break;

        case 0x8010006e:
                return "SCard warning cancelled by user";
                break;

        case 0x0000007b:
                return "SCard inaccessible boot device";
                break;

	default:
		return "invalid error code";

	}
}