#include <winscard.h>
#include <conio.h>
#include <stdio.h>

#ifndef PCSC_H_INCLUDE
#define PCSC_H_INCLUDE

#define PRIVATE_KEY_LEGNTH 256 //2048 bit

#define PCSC_RESPONSE_SUCCESS 1
#define PCSC_RESPONSE_ERROR 0

#define PCSC_RESPONSE_CODE_SUCCESS 0x9000

	#define PCSC_STATUS(lRetValue, msg)						  \
		if(lRetValue == SCARD_S_SUCCESS)					  \
		{													  \
			printf("\n   " msg  ": %s\n",						  \
					sCardGetErrorString(lRetValue));		  \
		}													  \
		else												  \
		{													  \
			printf("\n   " msg  ": Error 0x%04X %s",		  \
				   lRetValue, sCardGetErrorString(lRetValue)); \
			return lRetValue;								  \
	    }								

	#define PCSC_ERROR(lRetValue, msg)				          \
		if(lRetValue != SCARD_S_SUCCESS)					  \
		{													  \
			printf("\n   " msg  ": Error 0x%04X %s",		  \
				   lRetValue, sCardGetErrorString(lRetValue)); \
			return lRetValue;								  \
		}
	
    #define PCSC_EXIT_ON_ERROR(lRetValue)   	              \
		if(lRetValue != SCARD_S_SUCCESS)					  \
		{													  \
            while(!_kbhit());                                 \
			return 0;								          \
		}

	 #define PCSC_EXIT_ON_RESPONSE_ERROR(lRetValue)   					\
	 if(lRetValue.isSuccess != PCSC_RESPONSE_SUCCESS)					\
		{																\
			printf("Error string: %s\n", lRetValue.errorString);		\
			printf("Error code: %04X\n", lRetValue.sCardResponseCode);	\
			return 0;													\
		}

	struct PCSCResponse {
		int isSuccess;
		int sCardResponseCode;
		char errorString[100];
		BYTE data[256];
	};

	LONG PCSC_Connect(LPTSTR sReader );
	LONG PCSC_ActivateCard(void);
	
	PCSCResponse PCSC_ClearAll(void);
	PCSCResponse PCSC_Select(void);
	PCSCResponse PCSC_Activate(void);
	PCSCResponse PCSC_GetSerial(void);
	PCSCResponse PCSC_CheckPin(BYTE pin[], int pinLength);
	PCSCResponse PCSC_Challenge(void);
	PCSCResponse PCSC_InitImport(BYTE data[], int dataLength, int P2);
	PCSCResponse PCSC_Import(BYTE P1, BYTE size[]);
	PCSCResponse PCSC_Sign(BYTE P1, BYTE hash[], BYTE hashLength);
	PCSCResponse PCSC_SelectFile(BYTE fileIndex[]);
	PCSCResponse PCSC_ReadBinary(BYTE P1, BYTE P2, BYTE LE[], int LELength);
	PCSCResponse PCSC_CheckIfKeyPresent(BYTE KeyID);

	LONG PCSC_Exchange(LPCBYTE pbSendBuffer ,DWORD  cbSendLength ,
					   LPBYTE  pbRecvBuffer ,LPDWORD pcbRecvLength );
	LONG PCSC_Disconnect(void);
	CHAR* PCSC_GetError(unsigned short int code);

#endif